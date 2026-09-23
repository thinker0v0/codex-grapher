"""Offline adversarial socket fixtures; no runtime service or credentials."""

import concurrent.futures
import contextlib
import io
import json
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from control_plane.graph_client import main as client_main, request
from control_plane.graph_service import BoundedConnectionPool, handle
from control_plane.graph_transport import (
    MAX_REQUEST, MAX_RESPONSE, FrameError, decode_frame, encode_frame,
    receive_frame, timeout_seconds,
)


class GraphFramingTests(unittest.TestCase):
    def test_frame_rejects_incomplete_multiple_non_object_duplicate_and_nonfinite_json(self):
        for value in (b'{}', b'{}\n{}\n', b'{}\ntrailing', b'[]\n', b'null\n',
                      b'{"x":1,"x":2}\n', b'{"x":NaN}\n', b'{"x":Infinity}\n',
                      b'{"x":1e999}\n', b'{"x":"\xff"}\n'):
            with self.subTest(value=value), self.assertRaises(FrameError):
                decode_frame(value, MAX_REQUEST)
        self.assertEqual(decode_frame(b'{"action":"status"}\n', MAX_REQUEST), {"action": "status"})

    def test_limits_include_newline_and_timeout_is_finite(self):
        self.assertEqual(encode_frame({}, 3), b'{}\n')
        self.assertEqual(decode_frame(b'{}\n', 3), {})
        with self.assertRaises(FrameError):
            encode_frame({}, 2)
        with self.assertRaises(FrameError):
            decode_frame(b'{}\n', 2)
        for value in (True, "1", 0, -1, float("nan"), float("inf"), 301):
            with self.subTest(value=value), self.assertRaises(ValueError):
                timeout_seconds(value)


class GraphHandlerTests(unittest.TestCase):
    def run_handler(self, payload, *, result=None, error=None):
        server, client = socket.socketpair()
        client.settimeout(1)
        with client, concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            with patch("control_plane.graph_service.dispatch", return_value=result, side_effect=error) as dispatch:
                future = executor.submit(handle, server, None, {}, {}, {}, threading.RLock(), timeout_seconds=0.5)
                client.sendall(payload)
                client.shutdown(socket.SHUT_WR)
                response = receive_frame(client, time.monotonic() + 1, MAX_RESPONSE)
                future.result(timeout=1)
                return response, dispatch.call_count

    def test_normal_request_dispatches_once(self):
        response, calls = self.run_handler(b'{"action":"status"}\n', result={"nodes": []})
        self.assertEqual(response, {"ok": True, "result": {"nodes": []}})
        self.assertEqual(calls, 1)

    def test_invalid_request_is_rejected_before_dispatch(self):
        for payload in (b'{}', b'[]\n', b'{}\n{}\n', b'{"a":1,"a":2}\n',
                        b'{"value":"' + b'x' * MAX_REQUEST + b'"}\n'):
            with self.subTest(length=len(payload)):
                # Large requests may be rejected while the writer is still
                # sending; keep the writer bounded and tolerate peer closure.
                if len(payload) > MAX_REQUEST:
                    server, client = socket.socketpair()
                    with client, concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                        with patch("control_plane.graph_service.dispatch") as dispatch:
                            future = executor.submit(handle, server, None, {}, {}, {}, threading.RLock(), timeout_seconds=0.5)
                            client.settimeout(1)
                            try:
                                client.sendall(payload)
                            except (BrokenPipeError, ConnectionResetError):
                                pass
                            future.result(timeout=1)
                            dispatch.assert_not_called()
                else:
                    response, calls = self.run_handler(payload)
                    self.assertFalse(response["ok"])
                    self.assertEqual(calls, 0)

    def test_oversized_response_and_error_details_do_not_escape(self):
        response, _ = self.run_handler(b'{}\n', result="x" * MAX_RESPONSE)
        self.assertFalse(response["ok"])
        self.assertLess(len(json.dumps(response)), 200)
        response, _ = self.run_handler(b'{}\n', error=ValueError("private fixture detail"))
        self.assertFalse(response["ok"])
        self.assertNotIn("private fixture detail", response["error"])

    def test_slow_drip_does_not_reset_absolute_read_deadline(self):
        server, client = socket.socketpair()
        with client, concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            with patch("control_plane.graph_service.dispatch") as dispatch:
                start = time.monotonic()
                future = executor.submit(handle, server, None, {}, {}, {}, threading.RLock(), timeout_seconds=0.08)
                while not future.done() and time.monotonic() - start < 0.8:
                    try:
                        client.sendall(b' ')
                    except (BrokenPipeError, ConnectionResetError):
                        break
                    time.sleep(0.01)
                future.result(timeout=1)
                self.assertLess(time.monotonic() - start, 0.6)
                dispatch.assert_not_called()

    def test_database_lock_wait_obeys_deadline_without_dispatch(self):
        server, client = socket.socketpair()
        lock = threading.RLock()
        with client, concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            with lock, patch("control_plane.graph_service.dispatch") as dispatch:
                client.sendall(b'{}\n')
                future = executor.submit(handle, server, None, {}, {}, {}, lock, timeout_seconds=0.05)
                future.result(timeout=0.8)
                dispatch.assert_not_called()

    def test_peer_that_does_not_read_cannot_hold_response_writer(self):
        server, client = socket.socketpair()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        with client, concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            with patch("control_plane.graph_service.dispatch", return_value="x" * (MAX_RESPONSE // 2)):
                client.sendall(b'{}\n')
                future = executor.submit(handle, server, None, {}, {}, {}, threading.RLock(), timeout_seconds=0.08)
                future.result(timeout=0.8)

    def test_dispatch_completion_is_not_interrupted_by_response_deadline(self):
        server, client = socket.socketpair()
        completed = threading.Event()

        def atomic_work(*args):
            time.sleep(0.06)
            completed.set()
            return {"committed": True}

        with client, concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            with patch("control_plane.graph_service.dispatch", side_effect=atomic_work):
                client.sendall(b'{}\n')
                future = executor.submit(handle, server, None, {}, {}, {}, threading.RLock(), timeout_seconds=0.02)
                future.result(timeout=0.8)
                self.assertTrue(completed.is_set())
                client.settimeout(0.5)
                self.assertEqual(client.recv(1), b'')

    def test_eight_partial_clients_and_bounded_queue_release_capacity(self):
        pairs = [socket.socketpair() for _ in range(17)]
        futures = []
        lock = threading.RLock()
        try:
            with patch("control_plane.graph_service.dispatch", return_value={"available": True}) as dispatch:
                with BoundedConnectionPool(timeout_seconds=0.3) as pool:
                    for server, client in pairs[:16]:
                        client.sendall(b'{')
                        future = pool.submit(server, None, {}, {}, {}, lock)
                        self.assertIsNotNone(future)
                        futures.append(future)
                    self.assertIsNone(pool.submit(pairs[16][0], None, {}, {}, {}, lock))
                    self.assertEqual(pairs[16][0].fileno(), -1)
                    for future in futures:
                        future.result(timeout=1)
                    dispatch.assert_not_called()
                    server, client = socket.socketpair()
                    with client:
                        client.sendall(b'{}\n')
                        future = pool.submit(server, None, {}, {}, {}, lock)
                        self.assertIsNotNone(future)
                        response = receive_frame(client, time.monotonic() + 1, MAX_RESPONSE)
                        future.result(timeout=1)
                        self.assertTrue(response["ok"])
                        dispatch.assert_called_once()
        finally:
            for server, client in pairs:
                server.close()
                client.close()

    def test_queue_wait_uses_admission_deadline(self):
        first_server, first_client = socket.socketpair()
        second_server, second_client = socket.socketpair()
        try:
            with patch("control_plane.graph_service.dispatch") as dispatch:
                with BoundedConnectionPool(max_workers=1, max_pending=1, timeout_seconds=0.1) as pool:
                    first_client.sendall(b'{')
                    first = pool.submit(first_server, None, {}, {}, {}, threading.RLock())
                    second_client.sendall(b'{')
                    start = time.monotonic()
                    second = pool.submit(second_server, None, {}, {}, {}, threading.RLock())
                    first.result(timeout=1)
                    second.result(timeout=1)
                    self.assertLess(time.monotonic() - start, 0.18)
                    dispatch.assert_not_called()
        finally:
            first_client.close()
            second_client.close()

    def test_shutdown_closes_cancelled_pending_connections(self):
        first_server, first_client = socket.socketpair()
        second_server, second_client = socket.socketpair()
        try:
            with BoundedConnectionPool(max_workers=1, max_pending=1, timeout_seconds=0.08) as pool:
                first_client.sendall(b'{')
                pool.submit(first_server, None, {}, {}, {}, threading.RLock())
                pool.submit(second_server, None, {}, {}, {}, threading.RLock())
            self.assertEqual(first_server.fileno(), -1)
            self.assertEqual(second_server.fileno(), -1)
        finally:
            first_client.close()
            second_client.close()


class GraphClientTests(unittest.TestCase):
    def call_fixture(self, reply, *, timeout=0.3):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "graph.sock"
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
                listener.bind(str(path))
                listener.listen(1)
                listener.settimeout(1)

                def peer():
                    connection, _ = listener.accept()
                    with connection:
                        receive_frame(connection, time.monotonic() + 1, MAX_REQUEST)
                        if reply is None:
                            # Wait for the bounded client to close, never sleep
                            # indefinitely and never spawn a runtime service.
                            connection.settimeout(1)
                            connection.recv(1)
                        elif callable(reply):
                            reply(connection)
                        else:
                            connection.settimeout(1)
                            try:
                                connection.sendall(reply)
                            except (BrokenPipeError, ConnectionResetError):
                                pass

                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(peer)
                    try:
                        return request(path, {"action": "status"}, timeout_seconds=timeout)
                    finally:
                        future.result(timeout=2)

    def test_client_success_and_remote_denial(self):
        self.assertEqual(self.call_fixture(b'{"ok":true,"result":[]}\n'), {"ok": True, "result": []})
        self.assertFalse(self.call_fixture(b'{"ok":false,"error":"denied"}\n')["ok"])

    def test_client_deadline_bounds_stalled_peer(self):
        start = time.monotonic()
        with self.assertRaises(TimeoutError):
            self.call_fixture(None, timeout=0.08)
        self.assertLess(time.monotonic() - start, 0.6)

    def test_client_deadline_is_not_extended_by_partial_response_bytes(self):
        def drip(connection):
            connection.settimeout(1)
            for _ in range(30):
                try:
                    connection.sendall(b' ')
                except (BrokenPipeError, ConnectionResetError):
                    return
                time.sleep(0.01)

        start = time.monotonic()
        with self.assertRaises(TimeoutError):
            self.call_fixture(drip, timeout=0.08)
        self.assertLess(time.monotonic() - start, 0.6)

    def test_client_rejects_malformed_oversized_and_incomplete_responses(self):
        for reply in (b'{}\n', b'[]\n', b'{"ok":1,"result":[]}\n',
                      b'{"ok":true,"result":[]}\n{}\n', b'{"ok":true,"result":[]}',
                      b'{"ok":false,"error":null}\n',
                      b'{"ok":true,"result":"' + b'x' * MAX_RESPONSE + b'"}\n'):
            with self.subTest(length=len(reply)), self.assertRaises(FrameError):
                self.call_fixture(reply)

    def test_invalid_and_oversized_request_never_opens_socket(self):
        with patch("control_plane.graph_client.socket.socket") as constructor:
            for payload in ([], {"data": "x" * MAX_REQUEST}):
                with self.assertRaises(FrameError):
                    request(Path("/not-used"), payload)
            constructor.assert_not_called()

    def test_client_stdin_rejects_extra_json_before_connecting(self):
        output = io.StringIO()
        with patch("sys.argv", ["graph-client", "--socket", "/not-used"]):
            with patch("sys.stdin", SimpleNamespace(buffer=io.BytesIO(b'{"action":"status"}\n{}\n'))):
                with patch("control_plane.graph_client.socket.socket") as constructor:
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(client_main(), 77)
                    constructor.assert_not_called()
        self.assertFalse(json.loads(output.getvalue())["ok"])


if __name__ == "__main__":
    unittest.main()
