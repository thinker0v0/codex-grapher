"""Bounded one-object JSON-line framing shared by the Unix API and its client."""

from __future__ import annotations

import json
import math
import socket
import time
from typing import Any


MAX_REQUEST = 1024 * 1024
MAX_RESPONSE = 1024 * 1024
SERVER_TIMEOUT_SECONDS = 10.0
CLIENT_TIMEOUT_SECONDS = 30.0


class FrameError(ValueError):
    """An incomplete, ambiguous, oversized, or non-object JSON frame."""


def timeout_seconds(value: float) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 300:
        raise ValueError("timeout must be finite and greater than zero, at most 300 seconds")
    return float(value)


def remaining(deadline: float) -> float:
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise TimeoutError("graph transport deadline expired")
    return seconds


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FrameError("duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise FrameError("non-finite JSON number")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise FrameError("non-finite JSON number")
    return number


def decode_object(payload: bytes, limit: int) -> dict[str, Any]:
    if len(payload) > limit:
        raise FrameError("JSON frame exceeds size limit")
    try:
        value = json.loads(
            payload.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_constant=_reject_constant, parse_float=_finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, FrameError):
            raise
        raise FrameError("invalid JSON frame") from None
    if type(value) is not dict:
        raise FrameError("JSON frame must contain an object")
    return value


def decode_frame(payload: bytes, limit: int) -> dict[str, Any]:
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        raise FrameError("exactly one newline-terminated JSON frame required")
    return decode_object(payload, limit)


def encode_frame(value: dict[str, Any], limit: int) -> bytes:
    if type(value) is not dict:
        raise FrameError("JSON frame must contain an object")
    # Bound the accumulation as well as the final wire frame. A single string
    # chunk is still allocated by JSONEncoder; graph results are trusted data.
    payload = bytearray()
    try:
        chunks = json.JSONEncoder(sort_keys=True, allow_nan=False).iterencode(value)
        for chunk in chunks:
            encoded = chunk.encode("utf-8")
            if len(payload) + len(encoded) + 1 > limit:
                raise FrameError("JSON frame exceeds size limit")
            payload.extend(encoded)
    except (ValueError, TypeError, RecursionError):
        raise FrameError("JSON response is invalid or exceeds size limit") from None
    payload.extend(b"\n")
    return bytes(payload)


def receive_frame(connection: socket.socket, deadline: float, limit: int) -> dict[str, Any]:
    payload = bytearray()
    while True:
        connection.settimeout(remaining(deadline))
        chunk = connection.recv(min(65536, limit + 1 - len(payload)))
        if not chunk:
            raise FrameError("peer closed before a complete JSON frame")
        payload.extend(chunk)
        if len(payload) > limit:
            raise FrameError("JSON frame exceeds size limit")
        if b"\n" in chunk:
            remaining(deadline)
            return decode_frame(bytes(payload), limit)


def send_frame(connection: socket.socket, value: dict[str, Any], deadline: float, limit: int) -> None:
    payload = encode_frame(value, limit)
    connection.settimeout(remaining(deadline))
    connection.sendall(payload)
