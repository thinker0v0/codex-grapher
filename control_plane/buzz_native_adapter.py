"""Fixture-only native-like Buzz ingress boundary.

This module deliberately does not implement production Nostr cryptography or a
Buzz transport.  A caller must inject a signature verifier.  The local tests use
an explicitly non-production deterministic fixture verifier and prove only the
parsing, binding, routing, replay, and denial behavior at this seam.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from control_plane.buzz_router import BuzzMutationIntegrityError, BuzzRouter
from control_plane.project_graph import PROJECTS, canonical, digest


FIXTURE_RESULT = "FIXTURE_PASS"
HG10_RESULT = "UNPROVEN"
NATIVE_CHANNEL_MESSAGE_KIND = 42
EVENT_FIELDS = frozenset({"id", "pubkey", "created_at", "kind", "tags", "content", "sig"})
HEX_40 = re.compile(r"[0-9a-f]{40}\Z")
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
HEX_128 = re.compile(r"[0-9a-f]{128}\Z")
CONTROL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}\Z")
CONFIG_FIELDS = frozenset(
    {
        "surface",
        "production_use",
        "result_label",
        "hg10",
        "event_kind",
        "max_age_seconds",
        "max_future_skew_seconds",
        "max_content_bytes",
        "channel_routes",
    }
)
COMMAND_FIELDS = {
    "goal": frozenset({"command", "goal_id", "objective", "accepted_sha"}),
    "status": frozenset({"command"}),
    "evidence": frozenset({"command", "node_id"}),
    "approve": frozenset({"command", "node_id"}),
    "reject": frozenset({"command", "node_id"}),
    "cancel": frozenset({"command", "node_id"}),
    "resume": frozenset({"command", "node_id"}),
}

SignatureVerifier = Callable[[str, str, str], bool]
Clock = Callable[[], int]


class BuzzEnvelopeError(ValueError):
    """A fail-closed event, configuration, or replay validation failure."""


class _ReplayBindingError(BuzzEnvelopeError):
    """A trusted event conflicts with its durable replay identity or response."""


def _reject_json_constant(value: str) -> None:
    raise BuzzEnvelopeError(f"non-finite JSON constant is forbidden: {value}")


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BuzzEnvelopeError("duplicate JSON object key")
        result[key] = value
    return result


def _strict_json(text: str) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except BuzzEnvelopeError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise BuzzEnvelopeError("invalid JSON") from exc


def canonical_event_id(event: Mapping[str, Any]) -> str:
    """Return the NIP-01-shaped canonical ID for the signed event fields."""

    try:
        body = [
            0,
            event["pubkey"],
            event["created_at"],
            event["kind"],
            event["tags"],
            event["content"],
        ]
        encoded = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    except (KeyError, TypeError, ValueError, UnicodeEncodeError) as exc:
        raise BuzzEnvelopeError("event cannot be canonically encoded") from exc
    return hashlib.sha256(encoded).hexdigest()


class BuzzNativeAdapter:
    """Validate signed native-like events before calling the behavioral router."""

    def __init__(
        self,
        router: BuzzRouter,
        adapter_config: Path,
        signature_verifier: SignatureVerifier,
        clock: Clock | None = None,
    ):
        if not callable(signature_verifier):
            raise TypeError("an injected signature verifier is required")
        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable")
        self.router = router
        self.config = self._load_config(adapter_config)
        self.signature_verifier = signature_verifier
        self.clock = clock or (lambda: int(time.time()))
        self.channel_routes: dict[str, str] = self.config["channel_routes"]
        self.route_channels = {route: channel for channel, route in self.channel_routes.items()}

    @staticmethod
    def _load_config(path: Path) -> dict[str, Any]:
        try:
            config = _strict_json(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError) as exc:
            raise BuzzEnvelopeError("adapter config is unreadable") from exc
        if type(config) is not dict or set(config) != CONFIG_FIELDS:
            raise BuzzEnvelopeError("adapter config fields must match the fixture contract exactly")
        if (
            config["surface"] != "native-like-fixture-only"
            or config["production_use"] != "forbidden"
            or config["result_label"] != FIXTURE_RESULT
            or config["hg10"] != HG10_RESULT
            or config["event_kind"] != NATIVE_CHANNEL_MESSAGE_KIND
        ):
            raise BuzzEnvelopeError("adapter config must preserve fixture-only evidence labels")
        integer_bounds = {
            "max_age_seconds": (1, 3600),
            "max_future_skew_seconds": (0, 300),
            "max_content_bytes": (128, 65536),
        }
        for field, (minimum, maximum) in integer_bounds.items():
            value = config[field]
            if type(value) is not int or not minimum <= value <= maximum:
                raise BuzzEnvelopeError(f"invalid {field}")
        channels = config["channel_routes"]
        if type(channels) is not dict or len(channels) != 4:
            raise BuzzEnvelopeError("fixture config requires exactly four channels")
        if any(type(channel) is not str or not HEX_64.fullmatch(channel) for channel in channels):
            raise BuzzEnvelopeError("channel IDs must be canonical lowercase 32-byte hex")
        if any(type(route) is not str for route in channels.values()) or set(channels.values()) != PROJECTS:
            raise BuzzEnvelopeError("channels must map one-to-one to exactly the four active routes")
        return config

    def handle_event(self, event: dict[str, Any]) -> dict[str, Any]:
        """Verify, bind, replay-suppress, and dispatch one fixture event."""

        try:
            self._verify_envelope(event)
        except BuzzEnvelopeError:
            return self._fixture_denial("event verification denied")

        # These values are derived only after the canonical ID, freshness, and
        # injected signature verifier have all succeeded.
        sender_pubkey = event["pubkey"]
        channel_id = event["tags"][0][1]
        thread_id = event["tags"][1][1]
        route = self.channel_routes.get(channel_id)
        request_hash = hashlib.sha256(event["content"].encode("utf-8")).hexdigest()

        # Parsing also precedes the SQLite writer lock.  For an unmapped channel,
        # the channel denial retains precedence over any payload defect.
        try:
            request = self._parse_request(event["content"])
        except BuzzEnvelopeError:
            request = None

        connection = self.router.graph.connection
        if connection.in_transaction:
            return self._fixture_denial("durable replay binding denied")
        try:
            connection.execute("BEGIN IMMEDIATE")
            self.router._assert_mutation_integrity_locked()
            replay = self._replay_locked(
                event["id"],
                sender_pubkey,
                channel_id,
                thread_id,
                route,
                request_hash,
            )
            if replay is not None:
                connection.commit()
                return replay

            if route is None:
                response = self._fixture_denial(
                    "verified event channel is not mapped",
                    event_id=event["id"],
                    thread_id=thread_id,
                )
            elif request is None:
                response = self._fixture_denial(
                    "verified event payload denied",
                    event_id=event["id"],
                    route=route,
                    thread_id=thread_id,
                )
            else:
                # Project is never accepted from content.  It is injected from
                # the verified root-channel tag and exact config mapping.
                request["project"] = route
                routed = self.router.handle_locked(
                    sender_pubkey, thread_id, request
                )
                self._transaction_checkpoint("after_router")
                response = {
                    **routed,
                    "event_id": event["id"],
                    "route": route,
                    "thread_id": thread_id,
                    "fixture_result": FIXTURE_RESULT,
                    "hg10": HG10_RESULT,
                }

            self._insert_complete_locked(
                event["id"],
                sender_pubkey,
                channel_id,
                thread_id,
                route,
                request_hash,
                response,
            )
            self._transaction_checkpoint("after_response_persist")
            self.router._assert_mutation_integrity_locked()
            connection.commit()
            return response
        except BuzzMutationIntegrityError:
            connection.rollback()
            return self._fixture_denial(
                "durable graph integrity denied",
                event_id=event["id"],
                route=route,
                thread_id=thread_id,
            )
        except _ReplayBindingError:
            connection.rollback()
            return self._fixture_denial("durable replay binding denied")
        except Exception:
            connection.rollback()
            # This fixture has no external side effects.  A pre-commit failure
            # therefore remains unclaimed so the exact signed event can retry.
            return self._fixture_denial(
                "verified event dispatch failed closed",
                event_id=event["id"],
                route=route,
                thread_id=thread_id,
            )

    def scheduled_digest(self) -> dict[str, Any]:
        """Build a no-delivery fixture digest bound to the exact four channels."""

        return {
            "fixture_result": FIXTURE_RESULT,
            "hg10": HG10_RESULT,
            "delivery": "fixture-only-no-network-or-service-action",
            "channel_routes": [
                {"route": route, "channel_id": self.route_channels[route]}
                for route in sorted(PROJECTS)
            ],
            "digest": self.router.scheduled_digest(),
        }

    def _verify_envelope(self, event: dict[str, Any]) -> None:
        if type(event) is not dict or set(event) != EVENT_FIELDS:
            raise BuzzEnvelopeError("event fields do not match the strict envelope")
        if type(event["id"]) is not str or not HEX_64.fullmatch(event["id"]):
            raise BuzzEnvelopeError("invalid event ID")
        if type(event["pubkey"]) is not str or not HEX_64.fullmatch(event["pubkey"]):
            raise BuzzEnvelopeError("invalid sender public key")
        if type(event["sig"]) is not str or not HEX_128.fullmatch(event["sig"]):
            raise BuzzEnvelopeError("invalid event signature encoding")
        if type(event["created_at"]) is not int:
            raise BuzzEnvelopeError("invalid event timestamp")
        if type(event["kind"]) is not int or event["kind"] != self.config["event_kind"]:
            raise BuzzEnvelopeError("invalid event kind")
        if type(event["content"]) is not str:
            raise BuzzEnvelopeError("event content must be text")
        try:
            content_bytes = event["content"].encode("utf-8")
        except UnicodeEncodeError as exc:
            raise BuzzEnvelopeError("event content must be valid UTF-8") from exc
        if len(content_bytes) > self.config["max_content_bytes"]:
            raise BuzzEnvelopeError("event content is too large")
        self._validate_tags(event["tags"])

        expected_id = canonical_event_id(event)
        if not hmac.compare_digest(event["id"], expected_id):
            raise BuzzEnvelopeError("event ID does not bind the canonical event body")
        now = self.clock()
        if type(now) is not int:
            raise BuzzEnvelopeError("clock must return integer epoch seconds")
        if (
            event["created_at"] < now - self.config["max_age_seconds"]
            or event["created_at"] > now + self.config["max_future_skew_seconds"]
        ):
            raise BuzzEnvelopeError("event is outside the freshness window")
        try:
            verified = self.signature_verifier(event["pubkey"], expected_id, event["sig"])
        except Exception as exc:
            raise BuzzEnvelopeError("signature verifier failed closed") from exc
        if verified is not True:
            raise BuzzEnvelopeError("signature verification denied")

    @staticmethod
    def _validate_tags(tags: Any) -> None:
        if type(tags) is not list or len(tags) != 2:
            raise BuzzEnvelopeError("exact root-channel and reply-thread tags are required")
        root, reply = tags
        if (
            type(root) is not list
            or type(reply) is not list
            or len(root) != 4
            or len(reply) != 4
            or any(type(value) is not str for value in root + reply)
            or root[0] != "e"
            or root[2:] != ["", "root"]
            or reply[0] != "e"
            or reply[2:] != ["", "reply"]
            or not HEX_64.fullmatch(root[1])
            or not HEX_64.fullmatch(reply[1])
            or root[1] == reply[1]
        ):
            raise BuzzEnvelopeError("invalid native-like channel/thread tag binding")

    @staticmethod
    def _parse_request(content: str) -> dict[str, Any]:
        request = _strict_json(content)
        if type(request) is not dict:
            raise BuzzEnvelopeError("event content must be one JSON object")
        command = request.get("command")
        if type(command) is not str or command not in COMMAND_FIELDS:
            raise BuzzEnvelopeError("unsupported command")
        if set(request) != COMMAND_FIELDS[command]:
            raise BuzzEnvelopeError("command fields must match the strict contract exactly")
        if command == "goal":
            goal_id = request["goal_id"]
            objective = request["objective"]
            accepted_sha = request["accepted_sha"]
            if type(goal_id) is not str or not CONTROL_ID.fullmatch(goal_id):
                raise BuzzEnvelopeError("invalid goal ID")
            if (
                type(objective) is not str
                or not 10 <= len(objective) <= 4096
                or not objective.strip()
            ):
                raise BuzzEnvelopeError("invalid objective")
            if type(accepted_sha) is not str or not HEX_40.fullmatch(accepted_sha):
                raise BuzzEnvelopeError("invalid accepted SHA")
        elif command != "status":
            node_id = request["node_id"]
            if type(node_id) is not str or not CONTROL_ID.fullmatch(node_id):
                raise BuzzEnvelopeError("invalid node ID")
        return request

    def _replay_locked(
        self,
        event_id: str,
        sender_pubkey: str,
        channel_id: str,
        thread_id: str,
        route: str | None,
        request_hash: str,
    ) -> dict[str, Any] | None:
        connection = self.router.graph.connection
        if not connection.in_transaction:
            raise RuntimeError("locked Buzz replay lookup requires an active transaction")
        row = connection.execute(
            "SELECT * FROM buzz_ingress_responses WHERE event_id=?", (event_id,)
        ).fetchone()
        if row is None:
            return None
        binding = (
            row["event_body_hash"],
            row["sender_pubkey"],
            row["channel_id"],
            row["thread_id"],
            row["route"],
            row["request_hash"],
        )
        expected = (event_id, sender_pubkey, channel_id, thread_id, route, request_hash)
        if binding != expected or row["state"] != "COMPLETE":
            raise _ReplayBindingError(
                "event replay is incomplete or bound differently"
            )
        try:
            response = _strict_json(row["response_json"])
        except BuzzEnvelopeError:
            raise _ReplayBindingError("stored response is invalid") from None
        if (
            type(response) is not dict
            or canonical(response) != row["response_json"]
            or digest(response) != row["response_hash"]
        ):
            raise _ReplayBindingError("stored response hash or encoding mismatch")
        return response

    def _insert_complete_locked(
        self,
        event_id: str,
        sender_pubkey: str,
        channel_id: str,
        thread_id: str,
        route: str | None,
        request_hash: str,
        response: dict[str, Any],
    ) -> None:
        connection = self.router.graph.connection
        if not connection.in_transaction:
            raise RuntimeError("locked Buzz response persistence requires an active transaction")
        connection.execute(
            "INSERT INTO buzz_ingress_responses("
            "event_id,event_body_hash,sender_pubkey,channel_id,thread_id,route,request_hash,"
            "state,response_json,response_hash"
            ") VALUES(?,?,?,?,?,?,?,'COMPLETE',?,?)",
            (
                event_id,
                event_id,
                sender_pubkey,
                channel_id,
                thread_id,
                route,
                request_hash,
                canonical(response),
                digest(response),
            ),
        )

    def _transaction_checkpoint(self, stage: str) -> None:
        """No-op fault boundary overridden only by deterministic local tests."""

    @staticmethod
    def _fixture_denial(
        error: str,
        *,
        event_id: str | None = None,
        route: str | None = None,
        thread_id: str | None = None,
    ) -> dict[str, Any]:
        response: dict[str, Any] = {
            "ok": False,
            "error": error,
            "fixture_result": FIXTURE_RESULT,
            "hg10": HG10_RESULT,
        }
        if event_id is not None:
            response["event_id"] = event_id
        if route is not None:
            response["route"] = route
        if thread_id is not None:
            response["thread_id"] = thread_id
        return response
