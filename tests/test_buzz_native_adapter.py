"""Local fixture evidence for the native-like Buzz adapter.

The verifier below is a deterministic keyed digest for tests only.  It is not a
Nostr/Schnorr implementation, is not production cryptography, and cannot prove
Buzz staging or frozen hard gate HG10.
"""

import copy
import hashlib
import hmac
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from control_plane.buzz_native_adapter import (
    BuzzEnvelopeError,
    BuzzNativeAdapter,
    FIXTURE_RESULT,
    HG10_RESULT,
    canonical_event_id,
)
from control_plane.buzz_router import BuzzRouter
from control_plane.graph_planner import load_templates
from control_plane.graph_bootstrap import apply_database
from control_plane.project_graph import PROJECTS, ProjectGraph


ROOT = Path(__file__).resolve().parents[1]
ADAPTER_CONFIG = ROOT / "config/buzz-native-fixture.example.json"
NOW = 1_800_000_000
SHA = "d" * 40
FIXTURE_KEY_A = b"buzz-local-fixture-key-a-not-a-real-secret"
FIXTURE_KEY_B = b"buzz-local-fixture-key-b-not-a-real-secret"


def fixture_pubkey(key: bytes) -> str:
    return hashlib.sha256(b"fixture-pubkey-v1\0" + key).hexdigest()


def fixture_signature(key: bytes, event_id: str) -> str:
    return hmac.new(
        key, b"fixture-signature-v1\0" + bytes.fromhex(event_id), hashlib.sha512
    ).hexdigest()


PUBKEY_A = fixture_pubkey(FIXTURE_KEY_A)
PUBKEY_B = fixture_pubkey(FIXTURE_KEY_B)


class DeterministicFixtureVerifier:
    """Keyed local fixture verifier; intentionally not production crypto."""

    def __init__(self):
        self.keys = {PUBKEY_A: FIXTURE_KEY_A, PUBKEY_B: FIXTURE_KEY_B}

    def __call__(self, pubkey: str, event_id: str, signature: str) -> bool:
        key = self.keys.get(pubkey)
        if key is None:
            return False
        return hmac.compare_digest(signature, fixture_signature(key, event_id))


def stable_id(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class BuzzNativeAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp.name)
        self.database = self.temp_path / "graph.db"
        apply_database(self.database)
        self.router_config = self.temp_path / "buzz-routing.json"
        source = json.loads((ROOT / "config/buzz-routing.example.json").read_text(encoding="utf-8"))
        operator = next(iter(source["identity_map"].values()))
        source["identity_map"] = {PUBKEY_A: operator, PUBKEY_B: copy.deepcopy(operator)}
        self.router_config.write_text(json.dumps(source), encoding="utf-8")
        self.fixture_config = json.loads(ADAPTER_CONFIG.read_text(encoding="utf-8"))
        self.channels = {route: channel for channel, route in self.fixture_config["channel_routes"].items()}
        self.threads = {route: stable_id(f"fixture-thread:{route}") for route in PROJECTS}
        self.verifier = DeterministicFixtureVerifier()
        self._open_adapter()

    def tearDown(self):
        self.graph.connection.close()
        self.temp.cleanup()

    def _open_adapter(self) -> None:
        self.graph = ProjectGraph(self.database)
        self.router = BuzzRouter(
            self.graph,
            self.router_config,
            load_templates(ROOT / "config/project-graphs.json"),
        )
        self.adapter = BuzzNativeAdapter(
            self.router,
            ADAPTER_CONFIG,
            self.verifier,
            clock=lambda: NOW,
        )

    def event(
        self,
        payload: dict[str, Any] | None,
        route: str = "opensource",
        *,
        thread_id: str | None = None,
        sender_key: bytes = FIXTURE_KEY_A,
        signing_key: bytes | None = None,
        channel_id: str | None = None,
        created_at: int = NOW,
        kind: int = 42,
        tags: list[list[str]] | None = None,
        raw_content: str | None = None,
    ) -> dict[str, Any]:
        pubkey = fixture_pubkey(sender_key)
        channel = channel_id or self.channels[route]
        thread = thread_id or self.threads[route]
        event: dict[str, Any] = {
            "pubkey": pubkey,
            "created_at": created_at,
            "kind": kind,
            "tags": tags
            if tags is not None
            else [["e", channel, "", "root"], ["e", thread, "", "reply"]],
            "content": raw_content
            if raw_content is not None
            else json.dumps(payload, sort_keys=True, separators=(",", ":")),
        }
        event["id"] = canonical_event_id(event)
        event["sig"] = fixture_signature(signing_key or sender_key, event["id"])
        return event

    def goal_event(self, route: str, *, sender_key: bytes = FIXTURE_KEY_A) -> dict[str, Any]:
        return self.event(
            {
                "command": "goal",
                "goal_id": f"goal-{route}-fixture",
                "objective": f"deliver verified {route} fixture value",
                "accepted_sha": SHA,
            },
            route,
            sender_key=sender_key,
        )

    def assert_fixture_metadata(self, response: dict[str, Any]) -> None:
        self.assertEqual(response["fixture_result"], FIXTURE_RESULT)
        self.assertEqual(response["hg10"], HG10_RESULT)

    def atomic_counts(self) -> dict[str, int]:
        return {
            table: self.graph.connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            for table in (
                "goals",
                "nodes",
                "events",
                "buzz_threads",
                "buzz_audit",
                "buzz_ingress_responses",
            )
        }

    def checkpointed_database_image(self) -> tuple[bytes, bytes]:
        checkpoint = self.graph.connection.execute(
            "PRAGMA wal_checkpoint(TRUNCATE)"
        ).fetchone()
        self.assertEqual(checkpoint[0], 0)
        return self.database.read_bytes(), self.graph.connection.serialize()

    def test_all_commands_four_routes_and_scheduled_digest_are_fixture_bound(self):
        created: dict[str, dict[str, Any]] = {}
        for route in sorted(PROJECTS):
            created[route] = self.adapter.handle_event(self.goal_event(route))
            self.assertTrue(created[route]["ok"])
            self.assertEqual(created[route]["project"], route)
            self.assertEqual(created[route]["route"], route)
            self.assertEqual(created[route]["thread_id"], self.threads[route])
            self.assert_fixture_metadata(created[route])

        status = self.adapter.handle_event(
            self.event({"command": "status"}, "opensource")
        )
        self.assertTrue(status["ok"])
        self.assertEqual(status["goal_id"], "goal-opensource-fixture")

        evidence = self.adapter.handle_event(
            self.event(
                {"command": "evidence", "node_id": created["opensource"]["next_node"]},
                "opensource",
            )
        )
        self.assertTrue(evidence["ok"])
        self.assertEqual(evidence["node_id"], created["opensource"]["next_node"])

        nomad_node = self.graph.get_node(created["nomad"]["next_node"])
        self.graph.transition(
            nomad_node["node_id"], nomad_node["version"], "NEEDS_HUMAN", "fixture ordinary gate"
        )
        approved = self.adapter.handle_event(
            self.event({"command": "approve", "node_id": nomad_node["node_id"]}, "nomad")
        )
        self.assertTrue(approved["ok"])
        self.assertEqual(approved["state"], "READY")

        nomad_node = self.graph.get_node(nomad_node["node_id"])
        self.graph.transition(
            nomad_node["node_id"], nomad_node["version"], "NEEDS_HUMAN", "fixture resumable gate"
        )
        resumed = self.adapter.handle_event(
            self.event({"command": "resume", "node_id": nomad_node["node_id"]}, "nomad")
        )
        self.assertTrue(resumed["ok"])
        self.assertEqual(resumed["state"], "READY")

        rejected = self.adapter.handle_event(
            self.event(
                {"command": "reject", "node_id": created["business"]["next_node"]},
                "business",
            )
        )
        self.assertTrue(rejected["ok"])
        self.assertEqual(rejected["state"], "CANCELLED")
        cancelled = self.adapter.handle_event(
            self.event(
                {"command": "cancel", "node_id": created["hynix"]["next_node"]},
                "hynix",
            )
        )
        self.assertTrue(cancelled["ok"])
        self.assertEqual(cancelled["state"], "CANCELLED")

        digest_result = self.adapter.scheduled_digest()
        self.assert_fixture_metadata(digest_result)
        self.assertEqual(digest_result["delivery"], "fixture-only-no-network-or-service-action")
        self.assertEqual(
            digest_result["channel_routes"],
            [
                {"route": route, "channel_id": self.channels[route]}
                for route in sorted(PROJECTS)
            ],
        )
        self.assertEqual(digest_result["digest"]["projects"], sorted(PROJECTS))

    def test_response_replay_is_exact_durable_and_does_not_redispatch(self):
        event = self.goal_event("opensource")
        first = self.adapter.handle_event(event)
        self.assertTrue(first["ok"])
        second = self.adapter.handle_event(copy.deepcopy(event))
        self.assertEqual(second, first)
        self.assertEqual(
            self.graph.connection.execute("SELECT count(*) FROM buzz_audit").fetchone()[0], 1
        )
        replay = self.graph.connection.execute(
            "SELECT event_body_hash,state,response_hash FROM buzz_ingress_responses WHERE event_id=?",
            (event["id"],),
        ).fetchone()
        self.assertEqual(replay["event_body_hash"], event["id"])
        self.assertEqual(replay["state"], "COMPLETE")
        self.assertEqual(len(replay["response_hash"]), 64)

        self.graph.connection.close()
        self._open_adapter()
        after_restart = self.adapter.handle_event(copy.deepcopy(event))
        self.assertEqual(after_restart, first)
        self.assertEqual(
            self.graph.connection.execute("SELECT count(*) FROM goals").fetchone()[0], 1
        )
        self.assertEqual(
            self.graph.connection.execute("SELECT count(*) FROM buzz_audit").fetchone()[0], 1
        )

    def test_accepted_and_denied_events_each_use_one_direct_complete_transaction(self):
        def traced(event):
            statements = []
            self.graph.connection.set_trace_callback(statements.append)
            try:
                response = self.adapter.handle_event(copy.deepcopy(event))
            finally:
                self.graph.connection.set_trace_callback(None)
            transaction_control = [
                statement.strip().upper()
                for statement in statements
                if statement.strip().upper().startswith(
                    ("BEGIN", "COMMIT", "ROLLBACK")
                )
            ]
            response_inserts = [
                statement
                for statement in statements
                if statement.lstrip().upper().startswith(
                    "INSERT INTO BUZZ_INGRESS_RESPONSES"
                )
            ]
            self.assertEqual(transaction_control, ["BEGIN IMMEDIATE", "COMMIT"])
            self.assertEqual(len(response_inserts), 1)
            self.assertIn("'COMPLETE'", response_inserts[0])
            self.assertNotIn("'PROCESSING'", response_inserts[0])
            return response

        created = traced(self.goal_event("opensource"))
        self.assertTrue(created["ok"])
        denied = traced(self.event(
            {"command": "status"},
            "opensource",
            sender_key=FIXTURE_KEY_B,
        ))
        self.assertFalse(denied["ok"])
        self.assertEqual(
            denied["error"], "thread is bound to another identity or project"
        )

    def test_goal_precommit_fault_rolls_back_every_row_and_retries_once(self):
        event = self.goal_event("opensource")
        before_counts = self.atomic_counts()
        before_image = self.checkpointed_database_image()

        def fail_after_dispatch(stage):
            if stage == "after_dispatch":
                raise RuntimeError("injected goal pre-commit failure")

        with mock.patch.object(
            self.router, "_transaction_checkpoint", side_effect=fail_after_dispatch
        ):
            failed = self.adapter.handle_event(copy.deepcopy(event))

        self.assertFalse(failed["ok"])
        self.assertEqual(failed["error"], "verified event dispatch failed closed")
        self.assert_fixture_metadata(failed)
        self.assertFalse(self.graph.connection.in_transaction)
        self.assertEqual(self.atomic_counts(), before_counts)
        self.assertEqual(self.checkpointed_database_image(), before_image)

        completed = self.adapter.handle_event(copy.deepcopy(event))
        self.assertTrue(completed["ok"])
        completed_counts = self.atomic_counts()
        self.assertEqual(completed_counts["goals"], 1)
        self.assertEqual(completed_counts["buzz_threads"], 1)
        self.assertEqual(completed_counts["buzz_audit"], 1)
        self.assertEqual(completed_counts["buzz_ingress_responses"], 1)
        self.assertEqual(
            self.graph.connection.execute(
                "SELECT COUNT(*) FROM buzz_ingress_responses WHERE state='PROCESSING'"
            ).fetchone()[0],
            0,
        )

        replay = self.adapter.handle_event(copy.deepcopy(event))
        self.assertEqual(replay, completed)
        self.assertEqual(self.atomic_counts(), completed_counts)

    def test_state_transition_precommit_fault_rolls_back_and_retries_once(self):
        created = self.adapter.handle_event(self.goal_event("nomad"))
        node = self.graph.get_node(created["next_node"])
        gated = self.graph.transition(
            node["node_id"],
            node["version"],
            "NEEDS_HUMAN",
            "fixture atomicity gate",
        )
        event = self.event(
            {"command": "approve", "node_id": node["node_id"]}, "nomad"
        )
        before_counts = self.atomic_counts()
        before_node = self.graph.get_node(node["node_id"])
        before_image = self.checkpointed_database_image()

        def fail_after_response(stage):
            if stage == "after_response_persist":
                raise RuntimeError("injected transition pre-commit failure")

        with mock.patch.object(
            self.adapter, "_transaction_checkpoint", side_effect=fail_after_response
        ):
            failed = self.adapter.handle_event(copy.deepcopy(event))

        self.assertFalse(failed["ok"])
        self.assertEqual(failed["error"], "verified event dispatch failed closed")
        self.assert_fixture_metadata(failed)
        self.assertFalse(self.graph.connection.in_transaction)
        self.assertEqual(self.atomic_counts(), before_counts)
        self.assertEqual(self.graph.get_node(node["node_id"]), before_node)
        self.assertEqual(self.checkpointed_database_image(), before_image)

        completed = self.adapter.handle_event(copy.deepcopy(event))
        self.assertTrue(completed["ok"])
        self.assertEqual(completed["state"], "READY")
        completed_counts = self.atomic_counts()
        self.assertEqual(completed_counts["events"], before_counts["events"] + 1)
        self.assertEqual(
            completed_counts["buzz_audit"], before_counts["buzz_audit"] + 1
        )
        self.assertEqual(
            completed_counts["buzz_ingress_responses"],
            before_counts["buzz_ingress_responses"] + 1,
        )
        self.assertEqual(
            self.graph.get_node(node["node_id"])["version"], gated["version"] + 1
        )

        replay = self.adapter.handle_event(copy.deepcopy(event))
        self.assertEqual(replay, completed)
        self.assertEqual(self.atomic_counts(), completed_counts)

    def test_router_denial_audit_and_response_roll_back_and_replay_atomically(self):
        created = self.adapter.handle_event(self.goal_event("opensource"))
        self.assertTrue(created["ok"])
        event = self.event(
            {"command": "status"},
            "opensource",
            sender_key=FIXTURE_KEY_B,
        )
        before_counts = self.atomic_counts()
        before_image = self.checkpointed_database_image()

        def fail_after_response(stage):
            if stage == "after_response_persist":
                raise RuntimeError("injected denied response pre-commit failure")

        with mock.patch.object(
            self.adapter, "_transaction_checkpoint", side_effect=fail_after_response
        ):
            failed = self.adapter.handle_event(copy.deepcopy(event))

        self.assertFalse(failed["ok"])
        self.assertEqual(failed["error"], "verified event dispatch failed closed")
        self.assertEqual(self.atomic_counts(), before_counts)
        self.assertEqual(self.checkpointed_database_image(), before_image)

        denied = self.adapter.handle_event(copy.deepcopy(event))
        self.assertFalse(denied["ok"])
        self.assertEqual(
            denied["error"], "thread is bound to another identity or project"
        )
        denied_counts = self.atomic_counts()
        self.assertEqual(
            denied_counts["buzz_audit"], before_counts["buzz_audit"] + 1
        )
        self.assertEqual(
            denied_counts["buzz_ingress_responses"],
            before_counts["buzz_ingress_responses"] + 1,
        )
        self.assertEqual(self.graph.connection.execute(
            "SELECT outcome FROM buzz_audit ORDER BY audit_id DESC LIMIT 1"
        ).fetchone()["outcome"], "DENY")

        replay = self.adapter.handle_event(copy.deepcopy(event))
        self.assertEqual(replay, denied)
        self.assertEqual(self.atomic_counts(), denied_counts)

    def test_verified_payload_and_unmapped_denials_are_durable_replays(self):
        malformed = self.event(
            {"command": "status", "unexpected": True}, "opensource"
        )
        unmapped = self.event(
            {"command": "status"},
            "opensource",
            channel_id=stable_id("durable-unmapped-channel"),
        )
        for event, error in (
            (malformed, "verified event payload denied"),
            (unmapped, "verified event channel is not mapped"),
        ):
            with self.subTest(error=error):
                before = self.atomic_counts()
                first = self.adapter.handle_event(copy.deepcopy(event))
                self.assertFalse(first["ok"])
                self.assertEqual(first["error"], error)
                replay = self.adapter.handle_event(copy.deepcopy(event))
                self.assertEqual(replay, first)
                after = self.atomic_counts()
                self.assertEqual(after["buzz_audit"], before["buzz_audit"])
                self.assertEqual(
                    after["buzz_ingress_responses"],
                    before["buzz_ingress_responses"] + 1,
                )
        self.assertEqual(
            self.graph.connection.execute(
                "SELECT COUNT(*) FROM buzz_ingress_responses WHERE state!='COMPLETE'"
            ).fetchone()[0],
            0,
        )

    def test_existing_processing_row_fails_closed_without_guessing_completion(self):
        event = self.goal_event("opensource")
        channel_id = event["tags"][0][1]
        thread_id = event["tags"][1][1]
        request_hash = hashlib.sha256(event["content"].encode("utf-8")).hexdigest()
        self.graph.connection.execute(
            "INSERT INTO buzz_ingress_responses("
            "event_id,event_body_hash,sender_pubkey,channel_id,thread_id,route,request_hash,state"
            ") VALUES(?,?,?,?,?,?,?,'PROCESSING')",
            (
                event["id"],
                event["id"],
                event["pubkey"],
                channel_id,
                thread_id,
                "opensource",
                request_hash,
            ),
        )
        self.graph.connection.commit()
        before_counts = self.atomic_counts()
        before_image = self.checkpointed_database_image()

        denied = self.adapter.handle_event(copy.deepcopy(event))

        self.assertEqual(
            denied,
            {
                "ok": False,
                "error": "durable replay binding denied",
                "fixture_result": FIXTURE_RESULT,
                "hg10": HG10_RESULT,
            },
        )
        self.assertEqual(self.atomic_counts(), before_counts)
        self.assertEqual(self.checkpointed_database_image(), before_image)
        row = self.graph.connection.execute(
            "SELECT state,response_json,response_hash FROM buzz_ingress_responses "
            "WHERE event_id=?",
            (event["id"],),
        ).fetchone()
        self.assertEqual((row["state"], row["response_json"], row["response_hash"]), (
            "PROCESSING", None, None,
        ))

    def test_verified_route_thread_and_sender_crossing_are_denied(self):
        created = self.adapter.handle_event(self.goal_event("opensource"))
        self.assertTrue(created["ok"])

        cross_route = self.adapter.handle_event(
            self.event(
                {"command": "status"},
                "business",
                thread_id=self.threads["opensource"],
            )
        )
        self.assertFalse(cross_route["ok"])
        self.assertEqual(cross_route["route"], "business")

        cross_thread = self.adapter.handle_event(
            self.event(
                {"command": "status"},
                "opensource",
                thread_id=stable_id("a-different-verified-thread"),
            )
        )
        self.assertFalse(cross_thread["ok"])

        cross_sender = self.adapter.handle_event(
            self.event(
                {"command": "status"},
                "opensource",
                sender_key=FIXTURE_KEY_B,
            )
        )
        self.assertFalse(cross_sender["ok"])

        injected_route = self.adapter.handle_event(
            self.event({"command": "status", "project": "business"}, "opensource")
        )
        self.assertFalse(injected_route["ok"])
        self.assertEqual(injected_route["error"], "verified event payload denied")

        unknown_channel = self.adapter.handle_event(
            self.event(
                {"command": "status"},
                "opensource",
                channel_id=stable_id("unmapped-fixture-channel"),
            )
        )
        self.assertFalse(unknown_channel["ok"])
        self.assertEqual(unknown_channel["error"], "verified event channel is not mapped")

    def test_malformed_stale_bad_signature_and_extra_fields_fail_closed(self):
        baseline = self.event({"command": "status"}, "opensource")
        before_untrusted = self.atomic_counts()

        wrong_id = copy.deepcopy(baseline)
        wrong_id["id"] = "0" * 64
        bad_signature = copy.deepcopy(baseline)
        bad_signature["sig"] = "0" * 128
        content_not_bound_to_id = copy.deepcopy(baseline)
        content_not_bound_to_id["content"] = '{"command":"goal"}'
        extra_envelope = copy.deepcopy(baseline)
        extra_envelope["project"] = "business"
        extra_tags = self.event(
            {"command": "status"},
            "opensource",
            tags=baseline["tags"] + [["p", PUBKEY_A]],
        )
        wrong_kind = self.event({"command": "status"}, "opensource", kind=43)
        stale = self.event(
            {"command": "status"},
            "opensource",
            created_at=NOW - self.fixture_config["max_age_seconds"] - 1,
        )
        future = self.event(
            {"command": "status"},
            "opensource",
            created_at=NOW + self.fixture_config["max_future_skew_seconds"] + 1,
        )
        forged_sender = self.event(
            {"command": "status"},
            "opensource",
            sender_key=FIXTURE_KEY_B,
            signing_key=FIXTURE_KEY_A,
        )

        for event in (
            wrong_id,
            bad_signature,
            content_not_bound_to_id,
            extra_envelope,
            extra_tags,
            wrong_kind,
            stale,
            future,
            forged_sender,
        ):
            with self.subTest(event=event):
                response = self.adapter.handle_event(event)
                self.assertFalse(response["ok"])
                self.assertEqual(response["error"], "event verification denied")
                self.assertNotIn("route", response)
                self.assertNotIn("thread_id", response)
                self.assert_fixture_metadata(response)

        self.assertEqual(self.atomic_counts(), before_untrusted)

        for event in (
            self.event({"command": "status", "unexpected": True}, "opensource"),
            self.event(None, "opensource", raw_content='{"command":"status","command":"goal"}'),
            self.event({"command": "digest"}, "opensource"),
        ):
            response = self.adapter.handle_event(event)
            self.assertFalse(response["ok"])
            self.assertEqual(response["error"], "verified event payload denied")
            self.assertEqual(response["route"], "opensource")
            self.assert_fixture_metadata(response)

    def test_consequential_authority_fields_cannot_ride_ordinary_approval(self):
        created = self.adapter.handle_event(self.goal_event("nomad"))
        node = self.graph.get_node(created["next_node"])
        gated = self.graph.transition(
            node["node_id"], node["version"], "NEEDS_HUMAN", "fixture ordinary human gate"
        )
        attacks = (
            {"command": "approve", "node_id": node["node_id"], "authority": "live_order"},
            {"command": "approve", "node_id": node["node_id"], "action": "publish"},
            {"command": "approve", "node_id": node["node_id"], "capability": "production_deploy"},
            {"command": "approve", "node_id": node["node_id"], "credential": "fixture-sensitive"},
        )
        for payload in attacks:
            response = self.adapter.handle_event(self.event(payload, "nomad"))
            self.assertFalse(response["ok"])
            self.assertEqual(response["error"], "verified event payload denied")
            self.assertEqual(self.graph.get_node(node["node_id"])["state"], "NEEDS_HUMAN")
            self.assert_fixture_metadata(response)

        self.assertEqual(self.graph.get_node(node["node_id"])["version"], gated["version"])
        stored = " ".join(
            row[0]
            for row in self.graph.connection.execute(
                "SELECT response_json FROM buzz_ingress_responses WHERE response_json IS NOT NULL"
            ).fetchall()
        )
        self.assertNotIn("fixture-sensitive", stored)
        self.assertNotIn("live_order", stored)

    def test_config_requires_fixture_labels_and_exact_four_channel_mapping(self):
        mutations = []
        missing_route = copy.deepcopy(self.fixture_config)
        missing_route["channel_routes"].pop(self.channels["hynix"])
        mutations.append(missing_route)
        duplicate_route = copy.deepcopy(self.fixture_config)
        duplicate_route["channel_routes"][self.channels["hynix"]] = "nomad"
        mutations.append(duplicate_route)
        extra_legacy_route = copy.deepcopy(self.fixture_config)
        extra_legacy_route["channel_routes"][stable_id("legacy-channel")] = "fin-global"
        mutations.append(extra_legacy_route)
        false_hg10 = copy.deepcopy(self.fixture_config)
        false_hg10["hg10"] = "PASS"
        mutations.append(false_hg10)

        for index, config in enumerate(mutations):
            path = self.temp_path / f"invalid-adapter-{index}.json"
            path.write_text(json.dumps(config), encoding="utf-8")
            with self.subTest(index=index), self.assertRaises(BuzzEnvelopeError):
                BuzzNativeAdapter(self.router, path, self.verifier, clock=lambda: NOW)

        with self.assertRaises(TypeError):
            BuzzNativeAdapter(self.router, ADAPTER_CONFIG, None, clock=lambda: NOW)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
