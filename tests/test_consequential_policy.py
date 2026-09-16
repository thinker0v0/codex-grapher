import datetime as dt
import hashlib
import hmac
import json
import unittest

from control_plane.consequential_policy import authorize_action, redact


KEY = b"test-only-verification-key"


def capability(action="live_order", lifetime=30):
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    value = {
        "capability_id": "human-grant-1", "issuer": "human-approver", "action": action,
        "account_id": "acct-123", "environment": "live", "instrument": "MES",
        "max_quantity": 1, "max_notional": 25000, "max_loss": 100,
        "issued_at": now.isoformat(), "expires_at": (now + dt.timedelta(minutes=lifetime)).isoformat(),
        "nonce": "unique-nonce-1234",
    }
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    value["signature"] = hmac.new(KEY, raw, hashlib.sha256).hexdigest()
    return value


class ConsequentialPolicyTests(unittest.TestCase):
    def test_live_order_denied_without_distinct_human_grant(self):
        self.assertFalse(authorize_action("live_order", None, KEY))
        self.assertFalse(authorize_action("live_order", {"issuer": "model"}, KEY))

    def test_valid_expiring_grant_is_narrow_and_tamper_evident(self):
        grant = capability()
        self.assertTrue(authorize_action("live_order", grant, KEY))
        self.assertFalse(authorize_action("payment", grant, KEY))
        grant["account_id"] = "all"
        self.assertFalse(authorize_action("live_order", grant, KEY))

    def test_unknown_and_every_irreversible_action_fail_closed(self):
        for action in ("unknown_tool", "external_message", "protected_merge", "credential_grant", "sign_contract"):
            self.assertFalse(authorize_action(action, None, KEY), action)

    def test_scope_and_nonce_are_enforced(self):
        used = set()
        grant = capability()
        scope = {"account_id": "acct-123", "instrument": "MES"}
        self.assertTrue(authorize_action("live_order", grant, KEY, used_nonces=used, expected_scope=scope))
        self.assertFalse(authorize_action("live_order", grant, KEY, used_nonces=used, expected_scope=scope))
        wrong = capability()
        self.assertFalse(authorize_action("live_order", wrong, KEY, expected_scope={"account_id": "acct-other"}))

    def test_overlong_grant_denied(self):
        self.assertFalse(authorize_action("live_order", capability(lifetime=61), KEY))

    def test_credentials_are_redacted_recursively(self):
        value = redact({"api_key": "sk-secret", "nested": [{"password": "pw", "safe": "ok"}]})
        self.assertNotIn("sk-secret", json.dumps(value))
        self.assertNotIn("pw", json.dumps(value))
        self.assertEqual(value["nested"][0]["safe"], "ok")
