"""Fail-closed policy for finance and other irreversible actions."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
from typing import Any


SAFE_ACTIONS = {"read", "research", "backtest", "paper_order", "test", "status", "cancel"}
CONSEQUENTIAL = {
    "live_order", "change_risk_limit", "payment", "publish", "release",
    "protected_merge", "external_message", "credential_grant", "sign_contract",
    "production_deploy",
}


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def authorize_action(action: str, capability: dict[str, Any] | None, verification_key: bytes,
                     now: dt.datetime | None = None, used_nonces: set[str] | None = None,
                     expected_scope: dict[str, Any] | None = None) -> bool:
    if action in SAFE_ACTIONS:
        return True
    if action not in CONSEQUENTIAL:
        return False
    if not capability or capability.get("action") != action or capability.get("issuer") != "human-approver":
        return False
    now = now or dt.datetime.now(dt.timezone.utc)
    try:
        expires = dt.datetime.fromisoformat(capability["expires_at"].replace("Z", "+00:00"))
        issued = dt.datetime.fromisoformat(capability["issued_at"].replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError):
        return False
    if not issued <= now < expires or expires - issued > dt.timedelta(hours=1):
        return False
    nonce = capability.get("nonce")
    if not isinstance(nonce, str) or len(nonce) < 16 or (used_nonces is not None and nonce in used_nonces):
        return False
    if action in {"live_order", "change_risk_limit"}:
        required = {"account_id", "environment", "instrument", "max_quantity", "max_notional", "max_loss"}
        if not required.issubset(capability) or capability.get("environment") != "live":
            return False
        if capability.get("account_id") in {"*", "all", "ALL"} or capability.get("instrument") in {"*", "all", "ALL"}:
            return False
        if any(not isinstance(capability.get(name), (int, float)) or capability[name] <= 0
               for name in ("max_quantity", "max_notional", "max_loss")):
            return False
    if expected_scope and any(capability.get(name) != value for name, value in expected_scope.items()):
        return False
    signature = capability.get("signature", "")
    subject = {key: value for key, value in capability.items() if key != "signature"}
    expected = hmac.new(verification_key, _canonical(subject), hashlib.sha256).hexdigest()
    valid = hmac.compare_digest(signature, expected)
    if valid and used_nonces is not None:
        used_nonces.add(nonce)
    return valid


def redact(value: Any) -> Any:
    """Remove common credential-bearing fields before logs or evidence."""
    blocked = {"password", "secret", "token", "api_key", "private_key", "account_number"}
    if isinstance(value, dict):
        return {key: "[REDACTED]" if key.lower() in blocked else redact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value
