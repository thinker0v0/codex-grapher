"""Finite retry policy and server-derived failure identities (stdlib only)."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any


RETRY_EVENT_PREFIX = "retry:v1:"
CONTROLLER_STATES = frozenset({
    "UNKNOWN", "RECEIVED", "AUTHORIZED", "NORMALIZED", "PLANNED", "QUEUED",
    "LEASED", "RUNNING", "EVIDENCE_PENDING", "EVALUATING", "REWORK_REQUESTED",
    "PASSED", "HUMAN_APPROVAL_PENDING", "COMPLETED", "REJECTED", "CANCELLED",
    "FAILED_PERMANENT", "FAILED_BUDGET", "FAILED_TIMEOUT", "FAILED_STAGNATION",
    "FAILED_GATE", "NEEDS_HUMAN", "SUPERSEDED",
})


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    initial_delay_seconds: int = 5
    backoff_multiplier: float = 2
    max_delay_seconds: int = 300
    max_identical_failures: int = 2

    @classmethod
    def from_spec(cls, spec: dict[str, Any]) -> "RetryPolicy":
        value = spec.get("retry_policy", {})
        if type(value) is not dict or set(value) - set(cls.__dataclass_fields__):
            raise ValueError("retry_policy must contain only the documented policy fields")
        policy = cls(**value)
        for name, maximum in (
            ("max_attempts", 100), ("max_identical_failures", 2),
            ("initial_delay_seconds", 3600), ("max_delay_seconds", 3600),
        ):
            number = getattr(policy, name)
            if type(number) is not int or not 1 <= number <= maximum:
                raise ValueError(f"retry_policy {name} requires an integer in 1..{maximum}")
        multiplier = policy.backoff_multiplier
        if (type(multiplier) not in {int, float} or not 1 <= multiplier <= 10
                or not math.isfinite(multiplier)):
            raise ValueError("retry_policy backoff_multiplier requires a finite number in 1..10")
        return policy

    def delay(self, attempt: int) -> float:
        if type(attempt) is not int or attempt < 1:
            raise ValueError("retry attempt must be a positive integer")
        # Old databases can contain counters beyond today's maximum of 100.
        # Those attempts are exhausted; avoid unbounded exponentiation on them.
        if attempt > 100:
            return self.max_delay_seconds
        return min(self.max_delay_seconds,
                   self.initial_delay_seconds * self.backoff_multiplier ** (attempt - 1))


def validate_node_policy(spec: dict[str, Any]) -> RetryPolicy:
    if type(spec) is not dict:
        raise ValueError("node specification must be an object")
    if "human_gate" in spec and type(spec["human_gate"]) is not bool:
        raise ValueError("human_gate must be a boolean")
    return RetryPolicy.from_spec(spec)


def classify_failure(returncode: int, controller_state: str | None) -> tuple[str, str]:
    if type(returncode) is not int or not -(2 ** 31) <= returncode < 2 ** 31:
        raise ValueError("worker returncode must be an integer in signed 32-bit range")
    state = "UNKNOWN" if controller_state is None else controller_state
    if type(state) is not str or state not in CONTROLLER_STATES:
        raise ValueError("unknown controller state")
    permanent = {
        "FAILED_GATE": "SAFETY", "FAILED_PERMANENT": "PERMANENT",
        "FAILED_BUDGET": "BUDGET", "REJECTED": "PERMANENT",
        "CANCELLED": "CANCELLED", "SUPERSEDED": "CANCELLED",
        "NEEDS_HUMAN": "HUMAN", "FAILED_STAGNATION": "HUMAN",
        "HUMAN_APPROVAL_PENDING": "HUMAN",
    }
    if state in permanent:
        return permanent[state], state
    if state == "FAILED_TIMEOUT" or returncode == 124:
        return "TIMEOUT", state
    # Successful transport cannot authenticate a controller result or artifact.
    return ("UNKNOWN" if returncode == 0 else "PROCESS"), state


def failure_fingerprint(failure_class: str, controller_state: str, returncode: int | None) -> str:
    value = {"failure_class": failure_class, "controller_state": controller_state,
             "returncode": returncode}
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def parse_retry_event(reason: str) -> dict[str, Any] | None:
    if type(reason) is not str:
        raise ValueError("event reason must be a string")
    if not reason.startswith(RETRY_EVENT_PREFIX):
        return None
    value = json.loads(reason[len(RETRY_EVENT_PREFIX):])
    if type(value) is not dict or set(value) != {
        "attempt", "failure_class", "controller_state", "returncode", "fingerprint",
        "recorded_at", "next_eligible_at",
    }:
        raise ValueError("malformed retry event")
    if type(value["attempt"]) is not int or value["attempt"] < 1:
        raise ValueError("malformed retry attempt")
    return value
