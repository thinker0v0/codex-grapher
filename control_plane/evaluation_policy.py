"""Explicit frozen task acceptance, independent of the legacy release rubric."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("task policy contains a duplicate JSON key")
        result[key] = value
    return result


def _number(value: Any) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _name(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and value == value.strip()


@dataclass(frozen=True, slots=True)
class TaskEvaluationPolicy:
    """Immutable values derived only from validated, exact JSON source bytes."""

    source_bytes: bytes = field(repr=False)
    name: str = field(init=False)
    sections: tuple[tuple[str, float, float], ...] = field(init=False)
    mandatory_gates: frozenset[str] = field(init=False)
    threshold: float = field(init=False)
    sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.source_bytes) is not bytes:
            raise ValueError("task policy requires immutable JSON bytes")
        try:
            value = json.loads(self.source_bytes, object_pairs_hook=_object)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("task policy is not valid JSON") from exc
        if not isinstance(value, dict) or set(value) != {
            "schema_version", "name", "sections", "mandatory_gates", "threshold",
        }:
            raise ValueError("task policy does not match the exact version-1 schema")
        if type(value["schema_version"]) is not int or value["schema_version"] != 1:
            raise ValueError("unsupported task policy schema version")
        if not _name(value["name"]):
            raise ValueError("task policy name must be nonempty")
        sections = value["sections"]
        if not isinstance(sections, dict) or not sections:
            raise ValueError("task policy sections must be nonempty")
        limits = []
        for name, bounds in sections.items():
            if (not _name(name) or not isinstance(bounds, dict)
                    or set(bounds) != {"minimum", "maximum"}):
                raise ValueError("task policy section has invalid name or bounds")
            minimum, maximum = bounds["minimum"], bounds["maximum"]
            if (not _number(minimum) or not _number(maximum)
                    or not 0 <= minimum <= maximum <= 100 or maximum <= 0):
                raise ValueError("task policy section bounds must be finite and nondegenerate")
            limits.append((name, float(minimum), float(maximum)))
        if math.fsum(item[2] for item in limits) != 100:
            raise ValueError("task policy section maxima must sum to 100")
        gates = value["mandatory_gates"]
        if (not isinstance(gates, list) or not gates
                or any(not _name(gate) for gate in gates) or len(set(gates)) != len(gates)):
            raise ValueError("task policy requires nonempty unique mandatory gate names")
        threshold = value["threshold"]
        if not _number(threshold) or not 95 <= threshold <= 100:
            raise ValueError("task policy threshold must be finite and within 95..100")
        object.__setattr__(self, "name", value["name"])
        object.__setattr__(self, "sections", tuple(sorted(limits)))
        object.__setattr__(self, "mandatory_gates", frozenset(gates))
        object.__setattr__(self, "threshold", float(threshold))
        object.__setattr__(self, "sha256", hashlib.sha256(self.source_bytes).hexdigest())


def load_task_policy(path: Path | str) -> TaskEvaluationPolicy:
    """Load a trusted planner/evaluator policy; results never choose this path."""
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("task policy must be a regular non-symlink file")
    return TaskEvaluationPolicy(path.read_bytes())


def validate_task_policy(policy: TaskEvaluationPolicy, rubric_sha256: str | None) -> None:
    """Re-derive all fields, including the digest, at each verification boundary."""
    if type(policy) is not TaskEvaluationPolicy:
        raise TypeError("evaluation policy must be an actual TaskEvaluationPolicy")
    if policy != TaskEvaluationPolicy(policy.source_bytes):
        raise PermissionError("task policy differs from its immutable source bytes")
    if rubric_sha256 != policy.sha256:
        raise PermissionError("task policy and rubric SHA-256 must match")
