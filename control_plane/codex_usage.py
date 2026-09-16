#!/usr/bin/env python3
"""Extract conservative cumulative token usage from Codex JSONL events."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def totals(value: Any) -> list[int]:
    found: list[int] = []
    if isinstance(value, dict):
        usage = value.get("usage")
        if isinstance(usage, dict):
            total = usage.get("total_tokens")
            if isinstance(total, int) and total >= 0:
                found.append(total)
            else:
                parts = [usage.get(name) for name in ("input_tokens", "output_tokens")]
                if all(isinstance(part, int) and part >= 0 for part in parts):
                    found.append(sum(parts))
        for child in value.values():
            found.extend(totals(child))
    elif isinstance(value, list):
        for child in value:
            found.extend(totals(child))
    return found


def parse_jsonl(path: Path) -> int:
    maximum = 0
    if not path.exists():
        return maximum
    with path.open(errors="replace") as handle:
        for line in handle:
            try:
                maximum = max([maximum, *totals(json.loads(line))])
            except json.JSONDecodeError:
                continue
    return maximum


if __name__ == "__main__":
    print(parse_jsonl(Path(sys.argv[1])))
