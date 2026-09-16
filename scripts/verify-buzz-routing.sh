#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
python3 - <<'PY'
import json
from pathlib import Path

root = Path.cwd()
config = json.loads((root / "config/buzz-routing.example.json").read_text())
fixture = json.loads((root / "config/buzz-native-fixture.example.json").read_text())
prompt = (root / "prompts/hermes/buzz-supervisor.md").read_text()
assert config["default_policy"] == "deny"
assert config["transport"] == "hermes-native-buzz-gateway"
assert fixture["surface"] == "native-like-fixture-only"
assert fixture["production_use"] == "forbidden"
assert fixture["result_label"] == "FIXTURE_PASS"
assert fixture["hg10"] == "UNPROVEN"
assert set(fixture["channel_routes"].values()) == {"nomad", "opensource", "business", "hynix"}
assert len(fixture["channel_routes"]) == 4
for command in ("goal", "status", "evidence", "approve", "reject", "cancel", "resume"):
    assert command in prompt
assert "RECONCILING" in prompt
assert "return code is not a" in prompt.lower() and "task result" in prompt.lower()
print("Buzz static routing and fixture contracts parsed; no staging or service action was attempted")
PY
python3 -m unittest tests.test_buzz_router -v
python3 -m unittest tests.test_buzz_native_adapter -v
printf '%s\n' 'FIXTURE_PASS: native-like Buzz adapter fixtures passed; HG10=UNPROVEN without real Buzz staging credentials and E2E evidence'
