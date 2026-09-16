#!/usr/bin/env python3
"""Drive the existing four-route campaign with maximum-results contracts."""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path


CAMPAIGN = Path("/srv/hermes/oss/.hermes/campaign/campaign.py")


def load_campaign():
    spec = importlib.util.spec_from_file_location("hermes_campaign", CAMPAIGN)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {CAMPAIGN}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def maximize(module) -> None:
    module.POLICY_DRAFT = {"decision": "allow", "policy_version": "max-codex-v1"}
    module.MAX_INFLIGHT = 4
    module.LOST_AFTER_S = 21660
    module.ECONOMY = (
        " MAXIMUM-RESULTS POLICY: do not minimize Codex tokens or tool calls. "
        "Investigate deeply, implement the strongest scoped result, run all required tests, "
        "and preserve complete evidence. Continue until verified or genuinely blocked."
    )
    original = module.build_contract

    def build_contract(route, stage, state, shrink):
        path = original(route, stage, state, False)
        value = json.loads(path.read_text(encoding="utf-8"))
        now = dt.datetime.now(dt.timezone.utc)
        value["authorization"] = module.POLICY_DRAFT
        value["budget"] = {"max_cost_usd": 1000000, "max_tokens": 1000000000}
        value["deadline"] = (now + dt.timedelta(hours=23)).isoformat()
        value["timeout_seconds"] = 21600
        value["max_iterations"] = 5
        value["objective"] += module.ECONOMY
        path.write_text(json.dumps(value, indent=1) + "\n", encoding="utf-8")
        return path

    module.build_contract = build_contract


def renew_expired_campaign(module, force: bool = False) -> None:
    now = dt.datetime.now(dt.timezone.utc)
    current = json.loads(module.STATE_F.read_text(encoding="utf-8"))
    end = dt.datetime.fromisoformat(current["campaign_end"].replace("Z", "+00:00"))
    if end > now and not force:
        return
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    os.replace(module.STATE_F, module.STATE_F.with_name(f"state-{stamp}.json"))
    routes = {}
    for route in module.ROUTE_ORDER:
        profile = module.ROUTE_PROFILE[route]
        result = subprocess.run(
            [module.ROUTER, "status", route], check=True, capture_output=True, text=True, timeout=60
        )
        binding = json.loads(result.stdout)
        routes[route] = {
            "profile": profile,
            "repo": binding["repo"],
            "base_sha": binding["base_sha"],
            "stage": 1,
            "status": "pending",
            "blocker": "",
            "tasks": [],
            "attempts": {},
        }
    state = {
        "campaign_start": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "campaign_end": (now + dt.timedelta(hours=24)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "final_emitted": False,
        "inflight": {},
        "routes": routes,
    }
    module.STATE_F.write_text(json.dumps(state, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    if not CAMPAIGN.is_file():
        print(f"campaign definition is missing: {CAMPAIGN}", file=sys.stderr)
        return 69
    campaign = load_campaign()
    maximize(campaign)
    force_renew = len(sys.argv) > 1 and sys.argv[1] == "renew"
    if force_renew:
        del sys.argv[1]
    renew_expired_campaign(campaign, force=force_renew)
    return campaign.main()


if __name__ == "__main__":
    raise SystemExit(main())
