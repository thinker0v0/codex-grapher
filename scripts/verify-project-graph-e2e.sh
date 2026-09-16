#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
python3 -m unittest tests.test_project_graph tests.test_graph_planner tests.test_project_integrator tests.test_project_coordinator tests.test_graph_service -v
