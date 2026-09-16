#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
python3 -m unittest tests.test_project_graph.ProjectGraphTests.test_restart_recovers_work_without_terminalizing_it -v

