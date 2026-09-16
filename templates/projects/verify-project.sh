#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

test -d .git
test -s AGENTS.md
test -s HERMES.md
test -s .gitignore

if git ls-files | rg -q '(^|/)(\.env|auth\.json|secrets?|credentials?)(/|$)'; then
  echo "Tracked secret-like path detected" >&2
  exit 1
fi

if rg -l --hidden --glob '!.git/**' --glob '!scripts/verify-project.sh' \
  '(xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|DASHSCOPE_API_KEY=[^[:space:]]+)' .; then
  echo "Possible credential detected" >&2
  exit 1
fi

git diff --check
echo "project verification passed"

