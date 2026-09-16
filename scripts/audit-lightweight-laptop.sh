#!/usr/bin/env bash
set -euo pipefail

failed=0
for pattern in 'hermes gateway' 'codex exec-server' 'ollama serve' 'qdrant' 'chromadb'; do
  if pgrep -af "$pattern" | rg -v 'audit-lightweight-laptop|pgrep -af' >/dev/null; then
    echo "FAIL unexpected local process: $pattern"
    failed=1
  else
    echo "PASS no local process: $pattern"
  fi
done

available_kib="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
if (( available_kib < 524288 )); then
  echo "FAIL available laptop memory below 512 MiB"
  failed=1
else
  echo "PASS available laptop memory above 512 MiB"
fi

exit "$failed"

