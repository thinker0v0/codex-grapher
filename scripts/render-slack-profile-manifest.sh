#!/usr/bin/env bash
set -euo pipefail

profile="${1:-}"
case "$profile" in
  fin-korea) display_name="Hermes Finance Korea" ;;
  hynix) display_name="Hermes SK hynix" ;;
  business) display_name="Hermes Business" ;;
  oss) display_name="Hermes Open Source" ;;
  *) echo "Usage: $0 {fin-korea|hynix|business|oss}" >&2; exit 64 ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
template="${repo_root}/config/slack-app-manifest.example.yaml"
if [[ ! -r "$template" ]]; then
  template="/usr/local/share/ai-ops/slack-app-manifest.example.yaml"
fi
[[ -r "$template" ]] || { echo "Slack app manifest template is not installed" >&2; exit 69; }
sed \
  -e "s/Hermes PROJECT/${display_name}/g" \
  -e "s/Project-scoped Hermes/${profile} project-scoped Hermes/" \
  "$template"
