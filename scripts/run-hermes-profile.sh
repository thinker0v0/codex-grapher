#!/usr/bin/env bash
set -euo pipefail

profile_name="${1:?profile name is required}"

case "$profile_name" in
  fin-global|fin-korea|hynix|business|oss|evaluator) ;;
  *)
    echo "Unknown Hermes profile: $profile_name" >&2
    exit 64
    ;;
esac

export HOME="/srv/hermes/$profile_name"
export HERMES_HOME="$HOME/.hermes"
export HERMES_PROFILE="$profile_name"

exec hermes gateway run --replace --external-supervisor
