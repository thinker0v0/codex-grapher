#!/usr/bin/env bash
set -euo pipefail

archive="${1:-}"
if [[ -z "$archive" || ! -f "$archive" || ! -f "${archive}.sha256" ]]; then
  echo "Usage: $0 /path/to/hermes-config-*.tar.gz" >&2
  exit 64
fi

sha256sum -c "${archive}.sha256"
restore_root="$(mktemp -d)"
trap 'rm -rf -- "$restore_root"' EXIT
tar -C "$restore_root" -xzf "$archive"

profiles=(fin-global fin-korea hynix business oss evaluator)
test -s "$restore_root/etc-systemd/hermes-profile@.service"
test -s "$restore_root/etc-systemd/hermes-evaluator.service"
for profile_name in "${profiles[@]}"; do
  test -s "$restore_root/profiles/$profile_name/config.yaml"
  test -s "$restore_root/profiles/$profile_name/SOUL.md"
  ! rg -q 'DASHSCOPE_API_KEY|SLACK_(BOT|APP)_TOKEN|CODEX_API_KEY' \
    "$restore_root/profiles/$profile_name"
done

echo "restore drill passed: archive integrity, required files, and secret exclusion verified"

