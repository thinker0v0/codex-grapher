#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root" >&2
  exit 77
fi

backup_root="${HERMES_BACKUP_ROOT:-/var/lib/hermes-control-plane-backup}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
archive="${backup_root}/hermes-config-${timestamp}.tar.gz"
manifest="${archive}.sha256"
profiles=(fin-global fin-korea hynix business oss evaluator)

install -d -o root -g root -m 0700 "$backup_root"
staging="$(mktemp -d)"
trap 'rm -rf -- "$staging"' EXIT

install -d -m 0700 "$staging/etc-systemd" "$staging/profiles"
install -m 0644 /etc/systemd/system/hermes-profile@.service "$staging/etc-systemd/"
install -m 0644 /etc/systemd/system/hermes-evaluator.service "$staging/etc-systemd/"

for profile_name in "${profiles[@]}"; do
  install -d -m 0700 "$staging/profiles/$profile_name"
  install -m 0600 "/srv/hermes/$profile_name/.hermes/config.yaml" "$staging/profiles/$profile_name/"
  install -m 0600 "/srv/hermes/$profile_name/.hermes/SOUL.md" "$staging/profiles/$profile_name/"
done

# Credentials, sessions, memories, logs, and workspaces are deliberately excluded.
tar -C "$staging" -czf "$archive" .
chmod 0600 "$archive"
sha256sum "$archive" >"$manifest"
chmod 0600 "$manifest"
echo "$archive"
