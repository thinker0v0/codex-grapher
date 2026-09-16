#!/usr/bin/env bash
set -euo pipefail

profiles=(fin-global fin-korea hynix business oss evaluator)
failed=0

check() {
  local description="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "PASS $description"
  else
    echo "FAIL $description"
    failed=1
  fi
}

for profile_name in "${profiles[@]}"; do
  account_name="hermes-${profile_name}"
  check "account $account_name exists" getent passwd "$account_name"
  check "home /srv/hermes/$profile_name exists" test -d "/srv/hermes/$profile_name"
  check "environment /etc/hermes/$profile_name.env exists" test -f "/etc/hermes/$profile_name.env"
done

check "generic systemd unit exists" test -f /etc/systemd/system/hermes-profile@.service
check "evaluator systemd unit exists" test -f /etc/systemd/system/hermes-evaluator.service
check "profile runner exists" test -x /usr/local/libexec/ai-ops/run-hermes-profile

for profile_name in fin-global fin-korea hynix business oss; do
  if systemctl cat "hermes-profile@${profile_name}.service" >/dev/null 2>&1; then
    systemd-analyze security --no-pager "hermes-profile@${profile_name}.service" || failed=1
  fi
done

if systemctl cat hermes-evaluator.service >/dev/null 2>&1; then
  systemd-analyze security --no-pager hermes-evaluator.service || failed=1
fi

exit "$failed"
