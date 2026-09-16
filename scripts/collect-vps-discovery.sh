#!/usr/bin/env bash
set -euo pipefail

echo "== timestamp =="
date -u +%Y-%m-%dT%H:%M:%SZ

echo "== cpu =="
lscpu

echo "== memory =="
free -h

echo "== block devices =="
lsblk -o NAME,SIZE,FSTYPE,MOUNTPOINTS

echo "== filesystems =="
df -hT
findmnt

echo "== virtualization and kernel =="
systemd-detect-virt || true
uname -a

echo "== network addresses and routes =="
ip -br addr
ip route

echo "== listening services =="
ss -lntup

echo "== failed services =="
systemctl --failed --no-pager || true

echo "== hermes commands =="
command -v hermes || true
hermes --version 2>/dev/null || true
hermes status 2>/dev/null || true

echo "== codex commands =="
command -v codex || true
codex --version 2>/dev/null || true

echo "== container runtime =="
command -v docker || true
docker version 2>/dev/null || true
command -v podman || true
podman version 2>/dev/null || true

echo "== pressure =="
for pressure_file in /proc/pressure/cpu /proc/pressure/memory /proc/pressure/io; do
  if test -r "$pressure_file"; then
    echo "$pressure_file"
    sed -n '1,20p' "$pressure_file"
  fi
done

echo "== discovery complete =="
