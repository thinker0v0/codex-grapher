# Disposable guest recovery harness

This is a deterministic protocol fixture for service and guest interruption. It
does not use a real model, subscription, provider credential or production
service. Its provider emits deliberately synthetic Codex protocol/version/login
strings. Actual Codex acceptance is a separate experiment.

The host needs Linux x86-64, Python 3.12+, OpenSSH client tools, `dpkg-deb`,
OpenSSL and `setpriv`, with at least 3 GiB available RAM and 6 GiB free disk.
An existing non-root UID/GID must be able to traverse the task directory. Root
invocation drops QEMU to that UID; it creates no host account and changes no host
package database, service or network configuration. QEMU's inherited host dynamic
libraries are recorded individually, so this is not a hermetic host image claim.

Each command runs one scenario, one 1-vCPU/1-GiB QEMU TCG guest, a 64-MiB TCG
translation cache, a 180-second boot deadline and a 600-second total deadline.
The external command limit is 900 seconds, leaving cleanup room. An eight-second
SSH handshake timeout is retried until the overall boot deadline. SIGTERM/SIGINT
and exceptions stop and reap only the harness-owned QEMU process. Runtime disks,
fixture keys and serial logs remain in the explicit ignored runtime for review.
Never commit or distribute that directory.

## Provision once

From this public repository, use fresh runtime/output paths. `--download` permits
only the public, checksum-pinned inputs listed in `toolchain-lock.json` and
`guest-packages-lock.json`. An existing verified cache can be supplied with
`--cache PATH`. The pilot image basename is accepted only after matching the
dated image's exact length and SHA-512.

```sh
timeout 900s python3 scripts/verify-guest-recovery.py \
  --scenario provision --run-id provision-1 \
  --runtime artifacts/guest-provision-1 --download \
  --output artifacts/guest-provision-1/evidence.json
```

The guest receives the pinned Debian Git/bubblewrap dependency bundle through
SSH and installs it offline. QEMU user-mode networking permits only the ephemeral
loopback SSH forwarding; guest outbound traffic is disabled. There is no host
filesystem share. The harness verifies that no product source, workflow state or
signing key exists, requests an orderly guest shutdown and writes a hash-bound
`prepared-image.json`. The readonly prepared overlay is reusable; its fixture
SSH key stays at its original ignored location and is never copied.

## Run one boundary

After component integration and a clean source commit:

```sh
timeout 900s python3 scripts/verify-guest-recovery.py \
  --scenario B4-reset --run-id b4-reset-1 \
  --prepared-runtime artifacts/guest-provision-1 \
  --cache artifacts/guest-provision-1/cache \
  --runtime artifacts/guest-b4-reset-1 \
  --output artifacts/guest-b4-reset-1/evidence.json
```

Each `B1` through `B5` has separate `-service` and `-reset` cases. A root-owned
systemd fixture service uses the installed bootstrap; graph, worker, candidate
tests and signer execute under distinct real guest UIDs. A trusted callback
pauses the live graph operation at the named boundary. Service cases SIGKILL the
unit's entire control group and observe systemd restart. Reset cases SIGKILL
QEMU, restart the same overlay and require a different kernel boot UUID.

| Boundary | Durable point |
| --- | --- |
| B1 | Invocation reserved, no graph-admitted artifact; recovery must pause |
| B2 | Immutable artifact graph-admitted |
| B3 | Signed outcome committed |
| B4 | Promotion binding replaced, logical completion pending |
| B5 | Rollback binding replaced, logical completion pending |

The harness records exact source/tool/configuration hashes, boot and systemd
invocation IDs, reservation count, sealed test receipt IDs, accepted SHA, journal
tail/entry count/distinct operation count, closure verification and a separately
executed accepted-generation Git consumer. Replay must preserve accepted state,
invocation count and journal tail. B1 must not resume a worker; B3–B5 must not
rerun completed candidate tests. Actual deterministic-provider entry appends and
fsyncs an explicitly allowed, tracked `fixture-launches.jsonl`; frozen checks
require exactly one entry. This fixed-fixture witness distinguishes reservation
count from actual execution count, and makes no hostile-worker audit claim.
Fresh restore marks the scratch witness unavailable because backup deliberately
excludes worker checkouts. `boot-reboot` additionally requests an orderly
guest reboot and verifies its changed boot UUID.

## Fresh guest restore

Use `--scenario restore` with the same prepared runtime. The harness creates a
new fixture signing key outside all workspaces, provisions it separately into
the original guest, completes the workflow, and retrieves a quiescent full-state
backup. It then stops the original guest and boots a distinct overlay backed only
by the credential-free prepared image. No original workflow disk is attached and
no original root is reachable through a share or the network.

The new guest installs identical trusted code/tools at the same absolute paths,
receives only the archive and public key, and must initially report verify-only
restore. The matching fixture private key is then provisioned separately through
SSH from the task-local ignored key store; its bytes are never recorded in command
output, evidence or the backup. The driver verifies the original public-key
identity, idempotent recovery, an accepted consumer and predecessor rollback.

The image contains only fixture identities. No actual provider login store is
ever provisioned. After review, deleting the explicit runtime directories removes
the fixture disks and private fixture keys. A prepared image must be retained
while any overlay uses it as a backing image.

## Evidence boundary

`OBSERVED` means only that this harness completed the specified observations.
Independent evaluation owns all pass decisions. `INCOMPLETE` retains the error,
command outputs/hashes and cleanup record. `--allow-dirty-source` exists solely
for development and cannot establish clean-SHA acceptance. A QEMU SIGKILL proves
simulated abrupt guest loss; it does not certify physical storage-controller or
power-failure behavior. Corruption/archive adversarial checks also belong to
`verify-workspace-backup.py` and the independently evaluated backup tests.
