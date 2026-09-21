# Design amendment v3: Codex under external Linux isolation

Status: candidate for independent design review; implementation change not yet
authorized by this document. Record: `opensource.portable-workers.design-amendment.v3`.
Date: 2026-09-21 UTC; owner: root integrator; public. Root must commit this
amendment and obtain independent design approval before P/I change this strategy.
This narrowly supersedes the universal Codex `workspace-write` requirement in
SOLUTION for the verified isolated mode below. No rubric threshold/hard gate,
task criterion, authority, outer sandbox or Phase 2 decision changes.

## Observed incompatibility and evidence limits

Actual Codex 0.155.1 native-binary probes ran through the existing isolated
runner as UID 1000, all five capability masks zero, no-new-privileges enabled,
and private mount/PID/IPC/network namespaces. The runner denies unshare, setns,
mount and clone-based creation of new namespaces. No authentication was mounted,
no model request occurred, and fixture authority files remained unchanged.

| Probe | Observed result |
| --- | --- |
| `sandbox_mode="workspace-write"`, then native `sandbox --` | Exit 1: bwrap cannot create the required namespace |
| Same plus `features.use_legacy_landlock=true` | Exit 101: native panic reports direct-runtime permission profile incompatible with legacy Landlock |
| `sandbox_mode="danger-full-access"`, same outer runner | Exit 0: allowed scratch write; graph/policy/trusted-code writes and signer-key/cross-project reads denied with EACCES; namespace creation denied EPERM; offline network denied ENETUNREACH; descendants reaped |

Primary machine records are in the enclosing assessment packet's `provider/`:
`sandbox-compat-isolated-probe-v4-native.json`, SHA-256
`a35c2b8ce6e46ea36b36609c5fef4f60b14c50933a1ab13e43ce05fa5523ceb4`, and
`sandbox-external-mode-probe.json`, SHA-256
`2469b0d0f37770299e6cccd5d481274b2122a0eebe5f7c81c72102ea7eb6e58c`.
They retain exact argv, harmless probe source, observed credentials/namespaces,
raw results, cleanup and before/after authority hashes. Their sanitized hash-bound
[public inventory](provider-sandbox-provenance.json) accompanies this amendment. The result proves local command compatibility
and the enumerated probe denials, not real provider completion, all hostile-code
containment, credential-store secrecy or a final product pass.

Official [container guidance](https://learn.chatgpt.com/docs/agent-approvals-security)
documents external isolation when a containing environment prevents Codex's
nested sandbox. This design applies that mechanism to the existing Linux runner;
the documentation does not certify our implementation. The observed installed
binary governs version-specific behavior. Feature-name recognition alone does
not prove a legacy feature works. Review upon any CLI/runner/kernel/profile change.

## Pinned executable and provenance

Use the installed native executable selected by the trusted profile:
`/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex`.
Observed version: `codex-cli 0.155.1`; executable SHA-256:
`0753dfe1d8b87a52436deb13eb1c549661ef4c84fee2c5aa688385eebeccb761`.
Outer `@openai/codex` package metadata version `0.155.1` has SHA-256
`98862962c00eef34e3946f14a4345c26efbaaa733f8c6188069654a234adeee0`;
nested installed metadata version `0.155.1-linux-x64` has SHA-256
`56666c7463ffb1035a3e6abc78dc1a22cb1d768c873df71ec6dbad04fadbaeeb`.
This is observed installed package metadata and executable identity, not a verified
signed-download chain or reproducible vendor build. Preserve that provenance limit.

The JavaScript launcher requires Node outside the fixed worker PATH. Pinning the
actual native tool avoids expanding PATH or inheriting another runtime. Validate
its regular-file, read-only ownership/path/hash/version before admission; a copied
trusted installation may use its own frozen absolute path with identical bytes.
No candidate-controlled wrapper, PATH search, dynamic CLI substitution or implicit
upgrade is permitted. A changed binary requires explicit profile revalidation.

## Fixed profile-derived strategy

| Profile and actual launcher state | Strategy | Fixed CLI sandbox argument |
| --- | --- | --- |
| `trusted-local` | `codex-workspace-write-v1` | `--sandbox workspace-write` |
| `isolated-linux` with active validated v2 privileged bootstrap/runner | `external-linux-v1` | `--sandbox danger-full-access` |
| Isolated profile without that verified active boundary | Refuse before provider launch | None |

P never selects external mode from a caller flag, environment, request JSON,
observed failure or profile name alone. I first validates active bootstrap/runner
identity against frozen profile and trusted-code hashes; its actual child-boundary
checks must then confirm the configured UID, zero capabilities, no-new-privileges,
namespaces, mount allowlist and seccomp policy before exec. Missing/failed evidence
returns `ISOLATION_UNAVAILABLE`, with no provider launch and no fallback. A prior
compatibility report cannot stand in for current launch admission.

The existing finite root launcher resolves the registered request and invokes
only I's fixed production runner. Immediately before P constructs/runs the provider
command, I must assert that this is that active isolated launch, with matching
root-private request/profile/code bindings and fixed outer parameters. A caller
boolean, mode label, arbitrary runner callback or prior successful probe is not
this assertion. If no such nonforgeable active context exists, P/I must add a
narrow internal guard after design approval; no new control action or wire is
authorized. The child verifies required kernel primitives and privilege/mount/
namespace setup before exec; any failure aborts rather than launching unsandboxed.

After that admission, trusted code fixes `--ask-for-approval never` and the table's
sandbox value, preserving `--ignore-user-config`, `--ephemeral`, JSON protocol,
explicit `gpt-5.6-sol`/medium/default settings, stdin prompt, scoped auth handling,
owned cwd, output limits and descendant cleanup. Do not add bypass-approval flags,
extra writable paths, arbitrary config/argv/env/tool lists, capabilities or syscalls.
Do not relax the outer namespace restrictions to let the inner sandbox start.
Trusted-local failures remain failures; it can never retry in external mode.

Root-owned code/config/receipt store and v2 SO_PEERCRED launcher admission remain
unchanged. Worker mounts only its allowed attempt/auth inputs; signer key, graph
authority, checks/policy, accepted state, other projects and signer IPC retain
their protections. Candidate tests remain a separate UID with no network or auth.
An actual provider retains only its already authorized transport/login allowance;
the offline probe does not prove network denial for that authenticated run.

## Truthful metadata without changing receipt schemas

Keep strict WorkerReceipt v1, existing artifact/result schemas, root-private
request/result records and backup inventory unchanged. WorkerReceipt already
binds the request and profile hash; that frozen profile pins the entire trusted
code hash including the fixed sandbox strategy and runner. Existing launcher
records bind request/profile/code and actual execution observations. A profile
name alone does not replace the active-context checks above.

Additive CLI/preflight metadata may expose `configured_sandbox_strategy` and
`configured_cli_sandbox_mode` using the table's exact values. These label configured
behavior, not independently observed per-run isolation. Installed docs must state
that distinction and identify the external boundary. The existing release packet
must observe actual UID/capabilities/namespaces/mounts/no-new-privileges and denials
for the evaluated exact code under HG07. No new receipt kind, control action,
archive entry, auth/key storage or metadata-based privilege selection is introduced.

Never describe external mode as Codex-enforced workspace-write or retroactively
relabel historical receipt evidence. Task acceptance still requires valid provider
completion, candidate tests, independent evaluation and normal promotion.

## Falsifiable acceptance and ownership

P owns fixed argv selection and truthful reporting; I owns current-boundary
guard/launcher checks and refusal. G/B keep existing closure and backup contracts.
Negative tests must deny isolated mode with absent/stale/spoofed runner, wrong
UID/caps/namespaces/seccomp/mounts, changed trusted code/tool, missing/mismatched
active-context validation or caller-selected sandbox/argv/env. Prove no exec occurred on refusal.
Trusted-local must never emit external mode, including after a failed launch.

Re-run the harmless native compatibility/denial probe on the integrated trusted
installation, then the already-required actual Codex lifecycle and all applicable
OS denial/recovery gates. No mock, `--help`, offline probe or CLI zero exit replaces
actual-provider HG06 or isolation HG07. Independent design approval precedes
implementation of this compatibility change; existing unrelated work is preserved.
