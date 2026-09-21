# Run a bounded task on your repository

The repository workflow takes a clean, pinned source commit, a task and an
operator execution profile. It works in a separate managed copy. An accepted
result is a new immutable generation inside that workspace; your original
checkout, branches, hooks and remotes are not the publication destination.

This feature is an implementation candidate. Commands below describe the public
interface; they do not assert that the portable-worker release gates, real
provider execution or guest recovery have passed. See the current
[frozen acceptance contract](cycles/20260921-portable-workers/RUBRIC.md).

## Choose the execution boundary

`trusted-local` is for code you already trust on your own non-root account. All
four configured roles use that same authorized account. It provides
the durable task and verification workflow, with **no hostile-code OS role
separation**. Candidate commands can use that account's filesystem permissions.
Select this mode explicitly for the small example below.

`isolated-linux` requires x86-64 Linux, an explicitly invoked root bootstrap in
the initial kernel UID domain and four distinct
non-root worker, test, signer and graph UIDs. The bootstrap is privileged trusted
code. Accounts, protected installation, keys and kernel prerequisites must
already be provisioned by your operator. The CLI does not install packages,
create accounts, change services or silently select `trusted-local` when isolation
is unavailable. See [the isolated setup](#isolated-linux-setup) below.

An isolated workspace's canonical absolute path must fit in **80 filesystem-encoded
bytes**, including all parent directories. Multibyte characters consume more than
one byte. This leaves room for both Unix control sockets regardless of task-ID
length. `init` checks the limit before creating workspace state; existing isolated
workspaces are checked before bootstrap effects. Choose a shorter protected path
if needed. This socket limit does not apply to `trusted-local`.

Task IDs support up to 173 ASCII identifier characters, leaving room for derived
execution IDs within the sealed protocol. Check IDs support up to 192 characters;
project IDs and idempotency keys support up to 200. Task IDs cannot contain `..`
or end in `.lock`, because they become components of candidate Git refs. The
task/check loaders reject unsupported values before creating a workspace or
reserving a worker invocation.

For Codex CLI 0.155.1, the isolated runner enforces the Linux boundary and selects
`--sandbox danger-full-access` inside it. Codex's nested `workspace-write`
sandbox cannot create its namespaces under this runner's syscall restrictions.
External mode requires the current trusted launcher and successful kernel
boundary checks before execution; there is no automatic fallback.
`trusted-local` retains Codex `workspace-write`. The CLI's
`configured_sandbox_strategy` and `configured_cli_sandbox_mode` fields describe
configuration, not an independent isolation verdict. See
[the reviewed compatibility design](cycles/20260921-portable-workers/DESIGN_AMENDMENT_V3.md).

## Install and prepare a local profile

Use Python 3.12 or newer. These commands are for an ordinary non-root account
that already has a working Codex CLI login. They create a new private example
directory and a virtual environment. Substitute the path to your reviewed wheel
or source archive in the install command.

```sh
set -eu
test "$(id -u)" -ne 0
mkdir -p "$HOME/.local/share"
CG_HOME="$HOME/.local/share/codex-grapher-example"
mkdir -m 700 "$CG_HOME"
python3 -m venv --copies "$CG_HOME/venv"
CG_PYTHON="$CG_HOME/venv/bin/python3"
"$CG_PYTHON" -I -B -m pip install /absolute/path/to/codex_grapher-0.2.0-py3-none-any.whl
mkdir -m 700 "$CG_HOME/config"
CG_PROFILE="$CG_HOME/config/execution.json"
```

`--copies` matters: the profile rejects symlink path components. A resolved
system Python symlink would lose the virtual environment's import prefix. The
trusted code root is the import directory containing `control_plane` and
`control_plane/resources`, usually this virtual environment's `site-packages`.
Do not pin the package directory alone or the whole virtual environment; the
latter may contain a `lib64` convenience symlink. Use `-I -B` so Python imports the
installed package independently of your current checkout and writes no bytecode.

```sh
CG_CODE_ROOT="$("$CG_PYTHON" -I -B -c 'from pathlib import Path; import control_plane; print(Path(control_plane.__file__).resolve().parent.parent)')"
CG_RESOURCES="$("$CG_PYTHON" -I -B -c 'from pathlib import Path; import sys; print(Path(sys.prefix) / "share" / "codex-grapher")')"
CG_GIT="$(readlink -f "$(command -v git)")"
CG_OPENSSL="$(readlink -f "$(command -v openssl)")"
CG_PROVIDER="$(readlink -f "$(command -v codex)")"
CG_ACCOUNT="$(id -un)"
CG_UID="$(id -u)"
CG_GID="$(id -g)"
```

Check these explicit paths refer to the intended installed executables. Paths
must have no symlink ancestors. For a vendor launcher with external dependencies,
the operator must also protect its installed dependencies; a hash of the launcher
alone does not establish their provenance.

For isolated execution, select the native Codex executable explicitly. A
JavaScript launcher that needs Node outside the runner's fixed `/usr/bin:/bin`
PATH will fail preflight. With the inspected Linux x64 npm installation, the
native file is under
`@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex`.
Find it in your operator-managed installation and set `CG_PROVIDER` to its
canonical absolute path before creating the profile. The supported 0.155.1
native bytes and observed provenance are recorded in the compatibility design;
no executable is downloaded or substituted by profile creation.

Installed guides, schemas, scripts and examples are under `$CG_RESOURCES`.
Those public preparation resources are separate from the importable trusted code
tree; task, policy and check bytes are frozen into the workspace at initialization.
The profile command requires you to choose its code root, key paths and account;
it does not infer a trusted root from your repository.

Provision a separate Ed25519 signing key. This example creates it in the private
configuration directory, outside the source, pinned code and future workspace.
Keep the private key out of Git, distributions, task documents and backups.

```sh
umask 077
"$CG_OPENSSL" genpkey -algorithm ED25519 -out "$CG_HOME/config/signer-private.pem"
"$CG_OPENSSL" pkey -in "$CG_HOME/config/signer-private.pem" -pubout -out "$CG_HOME/config/signer-public.pem"
```

Read the selected tools' versions under this ordinary account. Profile creation
does not execute tools or inspect credential values; `--tool-version` records
operator-supplied metadata. The provider's later preflight must verify its actual
version and supported behavior under the worker identity. Supplying a version
string is not proof that a tool ran successfully.

```sh
CG_PYTHON_VERSION="$("$CG_PYTHON" --version)"
CG_GIT_VERSION="$("$CG_GIT" --version)"
CG_PROVIDER_VERSION="$("$CG_PROVIDER" --version)"
CG_OPENSSL_VERSION="$("$CG_OPENSSL" version)"
"$CG_PYTHON" -I -B -m control_plane profile create \
  --output "$CG_PROFILE" --mode trusted-local \
  --worker-account "$CG_ACCOUNT" \
  --worker-uid "$CG_UID" --worker-gid "$CG_GID" \
  --test-runner-uid "$CG_UID" --test-runner-gid "$CG_GID" \
  --signer-uid "$CG_UID" --signer-gid "$CG_GID" \
  --graph-uid "$CG_UID" --graph-gid "$CG_GID" \
  --model gpt-5.6-sol --reasoning-effort medium --service-tier default \
  --python "$CG_PYTHON" --git "$CG_GIT" --provider "$CG_PROVIDER" --openssl "$CG_OPENSSL" \
  --trusted-code-root "$CG_CODE_ROOT" \
  --signer-private-key "$CG_HOME/config/signer-private.pem" \
  --signer-public-key "$CG_HOME/config/signer-public.pem" \
  --tool-version "python=$CG_PYTHON_VERSION" \
  --tool-version "git=$CG_GIT_VERSION" \
  --tool-version "provider=$CG_PROVIDER_VERSION" \
  --tool-version "openssl=$CG_OPENSSL_VERSION" --json
```

The profile helper hashes the explicit tool bytes and complete trusted code
inventory, checks the strict configuration, and creates a new `0600` profile.
It never overwrites an existing profile. Version fields must name exactly the
enabled tools. Local role defaults are the invoking account; the authentication
account must match the worker's actual UID and primary GID. No API key, arbitrary
environment override or alternate login home belongs in the task or profile.
The commands bind all four local roles explicitly. Run them as the logged-in
non-root account; real provider execution as root is forbidden.

Use `-I -B` for installed CLI commands so imports cannot add bytecode to the pinned
code inventory. Finish installation before creating a profile. If you change
tools, installed code or configuration, create a new profile and a new explicit
workspace; an existing workspace must reject changed trust inputs.

## Create and run the small example

Follow [the example preparation recipe](../examples/repository-workflow/README.md)
to copy its two source files into a new Git repository, commit the seeded bug,
and create `task.json` with your exact commit and profile interpreter. Its policy
and independent checks remain outside both the source repository and workspace.
The template deliberately fails validation until its source and tool placeholders
are replaced. This small first-use example is not the three-repository acceptance
campaign. For a wheel install, that recipe is available at
`$CG_RESOURCES/examples/repository-workflow/README.md` and runs from any directory.
It sets `CG_SOURCE`, `CG_TASK` and `CG_WORKSPACE` in the same shell.

With `CG_SOURCE`, `CG_TASK` and `CG_WORKSPACE` set to those absolute paths:

```sh
"$CG_PYTHON" -I -B -m control_plane doctor --profile "$CG_PROFILE" --json
"$CG_PYTHON" -I -B -m control_plane init \
  --repo "$CG_SOURCE" --task "$CG_TASK" --workspace "$CG_WORKSPACE" \
  --profile "$CG_PROFILE" --json
"$CG_PYTHON" -I -B -m control_plane run --workspace "$CG_WORKSPACE" --json
"$CG_PYTHON" -I -B -m control_plane status --workspace "$CG_WORKSPACE" --json
```

`doctor` checks local prerequisites and profile admission. It does not run
provider authentication or prove role isolation. The current provider adapter
accepts Codex CLI `0.155.1` with model `gpt-5.6-sol`, reasoning `medium` and service
tier `default`; another explicit profile setting is not automatically supported.

`run` may invoke your existing Codex subscription. Review the objective, allowed
paths, required tests, independent checks, model and limits first. The example
allows one invocation and a 300-second worker timeout. Subscription login does
not imply unlimited allowance or a hard USD/token cap. Unsupported hard billing
limits must be rejected, never advertised as enforced.

The worker changes allowed files without committing. Required tests and separate
independent checks must pass before a signed task result can be promoted. A task
score of 100 means those frozen checks and scope gates passed; it is not a general
code-quality or release score. Inspect the returned accepted SHA and generation
path, then run your consumer against that generation rather than the source
checkout. Compare the source's complete contents, including `.git`, with the
inventory captured before initialization.

For an interrupted workflow, inspect `status` and use `recover`. A reservation
without graph-admitted immutable evidence is `WORKER_INTERRUPTED_UNSEALED` and
requires inspection; recovery must not secretly spend another model invocation.
`--stop-after built|evaluated|promoted` exposes the corresponding durable
boundaries during an explicitly bounded run.

```sh
"$CG_PYTHON" -I -B -m control_plane recover --workspace "$CG_WORKSPACE" --json
"$CG_PYTHON" -I -B -m control_plane rollback --workspace "$CG_WORKSPACE" --json
```

Rollback is an explicit publication change. It must identify the authorized
predecessor of the current accepted attempt. Repeated recovery must not add a
worker launch or a duplicate publication operation.

Pass the workspace's top directory to every lifecycle command. Its mutable
database and binding are `state/graph.sqlite` and `state/binding.json`; frozen
inputs are under `frozen/`, and accepted generations are under `publications/`.
Do not pass `state/` as `--workspace` or edit the binding/database to recover.
Status returns `accepted_sha`, `accepted_generation`, `workflow_state` and
`next_safe_action`; use these fields to inspect the current durable result.

## Isolated Linux setup

Use a separately reviewed root-owned installation on a disposable guest or an
operator-managed machine. The installation, pinned executables and every
ancestor must satisfy the loader's ownership, permission and symlink checks.
Do not launch root from the worker's writable checkout. The pinned code root
must be the installed import root containing `control_plane` and its resources.
All trusted Python children must also disable bytecode writes.

The operator provisions the following before profile creation:

- An existing logged-in worker account, plus distinct non-root test, signer and
  graph UIDs, with explicit UID/GID values. The CLI does not create them.
- Protected canonical Python, Git, provider, OpenSSL, bubblewrap and setpriv
  executable paths and the protected installed code root.
- A root-owned Ed25519 private key outside the workspace/code tree, mode `0640`
  with the signer's exclusive GID. Its parent directories are root-owned and
  not group/world writable. Only the signer receives its read-only mount. A
  root-owned `0600` key cannot be read after the signer drops privilege; do not
  reuse the local example's key permissions for this setup. Worker, test and
  graph GIDs must differ from the signer's key-reading group.
- The matching public key, protected task/policy/check/profile files and the
  supported namespace/capability features. A failed prerequisite stops admission.

For an already provisioned key, the root operator sets ownership to
`root:SIGNER_GID` and mode `0640`, and protects the containing directory, before
creating the profile. The matching public key is also root-owned and must be
readable by the trusted verification roles. Never change ownership of the whole
installation or key directory to the worker or signer.

Run `profile create` as the root operator with the explicit arguments shown
above, replacing the local paths/account/role values with this protected
installation and supplying all role IDs and isolation tools:

```text
--mode isolated-linux
--worker-uid WORKER_UID --worker-gid WORKER_GID
--test-runner-uid TEST_UID --test-runner-gid TEST_GID
--signer-uid SIGNER_UID --signer-gid SIGNER_GID
--graph-uid GRAPH_UID --graph-gid GRAPH_GID
--bwrap /canonical/path/to/bwrap --setpriv /canonical/path/to/setpriv
--tool-version 'bwrap=OBSERVED_BWRAP_VERSION'
--tool-version 'setpriv=OBSERVED_SETPRIV_VERSION'
```

These are argument placeholders, not a ready-to-run shell command. Gather provider
version/login observations as the actual worker, never by executing it as root.
The helper itself performs only read-only hashing and configuration validation.
Run the installed CLI as root for isolated `init` and lifecycle operations.
Initialization prepares workspace ownership; execution enters the explicit
bootstrap and launches the four dropped identities. `doctor` is a diagnostic,
not a bootstrap or provider login check. No candidate code runs as root. Run
any manual candidate consumer as an authorized non-root user too. Namespace and
role-denial evidence is still required before claiming isolation works in your
environment.

The worker's own provider login store remains part of the provider authentication
boundary. This setup does not isolate that login from the provider process or
commands it launches under the same worker identity. Candidate tests must have neither that login home nor network
or signer access. There is no automatic API-billed fallback.

## Provider diagnostics

In `isolated-linux`, each admitted provider execution retains bounded stdout,
stderr and a structural `diagnostic.json` in the root-only workspace directory
`.broker-receipts/.private/provider-diagnostics-<request-sha256>/`. Only the root
operator can read this directory. The JSON contains finite error categories and
event shapes; it excludes message text, commands, identifiers and exception text.
The raw streams may contain project content and stay private. Preflight, login
and Git-probe output is not captured by this mechanism.

Retention is bound to the actual process output and frozen request. Capture
failure prevents a worker receipt; retaining output never changes acceptance or
refunds an invocation. The directory is excluded from Git, distributions,
verification snapshots and workspace backups. Restore therefore preserves the
signed workflow evidence without restoring these private diagnostic streams.

## Backup, restore and runtime limits

The default SQLite profile is `delete-extra`: writable connections require
DELETE journal mode, EXTRA synchronization and one process owner. It reports
supported avoidance conditions separately from patch status; it does not claim
that the host SQLite library is patched.

Optional `wal-full` is an explicit fixed-runtime setup. The packaged
`$CG_RESOURCES/scripts/provision-sqlite-runtime.sh` can build pinned SQLite
`3.53.4` in a new task-local prefix without modifying host packages. A build
artifact alone is insufficient: the actual Python process used for profile
creation, CLI operations and trusted child execution must load the same library
and pass its exact attestation. Use `--sqlite-profile wal-full` and
`--sqlite-attestation /absolute/runtime/attestation.json` only with that verified
runtime. Do not assume changing the `sqlite3` command or setting a parent shell
variable changes the libraries loaded by sanitized child processes. This guide
does not provide an independently verified isolated-WAL setup recipe.

There is no automatic conversion of an existing WAL workspace. An old or unknown
WAL database without the required runtime provenance/maintenance receipt is
rejected, including by ordinary workspace backup. Do not attempt to unblock it
by editing profile JSON, deleting `-wal`/`-shm`/journal files or switching PRAGMAs.
Before any explicit offline maintenance, stop all writers, preserve a complete
cold preimage of the workspace and its runtime/configuration dependencies, and
rehearse recovery in a disposable environment at the original absolute paths.
That preimage includes database and sidecars, canonical Git and refs, binding,
all evidence, retained generations, frozen inputs and public receipts. The
SQLite maintenance command's database-only backup is not that full recovery
unit. Migrating such a legacy workspace remains outside the ordinary
backup/restore recipe below until the complete preimage and same-path drill have
been established; do not use the original as the rehearsal copy.

```sh
CG_BACKUP="$CG_HOME/workspace-backup"
"$CG_PYTHON" -I -B -m control_plane backup --workspace "$CG_WORKSPACE" --output "$CG_BACKUP" --json
```

On the fresh recovery machine, after separately provisioning the same absolute
tool/profile paths and copying the backup, set the same `CG_PYTHON`, `CG_PROFILE`,
`CG_BACKUP` and original `CG_WORKSPACE` values. The destination must not exist:

```sh
"$CG_PYTHON" -I -B -m control_plane restore \
  --backup "$CG_BACKUP" --workspace "$CG_WORKSPACE" \
  --profile "$CG_PROFILE" --json
```

Backup requires an exclusive quiescent workspace with no active work. Restore
v1 targets a fresh machine at the same original absolute workspace and tool
paths; it must not overwrite the original or silently relocate signed state.
Provision matching identities, installed tools and the public key separately.
Credentials, private keys and sockets are excluded. A missing private key permits
explicit verify-only inspection; continuing execution requires separately
provisioning the original matching key. Never generate a replacement key to
validate or re-sign historical results. Retain backup, restore and consumer
verification evidence before relying on recovery.
