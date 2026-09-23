# Local repository workflow example

This small seeded regression demonstrates the public task format. It is not the
three-repository acceptance experiment, a release result, or evidence of an actual
provider invocation. `source/clamp.py` deliberately mishandles values within an
inclusive interval. Both required and independent behavioral checks detect it.

`task.template.json` is valid JSON but intentionally fails task admission until
`base_sha` is replaced with the exact commit of your new seeded source repository.
Replace `REPLACE_WITH_PINNED_PYTHON` in both task and checks with the trusted
profile's exact resolved Python path. The preparation script below uses the
installed virtual environment; task execution uses the interpreter frozen in the
profile.

The worker may edit only `clamp.py`. `required_check.py` remains unchanged in the
source commit. Independent checks are inline code frozen from `checks.json`,
outside the editable source. The policy requires all declared gates and 100/100
for this small deterministic task; that score says nothing about product release
readiness. No third-party package or network access is needed by these checks.

## Prepare a new source and task

Run this in the same ordinary non-root shell after preparing the local profile
as described in [the workflow guide](../../docs/REPOSITORY_WORKFLOW.md). Keep its
`CG_HOME`, `CG_PYTHON`, `CG_PROFILE`, `CG_GIT` and `CG_RESOURCES` variables. A wheel
installs these examples under the virtual environment's
`share/codex-grapher/examples/repository-workflow`, so this recipe works outside a
source checkout. The source, task and future workspace are separate directories.
It changes neither the installed examples nor a codex-grapher checkout.

```sh
test "$(id -u)" -ne 0
example_root="$CG_RESOURCES/examples/repository-workflow"
example_run="$(mktemp -d "$CG_HOME/clamp.XXXXXX")"
mkdir "$example_run/source" "$example_run/task"
cp "$example_root/source/clamp.py" "$example_root/source/required_check.py" "$example_run/source/"
"$CG_GIT" -C "$example_run/source" -c init.templateDir= init --quiet
"$CG_GIT" -C "$example_run/source" config core.hooksPath /dev/null
"$CG_GIT" -C "$example_run/source" add -- clamp.py required_check.py
"$CG_GIT" -C "$example_run/source" -c user.name='Local Fixture' -c user.email='fixture@example.invalid' -c commit.gpgsign=false commit --quiet -m 'Seed local clamp regression'
"$CG_PYTHON" -I -B - "$example_root" "$example_run" "$CG_PROFILE" <<'PY'
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

example, run, profile_path = map(Path, sys.argv[1:])
profile = json.loads(profile_path.read_text())
python = profile['tools']['python']['path']
git = profile['tools']['git']['path']
assert Path(python).is_absolute(), 'Profile Python path must be absolute'
task = json.loads((example / 'task.template.json').read_text())
task['base_sha'] = subprocess.check_output(
    [git, '-C', str(run / 'source'), 'rev-parse', 'HEAD'], text=True
).strip()
task['required_tests'] = [shlex.quote(python) + ' -I -B required_check.py']
checks = json.loads((example / 'checks.json').read_text())
for check in checks['checks']:
    check['argv'][0] = python
for filename, value in [('task.json', task), ('checks.json', checks)]:
    (run / 'task' / filename).write_text(json.dumps(value, indent=2) + '\n')
shutil.copyfile(example / 'policy.json', run / 'task' / 'policy.json')
print('Source:', run / 'source')
print('Task:', run / 'task' / 'task.json')
print('Workspace to create:', run / 'workspace')
print('Pinned seeded commit:', task['base_sha'])
PY
CG_SOURCE="$example_run/source"
CG_TASK="$example_run/task/task.json"
CG_WORKSPACE="$example_run/workspace"
```

For an extracted source archive, you can instead set `example_root` to that
archive's absolute `examples/repository-workflow` directory before copying. The
profile and execution tools still come from the reviewed installed package.

Return to the guide's `init` command with the three `CG_` path variables set above;
pass `$CG_WORKSPACE` itself, not its future `state/` child. Keep policy/check inputs
outside the source and workspace; protect them according to the execution profile.
A local example does not remove the profile's root ownership or role-isolation
rules.

Before invoking a worker, run the task's required command and both independent
check argv arrays from the new source directory with the pinned interpreter.
The required check and `independent-inclusive-cases` must fail with a behavioral
`AssertionError`; `independent-reversed-bounds` already passes. An import error,
missing interpreter, or permission error is not the intended negative control.
All three checks must pass after an accepted repair. The guide explains how to
inspect the accepted generation; do not copy a repair back into the input source
as part of verification.

The following bounded preparation check verifies those intended outcomes without
calling the provider or changing the seeded source:

```sh
"$CG_PYTHON" -I -B - "$CG_SOURCE" "$CG_TASK" <<'PY'
import json
from pathlib import Path
import subprocess
import sys

source, task_path = map(Path, sys.argv[1:])
task = json.loads(task_path.read_text())
checks = json.loads((task_path.parent / task['evaluation']['checks']).read_text())
runs = [('required', task['required_tests'][0], True, 1)]
runs += [(check['id'], check['argv'], False,
          1 if check['id'] == 'independent-inclusive-cases' else 0)
         for check in checks['checks']]
for name, command, shell, expected in runs:
    result = subprocess.run(command, shell=shell, cwd=source,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == expected, (name, result.returncode, result.stderr)
    if expected:
        assert 'AssertionError' in result.stderr, (name, result.stderr)
    print(name + ': expected baseline result confirmed')
PY
```

## Preserve the source

Commit the seeded source once before initialization, then leave its files, index,
refs, config, remotes, hooks, and untracked inventory unchanged. Save a source
inventory outside that directory before initialization and compare it after both
successful and rejected operations. Include `.git` and file modes/content hashes;
`git status` alone cannot prove config, hook, or ref preservation. The workflow
works in its own copies and returns an accepted SHA and generation path. Neither
task success nor rollback should modify the input repository.

For another task, explicitly choose its allowed paths, behavior checks, identifiers,
and clean source commit before initialization. Keep the original frozen inputs
with their workspace; use a new workspace for a successor task.
