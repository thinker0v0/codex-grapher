import json
import pathlib
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

import jsonschema
import yaml

from control_plane.runtime_config import load_runtime


ROOT = pathlib.Path(__file__).resolve().parents[1]


class FoundationTests(unittest.TestCase):
    def test_standalone_controller_install_includes_sqlite_runtime(self):
        installer = (ROOT / "scripts/configure-codex-workers.sh").read_text()
        with tempfile.TemporaryDirectory() as temporary:
            staged = pathlib.Path(temporary)
            for module in ("task_controller.py", "sqlite_runtime.py"):
                self.assertRegex(installer, r'install [^\n]*"\$repo_root/control_plane/' +
                                 re.escape(module) + r'" /usr/local/libexec/ai-ops/' + re.escape(module))
                shutil.copyfile(ROOT / "control_plane" / module, staged / module)
            result = subprocess.run(
                [sys.executable, "-I", "-B", "-c",
                 "import pathlib,sys; sys.path.insert(0,sys.argv[1]); "
                 "from task_controller import TaskController; "
                 "c=TaskController(pathlib.Path(sys.argv[1])/'task.sqlite'); "
                 "assert c.connection.execute('PRAGMA journal_mode').fetchone()[0]=='delete'; "
                 "assert c.connection.execute('PRAGMA synchronous').fetchone()[0]==3; "
                 "c.connection.close()", str(staged)],
                cwd=staged, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_installer_module_set_imports_without_source_checkout(self):
        installer = (ROOT / "scripts/install-project-graph.sh").read_text(encoding="utf-8")
        match = re.search(r"^modules=\(([^)]*)\)$", installer, re.MULTILINE)
        self.assertIsNotNone(match, "installer must declare its module inventory")
        modules = shlex.split(match.group(1))
        self.assertTrue(modules)
        with tempfile.TemporaryDirectory() as temporary:
            staged = pathlib.Path(temporary)
            package = staged / "control_plane"
            package.mkdir()
            for module in modules:
                self.assertEqual(pathlib.Path(module).name, module)
                shutil.copyfile(ROOT / "control_plane" / module, package / module)
            result = subprocess.run(
                [sys.executable, "-I", "-B", "-c",
                 "import pathlib, sys; sys.path.insert(0, sys.argv[1]); "
                 "import control_plane.graph_bootstrap as bootstrap; "
                 "import control_plane.graph_service as service; "
                 "assert pathlib.Path(bootstrap.__file__).parent == pathlib.Path(sys.argv[1]) / 'control_plane'; "
                 "assert pathlib.Path(service.__file__).parent == pathlib.Path(sys.argv[1]) / 'control_plane'",
                 str(staged)],
                cwd=staged, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_runtime_model_is_keyless_ox_alpha(self):
        text = (ROOT / "config/hermes-runtime.example.yaml").read_text(encoding="utf-8")
        self.assertIn("provider: opencode-free", text)
        self.assertIn("default: x-preview-f-free", text)
        self.assertNotIn("api_key:", text)

    def test_operational_profiles_have_bounded_slack_routing(self):
        for profile in ("fin-korea", "hynix", "business", "oss"):
            text = (ROOT / f"prompts/hermes/{profile}.md").read_text(encoding="utf-8")
            self.assertIn("max-codex-v1" if profile == "oss" else "bounded-slack-v1", text)
            if profile == "oss":
                self.assertIn("project-router-client execute", text)
            else:
                self.assertIn(f"/run/ai-ops-{profile}/controller.sock", text)
                self.assertIn(f"run-codex-worker {profile}", text)

    def test_oss_router_prioritizes_maximum_codex_results(self):
        prompt = (ROOT / "prompts/hermes/oss.md").read_text(encoding="utf-8")
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        operations = (ROOT / "OPERATIONS.md").read_text(encoding="utf-8")
        self.assertIn("max-codex-v1", prompt)
        self.assertIn("1000000000", prompt)
        self.assertIn("maximum results, not efficiency", agents)
        self.assertIn("maximum results, not", operations)

    def test_max_codex_campaign_is_persistent_and_non_economic(self):
        runner = (ROOT / "scripts/run-max-codex-campaign.py").read_text(encoding="utf-8")
        timer = (ROOT / "deploy/systemd/ai-ops-max-codex-campaign.timer").read_text(encoding="utf-8")
        installer = (ROOT / "scripts/configure-codex-workers.sh").read_text(encoding="utf-8")
        self.assertIn('"max_tokens": 1000000000', runner)
        self.assertIn("do not minimize Codex tokens", runner)
        self.assertIn("OnUnitActiveSec=5min", timer)
        self.assertIn(
            'if [[ "$legacy_compatibility" == true ]]; then\n'
            "  systemctl enable ai-ops-project-router.service\n"
            "  systemctl restart ai-ops-project-router.service\n"
            "  systemctl enable --now ai-ops-max-codex-campaign.timer\n"
            "fi",
            installer,
        )

    def test_profile_env_has_required_empty_secrets(self):
        text = (ROOT / "config/hermes-profile.env.example").read_text(encoding="utf-8")
        self.assertIn("DASHSCOPE_API_KEY=", text)
        self.assertIn("SLACK_BOT_TOKEN=", text)
        self.assertIn("SLACK_APP_TOKEN=", text)
        self.assertIn("SLACK_ALLOWED_CHANNELS=", text)

    def test_credential_installer_defaults_to_keyless_ox(self):
        installer = (ROOT / "scripts/configure-hermes-credentials.sh").read_text(encoding="utf-8")
        self.assertIn('HERMES_PROVIDER:-opencode-free', installer)
        self.assertIn("openai-api", installer)
        self.assertIn("OPENAI_API_KEY", installer)
        self.assertIn("Slack bot token", installer)

    def test_profile_slack_manifests_render_distinct_apps(self):
        renderer = ROOT / "scripts/render-slack-profile-manifest.sh"
        names = {}
        for profile in ("fin-korea", "hynix", "business", "oss"):
            result = subprocess.run([renderer, profile], check=True, capture_output=True, text=True)
            manifest = yaml.safe_load(result.stdout)
            names[profile] = manifest["display_information"]["name"]
        self.assertEqual(len(set(names.values())), 4)
        default = subprocess.run(
            ["bash", str(ROOT / "scripts/install-hermes-foundation.sh"), "--dry-run"],
            check=True, capture_output=True, text=True,
        )
        legacy = subprocess.run(
            ["bash", str(ROOT / "scripts/install-hermes-foundation.sh"), "--dry-run",
             "--legacy-compatibility"],
            check=True, capture_output=True, text=True,
        )
        self.assertNotIn("slack-app-manifest.example.yaml", default.stdout)
        self.assertIn("slack-app-manifest.example.yaml", legacy.stdout)

    def load_yaml(self, relative_path):
        with (ROOT / relative_path).open(encoding="utf-8") as handle:
            return yaml.safe_load(handle)

    def test_all_json_schemas_are_valid(self):
        for path in (ROOT / "schemas").glob("*.schema.json"):
            with path.open(encoding="utf-8") as handle:
                jsonschema.Draft202012Validator.check_schema(json.load(handle))

    def test_profiles_have_unique_os_identities_and_workspaces(self):
        profiles = self.load_yaml("config/hermes-profiles.example.yaml")["profiles"]
        identities = [profile["os_identity"] for profile in profiles.values()]
        workspaces = [profile["workspace"] for profile in profiles.values()]
        self.assertEqual(len(identities), len(set(identities)))
        self.assertEqual(len(workspaces), len(set(workspaces)))

    def test_evaluator_is_read_only_except_ledger(self):
        evaluator = self.load_yaml("config/hermes-profiles.example.yaml")["profiles"]["evaluator"]
        self.assertEqual(evaluator["source_access"], "read-only")
        self.assertEqual(evaluator["artifact_access"], "read-only")
        self.assertEqual(evaluator["ledger_access"], "append-only")

    def test_zai_subscription_is_blocked(self):
        policy = self.load_yaml("config/model-routing.example.yaml")
        candidate = policy["candidates"]["planner_subscription"]
        self.assertEqual(candidate["status"], "blocked-pending-written-provider-approval")

    def test_models_remain_benchmark_candidates(self):
        policy = self.load_yaml("config/model-routing.example.yaml")
        self.assertEqual(policy["selection_status"], "benchmark-required")
        self.assertGreaterEqual(policy["benchmark"]["minimum_tasks_per_project"], 20)
        self.assertGreaterEqual(policy["benchmark"]["repeated_runs"], 3)

    def test_slack_forbids_financial_authority(self):
        rbac = self.load_yaml("config/slack-rbac.example.yaml")
        forbidden = set(rbac["permanently_forbidden"])
        required = {"enable_live_trading", "place_live_order", "increase_risk_limit", "release_kill_switch", "withdraw_funds"}
        self.assertTrue(required.issubset(forbidden))
        for actions in rbac["roles"].values():
            self.assertFalse(forbidden.intersection(actions))

    def test_slack_manifest_has_hermes_socket_mode_contract(self):
        manifest = self.load_yaml("config/slack-app-manifest.example.yaml")
        scopes = set(manifest["oauth_config"]["scopes"]["bot"])
        events = set(manifest["settings"]["event_subscriptions"]["bot_events"])
        self.assertTrue({"chat:write", "app_mentions:read", "channels:history", "groups:history", "files:read"}.issubset(scopes))
        self.assertTrue({"app_mention", "message.channels", "message.groups", "message.im"}.issubset(events))
        self.assertTrue(manifest["settings"]["socket_mode_enabled"])

    def test_task_terminals_have_no_transitions(self):
        machine = self.load_yaml("config/task-state.example.yaml")
        transitions = machine["transitions"]
        for terminal in machine["states"]["terminal"]:
            self.assertNotIn(terminal, transitions)

    def test_systemd_units_have_required_hardening(self):
        required = {
            "PrivateTmp=true",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "ProtectKernelTunables=true",
            "ProtectControlGroups=true",
            "LockPersonality=true",
        }
        for path in (ROOT / "deploy/systemd").glob("*.service"):
            content = path.read_text(encoding="utf-8")
            self.assertTrue(required.issubset(set(content.splitlines())), path.name)
            if path.name == "ai-ops-project-router.service":
                self.assertIn("NoNewPrivileges=true", content.splitlines())
                self.assertIn("RestrictSUIDSGID=true", content.splitlines())
            else:
                self.assertIn("NoNewPrivileges=true", content.splitlines())
                self.assertIn("RestrictSUIDSGID=true", content.splitlines())
            if path.name == "hermes-config-backup.service":
                self.assertIn("CapabilityBoundingSet=CAP_DAC_READ_SEARCH", content)
            elif path.name == "ai-ops-controller@.service":
                self.assertIn("CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE", content)
                self.assertIn("/srv/hermes/%i/runtime/authorizations", content)
            elif path.name == "ai-ops-project-graph.service":
                self.assertIn("CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE", content)
                self.assertIn("--evaluator-public-key /etc/ai-ops/evaluator-public.pem", content)
                self.assertNotIn("evaluator-signing.key", content)
                inaccessible = next(
                    line for line in content.splitlines() if line.startswith("InaccessiblePaths=")
                )
                for denied in (
                    "/etc/ai-ops/authorization-private.pem",
                    "/etc/ai-ops/evaluator-private.pem",
                    "/etc/hermes",
                ):
                    self.assertIn(denied, inaccessible)
                self.assertIn("/srv/hermes/evaluator/artifacts", content)
            elif path.name == "ai-ops-project-router.service":
                self.assertIn("CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE", content)
            else:
                self.assertIn("CapabilityBoundingSet=", content.splitlines())

    def test_backup_excludes_secrets_and_has_restore_drill(self):
        backup = (ROOT / "scripts/backup-hermes-config.sh").read_text(encoding="utf-8")
        restore = (ROOT / "scripts/restore-hermes-config-drill.sh").read_text(encoding="utf-8")
        self.assertNotIn("/etc/hermes/", backup)
        self.assertIn("sha256sum", backup)
        self.assertIn("sha256sum -c", restore)
        self.assertIn("secret exclusion verified", restore)

    def test_laptop_is_control_only(self):
        policy = self.load_yaml("config/resource-policy.yaml")
        laptop = policy["laptop"]
        self.assertEqual(laptop["role"], "control-and-review-only")
        self.assertEqual(laptop["max_local_codex_sessions"], 1)
        self.assertEqual(laptop["max_local_subagents"], 1)
        self.assertEqual(laptop["backtest_execution"], "forbidden")

    def test_problem_solving_skills_preserve_evaluator_independence(self):
        loop = (ROOT / "skills/sharp-solution-loop/SKILL.md").read_text(encoding="utf-8")
        judge = (ROOT / "skills/independent-ai-judge/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("must not award its own passing score", loop)
        self.assertIn("Do not edit project artifacts", judge)
        self.assertIn("UNPROVEN", judge)

    def test_profile_runner_rejects_unlisted_names(self):
        runner = (ROOT / "scripts/run-hermes-profile.sh").read_text(encoding="utf-8")
        self.assertRegex(
            runner,
            re.compile(r"fin-global\|fin-korea\|hynix\|business\|oss\|evaluator"),
        )

    def test_hermes_unit_supports_codex_bubblewrap_loopback(self):
        unit = (ROOT / "deploy/systemd/hermes-profile@.service").read_text(encoding="utf-8")
        self.assertIn("RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK", unit)

    def test_hermes_profile_starts_after_matching_controller(self):
        unit = (ROOT / "deploy/systemd/hermes-profile@.service").read_text(encoding="utf-8")
        self.assertIn("After=network-online.target ai-ops-controller@%i.service", unit)
        self.assertIn("Wants=network-online.target ai-ops-controller@%i.service", unit)

    def test_codex_worker_installer_preserves_userns_protection(self):
        installer = (ROOT / "scripts/configure-codex-workers.sh").read_text(encoding="utf-8")
        self.assertIn("command -v bwrap", installer)
        self.assertIn("bwrap-userns-restrict", installer)
        self.assertIn("apparmor_parser -r", installer)
        self.assertNotIn("apparmor_restrict_unprivileged_userns=0", installer)

    def test_oss_status_uses_control_plane_evidence(self):
        prompt = (ROOT / "prompts/hermes/oss.md").read_text(encoding="utf-8")
        reporter = (ROOT / "scripts/report-hermes-project-status.sh").read_text(encoding="utf-8")
        installer = (ROOT / "scripts/configure-codex-workers.sh").read_text(encoding="utf-8")
        self.assertIn("report-hermes-project-status oss", prompt)
        self.assertIn("repo-binding.json", reporter)
        self.assertIn("controller_reachable", reporter)
        self.assertIn("codex_authenticated", reporter)
        self.assertIn("report-hermes-project-status.sh", installer)

    def test_codex_evaluator_is_read_only(self):
        runner = (ROOT / "scripts/run-codex-worker.sh").read_text(encoding="utf-8")
        self.assertNotIn("danger-full-access", runner)
        self.assertIn("--json", runner)
        self.assertIn("--ephemeral", runner)
        self.assertIn('approval_policy="never"', runner)
        self.assertIn("Authorization evidence is absent", runner)
        self.assertIn("does not match worker profile", runner)
        self.assertIn("controller-client", runner)
        self.assertNotIn("runtime/tasks.db", runner)

    def test_vps_authorization_boundary_has_required_negative_cases(self):
        verifier = (ROOT / "scripts/verify-vps-authorization-boundary.sh").read_text(encoding="utf-8")
        for marker in ("mutation_denied_before_submit", "wrong_sha_denied_before_submit", "wrong_profile_denied_before_submit"):
            self.assertIn(marker, verifier)

    def test_live_e2e_verifier_requires_explicit_authority_and_real_evidence(self):
        verifier = (ROOT / "scripts/verify-vps-hermes-codex-e2e.sh").read_text(encoding="utf-8")
        for marker in (
            "RUN_LIVE_E2E",
            "controller-client",
            'authorize "$temp_dir/unsigned.json"',
            "bounded-slack-v1",
            "run-codex-worker",
            "EVIDENCE_PENDING",
            "artifact_sha256",
            "bwrap-userns-restrict",
        ):
            self.assertIn(marker, verifier)

    def test_vps_controller_isolation_covers_self_certification(self):
        verifier = (ROOT / "scripts/verify-vps-controller-isolation.sh").read_text(encoding="utf-8")
        for marker in ("builder_database_read_denied", "builder_self_certification_denied", "cross_project_controller_denied", "evaluator_usage_forgery_denied"):
            self.assertIn(marker, verifier)

    def test_committed_vps_evidence_is_scoped_and_git_bound(self):
        packets = list((ROOT / "evidence/vps").glob("*.json"))
        self.assertTrue(packets)
        for packet_path in packets:
            packet = json.loads(packet_path.read_text(encoding="utf-8"))
            self.assertRegex(packet["evaluated_git_sha"], r"^[a-f0-9]{40}$")
            self.assertIsInstance(packet["pass"], bool)
            self.assertTrue(packet["limitations"])
            if not packet["pass"]:
                self.assertTrue(packet.get("verdict"))

    def test_shell_scripts_parse(self):
        for path in (ROOT / "scripts").glob("*.sh"):
            subprocess.run(["bash", "-n", str(path)], check=True)

    def test_installer_defaults_to_dry_run(self):
        result = subprocess.run(
            ["bash", str(ROOT / "scripts/install-hermes-foundation.sh")],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertIn("Dry run complete", result.stdout)
        self.assertIn("DRY-RUN:", result.stdout)

    def test_d019_default_provisioning_excludes_frozen_legacy_routes(self):
        default = subprocess.run(
            ["bash", str(ROOT / "scripts/install-hermes-foundation.sh"), "--dry-run"],
            check=True, capture_output=True, text=True,
        )
        legacy = subprocess.run(
            ["bash", str(ROOT / "scripts/install-hermes-foundation.sh"), "--dry-run",
             "--legacy-compatibility"],
            check=True, capture_output=True, text=True,
        )
        self.assertNotIn("fin-global", default.stdout)
        self.assertNotIn("render-slack-profile-manifest", default.stdout)
        self.assertIn("fin-global", legacy.stdout)
        self.assertIn("render-slack-profile-manifest", legacy.stdout)

        worker_installer = (ROOT / "scripts/configure-codex-workers.sh").read_text(encoding="utf-8")
        profile_installer = (ROOT / "scripts/configure-hermes-profiles.sh").read_text(encoding="utf-8")
        self.assertIn("profiles=(fin-korea hynix business oss evaluator)", worker_installer)
        self.assertIn("controller_profiles=(fin-korea hynix business oss)", worker_installer)
        self.assertNotIn("for profile_name in fin-global fin-korea", worker_installer)
        self.assertIn(
            'if [[ "$legacy_compatibility" == true ]]; then\n'
            '  profiles=(fin-global "${profiles[@]}")\n'
            '  controller_profiles=(fin-global "${controller_profiles[@]}")\n'
            "fi",
            worker_installer,
        )
        self.assertIn(
            'if [[ "$legacy_compatibility" == true ]]; then\n'
            '  install -o root -g root -m 0755 "$repo_root/control_plane/project_router.py"',
            worker_installer,
        )
        self.assertIn("profiles=(fin-korea hynix business oss evaluator)", profile_installer)
        self.assertIn('profiles=(fin-global "${profiles[@]}")', profile_installer)

    def test_project_graph_runtime_is_explicit_reproducible_and_non_secret(self):
        example = ROOT / "config/project-runtime.example.json"
        runtime = load_runtime(example)
        self.assertEqual(set(runtime), {"nomad", "opensource", "business", "hynix"})
        self.assertFalse((ROOT / "config/project-runtime.json").exists())
        missing = subprocess.run(
            ["bash", str(ROOT / "scripts/install-project-graph.sh"), "--dry-run"],
            check=False, capture_output=True, text=True,
        )
        self.assertEqual(missing.returncode, 64)
        result = subprocess.run(
            ["bash", str(ROOT / "scripts/install-project-graph.sh"), "--dry-run", "--runtime", str(example)],
            check=True, capture_output=True, text=True,
        )
        self.assertIn("project-runtime.json", result.stdout)
        self.assertIn("Dry run complete", result.stdout)
        activate_without_apply = subprocess.run(
            ["bash", str(ROOT / "scripts/install-project-graph.sh"), "--dry-run",
             "--activate", "--runtime", str(example)],
            check=False, capture_output=True, text=True,
        )
        self.assertEqual(activate_without_apply.returncode, 64)
        installer = (ROOT / "scripts/install-project-graph.sh").read_text(encoding="utf-8")
        self.assertIn("activate=false", installer)
        self.assertLess(
            installer.index("for account in hermes-oss"),
            installer.index("run install -d -o root"),
        )
        self.assertIn(
            '  if [[ "$activate" == true ]]; then\n'
            "    systemctl daemon-reload\n"
            "    systemctl enable ai-ops-project-graph.service\n"
            "    systemctl restart ai-ops-project-graph.service",
            installer,
        )
        self.assertNotIn("systemctl enable --now ai-ops-project-graph.service", installer)

    def test_project_graph_installer_explicitly_bootstraps_database_before_activation(self):
        example = ROOT / "config/project-runtime.example.json"
        result = subprocess.run(
            ["bash", str(ROOT / "scripts/install-project-graph.sh"), "--dry-run",
             "--runtime", str(example)],
            check=True, capture_output=True, text=True,
        )
        state_directory = (
            "DRY-RUN: install -d -o root -g ai-ops-graph -m 0700 "
            "/var/lib/ai-ops-graph"
        )
        bootstrap = (
            "DRY-RUN: env PYTHONPATH=/usr/local/lib/ai-ops python3 "
            "/usr/local/lib/ai-ops/control_plane/graph_bootstrap.py database --apply "
            "--database /var/lib/ai-ops-graph/graphs.sqlite"
        )
        self.assertIn(state_directory, result.stdout)
        self.assertIn(bootstrap, result.stdout)
        self.assertEqual(result.stdout.count(bootstrap), 1)
        self.assertLess(result.stdout.index(state_directory), result.stdout.index(bootstrap))

        installer = (ROOT / "scripts/install-project-graph.sh").read_text(encoding="utf-8")
        explicit_bootstrap = (
            'run env "PYTHONPATH=$installed_library" python3 "$installed_bootstrap" \\\n'
            '  database --apply --database "$graph_database"'
        )
        self.assertIn(explicit_bootstrap, installer)
        self.assertLess(
            installer.index(explicit_bootstrap),
            installer.index("systemctl daemon-reload"),
        )

        preflight = "if systemctl is-active --quiet ai-ops-project-graph.service; then"
        refusal = '[[ "$activate" == true ]] || {'
        stop = "systemctl stop ai-ops-project-graph.service"
        first_install = "run install -d -o root -g root -m 0755"
        restart = "systemctl restart ai-ops-project-graph.service"
        for fragment in (preflight, refusal, stop, first_install, restart):
            self.assertIn(fragment, installer)
        self.assertLess(installer.index(preflight), installer.index(refusal))
        self.assertLess(installer.index(refusal), installer.index(stop))
        self.assertLess(installer.index(stop), installer.index(first_install))
        self.assertLess(installer.index(first_install), installer.index(explicit_bootstrap))
        self.assertLess(installer.index(explicit_bootstrap), installer.index(restart))
        self.assertIn(
            "DRY-RUN: preflight active ai-ops-project-graph.service before install writes",
            result.stdout,
        )

    def test_evaluator_signing_is_one_way_for_integrator(self):
        integrator = (ROOT / "control_plane/project_integrator.py").read_text(encoding="utf-8")
        installer = (ROOT / "scripts/install-project-graph.sh").read_text(encoding="utf-8")
        self.assertIn("openssl", integrator)
        self.assertNotIn("import hmac", integrator)
        self.assertIn("evaluator-private.pem", installer)
        self.assertIn("evaluator-public.pem", installer)
        self.assertIn("--evaluator-public-key", (ROOT / "control_plane/graph_service.py").read_text())


if __name__ == "__main__":
    unittest.main()
