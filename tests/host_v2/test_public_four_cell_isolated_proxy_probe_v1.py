from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = (
    REPO_ROOT
    / "experiments/host_boundary_v2/public_four_cell_canary_v3/isolated_proxy_probe.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location("isolated_proxy_probe_v1", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load isolated proxy probe")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PROBE = _load_module()


class IsolatedProxyProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.parent = Path(self.temporary.name)
        self.binary = self.parent / "cli-proxy-api"
        self.binary.write_bytes(b"fixture CLIProxy v7.2.145\n")
        self.binary.chmod(0o700)
        self.root = self.parent / "isolated-probe"
        self.auth = self.root / "auth-snapshot"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_image_only_config_is_exact_passthrough_baseline(self) -> None:
        observed = PROBE.build_temp_config("image_only", self.auth, self.root)
        expected = (
            'host: "127.0.0.1"\n'
            "port: 8318\n"
            f'auth-dir: "{self.auth}"\n'
            "api-keys:\n"
            '  - "agentmembrane-isolated-probe-local-client-v1"\n'
            "debug: false\n"
            "logging-to-file: true\n"
            "request-retry: 0\n"
            "max-retry-credentials: 1\n"
            'disable-image-generation: "passthrough"\n'
        ).encode()
        self.assertEqual(observed, expected)
        self.assertNotIn(b"payload:", observed)

    def test_each_override_profile_adds_exactly_one_parameter(self) -> None:
        expected = {
            "parallel": b"parallel_tool_calls: false",
            "max": b"max_output_tokens: 1100",
            "stream": b"stream: false",
            "temperature": b"temperature: 0",
        }
        for profile, parameter in expected.items():
            with self.subTest(profile=profile):
                config = PROBE.build_temp_config(profile, self.auth, self.root)
                self.assertIn(parameter, config)
                self.assertEqual(config.count(b"      params:\n"), 1)
                self.assertEqual(config.count(b"        - name:"), 1)
                for other in expected.values():
                    self.assertEqual(other in config, other == parameter)

    def test_all_profile_applies_complete_frozen_control_set(self) -> None:
        config = PROBE.build_temp_config("all", self.auth, self.root)
        for parameter in (
            b"parallel_tool_calls: false",
            b"max_output_tokens: 1100",
            b"stream: false",
            b"temperature: 0",
        ):
            self.assertIn(parameter, config)
        self.assertEqual(config.count(b"      params:\n"), 1)
        self.assertEqual(config.count(b"        - name:"), 1)

    def test_override_match_is_only_sol_codex_from_responses(self) -> None:
        config = PROBE.build_temp_config("parallel", self.auth, self.root)
        self.assertIn(b'        - name: "gpt-5.6-sol"\n', config)
        self.assertIn(b'          protocol: "codex"\n', config)
        self.assertIn(b'          from-protocol: "responses"\n', config)
        self.assertNotIn(b"gpt-*", config)
        self.assertNotIn(b"openai", config)

    def test_compatible_profile_covers_both_observed_input_protocols(self) -> None:
        config = PROBE.build_temp_config("compatible", self.auth, self.root)
        self.assertEqual(config.count(b"parallel_tool_calls: false"), 2)
        self.assertEqual(config.count(b'        - name: "gpt-5.6-sol"\n'), 2)
        self.assertEqual(config.count(b'          protocol: "codex"\n'), 2)
        self.assertIn(b'          from-protocol: "responses"\n', config)
        self.assertIn(b'          from-protocol: "openai"\n', config)
        self.assertNotIn(b"max_output_tokens", config)
        self.assertNotIn(b"temperature", config)
        self.assertNotIn(b"stream:", config)

    def test_unknown_profile_fails_closed(self) -> None:
        for profile in ("", "gpt-5.6-sol", "parallel=false"):
            with self.subTest(profile=profile):
                with self.assertRaises(PROBE.IsolatedProxyProbeError):
                    PROBE.build_temp_config(profile, self.auth, self.root)

    def test_auth_snapshot_must_be_exact_independent_child(self) -> None:
        invalid = (
            self.root / "auth",
            self.parent / "auth-snapshot",
            Path("relative/auth-snapshot"),
            self.root / "nested/auth-snapshot",
        )
        for auth in invalid:
            with self.subTest(auth=auth):
                with self.assertRaises(PROBE.IsolatedProxyProbeError):
                    PROBE.build_temp_config("image_only", auth, self.root)

    def test_paths_with_traversal_or_filesystem_root_fail_closed(self) -> None:
        with self.assertRaises(PROBE.IsolatedProxyProbeError):
            PROBE.build_temp_config(
                "image_only",
                Path("/private/tmp/a/../b/auth-snapshot"),
                Path("/private/tmp/a/../b"),
            )
        with self.assertRaises(PROBE.IsolatedProxyProbeError):
            PROBE.build_temp_config("image_only", Path("/auth-snapshot"), Path("/"))

    def test_prepare_is_zero_write_and_has_exact_argv(self) -> None:
        report = PROBE.prepare(
            profile="max", temp_root=self.root, binary_path=self.binary
        )
        self.assertEqual(report["status"], "ISOLATED_PROXY_OFFLINE_PREPARE_PASS")
        self.assertEqual(
            report["argv"],
            (
                str(self.binary),
                "-local-model",
                "-config",
                str(self.root / "config.yaml"),
            ),
        )
        self.assertFalse(self.root.exists())
        self.assertEqual(
            report["execution"],
            {
                "processes_started": 0,
                "network_calls": 0,
                "credential_files_read": 0,
                "credential_files_copied": 0,
                "upstream_secrets_materialized": 0,
                "files_written": 0,
            },
        )
        self.assertEqual(report["workspace_plan"]["temp_root_mode"], "0700")
        self.assertEqual(report["workspace_plan"]["config_mode"], "0600")

    def test_prepare_locates_pid_logs_and_bounded_cleanup(self) -> None:
        report = PROBE.prepare(
            profile="stream", temp_root=self.root, binary_path=self.binary
        )
        workspace = report["workspace_plan"]
        self.assertEqual(workspace["pid_path"], str(self.root / "run/cliproxy.pid"))
        self.assertEqual(
            workspace["stdout_log"], str(self.root / "logs/launcher.stdout.log")
        )
        self.assertEqual(
            workspace["stderr_log"], str(self.root / "logs/launcher.stderr.log")
        )
        cleanup = report["cleanup_plan"]
        self.assertEqual(cleanup["scope_guard"], str(self.root))
        self.assertEqual(cleanup["precondition"], "pid_absent_or_verified_stopped")
        self.assertEqual(cleanup["preserve_binary"], str(self.binary))
        self.assertFalse(cleanup["automatic_cleanup_performed"])

    def test_existing_namespace_including_symlink_fails_closed(self) -> None:
        self.root.mkdir(mode=0o700)
        with self.assertRaisesRegex(PROBE.IsolatedProxyProbeError, "already exists"):
            PROBE.prepare(
                profile="image_only", temp_root=self.root, binary_path=self.binary
            )
        self.root.rmdir()
        os.symlink(self.parent / "missing-target", self.root)
        with self.assertRaisesRegex(PROBE.IsolatedProxyProbeError, "already exists"):
            PROBE.prepare(
                profile="image_only", temp_root=self.root, binary_path=self.binary
            )

    def test_binary_must_be_absolute_executable_nonwritable_regular_file(self) -> None:
        self.binary.chmod(0o600)
        with self.assertRaises(PROBE.IsolatedProxyProbeError):
            PROBE.prepare(
                profile="temperature", temp_root=self.root, binary_path=self.binary
            )
        self.binary.chmod(0o722)
        with self.assertRaises(PROBE.IsolatedProxyProbeError):
            PROBE.prepare(
                profile="temperature", temp_root=self.root, binary_path=self.binary
            )
        with self.assertRaises(PROBE.IsolatedProxyProbeError):
            PROBE.prepare(
                profile="temperature",
                temp_root=self.root,
                binary_path=Path("cli-proxy-api"),
            )

    def test_module_exposes_no_runner_or_execute_entrypoint(self) -> None:
        self.assertFalse(hasattr(PROBE, "execute"))
        self.assertFalse(hasattr(PROBE, "run"))
        source = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("import subprocess", source)
        self.assertNotIn("import socket", source)
        self.assertNotIn("urllib", source)


if __name__ == "__main__":
    unittest.main()
