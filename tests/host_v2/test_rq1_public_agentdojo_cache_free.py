from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from uuid import uuid4


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = (
    REPO_ROOT
    / "experiments/host_boundary_v2/rq1_public_preflight_v1/materialize_agentdojo_cache_free.py"
)


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "rq1_public_agentdojo_cache_free_test", MODULE_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load runtime recovery module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


RECOVERY = _load_module()


class _Fixture:
    def __init__(self) -> None:
        self.temp = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.root = Path(self.temp.name)
        self.fresh_root = Path(
            f"/private/tmp/agentmembrane-rq1-agentdojo-runtime-test-{uuid4().hex}"
        )
        self.offline_cache_root = self.root / "offline-cache"
        self.offline_cache_root.mkdir()
        self.source = self.root / RECOVERY.SOURCE_ROOT
        (self.source / "src").mkdir(parents=True)
        self.native_source = self.source / "src/native.py"
        self.native_source.write_text("NATIVE = True\n", encoding="utf-8")
        self.lock = self.root / RECOVERY.LOCK_PATH
        self.lock.write_text("version = 1\n", encoding="utf-8")
        self.implementation = self.root / RECOVERY.RECOVERY_IMPLEMENTATION_PATH
        self.implementation.parent.mkdir(parents=True)
        self.implementation.write_text("IMPLEMENTATION = True\n", encoding="utf-8")
        self.python = self.root / "tools/python3.12"
        self.uv = self.root / "tools/uv"
        self.python.parent.mkdir(parents=True)
        self.python.write_bytes(b"python-3.12.3")
        self.uv.write_bytes(b"uv-0.8.17")
        self.calls: list[tuple[tuple[str, ...], dict[str, str]]] = []
        self.omit_callable = False
        self.inject_pyc = False

    def close(self) -> None:
        if self.fresh_root.exists():
            shutil.rmtree(self.fresh_root)
        self.temp.cleanup()

    def runner(self, command, cwd, environment, timeout):
        command = tuple(command)
        self.calls.append((command, dict(environment)))
        if command == (str(self.python.resolve()), "--version"):
            return subprocess.CompletedProcess(command, 0, "Python 3.12.3\n", "")
        if command == (str(self.uv.resolve()), "--version"):
            return subprocess.CompletedProcess(command, 0, "uv 0.8.17\n", "")
        if len(command) > 1 and command[1] == "sync":
            runtime = Path(environment["UV_PROJECT_ENVIRONMENT"])
            (runtime / "bin").mkdir(parents=True)
            (runtime / "bin/python").write_bytes(b"runtime-python")
            (runtime / "site-packages").mkdir()
            (runtime / "site-packages/agentdojo.txt").write_bytes(b"installed")
            if self.inject_pyc:
                (runtime / "__pycache__").mkdir()
                (runtime / "__pycache__/bad.pyc").write_bytes(b"bytecode")
            return subprocess.CompletedProcess(command, 0, "", "")
        if len(command) > 3 and command[1:3] == ("-I", "-B"):
            token = self.fresh_root.name.removeprefix(
                "agentmembrane-rq1-agentdojo-runtime-"
            ).lower()
            runtime_id = (
                "agentdojo-0.1.35-py3123-lock-395e3d0a5921-rq1-public-" + token
            )
            refs = list(RECOVERY.REQUIRED_CALLABLE_REFS)
            if self.omit_callable:
                refs.pop()
            source_sha = hashlib.sha256(self.native_source.read_bytes()).hexdigest()
            value = {
                "runtime_id": runtime_id,
                "network_attempts": 0,
                "callable_bindings": [
                    {
                        "callable_ref": ref,
                        "callable": True,
                        "source_path": str(self.native_source),
                        "source_sha256": source_sha,
                    }
                    for ref in refs
                ],
                "execution_counts": dict(RECOVERY.ZERO_EXECUTION_COUNTS),
            }
            return subprocess.CompletedProcess(
                command, 0, json.dumps(value, sort_keys=True), ""
            )
        return subprocess.CompletedProcess(command, 99, "", "unexpected command")

    def build(self):
        source_sha, _ = RECOVERY.tree_manifest_sha256(
            self.source,
            excluded_directory_names=RECOVERY.SOURCE_EXCLUDED_DIRECTORY_NAMES,
        )
        return RECOVERY._private_build_fresh_runtime(
            repo_root=self.root,
            fresh_root=self.fresh_root,
            offline_cache_root=self.offline_cache_root,
            python_executable=self.python,
            uv_executable=self.uv,
            command_runner=self.runner,
            expected_python_sha256=hashlib.sha256(self.python.read_bytes()).hexdigest(),
            expected_uv_sha256=hashlib.sha256(self.uv.read_bytes()).hexdigest(),
            expected_lock_sha256=hashlib.sha256(self.lock.read_bytes()).hexdigest(),
            expected_source_tree_sha256=source_sha,
            expected_python_version="3.12.3",
            expected_uv_version="0.8.17",
        )


class RQ1PublicAgentDojoCacheFreeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = _Fixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_fake_build_materializes_fresh_zero_execution_triplet(self) -> None:
        result = self.fixture.build()
        self.assertTrue(result["runtime_id"].endswith(self.fixture.fresh_root.name.split("runtime-")[1]))
        self.assertEqual(result["execution_counts"], RECOVERY.ZERO_EXECUTION_COUNTS)
        self.assertFalse(result["execution_authorized"])
        for role in ("receipt", "live_validator", "runtime_binding"):
            binding = result[role]
            path = self.fixture.root / binding["path"]
            self.assertTrue(path.is_file())
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), binding["sha256"])
        binding_document = json.loads(
            (self.fixture.root / result["runtime_binding"]["path"]).read_text()
        )
        self.assertTrue(binding_document["fresh_runtime_triplet_complete"])
        self.assertEqual(binding_document["execution_counts"], RECOVERY.ZERO_EXECUTION_COUNTS)

    def test_sync_command_and_environment_are_exact(self) -> None:
        self.fixture.build()
        sync_command, environment = next(
            row for row in self.fixture.calls if len(row[0]) > 1 and row[0][1] == "sync"
        )
        self.assertEqual(sync_command[1:7], RECOVERY.SYNC_ARGUMENT_PREFIX)
        self.assertEqual(environment["UV_LINK_MODE"], "copy")
        self.assertEqual(environment["PYTHONDONTWRITEBYTECODE"], "1")
        self.assertEqual(environment["UV_OFFLINE"], "1")
        self.assertEqual(environment["UV_PYTHON_DOWNLOADS"], "never")
        self.assertEqual(environment["ALL_PROXY"], "http://127.0.0.1:9")
        self.assertEqual(environment["NO_PROXY"], "*")
        self.assertEqual(environment["UV_CACHE_DIR"], str(self.fixture.offline_cache_root))
        self.assertEqual(environment["UV_PROJECT_ENVIRONMENT"], str(self.fixture.fresh_root / "environment-v2"))
        probe = next(row[0] for row in self.fixture.calls if "-I" in row[0])
        self.assertEqual(probe[1:3], ("-I", "-B"))

    def test_uv_semantic_version_accepts_build_metadata_and_rejects_drift(self) -> None:
        self.assertEqual(
            RECOVERY._parse_exact_uv_version("uv 0.8.17 (10960bc13 2025-09-10)"),
            "0.8.17",
        )
        for output in (
            "uv 0.8.18 (10960bc13 2025-09-10)",
            "uv 0.8.17 dirty",
            "0.8.17",
            "uv 0.8.170 (10960bc13 2025-09-10)",
        ):
            with self.subTest(output=output):
                if output.startswith("uv 0.8.18") or output.startswith("uv 0.8.170"):
                    self.assertNotEqual(
                        RECOVERY._parse_exact_uv_version(output), RECOVERY.UV_VERSION
                    )
                else:
                    with self.assertRaises(RECOVERY.RuntimeRecoveryError):
                        RECOVERY._parse_exact_uv_version(output)

    def test_existing_or_out_of_scope_root_is_rejected_before_command(self) -> None:
        self.fixture.fresh_root.mkdir()
        with self.assertRaises(RECOVERY.RuntimeRecoveryError):
            self.fixture.build()
        self.assertEqual(self.fixture.calls, [])
        self.fixture.fresh_root.rmdir()
        self.fixture.fresh_root = self.fixture.root / "not-private-prefix"
        with self.assertRaises(RECOVERY.RuntimeRecoveryError):
            self.fixture.build()
        self.assertEqual(self.fixture.calls, [])

    def test_hash_drift_is_rejected_before_sync(self) -> None:
        self.fixture.lock.write_text("changed\n", encoding="utf-8")
        source_sha, _ = RECOVERY.tree_manifest_sha256(
            self.fixture.source,
            excluded_directory_names=RECOVERY.SOURCE_EXCLUDED_DIRECTORY_NAMES,
        )
        with self.assertRaises(RECOVERY.RuntimeRecoveryError):
            RECOVERY._private_build_fresh_runtime(
                repo_root=self.fixture.root,
                fresh_root=self.fixture.fresh_root,
                offline_cache_root=self.fixture.offline_cache_root,
                python_executable=self.fixture.python,
                uv_executable=self.fixture.uv,
                command_runner=self.fixture.runner,
                expected_python_sha256=hashlib.sha256(self.fixture.python.read_bytes()).hexdigest(),
                expected_uv_sha256=hashlib.sha256(self.fixture.uv.read_bytes()).hexdigest(),
                expected_lock_sha256="0" * 64,
                expected_source_tree_sha256=source_sha,
                expected_python_version="3.12.3",
                expected_uv_version="0.8.17",
            )
        self.assertEqual(self.fixture.calls, [])

    def test_offline_cache_must_exist_under_private_tmp(self) -> None:
        self.fixture.offline_cache_root = Path(
            f"/private/tmp/missing-offline-cache-{uuid4().hex}"
        )
        with self.assertRaises(RECOVERY.RuntimeRecoveryError):
            self.fixture.build()
        self.fixture.offline_cache_root = Path("/var/tmp/not-authorized-cache")
        with self.assertRaises(RECOVERY.RuntimeRecoveryError):
            self.fixture.build()
        self.assertEqual(self.fixture.calls, [])

    def test_incomplete_probe_fails_closed(self) -> None:
        self.fixture.omit_callable = True
        with self.assertRaises(RECOVERY.RuntimeRecoveryError):
            self.fixture.build()
        candidates = self.fixture.fresh_root / "artifacts"
        self.assertFalse(candidates.exists())

    def test_probe_rejects_any_extra_callable_binding(self) -> None:
        source_sha = hashlib.sha256(self.fixture.native_source.read_bytes()).hexdigest()
        rows = [
            {
                "callable_ref": ref,
                "callable": True,
                "source_path": str(self.fixture.native_source),
                "source_sha256": source_sha,
            }
            for ref in RECOVERY.REQUIRED_CALLABLE_REFS
        ]
        rows.append(
            {
                "callable_ref": "agentdojo.task_suite.task_suite:TaskSuite",
                "callable": True,
                "source_path": str(self.fixture.native_source),
                "source_sha256": source_sha,
            }
        )
        with self.assertRaises(RECOVERY.RuntimeRecoveryError):
            RECOVERY._validate_probe(
                {
                    "runtime_id": "agentdojo-recovered-test",
                    "network_attempts": 0,
                    "callable_bindings": rows,
                    "execution_counts": dict(RECOVERY.ZERO_EXECUTION_COUNTS),
                },
                runtime_id="agentdojo-recovered-test",
                source_root=self.fixture.source,
            )

    def test_pyc_or_pycache_hygiene_fails_closed(self) -> None:
        self.fixture.inject_pyc = True
        with self.assertRaises(RECOVERY.RuntimeRecoveryError):
            self.fixture.build()
        self.assertFalse(
            (self.fixture.fresh_root / "artifacts").exists()
        )


if __name__ == "__main__":
    unittest.main()
