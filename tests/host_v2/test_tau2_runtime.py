from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.runtime_provisioning import (
    CallableEvidence,
    EnvironmentIdentity,
    ExecutionCounters,
    FreezeEvidence,
    ImportEvidence,
    ProvisioningReceipt,
    ProvisioningWarning,
    RecordedCommand,
    RunAuthorizations,
    UpstreamIdentity,
    freeze_output_sha256,
    receipt_payload_sha256,
    receipt_sha256,
)
from agentmembrane.host_v2.schema import canonical_json_bytes
from agentmembrane.host_v2.tau2_runtime import (
    TAU2_CALLABLE_BINDINGS,
    TAU2_FREEZE_LINE_COUNT,
    TAU2_INTERPRETER,
    TAU2_INTERPRETER_SHA256,
    TAU2_INTERPRETER_VERSION,
    TAU2_PIN,
    TAU2_REQUIRED_IMPORTS,
    TAU2_RUNTIME_ID,
    TAU2_VERSION_MISMATCH_WARNING_CODE,
    TAU2_VERSION_MISMATCH_WARNING_MESSAGE,
    UV_EXECUTABLE_SHA256,
    UV_WHEEL_SHA256,
    load_tau2_runtime_receipt,
    tau2_runtime_expectation,
    validate_tau2_runtime_receipt,
)


SOURCE_TREE_SHA256 = "a" * 64
ENVIRONMENT_TREE_SHA256 = "b" * 64


def _origin(module: str, *, checkout: Path, environment: Path) -> str:
    if module == "tau2" or module.startswith("tau2."):
        relative = module.replace(".", "/")
        return str(checkout / "src" / relative / "__init__.py")
    return str(
        environment
        / "lib/python3.12/site-packages"
        / (module.replace(".", "/") + ".py")
    )


def _fixture(repo_root: Path):
    expectation = tau2_runtime_expectation(repo_root=repo_root)
    checkout = Path(expectation.checkout_root)
    environment = Path(expectation.environment_root)
    imports = tuple(
        ImportEvidence(
            module=module,
            origin=_origin(module, checkout=checkout, environment=environment),
            package=TAU2_REQUIRED_IMPORTS[module][0],
            version=TAU2_REQUIRED_IMPORTS[module][1],
        )
        for module in sorted(TAU2_REQUIRED_IMPORTS)
    )
    bindings = tuple(
        CallableEvidence(
            binding_id=binding_id,
            callable_ref=callable_ref,
            source_path=str((checkout / source_path).resolve()),
            source_sha256=source_sha256,
        )
        for binding_id, callable_ref, source_path, source_sha256 in sorted(
            TAU2_CALLABLE_BINDINGS, key=lambda row: row[1]
        )
    )
    freeze_lines = tuple(
        f"fixture-package-{index:03d}==1.0"
        for index in range(TAU2_FREEZE_LINE_COUNT)
    )
    receipt = ProvisioningReceipt(
        schema_version=1,
        artifact_type="agentmembrane_native_runtime_provisioning_receipt",
        runtime_id=TAU2_RUNTIME_ID,
        benchmark="tau2-bench",
        upstream_version_or_commit=TAU2_PIN,
        created_at="2026-08-30T04:00:00Z",
        interpreter=expectation.interpreter,
        bootstrap=expectation.bootstrap,
        upstream=UpstreamIdentity(
            checkout_root=expectation.checkout_root,
            checkout_head=expectation.checkout_head,
            pyproject_path=expectation.pyproject_path,
            pyproject_sha256=expectation.pyproject_sha256,
            pyproject_version=expectation.pyproject_version,
            lock_path=expectation.lock_path,
            lock_sha256=expectation.lock_sha256,
            lock_root_version=expectation.lock_root_version,
            tree_manifest_pre_sha256=SOURCE_TREE_SHA256,
            tree_manifest_post_sha256=SOURCE_TREE_SHA256,
        ),
        environment=EnvironmentIdentity(
            root=expectation.environment_root,
            python_executable=expectation.environment_python_executable,
            tree_sha256=ENVIRONMENT_TREE_SHA256,
        ),
        sync=RecordedCommand(
            executable=expectation.sync_executable,
            arguments=expectation.sync_arguments,
            cwd=expectation.sync_cwd,
            environment_overrides=expectation.sync_environment_overrides,
            exit_code=0,
        ),
        freeze=FreezeEvidence(
            command=RecordedCommand(
                executable=expectation.freeze_executable,
                arguments=expectation.freeze_arguments,
                cwd=expectation.freeze_cwd,
                environment_overrides=expectation.freeze_environment_overrides,
                exit_code=0,
            ),
            lines=freeze_lines,
            output_sha256=freeze_output_sha256(freeze_lines),
        ),
        import_probe=RecordedCommand(
            executable=expectation.import_probe_executable,
            arguments=expectation.import_probe_arguments,
            cwd=expectation.import_probe_cwd,
            environment_overrides=expectation.import_probe_environment_overrides,
            exit_code=0,
        ),
        imports=imports,
        callable_bindings=bindings,
        warnings=(
            ProvisioningWarning(
                code=TAU2_VERSION_MISMATCH_WARNING_CODE,
                message=TAU2_VERSION_MISMATCH_WARNING_MESSAGE,
                blocking=False,
            ),
        ),
        execution_counts=ExecutionCounters(
            task_executions=0,
            parity_executions=0,
            native_checker_executions=0,
            provider_calls=0,
            model_calls=0,
            api_calls=0,
            provisioning_downloads=1,
            runtime_probe_network_attempts=0,
        ),
        authorizations=RunAuthorizations(
            task_execution=False,
            checker_parity=False,
            calibration=False,
            formal_run=False,
            public_run=False,
            provider_calls=False,
            model_calls=False,
            api_calls=False,
        ),
        payload_sha256="0" * 64,
    )
    receipt = replace(receipt, payload_sha256=receipt_payload_sha256(receipt))

    live_probe = {
        "schema_version": 1,
        "probe_kind": "tau2_receipt_bound_import_only",
        "python_executable": expectation.environment_python_executable,
        "python_version": TAU2_INTERPRETER_VERSION,
        "python_executable_sha256": TAU2_INTERPRETER_SHA256,
        "prefix": expectation.environment_root,
        "base_prefix": str(TAU2_INTERPRETER.parent.parent),
        "isolated": True,
        "no_user_site": True,
        "dont_write_bytecode": True,
        "sys_path": [
            str(checkout / "src"),
            str(environment / "lib/python3.12/site-packages"),
            str(TAU2_INTERPRETER.parent.parent / "lib/python3.12"),
        ],
        "imports": [item.as_json() for item in imports],
        "callable_bindings": [item.as_json() for item in bindings],
        "network_attempts": 0,
        "task_executions": 0,
        "native_checker_executions": 0,
        "parity_executions": 0,
    }

    file_hashes = {
        str(TAU2_INTERPRETER): expectation.interpreter.executable_sha256,
        expectation.bootstrap.wheel_path: UV_WHEEL_SHA256,
        expectation.bootstrap.uv_executable: UV_EXECUTABLE_SHA256,
        expectation.pyproject_path: expectation.pyproject_sha256,
        expectation.lock_path: expectation.lock_sha256,
    }
    for _, _, source_path, source_sha256 in TAU2_CALLABLE_BINDINGS:
        file_hashes[str(checkout / source_path)] = source_sha256

    def file_sha256(path: Path) -> str | None:
        return file_hashes.get(str(path))

    hooks = {
        "repo_root": repo_root,
        "import_probe": lambda _command: live_probe,
        "file_sha256": file_sha256,
        "environment_tree_sha256": lambda _root: ENVIRONMENT_TREE_SHA256,
        "source_tree_sha256": lambda _root: SOURCE_TREE_SHA256,
        "lock_semantics": lambda _root: True,
        "environment_python_validator": lambda _path: True,
    }
    return receipt, live_probe, hooks


class Tau2RuntimeExpectationTests(unittest.TestCase):
    def test_exact_commands_versions_environment_and_warning_are_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            expectation = tau2_runtime_expectation(repo_root=root)

        self.assertEqual(expectation.interpreter.executable, str(TAU2_INTERPRETER))
        self.assertEqual(expectation.interpreter.version, "3.12.3")
        self.assertEqual(
            expectation.bootstrap.uv_executable_sha256, UV_EXECUTABLE_SHA256
        )
        self.assertEqual(
            expectation.sync_arguments[:5],
            ("sync", "--frozen", "--no-dev", "--no-editable", "--no-install-project"),
        )
        self.assertEqual(expectation.pyproject_version, "1.0.1")
        self.assertEqual(expectation.lock_root_version, "1.0.0")
        self.assertEqual(
            expectation.required_warning_codes,
            (TAU2_VERSION_MISMATCH_WARNING_CODE,),
        )
        self.assertEqual(
            expectation.import_probe_cwd, expectation.environment_root
        )
        self.assertEqual(
            [
                (item.name, item.value)
                for item in expectation.import_probe_environment_overrides
            ],
            [
                ("LITELLM_LOCAL_MODEL_COST_MAP", "True"),
                ("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
                ("PYTHONDONTWRITEBYTECODE", "1"),
            ],
        )
        probe_source = expectation.import_probe_arguments[-1]
        self.assertIn("socket.create_connection = _deny_network", probe_source)
        self.assertIn('network_attempts": network_attempts', probe_source)
        self.assertNotIn("evaluate_simulation(", probe_source)
        self.assertNotIn("get_environment(", probe_source)


class Tau2RuntimeReceiptTests(unittest.TestCase):
    def test_synthetic_exact_receipt_allows_imports_but_never_parity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            receipt, _probe, hooks = _fixture(Path(temp_dir).resolve())
            synthetic_freeze_sha = receipt.freeze.output_sha256
            with patch(
                "agentmembrane.host_v2.tau2_runtime.TAU2_FREEZE_SHA256",
                synthetic_freeze_sha,
            ):
                report = validate_tau2_runtime_receipt(
                    receipt,
                    expected_receipt_sha256=receipt_sha256(receipt),
                    **hooks,
                )

        self.assertTrue(report.import_executable)
        self.assertTrue(report.executable)
        self.assertTrue(report.checker_dispatchers_importable)
        self.assertFalse(report.native_checker_parity_demonstrated)
        self.assertFalse(report.public_or_formal_readiness)
        self.assertEqual(report.task_executions, 0)
        self.assertEqual(report.checker_executions, 0)
        self.assertEqual(report.parity_executions, 0)
        self.assertEqual(report.network_attempts, 0)
        self.assertEqual(report.blockers, ())
        self.assertEqual(
            json.loads(canonical_json_bytes(report.as_json())), report.as_json()
        )

    def test_missing_or_substituted_receipt_hash_blocks_before_import(self) -> None:
        calls = []
        with tempfile.TemporaryDirectory() as temp_dir:
            receipt, _probe, hooks = _fixture(Path(temp_dir).resolve())
            hooks["import_probe"] = lambda command: calls.append(command)
            missing = validate_tau2_runtime_receipt(
                receipt, expected_receipt_sha256="", **hooks
            )
            wrong = validate_tau2_runtime_receipt(
                receipt, expected_receipt_sha256="0" * 64, **hooks
            )

        self.assertFalse(missing.executable)
        self.assertFalse(wrong.executable)
        self.assertEqual(calls, [])
        self.assertEqual(missing.blockers[0].code, "TAU2_RECEIPT_HASH_REQUIRED")
        self.assertEqual(wrong.blockers[0].code, "TAU2_RECEIPT_HASH_MISMATCH")

    def test_warning_or_frozen_sync_mutation_fails_closed_before_import(self) -> None:
        calls = []
        with tempfile.TemporaryDirectory() as temp_dir:
            receipt, _probe, hooks = _fixture(Path(temp_dir).resolve())
            receipt = replace(
                receipt,
                warnings=(
                    replace(receipt.warnings[0], message="discrepancy hidden"),
                ),
                payload_sha256="0" * 64,
            )
            receipt = replace(
                receipt, payload_sha256=receipt_payload_sha256(receipt)
            )
            hooks["import_probe"] = lambda command: calls.append(command)
            report = validate_tau2_runtime_receipt(
                receipt,
                expected_receipt_sha256=receipt_sha256(receipt),
                **hooks,
            )

        self.assertFalse(report.executable)
        self.assertEqual(calls, [])
        self.assertIn(
            "TAU2_VERSION_MISMATCH_WARNING_INVALID",
            [item.code for item in report.blockers],
        )

    def test_wrong_lock_environment_or_callable_bytes_blocks_before_import(
        self,
    ) -> None:
        calls = []
        with tempfile.TemporaryDirectory() as temp_dir:
            receipt, _probe, hooks = _fixture(Path(temp_dir).resolve())
            hooks.update(
                {
                    "import_probe": lambda command: calls.append(command),
                    "lock_semantics": lambda _root: False,
                    "environment_tree_sha256": lambda _root: "c" * 64,
                    "file_sha256": lambda _path: "d" * 64,
                }
            )
            report = validate_tau2_runtime_receipt(
                receipt,
                expected_receipt_sha256=receipt_sha256(receipt),
                **hooks,
            )

        codes = {item.code for item in report.blockers}
        self.assertFalse(report.executable)
        self.assertEqual(calls, [])
        self.assertIn("TAU2_LOCK_GRAPH_MISMATCH", codes)
        self.assertIn("TAU2_ENVIRONMENT_TREE_MISMATCH", codes)
        self.assertIn("TAU2_FROZEN_FILE_HASH_MISMATCH", codes)
        self.assertIn("TAU2_CALLABLE_SOURCE_MISMATCH", codes)

    def test_live_origin_version_network_and_sys_path_mismatches_fail_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            receipt, probe, hooks = _fixture(Path(temp_dir).resolve())
            changed_imports = [dict(item) for item in probe["imports"]]
            changed_imports[0]["origin"] = "/tmp/escaped.py"
            changed_imports[0]["version"] = "999"
            changed = {
                **probe,
                "imports": changed_imports,
                "network_attempts": 1,
                "sys_path": ["/tmp/escape"],
            }
            hooks["import_probe"] = lambda _command: changed
            with patch(
                "agentmembrane.host_v2.tau2_runtime.TAU2_FREEZE_SHA256",
                receipt.freeze.output_sha256,
            ):
                report = validate_tau2_runtime_receipt(
                    receipt,
                    expected_receipt_sha256=receipt_sha256(receipt),
                    **hooks,
                )

        codes = {item.code for item in report.blockers}
        self.assertFalse(report.executable)
        self.assertIn("TAU2_IMPORT_PROBE_SCOPE_MISMATCH", codes)
        self.assertIn("TAU2_SYS_PATH_MISMATCH", codes)
        self.assertIn("TAU2_IMPORT_EVIDENCE_MISMATCH", codes)
        self.assertIn("TAU2_DEPENDENCY_VERSION_MISMATCH", codes)
        self.assertIn("TAU2_IMPORT_ORIGIN_MISMATCH", codes)

    def test_missing_dependency_is_structured_and_never_runs_a_checker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            receipt, _probe, hooks = _fixture(Path(temp_dir).resolve())

            def missing(_command):
                raise ModuleNotFoundError("litellm", name="litellm")

            hooks["import_probe"] = missing
            with patch(
                "agentmembrane.host_v2.tau2_runtime.TAU2_FREEZE_SHA256",
                receipt.freeze.output_sha256,
            ):
                report = validate_tau2_runtime_receipt(
                    receipt,
                    expected_receipt_sha256=receipt_sha256(receipt),
                    **hooks,
                )

        self.assertFalse(report.executable)
        self.assertIn(
            "TAU2_DEPENDENCY_MISSING:litellm",
            [item.code for item in report.blockers],
        )
        self.assertEqual(report.task_executions, 0)
        self.assertEqual(report.checker_executions, 0)

    def test_loader_requires_canonical_bytes_and_exact_file_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            receipt, _probe, hooks = _fixture(root)
            receipt_path = root / "receipt.json"
            receipt_path.write_bytes(canonical_json_bytes(receipt.as_json()))
            exact_hash = receipt_sha256(receipt)
            with patch(
                "agentmembrane.host_v2.tau2_runtime.TAU2_FREEZE_SHA256",
                receipt.freeze.output_sha256,
            ):
                accepted = load_tau2_runtime_receipt(
                    receipt_path,
                    expected_receipt_sha256=exact_hash,
                    **hooks,
                )
            receipt_path.write_text(
                json.dumps(receipt.as_json(), indent=2), encoding="utf-8"
            )
            rejected = load_tau2_runtime_receipt(
                receipt_path,
                expected_receipt_sha256=exact_hash,
                **hooks,
            )

        self.assertTrue(accepted.executable)
        self.assertFalse(rejected.executable)
        self.assertEqual(rejected.blockers[0].code, "TAU2_RECEIPT_NOT_CANONICAL")


if __name__ == "__main__":
    unittest.main()
