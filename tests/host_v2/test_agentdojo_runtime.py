from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from agentmembrane.host_v2.agentdojo_runtime import (
    AGENTDOJO_BENCHMARK,
    AGENTDOJO_REQUIRED_CALLABLES,
    AGENTDOJO_REQUIRED_IMPORTS,
    AGENTDOJO_RUNTIME_ID,
    AGENTDOJO_VERSION_OR_COMMIT,
    FROZEN_LOCK_SHA256,
    FROZEN_PYPROJECT_SHA256,
    FROZEN_PYTHON_EXECUTABLE,
    FROZEN_PYTHON_SHA256,
    FROZEN_PYTHON_VERSION,
    FROZEN_UV_EXECUTABLE_SHA256,
    FROZEN_UV_WHEEL_SHA256,
    agentdojo_runtime_expectation,
    load_agentdojo_runtime_receipt,
    validate_agentdojo_runtime_receipt,
)
from agentmembrane.host_v2.runtime_provisioning import (
    CallableEvidence,
    EnvironmentIdentity,
    ExecutionCounters,
    FreezeEvidence,
    ImportEvidence,
    ProvisioningReceipt,
    RecordedCommand,
    RunAuthorizations,
    UpstreamIdentity,
    freeze_output_sha256,
    receipt_payload_sha256,
    receipt_sha256,
)
from agentmembrane.host_v2.schema import canonical_json_bytes


class _Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.expectation = agentdojo_runtime_expectation(repo_root=self.root)
        self.checkout = Path(self.expectation.checkout_root)
        self.environment = Path(self.expectation.environment_root)
        self.source_tree_hash = "a" * 64
        self.environment_tree_hash = "b" * 64
        self.imports = tuple(
            ImportEvidence(
                module=module,
                origin=str(
                    (
                        self.checkout / "src" / "agentdojo" / "fixture.py"
                        if module == "agentdojo" or module.startswith("agentdojo.")
                        else self.environment
                        / "lib/python3.12/site-packages"
                        / (module.replace(".", "/") + ".py")
                    ).resolve()
                ),
                package=package,
                version=version,
            )
            for module, (package, version) in sorted(
                AGENTDOJO_REQUIRED_IMPORTS.items()
            )
        )
        self.bindings = tuple(
            sorted(
                (
                    CallableEvidence(
                        binding_id=binding_id,
                        callable_ref=callable_ref,
                        source_path=str((self.checkout / source_path).resolve()),
                        source_sha256=source_sha256,
                    )
                    for (
                        binding_id,
                        callable_ref,
                        source_path,
                        source_sha256,
                    ) in AGENTDOJO_REQUIRED_CALLABLES
                ),
                key=lambda item: item.callable_ref,
            )
        )
        freeze_lines = ("agentdojo-core-dependencies==receipt-bound",)
        freeze_command = RecordedCommand(
            executable=self.expectation.freeze_executable,
            arguments=self.expectation.freeze_arguments,
            cwd=self.expectation.freeze_cwd,
            environment_overrides=self.expectation.freeze_environment_overrides,
            exit_code=0,
        )
        base = ProvisioningReceipt(
            schema_version=1,
            artifact_type="agentmembrane_native_runtime_provisioning_receipt",
            runtime_id=AGENTDOJO_RUNTIME_ID,
            benchmark=AGENTDOJO_BENCHMARK,
            upstream_version_or_commit=AGENTDOJO_VERSION_OR_COMMIT,
            created_at="2026-08-30T00:00:00Z",
            interpreter=self.expectation.interpreter,
            bootstrap=self.expectation.bootstrap,
            upstream=UpstreamIdentity(
                checkout_root=str(self.checkout),
                checkout_head=self.expectation.checkout_head,
                pyproject_path=self.expectation.pyproject_path,
                pyproject_sha256=FROZEN_PYPROJECT_SHA256,
                pyproject_version="0.1.35",
                lock_path=self.expectation.lock_path,
                lock_sha256=FROZEN_LOCK_SHA256,
                lock_root_version="0.1.35",
                tree_manifest_pre_sha256=self.source_tree_hash,
                tree_manifest_post_sha256=self.source_tree_hash,
            ),
            environment=EnvironmentIdentity(
                root=str(self.environment),
                python_executable=self.expectation.environment_python_executable,
                tree_sha256=self.environment_tree_hash,
            ),
            sync=RecordedCommand(
                executable=self.expectation.sync_executable,
                arguments=self.expectation.sync_arguments,
                cwd=self.expectation.sync_cwd,
                environment_overrides=self.expectation.sync_environment_overrides,
                exit_code=0,
            ),
            freeze=FreezeEvidence(
                command=freeze_command,
                lines=freeze_lines,
                output_sha256=freeze_output_sha256(freeze_lines),
            ),
            import_probe=RecordedCommand(
                executable=self.expectation.import_probe_executable,
                arguments=self.expectation.import_probe_arguments,
                cwd=self.expectation.import_probe_cwd,
                environment_overrides=(
                    self.expectation.import_probe_environment_overrides
                ),
                exit_code=0,
            ),
            imports=self.imports,
            callable_bindings=self.bindings,
            warnings=(),
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
        self.receipt = replace(base, payload_sha256=receipt_payload_sha256(base))
        self.receipt_sha256 = receipt_sha256(self.receipt)

    def probe(self) -> dict:
        return {
            "schema_version": 1,
            "runtime_id": AGENTDOJO_RUNTIME_ID,
            "interpreter": {
                "environment_python_executable": str(
                    self.environment / "bin/python"
                ),
                "base_executable": str(FROZEN_PYTHON_EXECUTABLE),
                "version": FROZEN_PYTHON_VERSION,
                "executable_sha256": FROZEN_PYTHON_SHA256,
                "environment_root": str(self.environment),
            },
            "imports": [item.as_json() for item in self.imports],
            "callable_bindings": [item.as_json() for item in self.bindings],
            "network_attempts": 0,
            "execution_counts": {
                "task_executions": 0,
                "native_checker_executions": 0,
                "parity_executions": 0,
                "provider_calls": 0,
                "model_calls": 0,
                "api_calls": 0,
            },
        }

    def file_hash(self, path: Path) -> str:
        candidate = Path(path)
        if candidate == FROZEN_PYTHON_EXECUTABLE:
            return FROZEN_PYTHON_SHA256
        if candidate == Path(self.expectation.bootstrap.wheel_path):
            return FROZEN_UV_WHEEL_SHA256
        if candidate == Path(self.expectation.bootstrap.uv_executable):
            return FROZEN_UV_EXECUTABLE_SHA256
        if candidate == Path(self.expectation.pyproject_path):
            return FROZEN_PYPROJECT_SHA256
        if candidate == Path(self.expectation.lock_path):
            return FROZEN_LOCK_SHA256
        raise OSError(candidate)

    def validate(self, *, probe=None, file_hash=None, environment_hash=None):
        return validate_agentdojo_runtime_receipt(
            self.receipt,
            expected_receipt_sha256=self.receipt_sha256,
            repo_root=self.root,
            import_probe=(lambda command: self.probe()) if probe is None else probe,
            file_sha256=self.file_hash if file_hash is None else file_hash,
            tree_sha256=(
                (lambda path: self.environment_tree_hash)
                if environment_hash is None
                else environment_hash
            ),
            source_tree_sha256=lambda path: self.source_tree_hash,
        )


class AgentDojoRuntimeReceiptTests(unittest.TestCase):
    def test_exact_receipt_is_import_executable_but_never_parity_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(Path(directory))
            report = fixture.validate()

        self.assertTrue(report.import_executable)
        self.assertTrue(report.executable)
        self.assertTrue(report.checker_dispatchers_importable)
        self.assertFalse(report.native_checker_parity_demonstrated)
        self.assertFalse(report.public_or_formal_readiness)
        self.assertEqual(report.task_executions, 0)
        self.assertEqual(report.checker_executions, 0)
        self.assertEqual(report.parity_executions, 0)
        self.assertEqual(report.blockers, ())
        canonical_json_bytes(report.as_json())

    def test_wrong_receipt_hash_fails_before_tree_or_import_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(Path(directory))
            touched = []

            report = validate_agentdojo_runtime_receipt(
                fixture.receipt,
                expected_receipt_sha256="f" * 64,
                repo_root=fixture.root,
                import_probe=lambda command: touched.append("probe"),
                file_sha256=lambda path: touched.append("file"),
                tree_sha256=lambda path: touched.append("tree"),
                source_tree_sha256=lambda path: touched.append("source"),
            )

        self.assertFalse(report.import_executable)
        self.assertEqual(touched, [])
        self.assertIn(
            "AGENTDOJO_RECEIPT_HASH_MISMATCH",
            {item.code for item in report.blockers},
        )

    def test_wrong_live_interpreter_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(Path(directory))
            wrong = fixture.probe()
            wrong["interpreter"] = dict(wrong["interpreter"])
            wrong["interpreter"]["version"] = "3.13.1"
            report = fixture.validate(probe=lambda command: wrong)

        self.assertFalse(report.import_executable)
        self.assertIn(
            "AGENTDOJO_INTERPRETER_MISMATCH",
            {item.code for item in report.blockers},
        )

    def test_missing_dependency_fails_closed_and_does_not_claim_parity(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(Path(directory))

            def missing(command):
                raise ModuleNotFoundError("deepdiff", name="deepdiff")

            report = fixture.validate(probe=missing)

        self.assertFalse(report.import_executable)
        self.assertFalse(report.native_checker_parity_demonstrated)
        self.assertIn(
            "AGENTDOJO_DEPENDENCY_MISSING:deepdiff",
            {item.code for item in report.blockers},
        )

    def test_wrong_import_origin_and_version_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(Path(directory))
            wrong = fixture.probe()
            rows = [dict(item) for item in wrong["imports"]]
            deepdiff = next(item for item in rows if item["module"] == "deepdiff")
            deepdiff["origin"] = "/tmp/ambient/deepdiff.py"
            deepdiff["version"] = "99.0"
            wrong["imports"] = rows
            report = fixture.validate(probe=lambda command: wrong)

        codes = {item.code for item in report.blockers}
        self.assertFalse(report.import_executable)
        self.assertIn("AGENTDOJO_IMPORT_ORIGIN_MISMATCH", codes)
        self.assertIn("AGENTDOJO_DEPENDENCY_VERSION_MISMATCH", codes)
        self.assertIn("AGENTDOJO_IMPORT_EVIDENCE_MISMATCH", codes)

    def test_mutated_environment_or_frozen_file_blocks_before_import(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = _Fixture(Path(directory))
            calls = []
            environment_report = fixture.validate(
                probe=lambda command: calls.append("probe"),
                environment_hash=lambda path: "c" * 64,
            )
            self.assertEqual(calls, [])
            self.assertIn(
                "AGENTDOJO_ENVIRONMENT_TREE_MISMATCH",
                {item.code for item in environment_report.blockers},
            )

            def wrong_file(path: Path) -> str:
                if Path(path) == Path(fixture.expectation.lock_path):
                    return "d" * 64
                return fixture.file_hash(path)

            file_report = fixture.validate(
                probe=lambda command: calls.append("probe"),
                file_hash=wrong_file,
            )
            self.assertEqual(calls, [])
            self.assertIn(
                "AGENTDOJO_FROZEN_FILE_HASH_MISMATCH",
                {item.code for item in file_report.blockers},
            )

    def test_exact_commands_bind_no_install_project_and_isolated_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            expectation = agentdojo_runtime_expectation(repo_root=Path(directory))

        self.assertIn("--frozen", expectation.sync_arguments)
        self.assertIn("--no-dev", expectation.sync_arguments)
        self.assertIn("--no-editable", expectation.sync_arguments)
        self.assertIn("--no-install-project", expectation.sync_arguments)
        self.assertEqual(expectation.import_probe_arguments[:3], ("-I", "-B", "-c"))
        self.assertIn(
            "network access is forbidden during AgentDojo import preflight",
            expectation.import_probe_arguments[3],
        )

    def test_missing_receipt_path_is_a_stable_no_go(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = load_agentdojo_runtime_receipt(
                root / "missing.json",
                expected_receipt_sha256="e" * 64,
                repo_root=root,
            )

        self.assertFalse(report.import_executable)
        self.assertIn(
            "AGENTDOJO_RECEIPT_MISSING_OR_INVALID",
            {item.code for item in report.blockers},
        )

    def test_noncanonical_receipt_file_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = _Fixture(root)
            path = root / "receipt.json"
            path.write_text(
                json.dumps(fixture.receipt.as_json(), indent=2), encoding="utf-8"
            )
            report = load_agentdojo_runtime_receipt(
                path,
                expected_receipt_sha256=fixture.receipt_sha256,
                repo_root=root,
                import_probe=lambda command: fixture.probe(),
                file_sha256=fixture.file_hash,
                tree_sha256=lambda candidate: fixture.environment_tree_hash,
                source_tree_sha256=lambda candidate: fixture.source_tree_hash,
            )

        self.assertFalse(report.import_executable)
        self.assertIn(
            "AGENTDOJO_RECEIPT_FILE_NOT_CANONICAL",
            {item.code for item in report.blockers},
        )


if __name__ == "__main__":
    unittest.main()
