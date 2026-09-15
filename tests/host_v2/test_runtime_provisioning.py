from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from agentmembrane.host_v2.runtime_provisioning import (
    CallableEvidence,
    EnvironmentIdentity,
    EnvironmentOverride,
    ExecutionCounters,
    FreezeEvidence,
    ImportEvidence,
    InterpreterIdentity,
    ProvisioningReceipt,
    ProvisioningWarning,
    RUNTIME_PROVISIONING_ARTIFACT_TYPE,
    RecordedCommand,
    RunAuthorizations,
    RuntimeProvisioningExpectation,
    UpstreamIdentity,
    UvBootstrapIdentity,
    file_sha256,
    freeze_output_sha256,
    freeze_lines_are_canonical,
    receipt_payload_sha256,
    source_tree_manifest_sha256,
    tree_manifest_sha256,
    validate_provisioning_receipt,
)
from agentmembrane.host_v2.schema import IntegrityError, sha256_bytes


def _overrides(**values: str) -> tuple[EnvironmentOverride, ...]:
    return tuple(
        EnvironmentOverride(name=name, value=value)
        for name, value in sorted(values.items())
    )


class RuntimeFixture:
    def __init__(self, root: Path, *, tau2: bool = False) -> None:
        self.root = root
        self.interpreter_path = root / "base" / "python3.12"
        self.wheel_path = root / "wheelhouse" / "uv.whl"
        self.bootstrap_root = root / "bootstrap"
        self.uv_path = self.bootstrap_root / "bin" / "uv"
        self.checkout = root / "checkout"
        self.pyproject = self.checkout / "pyproject.toml"
        self.lock = self.checkout / "uv.lock"
        self.source = self.checkout / "src" / "fixture_pkg.py"
        self.environment = root / "environment"
        self.env_python = self.environment / "bin" / "python"
        self.dependency = self.environment / "site-packages" / "fixture_dep.py"
        for path, payload in (
            (self.interpreter_path, b"fixture-python"),
            (self.wheel_path, b"fixture-wheel"),
            (self.uv_path, b"fixture-uv"),
            (self.pyproject, b"[project]\nversion='1.0.1'\n"),
            (self.lock, b"version = 1\n"),
            (self.source, b"def checker():\n    return None\n"),
            (self.env_python, b"fixture-env-python"),
            (self.dependency, b"VERSION='1'\n"),
            (self.checkout / ".git" / "index", b"ignored-vcs-state"),
            (self.checkout / "__pycache__" / "ignored.pyc", b"ignored-cache"),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        self.runtime_id = (
            "tau2-py3123-lock-62d3a8c4807b"
            if tau2
            else "agentdojo-0.1.35-py3123-lock-395e3d0a5921"
        )
        self.benchmark = "tau2-bench" if tau2 else "agentdojo"
        self.interpreter = InterpreterIdentity(
            executable=str(self.interpreter_path),
            version="Python 3.12.3",
            executable_sha256=file_sha256(self.interpreter_path),
        )
        self.bootstrap = UvBootstrapIdentity(
            version="0.8.17",
            wheel_path=str(self.wheel_path),
            wheel_sha256=file_sha256(self.wheel_path),
            bootstrap_root=str(self.bootstrap_root),
            uv_executable=str(self.uv_path),
            uv_executable_sha256=file_sha256(self.uv_path),
        )
        self.sync_env = _overrides(
            PATH="/fixture/bin",
            PYTHONDONTWRITEBYTECODE="1",
            UV_PROJECT_ENVIRONMENT=str(self.environment),
        )
        self.freeze_env = self.sync_env
        probe_values = {
            "PATH": "/fixture/bin",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        if tau2:
            probe_values["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
        self.probe_env = _overrides(**probe_values)
        self.sync = RecordedCommand(
            executable=str(self.uv_path),
            arguments=("sync", "--frozen", "--no-dev", "--no-editable"),
            cwd=str(self.checkout),
            environment_overrides=self.sync_env,
            exit_code=0,
        )
        freeze_command = RecordedCommand(
            executable=str(self.uv_path),
            arguments=("pip", "freeze", "--python", str(self.env_python)),
            cwd=str(self.checkout),
            environment_overrides=self.freeze_env,
            exit_code=0,
        )
        lines = ("fixture-dep==1", "fixture-pkg==1.0.1")
        self.freeze = FreezeEvidence(
            command=freeze_command,
            lines=lines,
            output_sha256=freeze_output_sha256(lines),
        )
        self.probe = RecordedCommand(
            executable=str(self.env_python),
            arguments=("-I", "-B", "-c", "fixture-import-only-probe"),
            cwd=str(self.checkout),
            environment_overrides=self.probe_env,
            exit_code=0,
        )
        self.imports = (
            ImportEvidence("fixture_dep", str(self.dependency), "fixture-dep", "1"),
            ImportEvidence("fixture_pkg", str(self.source), "fixture-pkg", "1.0.1"),
        )
        self.callables = (
            CallableEvidence(
                binding_id="fixture-checker",
                callable_ref="fixture_pkg:checker",
                source_path=str(self.source),
                source_sha256=file_sha256(self.source),
            ),
        )
        warning = (
            ProvisioningWarning(
                code="PYPROJECT_LOCK_ROOT_VERSION_MISMATCH",
                message="checkout project is 1.0.1 while lock root is 1.0.0",
                blocking=False,
            ),
        ) if tau2 else ()
        checkout_tree = source_tree_manifest_sha256(self.checkout)
        self.receipt = ProvisioningReceipt(
            schema_version=1,
            artifact_type=RUNTIME_PROVISIONING_ARTIFACT_TYPE,
            runtime_id=self.runtime_id,
            benchmark=self.benchmark,
            upstream_version_or_commit="fixture@abc123",
            created_at="2026-08-30T00:00:00Z",
            interpreter=self.interpreter,
            bootstrap=self.bootstrap,
            upstream=UpstreamIdentity(
                checkout_root=str(self.checkout),
                checkout_head="abc123",
                pyproject_path=str(self.pyproject),
                pyproject_sha256=file_sha256(self.pyproject),
                pyproject_version="1.0.1",
                lock_path=str(self.lock),
                lock_sha256=file_sha256(self.lock),
                lock_root_version="1.0.0" if tau2 else "1.0.1",
                tree_manifest_pre_sha256=checkout_tree,
                tree_manifest_post_sha256=checkout_tree,
            ),
            environment=EnvironmentIdentity(
                root=str(self.environment),
                python_executable=str(self.env_python),
                tree_sha256=tree_manifest_sha256(self.environment),
            ),
            sync=self.sync,
            freeze=self.freeze,
            import_probe=self.probe,
            imports=self.imports,
            callable_bindings=self.callables,
            warnings=warning,
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
        self.receipt = replace(
            self.receipt,
            payload_sha256=receipt_payload_sha256(self.receipt),
        )
        self.expectation = RuntimeProvisioningExpectation(
            runtime_id=self.runtime_id,
            benchmark=self.benchmark,
            upstream_version_or_commit="fixture@abc123",
            interpreter=self.interpreter,
            bootstrap=self.bootstrap,
            checkout_root=str(self.checkout),
            checkout_head="abc123",
            pyproject_path=str(self.pyproject),
            pyproject_sha256=file_sha256(self.pyproject),
            pyproject_version="1.0.1",
            lock_path=str(self.lock),
            lock_sha256=file_sha256(self.lock),
            lock_root_version="1.0.0" if tau2 else "1.0.1",
            environment_root=str(self.environment),
            environment_python_executable=str(self.env_python),
            sync_executable=self.sync.executable,
            sync_arguments=self.sync.arguments,
            sync_cwd=self.sync.cwd,
            sync_environment_overrides=self.sync_env,
            freeze_executable=self.freeze.command.executable,
            freeze_arguments=self.freeze.command.arguments,
            freeze_cwd=self.freeze.command.cwd,
            freeze_environment_overrides=self.freeze_env,
            import_probe_executable=self.probe.executable,
            import_probe_arguments=self.probe.arguments,
            import_probe_cwd=self.probe.cwd,
            import_probe_environment_overrides=self.probe_env,
            required_import_modules=("fixture_dep", "fixture_pkg"),
            required_callable_refs=("fixture_pkg:checker",),
            required_warning_codes=(
                ("PYPROJECT_LOCK_ROOT_VERSION_MISMATCH",) if tau2 else ()
            ),
        )


class RuntimeProvisioningTests(unittest.TestCase):
    def test_uv_normalized_freeze_order_is_canonical(self) -> None:
        self.assertTrue(
            freeze_lines_are_canonical(
                ("httpx==0.28.1", "httpx-sse==0.4.0")
            )
        )
        self.assertFalse(
            freeze_lines_are_canonical(
                ("httpx-sse==0.4.0", "httpx==0.28.1")
            )
        )

    def test_dataclass_receipt_still_requires_utc_z_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fixture = RuntimeFixture(Path(temp_dir), tau2=False)
            invalid = replace(
                fixture.receipt,
                created_at="2026-08-30T00:00:00+00:00",
            )
            invalid = replace(
                invalid, payload_sha256=receipt_payload_sha256(invalid)
            )
            with self.assertRaisesRegex(Exception, "RFC 3339 UTC"):
                validate_provisioning_receipt(
                    invalid,
                    expectation=fixture.expectation,
                    verify_live_files=False,
                )

    def test_exact_receipt_validates_live_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = RuntimeFixture(Path(directory))
            validated = validate_provisioning_receipt(
                fixture.receipt, expectation=fixture.expectation
            )
            self.assertTrue(validated.executable)
            self.assertEqual(validated.receipt.runtime_id, fixture.runtime_id)

    def test_live_uv_executable_mutation_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = RuntimeFixture(Path(directory))
            fixture.uv_path.write_bytes(b"mutated-uv")
            with self.assertRaisesRegex(IntegrityError, "live file SHA-256 mismatch"):
                validate_provisioning_receipt(
                    fixture.receipt, expectation=fixture.expectation
                )

    def test_source_manifest_excludes_git_cache_and_venv_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = RuntimeFixture(Path(directory))
            before = source_tree_manifest_sha256(fixture.checkout)
            (fixture.checkout / ".git" / "index").write_bytes(b"changed ignored bytes")
            (fixture.checkout / "__pycache__" / "ignored.pyc").write_bytes(b"changed")
            (fixture.checkout / ".venv" / "ignored").parent.mkdir()
            (fixture.checkout / ".venv" / "ignored").write_bytes(b"ignored")
            self.assertEqual(source_tree_manifest_sha256(fixture.checkout), before)
            validate_provisioning_receipt(
                fixture.receipt, expectation=fixture.expectation
            )
            fixture.source.write_bytes(b"changed source bytes")
            self.assertNotEqual(source_tree_manifest_sha256(fixture.checkout), before)
            with self.assertRaises(IntegrityError):
                validate_provisioning_receipt(
                    fixture.receipt, expectation=fixture.expectation
                )

    def test_tau2_probe_requires_local_cost_map_guard(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = RuntimeFixture(Path(directory), tau2=True)
            validate_provisioning_receipt(
                fixture.receipt, expectation=fixture.expectation
            )
            no_guard_probe = replace(fixture.probe, environment_overrides=())
            receipt = replace(fixture.receipt, import_probe=no_guard_probe)
            receipt = replace(receipt, payload_sha256=receipt_payload_sha256(receipt))
            expectation = replace(
                fixture.expectation, import_probe_environment_overrides=()
            )
            with self.assertRaisesRegex(IntegrityError, "LiteLLM cost-map guard"):
                validate_provisioning_receipt(receipt, expectation=expectation)

    def test_nonzero_task_or_probe_network_count_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = RuntimeFixture(Path(directory))
            for field in ("task_executions", "runtime_probe_network_attempts"):
                with self.subTest(field=field):
                    counts = replace(
                        fixture.receipt.execution_counts, **{field: 1}
                    )
                    receipt = replace(fixture.receipt, execution_counts=counts)
                    receipt = replace(
                        receipt, payload_sha256=receipt_payload_sha256(receipt)
                    )
                    with self.assertRaisesRegex(IntegrityError, "forbidden execution"):
                        validate_provisioning_receipt(
                            receipt,
                            expectation=fixture.expectation,
                            verify_live_files=False,
                        )


if __name__ == "__main__":
    unittest.main()
