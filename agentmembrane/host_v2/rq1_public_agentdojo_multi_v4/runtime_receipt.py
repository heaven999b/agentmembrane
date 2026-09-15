"""Version-isolated runtime expectation and preflight for RQ1 v4.

The dependency lock is identical to the shared AgentDojo 0.1.35 runtime, but
v4 uses its own environment and its own fresh upstream checkout.  Keeping both
roots separate prevents an iCloud placeholder or later v3 source drift from
invalidating a v4 authorization after it is prepared.
"""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import subprocess
from typing import Any, Mapping, Sequence

from ..agentdojo_runtime import (
    AGENTDOJO_REQUIRED_CALLABLES,
    AGENTDOJO_REQUIRED_IMPORTS,
    AGENTDOJO_RUNTIME_ID,
    FROZEN_PYTHON_EXECUTABLE,
    FROZEN_PYTHON_SHA256,
    FROZEN_PYTHON_VERSION,
    agentdojo_import_probe_source,
    agentdojo_runtime_expectation,
)
from ..runtime_provisioning import (
    EnvironmentOverride,
    ProvisioningReceipt,
    RuntimeProvisioningExpectation,
    validate_provisioning_receipt,
)
from ..schema import IntegrityError, canonical_json_bytes


V4_RUNTIME_ENVIRONMENT_NAME = (
    "agentdojo-0.1.35-py3123-lock-395e3d0a5921-rq1v4"
)
V4_RECEIPT_FILENAME = f"{V4_RUNTIME_ENVIRONMENT_NAME}.json"
V4_CHECKOUT_RELATIVE = Path(
    "data/host_boundary_v2/upstream/agentdojo-v4-runtime"
)


def _environment_overrides(
    rows: Sequence[EnvironmentOverride], *, environment_root: Path
) -> tuple[EnvironmentOverride, ...]:
    return tuple(
        replace(row, value=str(environment_root))
        if row.name == "UV_PROJECT_ENVIRONMENT"
        else row
        for row in rows
    )


def v4_runtime_expectation(
    *, repo_root: str | Path
) -> RuntimeProvisioningExpectation:
    root = Path(repo_root).resolve()
    base = agentdojo_runtime_expectation(repo_root=root)
    checkout_root = root / V4_CHECKOUT_RELATIVE
    runtime_root = root / "experiments/host_boundary_v2/runtime_envs"
    environment_root = runtime_root / V4_RUNTIME_ENVIRONMENT_NAME
    environment_python = environment_root / "bin/python"
    probe_source = agentdojo_import_probe_source(
        checkout_root=checkout_root,
        environment_root=environment_root,
    )
    common_overrides = _environment_overrides(
        base.sync_environment_overrides,
        environment_root=environment_root,
    )
    return replace(
        base,
        checkout_root=str(checkout_root),
        pyproject_path=str(checkout_root / "pyproject.toml"),
        lock_path=str(checkout_root / "uv.lock"),
        environment_root=str(environment_root),
        environment_python_executable=str(environment_python),
        sync_arguments=(
            "sync",
            "--frozen",
            "--no-dev",
            "--no-editable",
            "--no-install-project",
            "--python",
            str(FROZEN_PYTHON_EXECUTABLE),
            "--project",
            str(checkout_root),
        ),
        sync_environment_overrides=common_overrides,
        freeze_arguments=("pip", "freeze", "--python", str(environment_python)),
        freeze_environment_overrides=common_overrides,
        import_probe_executable=str(environment_python),
        import_probe_arguments=("-I", "-B", "-c", probe_source),
    )


def _inside(path: str, root: Path) -> bool:
    try:
        Path(path).resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def _normalized_rows(value: Any, *, label: str) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise IntegrityError(f"v4 import probe {label} must be a list")
    rows: list[dict[str, Any]] = []
    for row in value:
        if not isinstance(row, Mapping):
            raise IntegrityError(f"v4 import probe {label} row is not an object")
        item = dict(row)
        canonical_json_bytes(item)
        rows.append(item)
    return tuple(sorted(rows, key=lambda row: canonical_json_bytes(row)))


def validate_v4_runtime_receipt(
    value: Mapping[str, Any] | ProvisioningReceipt,
    *,
    expected_receipt_sha256: str,
    repo_root: str | Path,
) -> dict[str, Any]:
    """Validate live source/environment bytes, then rerun a socket-denied probe."""

    root = Path(repo_root).resolve()
    expectation = v4_runtime_expectation(repo_root=root)
    validated = validate_provisioning_receipt(
        value,
        expectation=expectation,
        expected_receipt_sha256=expected_receipt_sha256,
        verify_live_files=True,
    )
    receipt = validated.receipt
    command = receipt.import_probe
    completed = subprocess.run(
        [command.executable, *command.arguments],
        cwd=command.cwd,
        env={item.name: item.value for item in command.environment_overrides},
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    lines = completed.stdout.splitlines()
    if completed.returncode != 0 or len(lines) != 1:
        raise IntegrityError("v4 socket-denied import probe failed")
    try:
        probe = json.loads(lines[0])
    except json.JSONDecodeError as exc:
        raise IntegrityError("v4 import probe output is not JSON") from exc
    if not isinstance(probe, Mapping):
        raise IntegrityError("v4 import probe output is not an object")
    expected_counts = {
        "task_executions": 0,
        "native_checker_executions": 0,
        "parity_executions": 0,
        "provider_calls": 0,
        "model_calls": 0,
        "api_calls": 0,
    }
    environment_root = Path(expectation.environment_root)
    checkout_root = Path(expectation.checkout_root)
    interpreter_exact = probe.get("interpreter") == {
        "environment_python_executable": expectation.environment_python_executable,
        "base_executable": str(FROZEN_PYTHON_EXECUTABLE),
        "version": FROZEN_PYTHON_VERSION,
        "executable_sha256": FROZEN_PYTHON_SHA256,
        "environment_root": expectation.environment_root,
    }
    live_imports = _normalized_rows(probe.get("imports"), label="imports")
    receipt_imports = _normalized_rows(
        [row.as_json() for row in receipt.imports], label="receipt imports"
    )
    live_bindings = _normalized_rows(
        probe.get("callable_bindings"), label="callable bindings"
    )
    receipt_bindings = _normalized_rows(
        [row.as_json() for row in receipt.callable_bindings],
        label="receipt callable bindings",
    )
    imports_versioned_and_rooted = True
    for row in live_imports:
        module = row.get("module")
        expected = AGENTDOJO_REQUIRED_IMPORTS.get(module)
        origin = row.get("origin")
        origin_root = (
            checkout_root / "src"
            if isinstance(module, str)
            and (module == "agentdojo" or module.startswith("agentdojo."))
            else environment_root
        )
        if (
            expected is None
            or (row.get("package"), row.get("version")) != expected
            or not isinstance(origin, str)
            or not _inside(origin, origin_root)
        ):
            imports_versioned_and_rooted = False
    expected_bindings = _normalized_rows(
        [
            {
                "binding_id": binding_id,
                "callable_ref": callable_ref,
                "source_path": str((checkout_root / source_path).resolve()),
                "source_sha256": source_sha256,
            }
            for binding_id, callable_ref, source_path, source_sha256 in AGENTDOJO_REQUIRED_CALLABLES
        ],
        label="expected callable bindings",
    )
    checks = {
        "receipt_validated": True,
        "runtime_id_exact": probe.get("runtime_id") == AGENTDOJO_RUNTIME_ID,
        "network_denied_and_unused": probe.get("network_attempts") == 0,
        "zero_task_checker_provider_execution": probe.get("execution_counts")
        == expected_counts,
        "interpreter_exact": interpreter_exact,
        "receipt_bound_imports_exact": live_imports == receipt_imports,
        "dependency_versions_and_origins_exact": imports_versioned_and_rooted,
        "receipt_bound_callable_bindings_exact": (
            live_bindings == receipt_bindings == expected_bindings
        ),
    }
    if not all(checks.values()):
        failed = sorted(key for key, passed in checks.items() if not passed)
        raise IntegrityError(f"v4 runtime import preflight failed: {failed}")
    result = {
        "schema_version": 1,
        "artifact_type": "agentmembrane_rq1_v4_import_only_runtime_preflight",
        "runtime_id": AGENTDOJO_RUNTIME_ID,
        "runtime_environment_name": V4_RUNTIME_ENVIRONMENT_NAME,
        "receipt_sha256": validated.receipt_sha256,
        "checks": checks,
        "import_executable": True,
        "checker_dispatchers_importable": True,
        "task_executions": 0,
        "checker_executions": 0,
        "provider_calls": 0,
        "model_calls": 0,
        "network_attempts": 0,
        "public_or_formal_readiness": False,
    }
    canonical_json_bytes(result)
    return result


__all__ = [
    "V4_CHECKOUT_RELATIVE",
    "V4_RECEIPT_FILENAME",
    "V4_RUNTIME_ENVIRONMENT_NAME",
    "v4_runtime_expectation",
    "validate_v4_runtime_receipt",
]
