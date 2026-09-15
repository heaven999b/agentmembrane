"""Read-only validation for exact project-local native-runtime receipts.

This module never creates an environment, downloads a wheel, imports an
upstream package, or invokes a checker.  It validates a canonical receipt and
recomputes live byte identities so a stale or internally consistent fabrication
cannot make an import-only preflight executable.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Mapping, Sequence

from .schema import IntegrityError, SchemaError, canonical_json_bytes, sha256_bytes


RUNTIME_PROVISIONING_SCHEMA_VERSION = 1
RUNTIME_PROVISIONING_ARTIFACT_TYPE = (
    "agentmembrane_native_runtime_provisioning_receipt"
)
EXPECTED_UV_VERSION = "0.8.17"
SAFE_ENVIRONMENT_OVERRIDE_NAMES = frozenset(
    {
        "PATH",
        "PYTHONDONTWRITEBYTECODE",
        "UV_NO_CONFIG",
        "UV_PYTHON_DOWNLOADS",
        "UV_LINK_MODE",
        "UV_CACHE_DIR",
        "UV_PROJECT_ENVIRONMENT",
        "LITELLM_LOCAL_MODEL_COST_MAP",
    }
)
SOURCE_TREE_EXCLUDED_DIRECTORY_NAMES = frozenset({".git", ".venv", "__pycache__"})


@dataclass(frozen=True)
class InterpreterIdentity:
    executable: str
    version: str
    executable_sha256: str

    def as_json(self) -> dict[str, str]:
        return {
            "executable": self.executable,
            "version": self.version,
            "executable_sha256": self.executable_sha256,
        }


@dataclass(frozen=True)
class UvBootstrapIdentity:
    version: str
    wheel_path: str
    wheel_sha256: str
    bootstrap_root: str
    uv_executable: str
    uv_executable_sha256: str

    def as_json(self) -> dict[str, str]:
        return {
            "version": self.version,
            "wheel_path": self.wheel_path,
            "wheel_sha256": self.wheel_sha256,
            "bootstrap_root": self.bootstrap_root,
            "uv_executable": self.uv_executable,
            "uv_executable_sha256": self.uv_executable_sha256,
        }


@dataclass(frozen=True)
class EnvironmentOverride:
    name: str
    value: str

    def as_json(self) -> dict[str, str]:
        return {"name": self.name, "value": self.value}


@dataclass(frozen=True)
class RecordedCommand:
    executable: str
    arguments: tuple[str, ...]
    cwd: str
    environment_overrides: tuple[EnvironmentOverride, ...]
    exit_code: int

    def as_json(self) -> dict[str, Any]:
        return {
            "executable": self.executable,
            "arguments": list(self.arguments),
            "cwd": self.cwd,
            "environment_overrides": [
                item.as_json() for item in self.environment_overrides
            ],
            "exit_code": self.exit_code,
        }


@dataclass(frozen=True)
class UpstreamIdentity:
    checkout_root: str
    checkout_head: str
    pyproject_path: str
    pyproject_sha256: str
    pyproject_version: str
    lock_path: str
    lock_sha256: str
    lock_root_version: str
    tree_manifest_pre_sha256: str
    tree_manifest_post_sha256: str

    def as_json(self) -> dict[str, str]:
        return {
            "checkout_root": self.checkout_root,
            "checkout_head": self.checkout_head,
            "pyproject_path": self.pyproject_path,
            "pyproject_sha256": self.pyproject_sha256,
            "pyproject_version": self.pyproject_version,
            "lock_path": self.lock_path,
            "lock_sha256": self.lock_sha256,
            "lock_root_version": self.lock_root_version,
            "tree_manifest_pre_sha256": self.tree_manifest_pre_sha256,
            "tree_manifest_post_sha256": self.tree_manifest_post_sha256,
        }


@dataclass(frozen=True)
class EnvironmentIdentity:
    root: str
    python_executable: str
    tree_sha256: str

    def as_json(self) -> dict[str, str]:
        return {
            "root": self.root,
            "python_executable": self.python_executable,
            "tree_sha256": self.tree_sha256,
        }


@dataclass(frozen=True)
class FreezeEvidence:
    command: RecordedCommand
    lines: tuple[str, ...]
    output_sha256: str

    def as_json(self) -> dict[str, Any]:
        return {
            "command": self.command.as_json(),
            "lines": list(self.lines),
            "output_sha256": self.output_sha256,
        }


@dataclass(frozen=True)
class ImportEvidence:
    module: str
    origin: str
    package: str
    version: str

    def as_json(self) -> dict[str, str]:
        return {
            "module": self.module,
            "origin": self.origin,
            "package": self.package,
            "version": self.version,
        }


@dataclass(frozen=True)
class CallableEvidence:
    binding_id: str
    callable_ref: str
    source_path: str
    source_sha256: str

    def as_json(self) -> dict[str, str]:
        return {
            "binding_id": self.binding_id,
            "callable_ref": self.callable_ref,
            "source_path": self.source_path,
            "source_sha256": self.source_sha256,
        }


@dataclass(frozen=True)
class ProvisioningWarning:
    code: str
    message: str
    blocking: bool

    def as_json(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "blocking": self.blocking}


@dataclass(frozen=True)
class ExecutionCounters:
    task_executions: int
    parity_executions: int
    native_checker_executions: int
    provider_calls: int
    model_calls: int
    api_calls: int
    provisioning_downloads: int
    runtime_probe_network_attempts: int

    def as_json(self) -> dict[str, int]:
        return {
            "task_executions": self.task_executions,
            "parity_executions": self.parity_executions,
            "native_checker_executions": self.native_checker_executions,
            "provider_calls": self.provider_calls,
            "model_calls": self.model_calls,
            "api_calls": self.api_calls,
            "provisioning_downloads": self.provisioning_downloads,
            "runtime_probe_network_attempts": self.runtime_probe_network_attempts,
        }


@dataclass(frozen=True)
class RunAuthorizations:
    task_execution: bool
    checker_parity: bool
    calibration: bool
    formal_run: bool
    public_run: bool
    provider_calls: bool
    model_calls: bool
    api_calls: bool

    def as_json(self) -> dict[str, bool]:
        return {
            "task_execution": self.task_execution,
            "checker_parity": self.checker_parity,
            "calibration": self.calibration,
            "formal_run": self.formal_run,
            "public_run": self.public_run,
            "provider_calls": self.provider_calls,
            "model_calls": self.model_calls,
            "api_calls": self.api_calls,
        }


@dataclass(frozen=True)
class ProvisioningReceipt:
    schema_version: int
    artifact_type: str
    runtime_id: str
    benchmark: str
    upstream_version_or_commit: str
    created_at: str
    interpreter: InterpreterIdentity
    bootstrap: UvBootstrapIdentity
    upstream: UpstreamIdentity
    environment: EnvironmentIdentity
    sync: RecordedCommand
    freeze: FreezeEvidence
    import_probe: RecordedCommand
    imports: tuple[ImportEvidence, ...]
    callable_bindings: tuple[CallableEvidence, ...]
    warnings: tuple[ProvisioningWarning, ...]
    execution_counts: ExecutionCounters
    authorizations: RunAuthorizations
    payload_sha256: str

    def payload_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "artifact_type": self.artifact_type,
            "runtime_id": self.runtime_id,
            "benchmark": self.benchmark,
            "upstream_version_or_commit": self.upstream_version_or_commit,
            "created_at": self.created_at,
            "interpreter": self.interpreter.as_json(),
            "bootstrap": self.bootstrap.as_json(),
            "upstream": self.upstream.as_json(),
            "environment": self.environment.as_json(),
            "sync": self.sync.as_json(),
            "freeze": self.freeze.as_json(),
            "import_probe": self.import_probe.as_json(),
            "imports": [item.as_json() for item in self.imports],
            "callable_bindings": [item.as_json() for item in self.callable_bindings],
            "warnings": [item.as_json() for item in self.warnings],
            "execution_counts": self.execution_counts.as_json(),
            "authorizations": self.authorizations.as_json(),
        }

    def as_json(self) -> dict[str, Any]:
        return {**self.payload_json(), "payload_sha256": self.payload_sha256}


@dataclass(frozen=True)
class RuntimeProvisioningExpectation:
    runtime_id: str
    benchmark: str
    upstream_version_or_commit: str
    interpreter: InterpreterIdentity
    bootstrap: UvBootstrapIdentity
    checkout_root: str
    checkout_head: str
    pyproject_path: str
    pyproject_sha256: str
    pyproject_version: str
    lock_path: str
    lock_sha256: str
    lock_root_version: str
    environment_root: str
    environment_python_executable: str
    sync_executable: str
    sync_arguments: tuple[str, ...]
    sync_cwd: str
    sync_environment_overrides: tuple[EnvironmentOverride, ...]
    freeze_executable: str
    freeze_arguments: tuple[str, ...]
    freeze_cwd: str
    freeze_environment_overrides: tuple[EnvironmentOverride, ...]
    import_probe_executable: str
    import_probe_arguments: tuple[str, ...]
    import_probe_cwd: str
    import_probe_environment_overrides: tuple[EnvironmentOverride, ...]
    required_import_modules: tuple[str, ...]
    required_callable_refs: tuple[str, ...]
    required_warning_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ValidatedProvisioningReceipt:
    receipt: ProvisioningReceipt
    receipt_sha256: str

    @property
    def executable(self) -> bool:
        return True

    def as_json(self) -> dict[str, Any]:
        return {
            "receipt": self.receipt.as_json(),
            "receipt_sha256": self.receipt_sha256,
            "executable": True,
        }


def file_sha256(path: Path | str) -> str:
    """Hash one regular file, following a final symlink if present."""

    candidate = Path(path)
    if not candidate.is_file():
        raise IntegrityError(f"required file is missing: {candidate}")
    try:
        return sha256_bytes(candidate.read_bytes())
    except OSError as exc:
        raise IntegrityError(f"cannot hash required file {candidate}: {exc}") from exc


def tree_manifest(
    root: Path | str,
    *,
    excluded_directory_names: frozenset[str] = frozenset(),
) -> tuple[dict[str, str], ...]:
    """Return a deterministic byte/symlink manifest without following links."""

    base = Path(root)
    if not base.is_dir():
        raise IntegrityError(f"tree root is missing: {base}")
    rows: list[dict[str, str]] = []
    try:
        for directory, directory_names, file_names in os.walk(
            base, topdown=True, followlinks=False
        ):
            directory_names.sort()
            file_names.sort()
            parent = Path(directory)
            directory_names[:] = [
                name for name in directory_names
                if name not in excluded_directory_names
            ]
            symlink_directories = [
                name for name in directory_names if (parent / name).is_symlink()
            ]
            for name in symlink_directories:
                path = parent / name
                rows.append(
                    {
                        "path": path.relative_to(base).as_posix(),
                        "type": "symlink",
                        "target": os.readlink(path),
                    }
                )
                directory_names.remove(name)
            for name in file_names:
                path = parent / name
                relative = path.relative_to(base).as_posix()
                mode = path.lstat().st_mode
                if stat.S_ISLNK(mode):
                    rows.append(
                        {"path": relative, "type": "symlink", "target": os.readlink(path)}
                    )
                elif stat.S_ISREG(mode):
                    rows.append(
                        {"path": relative, "type": "file", "sha256": file_sha256(path)}
                    )
                else:
                    raise IntegrityError(f"unsupported tree entry type: {path}")
    except OSError as exc:
        raise IntegrityError(f"cannot walk tree {base}: {exc}") from exc
    return tuple(sorted(rows, key=lambda row: row["path"]))


def tree_manifest_sha256(root: Path | str) -> str:
    return sha256_bytes(canonical_json_bytes(list(tree_manifest(root))))


def source_tree_manifest(root: Path | str) -> tuple[dict[str, str], ...]:
    """Hash checkout source bytes, excluding VCS and mutable Python/env state."""

    return tree_manifest(
        root,
        excluded_directory_names=SOURCE_TREE_EXCLUDED_DIRECTORY_NAMES,
    )


def source_tree_manifest_sha256(root: Path | str) -> str:
    return sha256_bytes(canonical_json_bytes(list(source_tree_manifest(root))))


def freeze_output_sha256(lines: Sequence[str]) -> str:
    if any(not isinstance(line, str) or "\n" in line or "\r" in line for line in lines):
        raise SchemaError("freeze lines must be newline-free strings")
    payload = (("\n".join(lines) + "\n") if lines else "").encode("utf-8")
    return sha256_bytes(payload)


def freeze_lines_are_canonical(lines: Sequence[str]) -> bool:
    """Match uv's normalized-distribution ordering without rewriting output.

    Raw lexical ordering is wrong for valid adjacent names such as ``httpx``
    and ``httpx-sse`` because ``=`` sorts after ``-``.  ``uv pip freeze`` orders
    by normalized package identity, so validate that exact order instead.
    """

    parsed: list[tuple[str, str]] = []
    for line in lines:
        if not isinstance(line, str) or line.count("==") != 1:
            return False
        name, version = line.split("==", 1)
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name)
            or not version
            or any(character.isspace() for character in version)
        ):
            return False
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        parsed.append((normalized, line))
    return len(lines) == len(set(lines)) and parsed == sorted(parsed)


def receipt_payload_sha256(receipt: ProvisioningReceipt) -> str:
    return sha256_bytes(canonical_json_bytes(receipt.payload_json()))


def receipt_sha256(receipt: ProvisioningReceipt) -> str:
    return sha256_bytes(canonical_json_bytes(receipt.as_json()))


def _exact(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SchemaError(f"{label} must be an object")
    missing = sorted(fields - set(value))
    unknown = sorted(set(value) - fields)
    if missing or unknown:
        raise SchemaError(f"{label} fields invalid: missing={missing}, unknown={unknown}")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SchemaError(f"{label} must be a nonempty string")
    return value


def _sha(value: Any, label: str) -> str:
    text = _string(value, label)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise SchemaError(f"{label} must be a lowercase SHA-256")
    return text


def _absolute(value: Any, label: str) -> str:
    text = _string(value, label)
    if not Path(text).is_absolute():
        raise SchemaError(f"{label} must be an absolute path")
    return text


def _strings(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise SchemaError(f"{label} must be a list or tuple")
    result = tuple(_string(item, f"{label} item") for item in value)
    return result


def _timestamp(value: Any, label: str) -> str:
    text = _string(value, label)
    if not text.endswith("Z") or "T" not in text:
        raise SchemaError(f"{label} must be an RFC 3339 UTC timestamp")
    try:
        datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise SchemaError(f"{label} is invalid: {exc}") from exc
    return text


def _parse_interpreter(value: Any, label: str) -> InterpreterIdentity:
    item = _exact(value, {"executable", "version", "executable_sha256"}, label)
    return InterpreterIdentity(
        executable=_absolute(item["executable"], f"{label}.executable"),
        version=_string(item["version"], f"{label}.version"),
        executable_sha256=_sha(
            item["executable_sha256"], f"{label}.executable_sha256"
        ),
    )


def _parse_bootstrap(value: Any) -> UvBootstrapIdentity:
    item = _exact(
        value,
        {
            "version", "wheel_path", "wheel_sha256", "bootstrap_root",
            "uv_executable", "uv_executable_sha256",
        },
        "receipt.bootstrap",
    )
    return UvBootstrapIdentity(
        version=_string(item["version"], "bootstrap.version"),
        wheel_path=_absolute(item["wheel_path"], "bootstrap.wheel_path"),
        wheel_sha256=_sha(item["wheel_sha256"], "bootstrap.wheel_sha256"),
        bootstrap_root=_absolute(item["bootstrap_root"], "bootstrap.bootstrap_root"),
        uv_executable=_absolute(item["uv_executable"], "bootstrap.uv_executable"),
        uv_executable_sha256=_sha(
            item["uv_executable_sha256"], "bootstrap.uv_executable_sha256"
        ),
    )


def _parse_environment_overrides(value: Any, label: str) -> tuple[EnvironmentOverride, ...]:
    if not isinstance(value, (list, tuple)):
        raise SchemaError(f"{label} must be a list or tuple")
    result: list[EnvironmentOverride] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        item = _exact(raw, {"name", "value"}, f"{label}[{index}]")
        name = _string(item["name"], f"{label}[{index}].name")
        override_value = _string(item["value"], f"{label}[{index}].value")
        if name not in SAFE_ENVIRONMENT_OVERRIDE_NAMES:
            raise IntegrityError(f"receipt records forbidden ambient environment key: {name}")
        if name in seen:
            raise IntegrityError(f"duplicate command environment override: {name}")
        seen.add(name)
        result.append(EnvironmentOverride(name=name, value=override_value))
    if tuple(item.name for item in result) != tuple(sorted(seen)):
        raise IntegrityError(f"{label} must be ordered by environment name")
    return tuple(result)


def _parse_command(value: Any, label: str) -> RecordedCommand:
    item = _exact(
        value,
        {"executable", "arguments", "cwd", "environment_overrides", "exit_code"},
        label,
    )
    exit_code = item["exit_code"]
    if not isinstance(exit_code, int) or isinstance(exit_code, bool):
        raise SchemaError(f"{label}.exit_code must be an integer")
    return RecordedCommand(
        executable=_absolute(item["executable"], f"{label}.executable"),
        arguments=_strings(item["arguments"], f"{label}.arguments"),
        cwd=_absolute(item["cwd"], f"{label}.cwd"),
        environment_overrides=_parse_environment_overrides(
            item["environment_overrides"], f"{label}.environment_overrides"
        ),
        exit_code=exit_code,
    )


def _parse_upstream(value: Any) -> UpstreamIdentity:
    fields = {
        "checkout_root", "checkout_head", "pyproject_path", "pyproject_sha256",
        "pyproject_version", "lock_path", "lock_sha256", "lock_root_version",
        "tree_manifest_pre_sha256", "tree_manifest_post_sha256",
    }
    item = _exact(value, fields, "receipt.upstream")
    return UpstreamIdentity(
        checkout_root=_absolute(item["checkout_root"], "upstream.checkout_root"),
        checkout_head=_string(item["checkout_head"], "upstream.checkout_head"),
        pyproject_path=_absolute(item["pyproject_path"], "upstream.pyproject_path"),
        pyproject_sha256=_sha(item["pyproject_sha256"], "upstream.pyproject_sha256"),
        pyproject_version=_string(item["pyproject_version"], "upstream.pyproject_version"),
        lock_path=_absolute(item["lock_path"], "upstream.lock_path"),
        lock_sha256=_sha(item["lock_sha256"], "upstream.lock_sha256"),
        lock_root_version=_string(item["lock_root_version"], "upstream.lock_root_version"),
        tree_manifest_pre_sha256=_sha(
            item["tree_manifest_pre_sha256"], "upstream.tree_manifest_pre_sha256"
        ),
        tree_manifest_post_sha256=_sha(
            item["tree_manifest_post_sha256"], "upstream.tree_manifest_post_sha256"
        ),
    )


def _parse_environment(value: Any) -> EnvironmentIdentity:
    item = _exact(value, {"root", "python_executable", "tree_sha256"}, "environment")
    return EnvironmentIdentity(
        root=_absolute(item["root"], "environment.root"),
        python_executable=_absolute(
            item["python_executable"], "environment.python_executable"
        ),
        tree_sha256=_sha(item["tree_sha256"], "environment.tree_sha256"),
    )


def _parse_freeze(value: Any) -> FreezeEvidence:
    item = _exact(value, {"command", "lines", "output_sha256"}, "receipt.freeze")
    return FreezeEvidence(
        command=_parse_command(item["command"], "receipt.freeze.command"),
        lines=_strings(item["lines"], "receipt.freeze.lines"),
        output_sha256=_sha(item["output_sha256"], "receipt.freeze.output_sha256"),
    )


def _parse_imports(value: Any) -> tuple[ImportEvidence, ...]:
    if not isinstance(value, (list, tuple)):
        raise SchemaError("receipt.imports must be a list")
    rows: list[ImportEvidence] = []
    for index, raw in enumerate(value):
        item = _exact(raw, {"module", "origin", "package", "version"}, f"imports[{index}]")
        rows.append(
            ImportEvidence(
                module=_string(item["module"], f"imports[{index}].module"),
                origin=_absolute(item["origin"], f"imports[{index}].origin"),
                package=_string(item["package"], f"imports[{index}].package"),
                version=_string(item["version"], f"imports[{index}].version"),
            )
        )
    return tuple(rows)


def _parse_callables(value: Any) -> tuple[CallableEvidence, ...]:
    if not isinstance(value, (list, tuple)):
        raise SchemaError("receipt.callable_bindings must be a list")
    rows: list[CallableEvidence] = []
    for index, raw in enumerate(value):
        item = _exact(
            raw,
            {"binding_id", "callable_ref", "source_path", "source_sha256"},
            f"callable_bindings[{index}]",
        )
        rows.append(
            CallableEvidence(
                binding_id=_string(item["binding_id"], f"bindings[{index}].binding_id"),
                callable_ref=_string(item["callable_ref"], f"bindings[{index}].callable_ref"),
                source_path=_absolute(item["source_path"], f"bindings[{index}].source_path"),
                source_sha256=_sha(
                    item["source_sha256"], f"bindings[{index}].source_sha256"
                ),
            )
        )
    return tuple(rows)


def _parse_warnings(value: Any) -> tuple[ProvisioningWarning, ...]:
    if not isinstance(value, (list, tuple)):
        raise SchemaError("receipt.warnings must be a list")
    rows: list[ProvisioningWarning] = []
    for index, raw in enumerate(value):
        item = _exact(raw, {"code", "message", "blocking"}, f"warnings[{index}]")
        if not isinstance(item["blocking"], bool):
            raise SchemaError(f"warnings[{index}].blocking must be boolean")
        rows.append(
            ProvisioningWarning(
                code=_string(item["code"], f"warnings[{index}].code"),
                message=_string(item["message"], f"warnings[{index}].message"),
                blocking=item["blocking"],
            )
        )
    return tuple(rows)


def _parse_execution_counts(value: Any) -> ExecutionCounters:
    fields = {
        "task_executions", "parity_executions", "native_checker_executions",
        "provider_calls", "model_calls", "api_calls", "provisioning_downloads",
        "runtime_probe_network_attempts",
    }
    item = _exact(value, fields, "receipt.execution_counts")
    for field in fields:
        if (
            not isinstance(item[field], int)
            or isinstance(item[field], bool)
            or item[field] < 0
        ):
            raise SchemaError(f"execution_counts.{field} must be a nonnegative integer")
    return ExecutionCounters(**{field: item[field] for field in fields})


def _parse_authorizations(value: Any) -> RunAuthorizations:
    fields = {
        "task_execution", "checker_parity", "calibration", "formal_run",
        "public_run", "provider_calls", "model_calls", "api_calls",
    }
    item = _exact(value, fields, "receipt.authorizations")
    for field in fields:
        if not isinstance(item[field], bool):
            raise SchemaError(f"authorizations.{field} must be boolean")
    return RunAuthorizations(**{field: item[field] for field in fields})


def provisioning_receipt_from_mapping(value: Mapping[str, Any]) -> ProvisioningReceipt:
    fields = {
        "schema_version", "artifact_type", "runtime_id", "benchmark",
        "upstream_version_or_commit", "created_at", "interpreter", "bootstrap",
        "upstream", "environment", "sync", "freeze", "import_probe", "imports",
        "callable_bindings", "warnings", "execution_counts", "authorizations",
        "payload_sha256",
    }
    item = _exact(value, fields, "provisioning receipt")
    return ProvisioningReceipt(
        schema_version=item["schema_version"],
        artifact_type=item["artifact_type"],
        runtime_id=_string(item["runtime_id"], "receipt.runtime_id"),
        benchmark=_string(item["benchmark"], "receipt.benchmark"),
        upstream_version_or_commit=_string(
            item["upstream_version_or_commit"], "receipt.upstream_version_or_commit"
        ),
        created_at=_timestamp(item["created_at"], "receipt.created_at"),
        interpreter=_parse_interpreter(item["interpreter"], "receipt.interpreter"),
        bootstrap=_parse_bootstrap(item["bootstrap"]),
        upstream=_parse_upstream(item["upstream"]),
        environment=_parse_environment(item["environment"]),
        sync=_parse_command(item["sync"], "receipt.sync"),
        freeze=_parse_freeze(item["freeze"]),
        import_probe=_parse_command(item["import_probe"], "receipt.import_probe"),
        imports=_parse_imports(item["imports"]),
        callable_bindings=_parse_callables(item["callable_bindings"]),
        warnings=_parse_warnings(item["warnings"]),
        execution_counts=_parse_execution_counts(item["execution_counts"]),
        authorizations=_parse_authorizations(item["authorizations"]),
        payload_sha256=_sha(item["payload_sha256"], "receipt.payload_sha256"),
    )


def _command_matches(
    command: RecordedCommand,
    *,
    executable: str,
    arguments: tuple[str, ...],
    cwd: str,
    environment_overrides: tuple[EnvironmentOverride, ...],
) -> bool:
    return (
        command.executable == executable
        and command.arguments == arguments
        and command.cwd == cwd
        and command.environment_overrides == environment_overrides
        and command.exit_code == 0
    )


def _inside(path: str, roots: Sequence[str]) -> bool:
    candidate = Path(path).resolve()
    for root in roots:
        try:
            candidate.relative_to(Path(root).resolve())
            return True
        except ValueError:
            continue
    return False


def _validate_live_bytes(receipt: ProvisioningReceipt) -> None:
    checks = (
        (receipt.interpreter.executable, receipt.interpreter.executable_sha256),
        (receipt.bootstrap.wheel_path, receipt.bootstrap.wheel_sha256),
        (
            receipt.bootstrap.uv_executable,
            receipt.bootstrap.uv_executable_sha256,
        ),
        (receipt.upstream.pyproject_path, receipt.upstream.pyproject_sha256),
        (receipt.upstream.lock_path, receipt.upstream.lock_sha256),
    )
    for path, expected in checks:
        actual = file_sha256(path)
        if actual != expected:
            raise IntegrityError(f"live file SHA-256 mismatch: {path}")
    current_upstream = source_tree_manifest_sha256(receipt.upstream.checkout_root)
    if current_upstream != receipt.upstream.tree_manifest_post_sha256:
        raise IntegrityError("live upstream checkout tree differs from receipt")
    current_environment = tree_manifest_sha256(receipt.environment.root)
    if current_environment != receipt.environment.tree_sha256:
        raise IntegrityError("live runtime environment tree differs from receipt")
    for imported in receipt.imports:
        if not Path(imported.origin).is_file():
            raise IntegrityError(f"recorded import origin is missing: {imported.origin}")
    for binding in receipt.callable_bindings:
        if file_sha256(binding.source_path) != binding.source_sha256:
            raise IntegrityError(
                f"live callable source differs from receipt: {binding.binding_id}"
            )


def validate_provisioning_receipt(
    value: Mapping[str, Any] | ProvisioningReceipt,
    *,
    expectation: RuntimeProvisioningExpectation,
    expected_receipt_sha256: str | None = None,
    verify_live_files: bool = True,
) -> ValidatedProvisioningReceipt:
    """Fail closed unless receipt, expectation, and current bytes all agree."""

    if not isinstance(expectation, RuntimeProvisioningExpectation):
        raise TypeError("expectation must be RuntimeProvisioningExpectation")
    receipt = (
        value if isinstance(value, ProvisioningReceipt)
        else provisioning_receipt_from_mapping(value)
    )
    if receipt.schema_version != RUNTIME_PROVISIONING_SCHEMA_VERSION:
        raise SchemaError("runtime receipt schema_version must equal 1")
    if receipt.artifact_type != RUNTIME_PROVISIONING_ARTIFACT_TYPE:
        raise SchemaError("invalid runtime receipt artifact_type")
    _timestamp(receipt.created_at, "receipt.created_at")
    if receipt.bootstrap.version != EXPECTED_UV_VERSION:
        raise IntegrityError("runtime receipt uv version must equal 0.8.17")
    computed_payload = receipt_payload_sha256(receipt)
    if receipt.payload_sha256 != computed_payload:
        raise IntegrityError("runtime receipt payload_sha256 mismatch")
    computed_receipt = receipt_sha256(receipt)
    if expected_receipt_sha256 is not None:
        if _sha(expected_receipt_sha256, "expected_receipt_sha256") != computed_receipt:
            raise IntegrityError("runtime receipt SHA-256 differs from exact binding")

    for field in ("runtime_id", "benchmark", "upstream_version_or_commit"):
        if getattr(receipt, field) != getattr(expectation, field):
            raise IntegrityError(f"runtime receipt differs from expectation: {field}")
    if receipt.interpreter != expectation.interpreter:
        raise IntegrityError("runtime receipt interpreter identity mismatch")
    if receipt.bootstrap != expectation.bootstrap:
        raise IntegrityError("runtime receipt uv bootstrap identity mismatch")
    if not _inside(
        receipt.bootstrap.uv_executable, (receipt.bootstrap.bootstrap_root,)
    ):
        raise IntegrityError("uv executable escapes the exact bootstrap environment")
    upstream_expected = {
        "checkout_root": expectation.checkout_root,
        "checkout_head": expectation.checkout_head,
        "pyproject_path": expectation.pyproject_path,
        "pyproject_sha256": expectation.pyproject_sha256,
        "pyproject_version": expectation.pyproject_version,
        "lock_path": expectation.lock_path,
        "lock_sha256": expectation.lock_sha256,
        "lock_root_version": expectation.lock_root_version,
    }
    for field, expected in upstream_expected.items():
        if getattr(receipt.upstream, field) != expected:
            raise IntegrityError(f"runtime receipt upstream identity mismatch: {field}")
    if (
        receipt.upstream.tree_manifest_pre_sha256
        != receipt.upstream.tree_manifest_post_sha256
    ):
        raise IntegrityError("upstream checkout changed during provisioning")
    if (
        receipt.environment.root != expectation.environment_root
        or receipt.environment.python_executable
        != expectation.environment_python_executable
    ):
        raise IntegrityError("runtime receipt environment identity mismatch")
    if not _command_matches(
        receipt.sync,
        executable=expectation.sync_executable,
        arguments=expectation.sync_arguments,
        cwd=expectation.sync_cwd,
        environment_overrides=expectation.sync_environment_overrides,
    ):
        raise IntegrityError("runtime sync command differs from frozen expectation")
    if not _command_matches(
        receipt.freeze.command,
        executable=expectation.freeze_executable,
        arguments=expectation.freeze_arguments,
        cwd=expectation.freeze_cwd,
        environment_overrides=expectation.freeze_environment_overrides,
    ):
        raise IntegrityError("runtime freeze command differs from frozen expectation")
    if not _command_matches(
        receipt.import_probe,
        executable=expectation.import_probe_executable,
        arguments=expectation.import_probe_arguments,
        cwd=expectation.import_probe_cwd,
        environment_overrides=expectation.import_probe_environment_overrides,
    ):
        raise IntegrityError("runtime import probe differs from frozen expectation")
    if (
        not freeze_lines_are_canonical(receipt.freeze.lines)
        or receipt.freeze.output_sha256 != freeze_output_sha256(receipt.freeze.lines)
    ):
        raise IntegrityError("runtime freeze output is not canonical or hash-bound")

    modules = tuple(item.module for item in receipt.imports)
    if modules != tuple(sorted(set(modules))):
        raise IntegrityError("runtime imports must be unique and sorted by module")
    if set(modules) != set(expectation.required_import_modules):
        raise IntegrityError("runtime receipt import coverage mismatch")
    allowed_origin_roots = (receipt.environment.root, receipt.upstream.checkout_root)
    if any(not _inside(item.origin, allowed_origin_roots) for item in receipt.imports):
        raise IntegrityError("runtime import origin escapes environment/checkout roots")
    callable_refs = tuple(item.callable_ref for item in receipt.callable_bindings)
    if callable_refs != tuple(sorted(set(callable_refs))):
        raise IntegrityError("runtime callable bindings must be unique and sorted")
    if set(callable_refs) != set(expectation.required_callable_refs):
        raise IntegrityError("runtime receipt callable coverage mismatch")
    if any(
        not _inside(item.source_path, allowed_origin_roots)
        for item in receipt.callable_bindings
    ):
        raise IntegrityError("runtime callable source escapes environment/checkout roots")

    warning_codes = tuple(item.code for item in receipt.warnings)
    if warning_codes != tuple(sorted(set(warning_codes))):
        raise IntegrityError("runtime warnings must be unique and sorted")
    if set(warning_codes) != set(expectation.required_warning_codes):
        raise IntegrityError("runtime receipt warning coverage mismatch")
    if any(item.blocking for item in receipt.warnings):
        raise IntegrityError("blocking runtime warning prevents executable receipt")
    if (
        receipt.upstream.pyproject_version != receipt.upstream.lock_root_version
        and "PYPROJECT_LOCK_ROOT_VERSION_MISMATCH" not in warning_codes
    ):
        raise IntegrityError("pyproject/lock root-version discrepancy is unrecorded")

    zero_fields = (
        "task_executions", "parity_executions", "native_checker_executions",
        "provider_calls", "model_calls", "api_calls", "runtime_probe_network_attempts",
    )
    if any(getattr(receipt.execution_counts, field) != 0 for field in zero_fields):
        raise IntegrityError("runtime receipt records forbidden execution or probe network use")
    if any(receipt.authorizations.as_json().values()):
        raise IntegrityError("runtime receipt must keep every run authorization false")
    probe_env = {
        item.name: item.value for item in receipt.import_probe.environment_overrides
    }
    if receipt.benchmark == "tau2-bench" and probe_env.get(
        "LITELLM_LOCAL_MODEL_COST_MAP"
    ) != "True":
        raise IntegrityError("tau2 import probe lacks local LiteLLM cost-map guard")

    if verify_live_files:
        _validate_live_bytes(receipt)
    return ValidatedProvisioningReceipt(
        receipt=receipt,
        receipt_sha256=computed_receipt,
    )


def load_provisioning_receipt(
    path: Path | str,
    *,
    expectation: RuntimeProvisioningExpectation,
    expected_receipt_sha256: str | None = None,
    verify_live_files: bool = True,
) -> ValidatedProvisioningReceipt:
    candidate = Path(path)
    try:
        payload = candidate.read_bytes()
        value = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"cannot load runtime receipt {candidate}: {exc}") from exc
    if not isinstance(value, Mapping):
        raise SchemaError("runtime receipt top-level value must be an object")
    canonical = canonical_json_bytes(dict(value))
    if payload != canonical:
        raise IntegrityError("runtime receipt file is not exact canonical JSON")
    actual_file_sha256 = sha256_bytes(payload)
    if expected_receipt_sha256 is not None and actual_file_sha256 != _sha(
        expected_receipt_sha256, "expected_receipt_sha256"
    ):
        raise IntegrityError("runtime receipt file SHA-256 differs from binding")
    validated = validate_provisioning_receipt(
        value,
        expectation=expectation,
        expected_receipt_sha256=actual_file_sha256,
        verify_live_files=verify_live_files,
    )
    return validated


__all__ = [
    "CallableEvidence",
    "EXPECTED_UV_VERSION",
    "EnvironmentIdentity",
    "EnvironmentOverride",
    "ExecutionCounters",
    "FreezeEvidence",
    "ImportEvidence",
    "InterpreterIdentity",
    "ProvisioningReceipt",
    "ProvisioningWarning",
    "RUNTIME_PROVISIONING_ARTIFACT_TYPE",
    "RUNTIME_PROVISIONING_SCHEMA_VERSION",
    "RecordedCommand",
    "RunAuthorizations",
    "RuntimeProvisioningExpectation",
    "SAFE_ENVIRONMENT_OVERRIDE_NAMES",
    "SOURCE_TREE_EXCLUDED_DIRECTORY_NAMES",
    "UpstreamIdentity",
    "UvBootstrapIdentity",
    "ValidatedProvisioningReceipt",
    "file_sha256",
    "freeze_output_sha256",
    "freeze_lines_are_canonical",
    "load_provisioning_receipt",
    "provisioning_receipt_from_mapping",
    "receipt_payload_sha256",
    "receipt_sha256",
    "source_tree_manifest",
    "source_tree_manifest_sha256",
    "tree_manifest",
    "tree_manifest_sha256",
    "validate_provisioning_receipt",
]
