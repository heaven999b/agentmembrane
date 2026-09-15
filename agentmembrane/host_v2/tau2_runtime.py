"""Receipt-bound, import-only preflight for the frozen tau2 runtime.

This module never provisions an environment and never constructs or evaluates a
tau2 task.  It describes the one authorized frozen environment, validates a
shared provisioning receipt, and (only after that receipt is valid) repeats a
network-denied import/callable-origin probe.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import subprocess
import tomllib
from typing import Any, Callable, Mapping, Sequence


TAU2_RUNTIME_ID = "tau2-py3123-lock-62d3a8c4807b"
TAU2_BENCHMARK = "tau2-bench"
TAU2_VERSION = "1.0.1"
TAU2_LOCK_ROOT_VERSION = "1.0.0"
TAU2_COMMIT = "a2c024725189473d2d7cea3a5cfdbcc67478e41f"
TAU2_PIN = f"{TAU2_VERSION}@{TAU2_COMMIT}"

TAU2_PYPROJECT_SHA256 = (
    "23d59670b4ad7bbc0f57420fd9643a8d9188c24abe4f29c9c965544d8cc4cb8d"
)
TAU2_LOCK_SHA256 = (
    "62d3a8c4807b89e85703b3c03f2c21048a2da9736ca83d9af6f61adc74ac5314"
)
TAU2_INTERPRETER = Path(
    "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12"
)
TAU2_INTERPRETER_VERSION = "3.12.3"
TAU2_INTERPRETER_SHA256 = (
    "80ee2dd97bc26259d4e30853336f72ad38aa4aa0531bb196cc444d899422689d"
)
UV_VERSION = "0.8.17"
UV_WHEEL_FILENAME = "uv-0.8.17-py3-none-macosx_11_0_arm64.whl"
UV_WHEEL_SHA256 = (
    "b009f1ec9e28de00f76814ad66e35aaae82c98a0f24015de51943dcd1c2a1895"
)
UV_EXECUTABLE_SHA256 = (
    "16b94f4af20f485089c841eadb6280cf5d71af17ff1982fd798d41fcf9523031"
)
TAU2_FREEZE_LINE_COUNT = 74
TAU2_FREEZE_SHA256 = (
    "cdef58070fb2870a13477ad78a9e02009fa0edac3892fcfb61161094b62c1631"
)

TAU2_VERSION_MISMATCH_WARNING_CODE = "PYPROJECT_LOCK_ROOT_VERSION_MISMATCH"
TAU2_VERSION_MISMATCH_WARNING_MESSAGE = (
    "tau2 checkout pyproject version 1.0.1 differs from lock root version 1.0.0; "
    "the unchanged lock was accepted by uv sync --frozen"
)
TAU2_LITELLM_LOCAL_COST_ENV = "LITELLM_LOCAL_MODEL_COST_MAP"
TAU2_LITELLM_LOCAL_COST_VALUE = "True"
TAU2_RUNTIME_PREFLIGHT_SCHEMA_VERSION = 1
TAU2_RUNTIME_PREFLIGHT_ARTIFACT_TYPE = (
    "agentmembrane_tau2_import_only_runtime_preflight"
)

TAU2_REQUIRED_IMPORTS: Mapping[str, tuple[str, str]] = {
    "addict": ("addict", "2.4.0"),
    "deepdiff": ("deepdiff", "8.6.2"),
    "docstring_parser": ("docstring-parser", "0.17.0"),
    "dotenv": ("python-dotenv", "1.2.1"),
    "fastapi": ("fastapi", "0.121.2"),
    "httpx": ("httpx", "0.28.1"),
    "litellm": ("litellm", "1.81.11"),
    "loguru": ("loguru", "0.7.3"),
    "numpy": ("numpy", "2.3.5"),
    "pandas": ("pandas", "2.3.3"),
    "psutil": ("psutil", "7.1.3"),
    "pydantic": ("pydantic", "2.12.4"),
    "requests": ("requests", "2.32.5"),
    "rich": ("rich", "14.2.0"),
    "tabulate": ("tabulate", "0.9.0"),
    "tau2": ("tau2", TAU2_VERSION),
    "tau2.data_model.message": ("tau2", TAU2_VERSION),
    "tau2.data_model.tasks": ("tau2", TAU2_VERSION),
    "tau2.domains.airline.environment": ("tau2", TAU2_VERSION),
    "tau2.domains.retail.environment": ("tau2", TAU2_VERSION),
    "tau2.domains.telecom.environment": ("tau2", TAU2_VERSION),
    "tau2.evaluator.evaluator_action": ("tau2", TAU2_VERSION),
    "tau2.evaluator.evaluator_communicate": ("tau2", TAU2_VERSION),
    "tau2.evaluator.evaluator_env": ("tau2", TAU2_VERSION),
    "tenacity": ("tenacity", "9.1.2"),
    "toml": ("toml", "0.10.2"),
    "typer": ("typer", "0.20.0"),
    "typing_extensions": ("typing-extensions", "4.15.0"),
    "uvicorn": ("uvicorn", "0.38.0"),
    "yaml": ("PyYAML", "6.0.3"),
}
TAU2_REQUIRED_IMPORT_MODULES = tuple(sorted(TAU2_REQUIRED_IMPORTS))

TAU2_CALLABLE_BINDINGS = (
    (
        "tau2-v1.0.1-environment-utility",
        "tau2.evaluator.evaluator_env.EnvironmentEvaluator.calculate_reward",
        "src/tau2/evaluator/evaluator_env.py",
        "b53ebfe6b0b06d7a2071b5f9dd03ee6ca8ac6000b0ef44f3bd345b346c30d8ac",
    ),
    (
        "tau2-v1.0.1-action-utility",
        "tau2.evaluator.evaluator_action.ActionEvaluator.calculate_reward",
        "src/tau2/evaluator/evaluator_action.py",
        "4347ec90fd09db73b9f7e46515220363f91f0c3b12aeddf7ece83346f49227f8",
    ),
    (
        "tau2-v1.0.1-communicate-utility",
        (
            "tau2.evaluator.evaluator_communicate."
            "CommunicateEvaluator.calculate_reward"
        ),
        "src/tau2/evaluator/evaluator_communicate.py",
        "7a082f91c746b84cc37c6994eb6ff78f297222fd067503a4cc86d45750696507",
    ),
)


@dataclass(frozen=True)
class Tau2RuntimeBlocker:
    """One deterministic reason the import-only runtime remains unavailable."""

    code: str
    message: str

    def as_json(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class Tau2RuntimePreflight:
    """Immutable receipt-bound import-only result, never parity evidence."""

    schema_version: int
    artifact_type: str
    runtime_id: str
    benchmark: str
    upstream_version_or_commit: str
    receipt_sha256: str | None
    imports: tuple[Mapping[str, str], ...]
    callable_bindings: tuple[Mapping[str, str], ...]
    checks: Mapping[str, bool]
    blockers: tuple[Tau2RuntimeBlocker, ...]
    warnings: tuple[Mapping[str, Any], ...]
    import_executable: bool
    checker_dispatchers_importable: bool
    native_checker_parity_demonstrated: bool
    task_executions: int
    checker_executions: int
    parity_executions: int
    network_attempts: int
    public_or_formal_readiness: bool

    @property
    def executable(self) -> bool:
        """Compatibility alias scoped only to receipt-bound imports."""

        return self.import_executable

    def as_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "artifact_type": self.artifact_type,
            "runtime_id": self.runtime_id,
            "benchmark": self.benchmark,
            "upstream_version_or_commit": self.upstream_version_or_commit,
            "receipt_sha256": self.receipt_sha256,
            "scope": "import_only",
            "imports": [dict(item) for item in self.imports],
            "callable_bindings": [dict(item) for item in self.callable_bindings],
            "checks": {key: self.checks[key] for key in sorted(self.checks)},
            "blockers": [item.as_json() for item in self.blockers],
            "warnings": [dict(item) for item in self.warnings],
            "import_executable": self.import_executable,
            "executable": self.executable,
            "checker_dispatchers_importable": self.checker_dispatchers_importable,
            "native_checker_parity_demonstrated": (
                self.native_checker_parity_demonstrated
            ),
            "task_executions": self.task_executions,
            "checker_executions": self.checker_executions,
            "parity_executions": self.parity_executions,
            "network_attempts": self.network_attempts,
            "public_or_formal_readiness": self.public_or_formal_readiness,
        }


def _default_repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _paths(repo_root: Path) -> dict[str, Path]:
    runtime_root = repo_root / "experiments" / "host_boundary_v2" / "runtime_envs"
    bootstrap_root = runtime_root / "bootstrap-uv-0.8.17-py312"
    environment_root = runtime_root / TAU2_RUNTIME_ID
    checkout_root = (
        repo_root / "data" / "host_boundary_v2" / "upstream" / "tau2-bench"
    )
    return {
        "repo_root": repo_root,
        "runtime_root": runtime_root,
        "bootstrap_root": bootstrap_root,
        "uv_executable": bootstrap_root / "bin" / "uv",
        "wheel_path": runtime_root / "wheelhouse" / "uv-0.8.17" / UV_WHEEL_FILENAME,
        "environment_root": environment_root,
        "environment_python": environment_root / "bin" / "python",
        "checkout_root": checkout_root,
        "source_root": checkout_root / "src",
        "pyproject_path": checkout_root / "pyproject.toml",
        "lock_path": checkout_root / "uv.lock",
    }


def _import_probe_source(checkout_root: Path, environment_root: Path) -> str:
    """Return the exact network-denied import probe source recorded in receipts."""

    imports_required = repr(dict(TAU2_REQUIRED_IMPORTS))
    bindings = repr(TAU2_CALLABLE_BINDINGS)
    source_root = repr(str((checkout_root / "src").resolve()))
    checkout = repr(str(checkout_root.resolve()))
    environment = repr(str(environment_root.resolve()))
    return f'''import hashlib
import importlib
import importlib.metadata
import inspect
import json
import os
from pathlib import Path
import socket
import sys
import tomllib

SOURCE_ROOT = Path({source_root})
CHECKOUT_ROOT = Path({checkout})
ENVIRONMENT_ROOT = Path({environment})
IMPORTS_REQUIRED = {imports_required}
BINDINGS = {bindings}
network_attempts = 0

def _deny_network(*args, **kwargs):
    global network_attempts
    network_attempts += 1
    raise RuntimeError("network access is forbidden during tau2 import preflight")

class _NetworkDeniedSocket(socket.socket):
    def connect(self, *args, **kwargs):
        return _deny_network(*args, **kwargs)
    def connect_ex(self, *args, **kwargs):
        return _deny_network(*args, **kwargs)

socket.socket = _NetworkDeniedSocket
socket.create_connection = _deny_network
socket.getaddrinfo = _deny_network

if os.environ.get("{TAU2_LITELLM_LOCAL_COST_ENV}") != "{TAU2_LITELLM_LOCAL_COST_VALUE}":
    raise RuntimeError("the local LiteLLM model-cost map guard is required")
sys.path.insert(0, str(SOURCE_ROOT))
project = tomllib.loads((CHECKOUT_ROOT / "pyproject.toml").read_text("utf-8"))
project_version = project["project"]["version"]

imports = []
loaded = {{}}
for module_name in sorted(IMPORTS_REQUIRED):
    package, frozen_version = IMPORTS_REQUIRED[module_name]
    module = importlib.import_module(module_name)
    loaded[module_name] = module
    origin = Path(module.__file__ or "").resolve()
    version = (
        project_version
        if package == "tau2"
        else importlib.metadata.version(package)
    )
    if version != frozen_version:
        raise RuntimeError(f"{{package}} has the wrong locked version")
    imports.append({{
        "module": module_name,
        "origin": str(origin),
        "package": package,
        "version": version,
    }})

callable_bindings = []
for binding_id, callable_ref, relative_source, expected_sha256 in BINDINGS:
    module_name = callable_ref.rsplit(".", 2)[0]
    class_name, attribute_name = callable_ref.rsplit(".", 2)[1:]
    target = getattr(getattr(loaded[module_name], class_name), attribute_name)
    if not callable(target):
        raise RuntimeError(f"{{callable_ref}} is not callable")
    source_path = Path(inspect.getsourcefile(target) or "").resolve()
    source_sha256 = hashlib.sha256(source_path.read_bytes()).hexdigest()
    if source_path != (CHECKOUT_ROOT / relative_source).resolve():
        raise RuntimeError(f"{{callable_ref}} has the wrong source origin")
    if source_sha256 != expected_sha256:
        raise RuntimeError(f"{{callable_ref}} has the wrong source hash")
    callable_bindings.append({{
        "binding_id": binding_id,
        "callable_ref": callable_ref,
        "source_path": str(source_path),
        "source_sha256": source_sha256,
    }})

result = {{
    "schema_version": 1,
    "probe_kind": "tau2_receipt_bound_import_only",
    "python_executable": sys.executable,
    "python_version": ".".join(str(part) for part in sys.version_info[:3]),
    "python_executable_sha256": hashlib.sha256(
        Path(sys.executable).read_bytes()
    ).hexdigest(),
    "prefix": sys.prefix,
    "base_prefix": sys.base_prefix,
    "isolated": sys.flags.isolated == 1,
    "no_user_site": sys.flags.no_user_site == 1,
    "dont_write_bytecode": sys.flags.dont_write_bytecode == 1,
    "sys_path": list(sys.path),
    "imports": sorted(imports, key=lambda row: row["module"]),
    "callable_bindings": sorted(callable_bindings, key=lambda row: row["binding_id"]),
    "network_attempts": network_attempts,
    "task_executions": 0,
    "native_checker_executions": 0,
    "parity_executions": 0,
}}
print(json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
'''


def tau2_import_probe_arguments(
    *, repo_root: Path | None = None
) -> tuple[str, ...]:
    """Return the exact arguments for the authorized import-only probe."""

    paths = _paths(Path(repo_root or _default_repo_root()).resolve())
    source = _import_probe_source(paths["checkout_root"], paths["environment_root"])
    return ("-I", "-B", "-c", source)


def tau2_runtime_expectation(
    *, repo_root: str | Path | None = None
) -> Any:
    """Build the exact shared provisioning-receipt expectation for tau2."""

    from .runtime_provisioning import (
        EnvironmentOverride,
        InterpreterIdentity,
        RuntimeProvisioningExpectation,
        UvBootstrapIdentity,
    )

    root = Path(repo_root or _default_repo_root()).resolve()
    paths = _paths(root)
    return RuntimeProvisioningExpectation(
        runtime_id=TAU2_RUNTIME_ID,
        benchmark=TAU2_BENCHMARK,
        upstream_version_or_commit=TAU2_PIN,
        interpreter=InterpreterIdentity(
            executable=str(TAU2_INTERPRETER),
            version=TAU2_INTERPRETER_VERSION,
            executable_sha256=TAU2_INTERPRETER_SHA256,
        ),
        bootstrap=UvBootstrapIdentity(
            version=UV_VERSION,
            wheel_path=str(paths["wheel_path"]),
            wheel_sha256=UV_WHEEL_SHA256,
            bootstrap_root=str(paths["bootstrap_root"]),
            uv_executable=str(paths["uv_executable"]),
            uv_executable_sha256=UV_EXECUTABLE_SHA256,
        ),
        checkout_root=str(paths["checkout_root"]),
        checkout_head=TAU2_COMMIT,
        pyproject_path=str(paths["pyproject_path"]),
        pyproject_sha256=TAU2_PYPROJECT_SHA256,
        pyproject_version=TAU2_VERSION,
        lock_path=str(paths["lock_path"]),
        lock_sha256=TAU2_LOCK_SHA256,
        lock_root_version=TAU2_LOCK_ROOT_VERSION,
        environment_root=str(paths["environment_root"]),
        environment_python_executable=str(paths["environment_python"]),
        sync_executable=str(paths["uv_executable"]),
        sync_arguments=(
            "sync",
            "--frozen",
            "--no-dev",
            "--no-editable",
            "--no-install-project",
            "--python",
            str(TAU2_INTERPRETER),
            "--project",
            str(paths["checkout_root"]),
        ),
        sync_cwd=str(root),
        sync_environment_overrides=tuple(
            EnvironmentOverride(name=name, value=value)
            for name, value in sorted(
                {
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "UV_CACHE_DIR": str(paths["runtime_root"] / "uv-cache"),
                    "UV_LINK_MODE": "copy",
                    "UV_NO_CONFIG": "1",
                    "UV_PROJECT_ENVIRONMENT": str(paths["environment_root"]),
                    "UV_PYTHON_DOWNLOADS": "never",
                }.items()
            )
        ),
        freeze_executable=str(paths["uv_executable"]),
        freeze_arguments=(
            "pip",
            "freeze",
            "--python",
            str(paths["environment_python"]),
        ),
        freeze_cwd=str(root),
        freeze_environment_overrides=tuple(
            EnvironmentOverride(name=name, value=value)
            for name, value in sorted(
                {
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "UV_CACHE_DIR": str(paths["runtime_root"] / "uv-cache"),
                    "UV_LINK_MODE": "copy",
                    "UV_NO_CONFIG": "1",
                    "UV_PROJECT_ENVIRONMENT": str(paths["environment_root"]),
                    "UV_PYTHON_DOWNLOADS": "never",
                }.items()
            )
        ),
        import_probe_executable=str(paths["environment_python"]),
        import_probe_arguments=tau2_import_probe_arguments(repo_root=root),
        # Some pinned tau2/LiteLLM imports append the process cwd to sys.path.
        # Use the already byte-bound environment root so that this behavior
        # cannot widen imports to the repository or another ambient directory.
        import_probe_cwd=str(paths["environment_root"]),
        import_probe_environment_overrides=tuple(
            EnvironmentOverride(name=name, value=value)
            for name, value in sorted(
                {
                    "LITELLM_LOCAL_MODEL_COST_MAP": "True",
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "PYTHONDONTWRITEBYTECODE": "1",
                }.items()
            )
        ),
        required_import_modules=TAU2_REQUIRED_IMPORT_MODULES,
        required_callable_refs=tuple(
            sorted(binding[1] for binding in TAU2_CALLABLE_BINDINGS)
        ),
        required_warning_codes=(TAU2_VERSION_MISMATCH_WARNING_CODE,),
    )


def _sha256_file(path: Path) -> str | None:
    try:
        if not path.is_file():
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def _run_import_probe(
    *, executable: Path, arguments: tuple[str, ...], cwd: Path
) -> Mapping[str, Any]:
    """Run only the frozen import probe, with no ambient credentials or config."""

    environment = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "LITELLM_LOCAL_MODEL_COST_MAP": "True",
    }
    completed = subprocess.run(
        [str(executable), *arguments],
        cwd=str(cwd),
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        raise RuntimeError("tau2 import-only probe exited nonzero")
    stdout = completed.stdout.strip()
    if not stdout or "\n" in stdout:
        raise RuntimeError("tau2 import-only probe did not emit one JSON record")
    try:
        value = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("tau2 import-only probe emitted invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise RuntimeError("tau2 import-only probe output must be an object")
    return value


def _default_probe_runner(command: Any) -> Mapping[str, Any]:
    return _run_import_probe(
        executable=Path(command.executable),
        arguments=tuple(command.arguments),
        cwd=Path(command.cwd),
    )


def _mapping_rows(rows: Sequence[Any]) -> tuple[dict[str, str], ...]:
    result: list[dict[str, str]] = []
    for row in rows:
        value = row.as_json() if hasattr(row, "as_json") else row
        if not isinstance(value, Mapping) or not all(
            isinstance(key, str) and isinstance(item, str)
            for key, item in value.items()
        ):
            raise TypeError("evidence row is not a string mapping")
        result.append(dict(value))
    return tuple(sorted(result, key=lambda item: tuple(sorted(item.items()))))


def _is_within(path_text: str, root: Path) -> bool:
    try:
        Path(path_text).resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def _environment_override_rows(command: Any) -> tuple[tuple[str, str], ...]:
    rows: list[tuple[str, str]] = []
    for row in command.environment_overrides:
        value = row.as_json() if hasattr(row, "as_json") else row
        if not isinstance(value, Mapping):
            raise TypeError("environment override is not an object")
        name = value.get("name")
        item = value.get("value")
        if not isinstance(name, str) or not isinstance(item, str):
            raise TypeError("environment override must contain strings")
        rows.append((name, item))
    return tuple(sorted(rows))


def _lock_semantics_exact(checkout_root: Path) -> bool:
    """Verify the frozen project and complete lock-graph shape."""

    try:
        project = tomllib.loads(
            (checkout_root / "pyproject.toml").read_text(encoding="utf-8")
        )
        lock = tomllib.loads(
            (checkout_root / "uv.lock").read_text(encoding="utf-8")
        )
        packages = lock["package"]
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, KeyError, TypeError):
        return False
    if project.get("project", {}).get("name") != "tau2":
        return False
    if project["project"].get("version") != TAU2_VERSION:
        return False
    if project["project"].get("requires-python") != ">=3.12,<3.14":
        return False
    if (
        lock.get("version") != 1
        or lock.get("revision") != 3
        or lock.get("requires-python") != ">=3.12, <3.14"
        or not isinstance(packages, list)
        or len(packages) != 174
    ):
        return False
    registry = [row for row in packages if "registry" in row.get("source", {})]
    editable = [row for row in packages if "editable" in row.get("source", {})]
    if len(registry) != 173 or len(editable) != 1:
        return False
    if any("git" in row.get("source", {}) for row in packages):
        return False
    root = editable[0]
    if (
        root.get("name") != "tau2"
        or root.get("version") != TAU2_LOCK_ROOT_VERSION
        or root.get("source") != {"editable": "."}
    ):
        return False
    for package in registry:
        artifacts = []
        if "sdist" in package:
            artifacts.append(package["sdist"])
        artifacts.extend(package.get("wheels", []))
        if not artifacts or any(
            not str(artifact.get("hash", "")).startswith("sha256:")
            for artifact in artifacts
        ):
            return False
    return True


def _environment_python_exact(environment_python: Path) -> bool:
    try:
        return (
            environment_python.is_file()
            and environment_python.resolve() == TAU2_INTERPRETER.resolve()
            and _sha256_file(environment_python) == TAU2_INTERPRETER_SHA256
        )
    except (OSError, ValueError):
        return False


def _failed_preflight(
    *, code: str, message: str, receipt_sha256: str | None = None
) -> Tau2RuntimePreflight:
    return Tau2RuntimePreflight(
        schema_version=TAU2_RUNTIME_PREFLIGHT_SCHEMA_VERSION,
        artifact_type=TAU2_RUNTIME_PREFLIGHT_ARTIFACT_TYPE,
        runtime_id=TAU2_RUNTIME_ID,
        benchmark=TAU2_BENCHMARK,
        upstream_version_or_commit=TAU2_PIN,
        receipt_sha256=receipt_sha256,
        imports=(),
        callable_bindings=(),
        checks={"receipt_validated": False},
        blockers=(Tau2RuntimeBlocker(code=code, message=message),),
        warnings=(),
        import_executable=False,
        checker_dispatchers_importable=False,
        native_checker_parity_demonstrated=False,
        task_executions=0,
        checker_executions=0,
        parity_executions=0,
        network_attempts=0,
        public_or_formal_readiness=False,
    )


def validate_tau2_runtime_receipt(
    value: Mapping[str, Any] | Any,
    *,
    expected_receipt_sha256: str,
    repo_root: str | Path | None = None,
    import_probe: Callable[[Any], Mapping[str, Any]] | None = None,
    file_sha256: Callable[[Path], str | None] = _sha256_file,
    environment_tree_sha256: Callable[[Path], str] | None = None,
    source_tree_sha256: Callable[[Path], str] | None = None,
    lock_semantics: Callable[[Path], bool] = _lock_semantics_exact,
    environment_python_validator: Callable[[Path], bool] = (
        _environment_python_exact
    ),
) -> Tau2RuntimePreflight:
    """Validate exact receipt/live bytes, then repeat only the import probe.

    The external receipt SHA-256 is mandatory.  No tau2 import is attempted
    until the shared receipt, interpreter, lock graph, environment tree, source
    tree, and callable bytes all pass.  Injectable read-only probes are solely
    synthetic-test seams and never provision or execute a task.
    """

    from .runtime_provisioning import (
        source_tree_manifest_sha256,
        tree_manifest_sha256,
        validate_provisioning_receipt,
    )

    if (
        not isinstance(expected_receipt_sha256, str)
        or len(expected_receipt_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in expected_receipt_sha256
        )
    ):
        return _failed_preflight(
            code="TAU2_RECEIPT_HASH_REQUIRED",
            message="an exact external receipt SHA-256 is required",
        )
    expectation = tau2_runtime_expectation(repo_root=repo_root)
    try:
        validated = validate_provisioning_receipt(
            value,
            expectation=expectation,
            expected_receipt_sha256=expected_receipt_sha256,
            verify_live_files=False,
        )
    except Exception as exc:
        label = str(exc).lower()
        code = (
            "TAU2_RECEIPT_HASH_MISMATCH"
            if "sha" in label or "hash" in label
            else "TAU2_RECEIPT_INVALID"
        )
        return _failed_preflight(
            code=code,
            message=(
                "shared provisioning receipt validation failed "
                f"({type(exc).__name__})"
            ),
        )

    receipt = validated.receipt
    root = Path(repo_root or _default_repo_root()).resolve()
    paths = _paths(root)
    checkout_root = paths["checkout_root"]
    environment_root = paths["environment_root"]
    environment_tree = environment_tree_sha256 or tree_manifest_sha256
    source_tree = source_tree_sha256 or source_tree_manifest_sha256
    blockers: list[Tau2RuntimeBlocker] = []

    def block(code: str, message: str) -> None:
        blockers.append(Tau2RuntimeBlocker(code=code, message=message))

    checks: dict[str, bool] = {"receipt_validated": True}
    byte_locks = (
        (TAU2_INTERPRETER, TAU2_INTERPRETER_SHA256),
        (paths["wheel_path"], UV_WHEEL_SHA256),
        (paths["uv_executable"], UV_EXECUTABLE_SHA256),
        (paths["pyproject_path"], TAU2_PYPROJECT_SHA256),
        (paths["lock_path"], TAU2_LOCK_SHA256),
    )
    bytes_exact = True
    for path, expected in byte_locks:
        try:
            matches = file_sha256(path) == expected
        except (OSError, ValueError):
            matches = False
        bytes_exact = bytes_exact and matches
    checks["frozen_file_hashes_exact"] = bytes_exact
    if not bytes_exact:
        block(
            "TAU2_FROZEN_FILE_HASH_MISMATCH",
            "interpreter, uv, wheel, pyproject, or lock bytes differ",
        )

    environment_python_exact = False
    try:
        environment_python_exact = environment_python_validator(
            paths["environment_python"]
        )
    except (OSError, ValueError):
        environment_python_exact = False
    checks["environment_python_exact"] = environment_python_exact
    if not environment_python_exact:
        block(
            "TAU2_ENVIRONMENT_PYTHON_MISMATCH",
            "environment Python does not resolve to the frozen interpreter",
        )

    lock_semantics_exact = lock_semantics(checkout_root)
    checks["lock_graph_exact"] = lock_semantics_exact
    if not lock_semantics_exact:
        block(
            "TAU2_LOCK_GRAPH_MISMATCH",
            "tau2 project or complete uv lock-graph semantics changed",
        )

    warning_exact = (
        len(receipt.warnings) == 1
        and receipt.warnings[0].code == TAU2_VERSION_MISMATCH_WARNING_CODE
        and receipt.warnings[0].message == TAU2_VERSION_MISMATCH_WARNING_MESSAGE
        and receipt.warnings[0].blocking is False
        and receipt.sync.exit_code == 0
    )
    checks["pyproject_lock_mismatch_warning_exact"] = warning_exact
    if not warning_exact:
        block(
            "TAU2_VERSION_MISMATCH_WARNING_INVALID",
            "the 1.0.1/1.0.0 discrepancy or frozen-sync acceptance is unbound",
        )

    freeze_exact = (
        len(receipt.freeze.lines) == TAU2_FREEZE_LINE_COUNT
        and receipt.freeze.output_sha256 == TAU2_FREEZE_SHA256
        and all(not line.lower().startswith("tau2==") for line in receipt.freeze.lines)
    )
    checks["freeze_exact_no_project_install"] = freeze_exact
    if not freeze_exact:
        block(
            "TAU2_FREEZE_MISMATCH",
            "freeze output differs or tau2 was installed despite --no-install-project",
        )

    probe_environment_exact = False
    try:
        probe_environment_exact = _environment_override_rows(
            receipt.import_probe
        ) == (
            ("LITELLM_LOCAL_MODEL_COST_MAP", "True"),
            ("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
            ("PYTHONDONTWRITEBYTECODE", "1"),
        )
    except (TypeError, ValueError):
        probe_environment_exact = False
    checks["local_cost_map_and_sanitized_probe_environment"] = (
        probe_environment_exact
    )
    if not probe_environment_exact:
        block(
            "TAU2_IMPORT_ENVIRONMENT_UNSAFE",
            "the isolated import probe lacks the exact local-cost-map guard",
        )

    environment_exact_before = False
    source_exact_before = False
    try:
        environment_exact_before = (
            environment_tree(environment_root) == receipt.environment.tree_sha256
        )
    except (OSError, ValueError):
        environment_exact_before = False
    try:
        source_exact_before = (
            source_tree(checkout_root)
            == receipt.upstream.tree_manifest_post_sha256
        )
    except (OSError, ValueError):
        source_exact_before = False
    checks["environment_tree_exact_before_import"] = environment_exact_before
    checks["upstream_tree_exact_before_import"] = source_exact_before
    if not environment_exact_before:
        block(
            "TAU2_ENVIRONMENT_TREE_MISMATCH",
            "live environment differs from the receipt-bound tree",
        )
    if not source_exact_before:
        block(
            "TAU2_UPSTREAM_TREE_MISMATCH",
            "live upstream differs from the receipt-bound source manifest",
        )

    callable_bytes_exact = True
    for _, _, relative_source, expected_hash in TAU2_CALLABLE_BINDINGS:
        try:
            matches = file_sha256(checkout_root / relative_source) == expected_hash
        except (OSError, ValueError):
            matches = False
        callable_bytes_exact = callable_bytes_exact and matches
    checks["callable_source_bytes_exact"] = callable_bytes_exact
    if not callable_bytes_exact:
        block(
            "TAU2_CALLABLE_SOURCE_MISMATCH",
            "one or more native utility callable sources changed",
        )

    live_probe: Mapping[str, Any] | None = None
    if not blockers:
        try:
            live_probe = (import_probe or _default_probe_runner)(receipt.import_probe)
        except Exception as exc:
            if isinstance(exc, ModuleNotFoundError) and isinstance(exc.name, str):
                block(
                    f"TAU2_DEPENDENCY_MISSING:{exc.name}",
                    f"isolated import-only probe lacks module {exc.name}",
                )
            else:
                block(
                    "TAU2_IMPORT_PROBE_FAILED",
                    f"isolated import-only probe failed ({type(exc).__name__})",
                )

    environment_exact_after = False
    source_exact_after = False
    if live_probe is not None:
        try:
            environment_exact_after = (
                environment_tree(environment_root)
                == receipt.environment.tree_sha256
            )
        except (OSError, ValueError):
            environment_exact_after = False
        try:
            source_exact_after = (
                source_tree(checkout_root)
                == receipt.upstream.tree_manifest_post_sha256
            )
        except (OSError, ValueError):
            source_exact_after = False
    checks["environment_tree_exact_after_import"] = environment_exact_after
    checks["upstream_tree_exact_after_import"] = source_exact_after
    if live_probe is not None and not environment_exact_after:
        block(
            "TAU2_IMPORT_MUTATED_ENVIRONMENT",
            "import-only probe changed the frozen environment tree",
        )
    if live_probe is not None and not source_exact_after:
        block(
            "TAU2_IMPORT_MUTATED_UPSTREAM",
            "import-only probe changed the frozen upstream source tree",
        )

    try:
        receipt_imports = _mapping_rows(receipt.imports)
        receipt_bindings = _mapping_rows(receipt.callable_bindings)
    except (TypeError, ValueError):
        receipt_imports = ()
        receipt_bindings = ()
        block(
            "TAU2_RECEIPT_EVIDENCE_INVALID",
            "receipt import or callable evidence is malformed",
        )

    live_imports: tuple[dict[str, str], ...] = ()
    live_bindings: tuple[dict[str, str], ...] = ()
    live_interpreter_exact = False
    live_scope_exact = False
    sys_path_exact = False
    if live_probe is not None:
        try:
            live_interpreter_exact = (
                live_probe.get("python_executable")
                == str(paths["environment_python"])
                and live_probe.get("python_version") == TAU2_INTERPRETER_VERSION
                and live_probe.get("python_executable_sha256")
                == TAU2_INTERPRETER_SHA256
                and live_probe.get("prefix") == str(environment_root)
                and live_probe.get("base_prefix")
                == str(TAU2_INTERPRETER.parent.parent)
                and live_probe.get("isolated") is True
                and live_probe.get("no_user_site") is True
                and live_probe.get("dont_write_bytecode") is True
            )
            live_scope_exact = (
                live_probe.get("schema_version") == 1
                and live_probe.get("probe_kind")
                == "tau2_receipt_bound_import_only"
                and live_probe.get("network_attempts") == 0
                and live_probe.get("task_executions") == 0
                and live_probe.get("native_checker_executions") == 0
                and live_probe.get("parity_executions") == 0
            )
            raw_sys_path = live_probe["sys_path"]
            if not isinstance(raw_sys_path, list) or not all(
                isinstance(item, str) and item for item in raw_sys_path
            ):
                raise TypeError("sys_path")
            allowed_roots = (
                paths["source_root"],
                environment_root,
                TAU2_INTERPRETER.parent.parent,
            )
            sys_path_exact = (
                raw_sys_path[0] == str(paths["source_root"])
                and raw_sys_path.count(str(paths["source_root"])) == 1
                and all(
                    any(_is_within(item, allowed) for allowed in allowed_roots)
                    for item in raw_sys_path
                )
            )
            raw_imports = live_probe["imports"]
            raw_bindings = live_probe["callable_bindings"]
            if not isinstance(raw_imports, Sequence) or isinstance(raw_imports, str):
                raise TypeError("imports")
            if not isinstance(raw_bindings, Sequence) or isinstance(
                raw_bindings, str
            ):
                raise TypeError("callable_bindings")
            live_imports = _mapping_rows(raw_imports)
            live_bindings = _mapping_rows(raw_bindings)
        except (KeyError, TypeError, ValueError):
            block(
                "TAU2_IMPORT_PROBE_INVALID",
                "isolated import-only probe emitted malformed evidence",
            )

    checks["live_interpreter_exact"] = live_interpreter_exact
    checks["live_probe_import_only_scope_exact"] = live_scope_exact
    checks["isolated_sys_path_exact"] = sys_path_exact
    if live_probe is not None and not live_interpreter_exact:
        block(
            "TAU2_LIVE_INTERPRETER_MISMATCH",
            "live probe did not use the frozen interpreter and environment",
        )
    if live_probe is not None and not live_scope_exact:
        block(
            "TAU2_IMPORT_PROBE_SCOPE_MISMATCH",
            "live probe identity, execution counters, or network count differ",
        )
    if live_probe is not None and not sys_path_exact:
        block(
            "TAU2_SYS_PATH_MISMATCH",
            "isolated import path escapes checkout, environment, or base stdlib",
        )

    imports_exact = bool(live_imports) and live_imports == receipt_imports
    versions_exact = bool(live_imports)
    origins_exact = bool(live_imports)
    for row in live_imports:
        module = row.get("module", "")
        expected = TAU2_REQUIRED_IMPORTS.get(module)
        if expected is None or (row.get("package"), row.get("version")) != expected:
            versions_exact = False
        expected_origin_root = (
            paths["source_root"]
            if module == "tau2" or module.startswith("tau2.")
            else environment_root
        )
        if not _is_within(row.get("origin", ""), expected_origin_root):
            origins_exact = False
    checks["receipt_bound_imports_exact"] = imports_exact
    checks["dependency_versions_exact"] = versions_exact
    checks["import_origins_exact"] = origins_exact
    if live_probe is not None and not imports_exact:
        block(
            "TAU2_IMPORT_EVIDENCE_MISMATCH",
            "live imports differ from exact receipt evidence",
        )
    if live_probe is not None and not versions_exact:
        block(
            "TAU2_DEPENDENCY_VERSION_MISMATCH",
            "an imported package version differs from the frozen lock",
        )
    if live_probe is not None and not origins_exact:
        block(
            "TAU2_IMPORT_ORIGIN_MISMATCH",
            "an import escapes checkout/src or the frozen environment",
        )

    expected_bindings = tuple(
        sorted(
            (
                {
                    "binding_id": binding_id,
                    "callable_ref": callable_ref,
                    "source_path": str((checkout_root / source_path).resolve()),
                    "source_sha256": source_sha256,
                }
                for (
                    binding_id,
                    callable_ref,
                    source_path,
                    source_sha256,
                ) in TAU2_CALLABLE_BINDINGS
            ),
            key=lambda item: tuple(sorted(item.items())),
        )
    )
    bindings_exact = bool(live_bindings) and (
        live_bindings == receipt_bindings == expected_bindings
    )
    checks["callable_bindings_exact"] = bindings_exact
    if live_probe is not None and not bindings_exact:
        block(
            "TAU2_CALLABLE_BINDING_MISMATCH",
            "live callable identity differs from the frozen source bindings",
        )

    counters = receipt.execution_counts
    zero_executions = all(
        getattr(counters, name) == 0
        for name in (
            "task_executions",
            "parity_executions",
            "native_checker_executions",
            "provider_calls",
            "model_calls",
            "api_calls",
            "runtime_probe_network_attempts",
        )
    )
    checks["zero_runtime_executions_and_network_attempts"] = zero_executions
    if not zero_executions:
        block(
            "TAU2_NONZERO_EXECUTION_COUNT",
            "import-only receipt records a forbidden execution or network attempt",
        )

    blockers = sorted(
        {item.code + "\0" + item.message: item for item in blockers}.values(),
        key=lambda item: (item.code, item.message),
    )
    warnings = tuple(item.as_json() for item in receipt.warnings)
    import_executable = all(checks.values()) and not blockers
    return Tau2RuntimePreflight(
        schema_version=TAU2_RUNTIME_PREFLIGHT_SCHEMA_VERSION,
        artifact_type=TAU2_RUNTIME_PREFLIGHT_ARTIFACT_TYPE,
        runtime_id=TAU2_RUNTIME_ID,
        benchmark=TAU2_BENCHMARK,
        upstream_version_or_commit=TAU2_PIN,
        receipt_sha256=validated.receipt_sha256,
        imports=live_imports,
        callable_bindings=live_bindings,
        checks=checks,
        blockers=tuple(blockers),
        warnings=warnings,
        import_executable=import_executable,
        checker_dispatchers_importable=bindings_exact,
        native_checker_parity_demonstrated=False,
        task_executions=counters.task_executions,
        checker_executions=counters.native_checker_executions,
        parity_executions=counters.parity_executions,
        network_attempts=counters.runtime_probe_network_attempts,
        public_or_formal_readiness=False,
    )


def load_tau2_runtime_receipt(
    path: str | Path,
    *,
    expected_receipt_sha256: str,
    repo_root: str | Path | None = None,
    import_probe: Callable[[Any], Mapping[str, Any]] | None = None,
    file_sha256: Callable[[Path], str | None] = _sha256_file,
    environment_tree_sha256: Callable[[Path], str] | None = None,
    source_tree_sha256: Callable[[Path], str] | None = None,
    lock_semantics: Callable[[Path], bool] = _lock_semantics_exact,
    environment_python_validator: Callable[[Path], bool] = (
        _environment_python_exact
    ),
) -> Tau2RuntimePreflight:
    """Load canonical JSON and run the same fail-closed tau2 preflight."""

    from .schema import canonical_json_bytes, sha256_bytes

    receipt_path = Path(path)
    try:
        payload = receipt_path.read_bytes()
        value = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return _failed_preflight(
            code="TAU2_RECEIPT_MISSING_OR_INVALID",
            message=f"receipt could not be loaded ({type(exc).__name__})",
        )
    if not isinstance(value, Mapping):
        return _failed_preflight(
            code="TAU2_RECEIPT_INVALID",
            message="receipt root must be an object",
        )
    if payload != canonical_json_bytes(dict(value)):
        return _failed_preflight(
            code="TAU2_RECEIPT_NOT_CANONICAL",
            message="receipt bytes are not exact canonical JSON",
        )
    if sha256_bytes(payload) != expected_receipt_sha256:
        return _failed_preflight(
            code="TAU2_RECEIPT_HASH_MISMATCH",
            message="receipt file bytes differ from the exact external binding",
        )
    return validate_tau2_runtime_receipt(
        value,
        expected_receipt_sha256=expected_receipt_sha256,
        repo_root=repo_root,
        import_probe=import_probe,
        file_sha256=file_sha256,
        environment_tree_sha256=environment_tree_sha256,
        source_tree_sha256=source_tree_sha256,
        lock_semantics=lock_semantics,
        environment_python_validator=environment_python_validator,
    )


__all__ = [
    "TAU2_BENCHMARK",
    "TAU2_CALLABLE_BINDINGS",
    "TAU2_COMMIT",
    "TAU2_FREEZE_LINE_COUNT",
    "TAU2_FREEZE_SHA256",
    "TAU2_LOCK_ROOT_VERSION",
    "TAU2_LOCK_SHA256",
    "TAU2_PIN",
    "TAU2_PYPROJECT_SHA256",
    "TAU2_REQUIRED_IMPORTS",
    "TAU2_RUNTIME_ID",
    "TAU2_RUNTIME_PREFLIGHT_ARTIFACT_TYPE",
    "TAU2_RUNTIME_PREFLIGHT_SCHEMA_VERSION",
    "TAU2_VERSION",
    "TAU2_VERSION_MISMATCH_WARNING_CODE",
    "TAU2_VERSION_MISMATCH_WARNING_MESSAGE",
    "Tau2RuntimeBlocker",
    "Tau2RuntimePreflight",
    "load_tau2_runtime_receipt",
    "tau2_import_probe_arguments",
    "tau2_runtime_expectation",
    "validate_tau2_runtime_receipt",
]
