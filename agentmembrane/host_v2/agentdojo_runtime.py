"""Receipt-bound, import-only AgentDojo native-runtime preflight.

This module deliberately does not provision an environment and does not run an
AgentDojo task, tool, checker, provider, or model.  Its narrow positive claim is
that the frozen AgentDojo modules and checker *callables* can be imported from a
receipt-bound environment.  Native/projected checker parity is a different,
later gate and is always reported as undemonstrated here.

The file also contains the isolated import probe used by the provisioning
receipt.  The probe is safe to execute as a script with ``python -I -B``: all
AgentMembrane imports are intentionally deferred until validation functions are
called.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import importlib
import importlib.metadata
import inspect
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Callable, Mapping, Sequence


AGENTDOJO_RUNTIME_ID = "agentdojo-0.1.35-py3123-lock-395e3d0a5921"
AGENTDOJO_BENCHMARK = "AgentDojo"
AGENTDOJO_VERSION = "0.1.35"
AGENTDOJO_COMMIT = "089ed468cf3ed0322acc66b0211f26d9d90dbf60"
AGENTDOJO_VERSION_OR_COMMIT = f"{AGENTDOJO_VERSION}@{AGENTDOJO_COMMIT}"

FROZEN_PYTHON_EXECUTABLE = Path(
    "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12"
)
FROZEN_PYTHON_VERSION = "3.12.3"
FROZEN_PYTHON_SHA256 = (
    "80ee2dd97bc26259d4e30853336f72ad38aa4aa0531bb196cc444d899422689d"
)
FROZEN_UV_VERSION = "0.8.17"
FROZEN_UV_WHEEL_SHA256 = (
    "b009f1ec9e28de00f76814ad66e35aaae82c98a0f24015de51943dcd1c2a1895"
)
FROZEN_UV_EXECUTABLE_SHA256 = (
    "16b94f4af20f485089c841eadb6280cf5d71af17ff1982fd798d41fcf9523031"
)
FROZEN_PYPROJECT_SHA256 = (
    "f69dde819258d5dc2c6dca13ecbb116e54904374879a5c921332db36474e0a3b"
)
FROZEN_LOCK_SHA256 = (
    "395e3d0a59214515008d27c4462c9723ab7594374243f561ad5f19b3aa8a5330"
)

AGENTDOJO_IMPORT_PROBE_FLAG = "--receipt-import-probe"
AGENTDOJO_RUNTIME_PREFLIGHT_SCHEMA_VERSION = 1
AGENTDOJO_RUNTIME_PREFLIGHT_ARTIFACT_TYPE = (
    "agentmembrane_agentdojo_import_only_runtime_preflight"
)


# Every direct core dependency in the frozen uv.lock plus email-validator,
# which is selected by pydantic[email].  Values are (distribution, version).
AGENTDOJO_REQUIRED_IMPORTS: Mapping[str, tuple[str, str]] = {
    "agentdojo": ("agentdojo", "0.1.35"),
    "agentdojo.functions_runtime": ("agentdojo", "0.1.35"),
    "agentdojo.task_suite.load_suites": ("agentdojo", "0.1.35"),
    "agentdojo.task_suite.task_suite": ("agentdojo", "0.1.35"),
    "anthropic": ("anthropic", "0.50.0"),
    "click": ("click", "8.1.8"),
    "cohere": ("cohere", "5.15.0"),
    "deepdiff": ("deepdiff", "8.6.1"),
    "docstring_parser": ("docstring-parser", "0.16"),
    "dotenv": ("python-dotenv", "1.1.0"),
    "email_validator": ("email-validator", "2.2.0"),
    "google.genai": ("google-genai", "1.15.0"),
    "langchain": ("langchain", "0.3.24"),
    "openai": ("openai", "1.76.2"),
    "pydantic": ("pydantic", "2.11.4"),
    "rich": ("rich", "14.0.0"),
    "tenacity": ("tenacity", "9.1.2"),
    "typing_extensions": ("typing-extensions", "4.13.2"),
    "yaml": ("PyYAML", "6.0.2"),
}


# Source hashes are frozen upstream bytes.  Merely importing these callables
# does not execute either checker.
AGENTDOJO_REQUIRED_CALLABLES: tuple[tuple[str, str, str, str], ...] = (
    (
        "agentdojo-v0.1.35-get-suite",
        "agentdojo.task_suite.load_suites:get_suite",
        "src/agentdojo/task_suite/load_suites.py",
        "e9c97813ed8295f25526733df044e9adf8ba18567eaeec3455591c4fbc1caa12",
    ),
    (
        "agentdojo-v0.1.35-task-suite",
        "agentdojo.task_suite.task_suite:TaskSuite",
        "src/agentdojo/task_suite/task_suite.py",
        "2e69da06f7e150dd6d238c53a74845b56eebeb224e07f694e1051a6e0c6a2bc1",
    ),
    (
        "agentdojo-v0.1.35-native-utility-dispatcher",
        "agentdojo.task_suite.task_suite:TaskSuite._check_user_task_utility",
        "src/agentdojo/task_suite/task_suite.py",
        "2e69da06f7e150dd6d238c53a74845b56eebeb224e07f694e1051a6e0c6a2bc1",
    ),
    (
        "agentdojo-v0.1.35-native-security-dispatcher",
        "agentdojo.task_suite.task_suite:TaskSuite._check_injection_task_security",
        "src/agentdojo/task_suite/task_suite.py",
        "2e69da06f7e150dd6d238c53a74845b56eebeb224e07f694e1051a6e0c6a2bc1",
    ),
    (
        "agentdojo-v0.1.35-functions-runtime",
        "agentdojo.functions_runtime:FunctionsRuntime",
        "src/agentdojo/functions_runtime.py",
        "3c67f71eb8a7f15d2a15fe9595d84218c5e6868d95fd71d1cef679cd2192d0f7",
    ),
    (
        "agentdojo-v0.1.35-function-call",
        "agentdojo.functions_runtime:FunctionCall",
        "src/agentdojo/functions_runtime.py",
        "3c67f71eb8a7f15d2a15fe9595d84218c5e6868d95fd71d1cef679cd2192d0f7",
    ),
)


@dataclass(frozen=True)
class AgentDojoRuntimeBlocker:
    code: str
    message: str

    def as_json(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class AgentDojoRuntimePreflight:
    """Immutable result of the receipt-bound import-only preflight."""

    schema_version: int
    artifact_type: str
    runtime_id: str
    benchmark: str
    upstream_version_or_commit: str
    receipt_sha256: str | None
    imports: tuple[Mapping[str, str], ...]
    callable_bindings: tuple[Mapping[str, str], ...]
    checks: Mapping[str, bool]
    blockers: tuple[AgentDojoRuntimeBlocker, ...]
    warnings: tuple[Mapping[str, Any], ...]
    import_executable: bool
    checker_dispatchers_importable: bool
    native_checker_parity_demonstrated: bool
    task_executions: int
    checker_executions: int
    parity_executions: int
    public_or_formal_readiness: bool

    @property
    def executable(self) -> bool:
        """Compatibility alias scoped strictly to import-only executability."""

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
            "public_or_formal_readiness": self.public_or_formal_readiness,
        }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _origin(module: Any) -> str:
    spec = getattr(module, "__spec__", None)
    candidate = getattr(spec, "origin", None)
    if not isinstance(candidate, str) or candidate in {"built-in", "frozen"}:
        candidate = getattr(module, "__file__", None)
    if not isinstance(candidate, str) or not candidate:
        raise RuntimeError("module has no file-backed origin")
    return str(Path(candidate).resolve())


def _resolve_callable(callable_ref: str) -> Any:
    module_name, separator, dotted = callable_ref.partition(":")
    if not separator or not module_name or not dotted:
        raise ValueError("invalid callable reference")
    value: Any = importlib.import_module(module_name)
    for component in dotted.split("."):
        value = getattr(value, component)
    if not callable(value):
        raise TypeError("resolved object is not callable")
    return value


def _probe_imports(*, checkout_src: Path, environment_root: Path) -> dict[str, Any]:
    """Collect import facts without constructing or invoking a native task."""

    checkout_src = checkout_src.resolve()
    environment_root = environment_root.resolve()
    if Path(sys.prefix).resolve() != environment_root:
        raise RuntimeError("runtime prefix differs from frozen environment")
    base_executable = Path(getattr(sys, "_base_executable", sys.executable)).resolve()
    if base_executable != FROZEN_PYTHON_EXECUTABLE.resolve():
        raise RuntimeError("base interpreter differs from frozen executable")
    version = ".".join(str(part) for part in sys.version_info[:3])
    if version != FROZEN_PYTHON_VERSION:
        raise RuntimeError("interpreter version differs from frozen version")
    if _sha256_file(base_executable) != FROZEN_PYTHON_SHA256:
        raise RuntimeError("base interpreter bytes differ from frozen hash")
    if not checkout_src.is_dir():
        raise RuntimeError("checkout source root is missing")

    # Isolated mode supplies only stdlib and this environment's site-packages.
    # The immutable checkout source is the sole explicit insertion because the
    # sync intentionally used --no-install-project.
    source_text = str(checkout_src)
    if source_text in sys.path:
        sys.path.remove(source_text)
    sys.path.insert(0, source_text)

    imports: list[dict[str, str]] = []
    for module_name in sorted(AGENTDOJO_REQUIRED_IMPORTS):
        package, frozen_version = AGENTDOJO_REQUIRED_IMPORTS[module_name]
        module = importlib.import_module(module_name)
        version_value = (
            frozen_version
            if package == "agentdojo"
            else importlib.metadata.version(package)
        )
        imports.append(
            {
                "module": module_name,
                "origin": _origin(module),
                "package": package,
                "version": version_value,
            }
        )

    bindings: list[dict[str, str]] = []
    checkout_root = checkout_src.parent
    for binding_id, callable_ref, source_path, source_sha256 in sorted(
        AGENTDOJO_REQUIRED_CALLABLES
    ):
        value = _resolve_callable(callable_ref)
        actual_source = inspect.getsourcefile(value)
        if actual_source is None:
            raise RuntimeError("callable has no inspectable source")
        resolved_source = Path(actual_source).resolve()
        expected_source = (checkout_root / source_path).resolve()
        if resolved_source != expected_source:
            raise RuntimeError("callable source origin differs from frozen checkout")
        if _sha256_file(resolved_source) != source_sha256:
            raise RuntimeError("callable source bytes differ from frozen hash")
        bindings.append(
            {
                "binding_id": binding_id,
                "callable_ref": callable_ref,
                "source_path": source_path,
                "source_sha256": source_sha256,
            }
        )

    return {
        "schema_version": 1,
        "runtime_id": AGENTDOJO_RUNTIME_ID,
        "interpreter": {
            "environment_python_executable": str(Path(sys.executable).absolute()),
            "base_executable": str(base_executable),
            "version": version,
            "executable_sha256": _sha256_file(base_executable),
            "environment_root": str(environment_root),
        },
        "imports": imports,
        "callable_bindings": bindings,
        "execution_counts": {
            "task_executions": 0,
            "native_checker_executions": 0,
            "parity_executions": 0,
            "provider_calls": 0,
            "model_calls": 0,
            "api_calls": 0,
        },
    }


def agentdojo_import_probe_source(
    *, checkout_root: Path, environment_root: Path
) -> str:
    """Return the exact isolated, network-denied probe source bound in receipts."""

    imports = repr(dict(AGENTDOJO_REQUIRED_IMPORTS))
    callables = repr(AGENTDOJO_REQUIRED_CALLABLES)
    checkout = repr(str(checkout_root.resolve()))
    environment = repr(str(environment_root.resolve()))
    interpreter = repr(str(FROZEN_PYTHON_EXECUTABLE))
    interpreter_version = repr(FROZEN_PYTHON_VERSION)
    interpreter_sha256 = repr(FROZEN_PYTHON_SHA256)
    runtime_id = repr(AGENTDOJO_RUNTIME_ID)
    return f'''import hashlib
import importlib
import importlib.metadata
import inspect
import json
from pathlib import Path
import socket
import sys

CHECKOUT_ROOT = Path({checkout})
ENVIRONMENT_ROOT = Path({environment})
FROZEN_INTERPRETER = Path({interpreter})
FROZEN_VERSION = {interpreter_version}
FROZEN_INTERPRETER_SHA256 = {interpreter_sha256}
RUNTIME_ID = {runtime_id}
IMPORTS = {imports}
CALLABLES = {callables}
network_attempts = 0

def _deny_network(*args, **kwargs):
    global network_attempts
    network_attempts += 1
    raise RuntimeError("network access is forbidden during AgentDojo import preflight")

class _NetworkDeniedSocket(socket.socket):
    def connect(self, *args, **kwargs):
        return _deny_network(*args, **kwargs)
    def connect_ex(self, *args, **kwargs):
        return _deny_network(*args, **kwargs)

socket.socket = _NetworkDeniedSocket
socket.create_connection = _deny_network
socket.getaddrinfo = _deny_network

base_executable = Path(getattr(sys, "_base_executable", sys.executable)).resolve()
version = ".".join(str(part) for part in sys.version_info[:3])
if Path(sys.prefix).resolve() != ENVIRONMENT_ROOT:
    raise RuntimeError("runtime prefix differs from frozen environment")
if base_executable != FROZEN_INTERPRETER.resolve():
    raise RuntimeError("base interpreter differs from frozen executable")
if version != FROZEN_VERSION:
    raise RuntimeError("interpreter version differs from frozen version")
if hashlib.sha256(base_executable.read_bytes()).hexdigest() != FROZEN_INTERPRETER_SHA256:
    raise RuntimeError("base interpreter bytes differ from frozen hash")
sys.path.insert(0, str(CHECKOUT_ROOT / "src"))

import_rows = []
for module_name in sorted(IMPORTS):
    package, frozen_version = IMPORTS[module_name]
    module = importlib.import_module(module_name)
    spec_origin = getattr(getattr(module, "__spec__", None), "origin", None)
    origin = spec_origin if isinstance(spec_origin, str) else getattr(module, "__file__", None)
    if not isinstance(origin, str) or not origin:
        raise RuntimeError(f"{{module_name}} has no file-backed origin")
    version_value = frozen_version if package == "agentdojo" else importlib.metadata.version(package)
    import_rows.append({{
        "module": module_name,
        "origin": str(Path(origin).resolve()),
        "package": package,
        "version": version_value,
    }})

binding_rows = []
for binding_id, callable_ref, source_path, source_sha256 in CALLABLES:
    module_name, dotted = callable_ref.split(":", 1)
    target = importlib.import_module(module_name)
    for component in dotted.split("."):
        target = getattr(target, component)
    if not callable(target):
        raise RuntimeError(f"{{callable_ref}} is not callable")
    actual_source = Path(inspect.getsourcefile(target) or "").resolve()
    expected_source = (CHECKOUT_ROOT / source_path).resolve()
    if actual_source != expected_source:
        raise RuntimeError(f"{{callable_ref}} has the wrong source origin")
    if hashlib.sha256(actual_source.read_bytes()).hexdigest() != source_sha256:
        raise RuntimeError(f"{{callable_ref}} has the wrong source hash")
    binding_rows.append({{
        "binding_id": binding_id,
        "callable_ref": callable_ref,
        "source_path": str(actual_source),
        "source_sha256": source_sha256,
    }})

result = {{
    "schema_version": 1,
    "runtime_id": RUNTIME_ID,
    "interpreter": {{
        "environment_python_executable": str(Path(sys.executable).absolute()),
        "base_executable": str(base_executable),
        "version": version,
        "executable_sha256": hashlib.sha256(base_executable.read_bytes()).hexdigest(),
        "environment_root": str(ENVIRONMENT_ROOT),
    }},
    "imports": sorted(import_rows, key=lambda row: row["module"]),
    "callable_bindings": sorted(binding_rows, key=lambda row: row["binding_id"]),
    "network_attempts": network_attempts,
    "execution_counts": {{
        "task_executions": 0,
        "native_checker_executions": 0,
        "parity_executions": 0,
        "provider_calls": 0,
        "model_calls": 0,
        "api_calls": 0,
    }},
}}
print(json.dumps(result, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")))
'''


def _script_probe(argv: Sequence[str]) -> int:
    if len(argv) != 3 or argv[0] != AGENTDOJO_IMPORT_PROBE_FLAG:
        return 2
    try:
        result = _probe_imports(
            checkout_src=Path(argv[1]), environment_root=Path(argv[2])
        )
    except Exception as exc:
        failure = {
            "schema_version": 1,
            "runtime_id": AGENTDOJO_RUNTIME_ID,
            "ok": False,
            "error_type": type(exc).__name__,
        }
        if isinstance(exc, ModuleNotFoundError) and isinstance(exc.name, str):
            failure["missing_module"] = exc.name
        sys.stdout.buffer.write(_canonical_json_bytes(failure))
        return 1
    sys.stdout.buffer.write(_canonical_json_bytes(result))
    return 0


def _repo_root(repo_root: str | Path | None) -> Path:
    if repo_root is None:
        return Path(__file__).resolve().parents[2]
    return Path(repo_root).resolve()


def agentdojo_runtime_expectation(
    *, repo_root: str | Path | None = None
) -> Any:
    """Build the exact shared receipt expectation for AgentDojo.

    ``Any`` is intentional at the annotation boundary: importing this module as
    the isolated probe must not require the AgentMembrane package.  Normal
    callers receive ``RuntimeProvisioningExpectation``.
    """

    from .runtime_provisioning import (  # deferred for standalone probe safety
        EnvironmentOverride,
        InterpreterIdentity,
        RuntimeProvisioningExpectation,
        UvBootstrapIdentity,
    )

    root = _repo_root(repo_root)
    runtime_root = root / "experiments/host_boundary_v2/runtime_envs"
    bootstrap_root = runtime_root / "bootstrap-uv-0.8.17-py312"
    checkout_root = root / "data/host_boundary_v2/upstream/agentdojo"
    environment_root = runtime_root / AGENTDOJO_RUNTIME_ID
    environment_python = environment_root / "bin/python"
    uv_executable = bootstrap_root / "bin/uv"
    wheel_path = (
        runtime_root
        / "wheelhouse/uv-0.8.17/uv-0.8.17-py3-none-macosx_11_0_arm64.whl"
    )
    probe_source = agentdojo_import_probe_source(
        checkout_root=checkout_root, environment_root=environment_root
    )
    common_overrides = tuple(
        EnvironmentOverride(name=name, value=value)
        for name, value in sorted(
            {
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "PYTHONDONTWRITEBYTECODE": "1",
                "UV_CACHE_DIR": str(runtime_root / "uv-cache"),
                "UV_LINK_MODE": "copy",
                "UV_NO_CONFIG": "1",
                "UV_PROJECT_ENVIRONMENT": str(environment_root),
                "UV_PYTHON_DOWNLOADS": "never",
            }.items()
        )
    )
    probe_overrides = (
        EnvironmentOverride(name="PATH", value="/usr/bin:/bin:/usr/sbin:/sbin"),
        EnvironmentOverride(name="PYTHONDONTWRITEBYTECODE", value="1"),
    )

    return RuntimeProvisioningExpectation(
        runtime_id=AGENTDOJO_RUNTIME_ID,
        benchmark=AGENTDOJO_BENCHMARK,
        upstream_version_or_commit=AGENTDOJO_VERSION_OR_COMMIT,
        interpreter=InterpreterIdentity(
            executable=str(FROZEN_PYTHON_EXECUTABLE),
            version=FROZEN_PYTHON_VERSION,
            executable_sha256=FROZEN_PYTHON_SHA256,
        ),
        bootstrap=UvBootstrapIdentity(
            version=FROZEN_UV_VERSION,
            wheel_path=str(wheel_path),
            wheel_sha256=FROZEN_UV_WHEEL_SHA256,
            bootstrap_root=str(bootstrap_root),
            uv_executable=str(uv_executable),
            uv_executable_sha256=FROZEN_UV_EXECUTABLE_SHA256,
        ),
        checkout_root=str(checkout_root),
        checkout_head=AGENTDOJO_COMMIT,
        pyproject_path=str(checkout_root / "pyproject.toml"),
        pyproject_sha256=FROZEN_PYPROJECT_SHA256,
        pyproject_version=AGENTDOJO_VERSION,
        lock_path=str(checkout_root / "uv.lock"),
        lock_sha256=FROZEN_LOCK_SHA256,
        lock_root_version=AGENTDOJO_VERSION,
        environment_root=str(environment_root),
        environment_python_executable=str(environment_python),
        sync_executable=str(uv_executable),
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
        sync_cwd=str(root),
        sync_environment_overrides=common_overrides,
        freeze_executable=str(uv_executable),
        freeze_arguments=(
            "pip",
            "freeze",
            "--python",
            str(environment_python),
        ),
        freeze_cwd=str(root),
        freeze_environment_overrides=common_overrides,
        import_probe_executable=str(environment_python),
        import_probe_arguments=(
            "-I",
            "-B",
            "-c",
            probe_source,
        ),
        import_probe_cwd=str(root),
        import_probe_environment_overrides=probe_overrides,
        required_import_modules=tuple(sorted(AGENTDOJO_REQUIRED_IMPORTS)),
        required_callable_refs=tuple(
            sorted(row[1] for row in AGENTDOJO_REQUIRED_CALLABLES)
        ),
        required_warning_codes=(),
    )


def _default_probe_runner(command: Any) -> Mapping[str, Any]:
    environment = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    completed = subprocess.run(
        [command.executable, *command.arguments],
        cwd=command.cwd,
        env=environment,
        check=False,
        capture_output=True,
        timeout=120,
    )
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("isolated import probe output is not JSON") from exc
    if not isinstance(value, Mapping):
        raise RuntimeError("isolated import probe output is not an object")
    if completed.returncode != 0:
        missing = value.get("missing_module")
        if isinstance(missing, str) and missing:
            raise ModuleNotFoundError(missing, name=missing)
        raise RuntimeError("isolated import probe failed")
    return value


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


def _failed_preflight(
    *, code: str, message: str, receipt_sha256: str | None = None
) -> AgentDojoRuntimePreflight:
    return AgentDojoRuntimePreflight(
        schema_version=AGENTDOJO_RUNTIME_PREFLIGHT_SCHEMA_VERSION,
        artifact_type=AGENTDOJO_RUNTIME_PREFLIGHT_ARTIFACT_TYPE,
        runtime_id=AGENTDOJO_RUNTIME_ID,
        benchmark=AGENTDOJO_BENCHMARK,
        upstream_version_or_commit=AGENTDOJO_VERSION_OR_COMMIT,
        receipt_sha256=receipt_sha256,
        imports=(),
        callable_bindings=(),
        checks={"receipt_validated": False},
        blockers=(AgentDojoRuntimeBlocker(code=code, message=message),),
        warnings=(),
        import_executable=False,
        checker_dispatchers_importable=False,
        native_checker_parity_demonstrated=False,
        task_executions=0,
        checker_executions=0,
        parity_executions=0,
        public_or_formal_readiness=False,
    )


def validate_agentdojo_runtime_receipt(
    value: Mapping[str, Any] | Any,
    *,
    expected_receipt_sha256: str,
    repo_root: str | Path | None = None,
    import_probe: Callable[[Any], Mapping[str, Any]] | None = None,
    file_sha256: Callable[[Path], str] = _sha256_file,
    tree_sha256: Callable[[Path], str] | None = None,
    source_tree_sha256: Callable[[Path], str] | None = None,
) -> AgentDojoRuntimePreflight:
    """Validate a shared receipt and rerun its exact import-only probe.

    All receipt, identity, byte, and tree checks occur before importing an
    AgentDojo module.  ``expected_receipt_sha256`` is mandatory so a
    self-consistent but substituted receipt cannot authorize imports.
    Injectable read-only probes exist solely for synthetic unit tests.
    """

    from .runtime_provisioning import validate_provisioning_receipt

    if not isinstance(expected_receipt_sha256, str) or len(expected_receipt_sha256) != 64:
        return _failed_preflight(
            code="AGENTDOJO_RECEIPT_HASH_REQUIRED",
            message="an exact external receipt SHA-256 is required",
        )
    expectation = agentdojo_runtime_expectation(repo_root=repo_root)
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
            "AGENTDOJO_RECEIPT_HASH_MISMATCH"
            if "sha" in label or "hash" in label
            else "AGENTDOJO_RECEIPT_INVALID"
        )
        return _failed_preflight(
            code=code,
            message=f"shared provisioning receipt validation failed ({type(exc).__name__})",
        )

    receipt = validated.receipt
    receipt_sha256 = validated.receipt_sha256
    root = _repo_root(repo_root)
    checkout_root = root / "data/host_boundary_v2/upstream/agentdojo"
    environment_root = (
        root / "experiments/host_boundary_v2/runtime_envs" / AGENTDOJO_RUNTIME_ID
    )
    blockers: list[AgentDojoRuntimeBlocker] = []

    def block(code: str, message: str) -> None:
        blockers.append(AgentDojoRuntimeBlocker(code=code, message=message))

    checks: dict[str, bool] = {"receipt_validated": True}
    byte_locks = (
        (FROZEN_PYTHON_EXECUTABLE, FROZEN_PYTHON_SHA256),
        (Path(receipt.bootstrap.wheel_path), FROZEN_UV_WHEEL_SHA256),
        (Path(receipt.bootstrap.uv_executable), FROZEN_UV_EXECUTABLE_SHA256),
        (checkout_root / "pyproject.toml", FROZEN_PYPROJECT_SHA256),
        (checkout_root / "uv.lock", FROZEN_LOCK_SHA256),
    )
    bytes_exact = True
    for path, expected in byte_locks:
        try:
            matches = file_sha256(path) == expected
        except OSError:
            matches = False
        bytes_exact = bytes_exact and matches
    checks["frozen_file_hashes_exact"] = bytes_exact
    if not bytes_exact:
        block(
            "AGENTDOJO_FROZEN_FILE_HASH_MISMATCH",
            "interpreter, pyproject, or lock bytes differ from the frozen hashes",
        )

    if tree_sha256 is None:
        try:
            from .runtime_provisioning import tree_manifest_sha256

            tree_sha256 = tree_manifest_sha256
        except (ImportError, AttributeError):
            tree_sha256 = None
    environment_exact = False
    if tree_sha256 is not None:
        try:
            environment_exact = (
                tree_sha256(environment_root) == receipt.environment.tree_sha256
            )
        except (OSError, ValueError):
            environment_exact = False
    checks["environment_tree_hash_exact"] = environment_exact
    if not environment_exact:
        block(
            "AGENTDOJO_ENVIRONMENT_TREE_MISMATCH",
            "live environment tree differs from the receipt-bound tree hash",
        )

    checkout_manifest_exact = False
    if source_tree_sha256 is None:
        try:
            from .runtime_provisioning import source_tree_manifest_sha256

            source_tree_sha256 = source_tree_manifest_sha256
        except (ImportError, AttributeError):
            source_tree_sha256 = None
    if source_tree_sha256 is not None:
        try:
            checkout_manifest_exact = (
                source_tree_sha256(checkout_root)
                == receipt.upstream.tree_manifest_post_sha256
            )
        except (OSError, ValueError):
            checkout_manifest_exact = False
    checks["upstream_tree_hash_exact"] = checkout_manifest_exact
    if not checkout_manifest_exact:
        block(
            "AGENTDOJO_UPSTREAM_TREE_MISMATCH",
            "live upstream tree differs from the receipt-bound post-sync manifest",
        )

    # Nothing native is imported unless the receipt and every mutable byte root
    # have already passed their fail-closed checks.
    live_probe: Mapping[str, Any] | None = None
    if not blockers:
        try:
            live_probe = (import_probe or _default_probe_runner)(receipt.import_probe)
        except Exception as exc:
            if isinstance(exc, ModuleNotFoundError) and isinstance(exc.name, str):
                block(
                    f"AGENTDOJO_DEPENDENCY_MISSING:{exc.name}",
                    f"isolated import-only probe lacks module {exc.name}",
                )
            else:
                block(
                    "AGENTDOJO_IMPORT_PROBE_FAILED",
                    f"isolated import-only probe failed ({type(exc).__name__})",
                )

    receipt_imports: tuple[dict[str, str], ...] = ()
    receipt_bindings: tuple[dict[str, str], ...] = ()
    try:
        receipt_imports = _mapping_rows(receipt.imports)
        receipt_bindings = _mapping_rows(receipt.callable_bindings)
    except (TypeError, ValueError):
        block(
            "AGENTDOJO_RECEIPT_EVIDENCE_INVALID",
            "receipt import or callable evidence is malformed",
        )

    live_imports: tuple[dict[str, str], ...] = ()
    live_bindings: tuple[dict[str, str], ...] = ()
    live_interpreter_exact = False
    live_probe_scope_exact = False
    if live_probe is not None:
        try:
            live_probe_scope_exact = (
                live_probe.get("schema_version") == 1
                and live_probe.get("runtime_id") == AGENTDOJO_RUNTIME_ID
                and live_probe.get("network_attempts") == 0
                and live_probe.get("execution_counts")
                == {
                    "task_executions": 0,
                    "native_checker_executions": 0,
                    "parity_executions": 0,
                    "provider_calls": 0,
                    "model_calls": 0,
                    "api_calls": 0,
                }
            )
            interpreter = live_probe["interpreter"]
            if not isinstance(interpreter, Mapping):
                raise TypeError("interpreter")
            live_interpreter_exact = interpreter == {
                "environment_python_executable": str(
                    environment_root / "bin/python"
                ),
                "base_executable": str(FROZEN_PYTHON_EXECUTABLE),
                "version": FROZEN_PYTHON_VERSION,
                "executable_sha256": FROZEN_PYTHON_SHA256,
                "environment_root": str(environment_root),
            }
            raw_imports = live_probe["imports"]
            raw_bindings = live_probe["callable_bindings"]
            if not isinstance(raw_imports, Sequence) or isinstance(raw_imports, str):
                raise TypeError("imports")
            if not isinstance(raw_bindings, Sequence) or isinstance(raw_bindings, str):
                raise TypeError("callable_bindings")
            live_imports = _mapping_rows(raw_imports)
            live_bindings = _mapping_rows(raw_bindings)
        except (KeyError, TypeError, ValueError):
            block(
                "AGENTDOJO_IMPORT_PROBE_INVALID",
                "isolated import-only probe emitted malformed evidence",
            )
    checks["live_interpreter_exact"] = live_interpreter_exact
    if live_probe is not None and not live_interpreter_exact:
        block(
            "AGENTDOJO_INTERPRETER_MISMATCH",
            "live import probe did not use the frozen interpreter/environment",
        )
    checks["live_probe_import_only_scope_exact"] = live_probe_scope_exact
    if live_probe is not None and not live_probe_scope_exact:
        block(
            "AGENTDOJO_IMPORT_PROBE_SCOPE_MISMATCH",
            "live probe identity or zero-execution counters differ",
        )

    imports_exact = bool(live_imports) and live_imports == receipt_imports
    checks["receipt_bound_imports_exact"] = imports_exact
    if live_probe is not None and not imports_exact:
        block(
            "AGENTDOJO_IMPORT_EVIDENCE_MISMATCH",
            "live import evidence differs from the bound receipt",
        )

    versions_exact = bool(live_imports)
    origins_locked = bool(live_imports)
    for row in live_imports:
        module = row.get("module", "")
        expected = AGENTDOJO_REQUIRED_IMPORTS.get(module)
        if expected is None or (row.get("package"), row.get("version")) != expected:
            versions_exact = False
        origin = row.get("origin", "")
        expected_root = (
            checkout_root / "src"
            if module == "agentdojo" or module.startswith("agentdojo.")
            else environment_root
        )
        if not _is_within(origin, expected_root):
            origins_locked = False
    checks["dependency_versions_exact"] = versions_exact
    checks["import_origins_locked"] = origins_locked
    if live_probe is not None and not versions_exact:
        block(
            "AGENTDOJO_DEPENDENCY_VERSION_MISMATCH",
            "one or more imported package versions differ from uv.lock",
        )
    if live_probe is not None and not origins_locked:
        block(
            "AGENTDOJO_IMPORT_ORIGIN_MISMATCH",
            "one or more imports originate outside checkout/src or the frozen environment",
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
                for binding_id, callable_ref, source_path, source_sha256 in AGENTDOJO_REQUIRED_CALLABLES
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
            "AGENTDOJO_CALLABLE_BINDING_MISMATCH",
            "live callable identity differs from frozen source bindings",
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
        )
    )
    checks["zero_task_checker_parity_and_external_executions"] = zero_executions
    if not zero_executions:
        block(
            "AGENTDOJO_NONZERO_EXECUTION_COUNT",
            "import-only receipt records a forbidden execution",
        )

    blockers = sorted(
        {item.code + "\0" + item.message: item for item in blockers}.values(),
        key=lambda item: (item.code, item.message),
    )
    import_executable = all(checks.values()) and not blockers
    warnings = tuple(
        item.as_json() if hasattr(item, "as_json") else dict(item)
        for item in receipt.warnings
    )
    return AgentDojoRuntimePreflight(
        schema_version=AGENTDOJO_RUNTIME_PREFLIGHT_SCHEMA_VERSION,
        artifact_type=AGENTDOJO_RUNTIME_PREFLIGHT_ARTIFACT_TYPE,
        runtime_id=AGENTDOJO_RUNTIME_ID,
        benchmark=AGENTDOJO_BENCHMARK,
        upstream_version_or_commit=AGENTDOJO_VERSION_OR_COMMIT,
        receipt_sha256=receipt_sha256,
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
        public_or_formal_readiness=False,
    )


def load_agentdojo_runtime_receipt(
    path: str | Path,
    *,
    expected_receipt_sha256: str,
    repo_root: str | Path | None = None,
    import_probe: Callable[[Any], Mapping[str, Any]] | None = None,
    file_sha256: Callable[[Path], str] = _sha256_file,
    tree_sha256: Callable[[Path], str] | None = None,
    source_tree_sha256: Callable[[Path], str] | None = None,
) -> AgentDojoRuntimePreflight:
    """Load an exact receipt and run the same fail-closed import preflight."""

    receipt_path = Path(path)
    try:
        payload = receipt_path.read_bytes()
        value = json.loads(payload)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return _failed_preflight(
            code="AGENTDOJO_RECEIPT_MISSING_OR_INVALID",
            message=f"receipt could not be loaded ({type(exc).__name__})",
        )
    if not isinstance(value, Mapping):
        return _failed_preflight(
            code="AGENTDOJO_RECEIPT_INVALID",
            message="receipt root must be an object",
        )
    if payload != _canonical_json_bytes(dict(value)):
        return _failed_preflight(
            code="AGENTDOJO_RECEIPT_FILE_NOT_CANONICAL",
            message="receipt file bytes are not canonical JSON",
        )
    return validate_agentdojo_runtime_receipt(
        value,
        expected_receipt_sha256=expected_receipt_sha256,
        repo_root=repo_root,
        import_probe=import_probe,
        file_sha256=file_sha256,
        tree_sha256=tree_sha256,
        source_tree_sha256=source_tree_sha256,
    )


if __name__ == "__main__":  # pragma: no cover - exercised by exact subprocess
    raise SystemExit(_script_probe(sys.argv[1:]))


__all__ = [
    "AGENTDOJO_BENCHMARK",
    "AGENTDOJO_COMMIT",
    "AGENTDOJO_REQUIRED_CALLABLES",
    "AGENTDOJO_REQUIRED_IMPORTS",
    "AGENTDOJO_RUNTIME_ID",
    "AGENTDOJO_RUNTIME_PREFLIGHT_ARTIFACT_TYPE",
    "AGENTDOJO_RUNTIME_PREFLIGHT_SCHEMA_VERSION",
    "AGENTDOJO_VERSION",
    "AGENTDOJO_VERSION_OR_COMMIT",
    "AgentDojoRuntimeBlocker",
    "AgentDojoRuntimePreflight",
    "agentdojo_runtime_expectation",
    "load_agentdojo_runtime_receipt",
    "validate_agentdojo_runtime_receipt",
]
