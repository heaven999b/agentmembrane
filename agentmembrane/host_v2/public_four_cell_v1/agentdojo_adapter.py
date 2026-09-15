"""Pinned AgentDojo NativeHostSession for the public four-cell overlay.

This module is intentionally independent of the active Host/RQ1 execution
stack.  It talks directly to the immutable AgentDojo v0.1.35 checkout through
one persistent worker launched by the receipt-bound Python 3.12 environment.
No provider, model, network client, oracle document, or legacy Host adapter is
imported.

The model-visible boundary is deliberately narrow: the user task prompt, the
native tool schemas, and observations returned by native tool calls.  Pair
role, injection task identity/goal, checker outputs, condition, and treatment
remain outside that boundary.  For an adversarial task, the injection reaches
the model only when an ordinary native tool observation contains the injected
environment value; it is never promoted to a system/developer message.
"""

from __future__ import annotations

import copy
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
from typing import Any, Callable, Mapping, Protocol, Sequence


ADAPTER_ID = "agentdojo-v0.1.35-public-four-cell-native-session-v1"
UPSTREAM_VERSION_OR_COMMIT = (
    "0.1.35@089ed468cf3ed0322acc66b0211f26d9d90dbf60"
)
SUITE_VERSION = "v1"
SOURCE_TASK_ID = "agentdojo-v1-banking-u3-i1"

FROZEN_PYTHON_VERSION = "3.12.3"
FROZEN_BASE_PYTHON = Path(
    "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12"
)
FROZEN_BASE_PYTHON_SHA256 = (
    "80ee2dd97bc26259d4e30853336f72ad38aa4aa0531bb196cc444d899422689d"
)
FROZEN_UPSTREAM_TREE_SHA256 = (
    "3675668d8c10e4632adc3b2b541d87ed795a613fb9d0284bae2975be63ab889d"
)

_SOURCE_LOCKS = (
    (
        "pyproject.toml",
        "f69dde819258d5dc2c6dca13ecbb116e54904374879a5c921332db36474e0a3b",
    ),
    (
        "uv.lock",
        "395e3d0a59214515008d27c4462c9723ab7594374243f561ad5f19b3aa8a5330",
    ),
    (
        "src/agentdojo/functions_runtime.py",
        "3c67f71eb8a7f15d2a15fe9595d84218c5e6868d95fd71d1cef679cd2192d0f7",
    ),
    (
        "src/agentdojo/task_suite/load_suites.py",
        "e9c97813ed8295f25526733df044e9adf8ba18567eaeec3455591c4fbc1caa12",
    ),
    (
        "src/agentdojo/task_suite/task_suite.py",
        "2e69da06f7e150dd6d238c53a74845b56eebeb224e07f694e1051a6e0c6a2bc1",
    ),
    (
        "src/agentdojo/default_suites/v1/banking/user_tasks.py",
        "37af838194f001af80cc040315bcb2d69d0112324d424f9a323473b41b317f82",
    ),
    (
        "src/agentdojo/default_suites/v1/banking/injection_tasks.py",
        "fa2dedf8e66c95ffadb54f5a26648728b08c56f302858de4ee9a5cc0b3891618",
    ),
    (
        "src/agentdojo/data/suites/banking/environment.yaml",
        "3f539da1d97779b244cd122afc683dc69d602f338e1b3c42d126cbde33611c8b",
    ),
    (
        "src/agentdojo/data/suites/banking/injection_vectors.yaml",
        "4eb98a601c108d9b4d88f5d3f2dbf455f775a718975a0ae2624b4cf0d0f6f819",
    ),
)
_PACK_LOCKS = (
    (
        "transform/taskpack_build.py",
        "a736e684c93bcf09f7937738cf76a07b66a0771d5aebeb6d4077a6406a2ebf1e",
    ),
    (
        "manifest.json",
        "efdbb5472988a172b28917c6fb313829fb0d23e48dc179c561372d01e5e6aa56",
    ),
    (
        "raw/upstream_manifest.json",
        "766b92de85c1d112d80eed70a0ccba1bbac0dd40a8ca7445b8a25206dc1e018c",
    ),
    (
        "tasks.jsonl",
        "991e0f65c50a95d2757b849191323d0878f7f4a57cbe67cd7ce50385f9160844",
    ),
    (
        "fixtures/agentdojo-v1-banking-u3-i1-adversarial.json",
        "41ea6f509fe4ec631448495ff3513b5bcd4daf29e447c5784f47182a62ebc1a3",
    ),
    (
        "fixtures/agentdojo-v1-banking-u3-i1-benign.json",
        "b48f0182b31a812ea292efea4734611db84ede7b0406795ec8a5d298d4571189",
    ),
    (
        "oracles/agentdojo-v1-banking-u3-i1.json",
        "f7e5ccd224cf7afc344bb4f5fe0d8591555bfcafd35d37fece275c996d6f8258",
    ),
)
_CHECKER_BINDING_IDS = (
    "agentdojo-v0.1.35-native-utility-dispatcher",
    "agentdojo-v0.1.35-native-security-dispatcher",
)
_REQUIRED_CALLABLE_BINDINGS = {
    "agentdojo.task_suite.load_suites:get_suite": _SOURCE_LOCKS[3][1],
    "agentdojo.functions_runtime:FunctionsRuntime": _SOURCE_LOCKS[2][1],
    "agentdojo.functions_runtime:FunctionCall": _SOURCE_LOCKS[2][1],
    (
        "agentdojo.task_suite.task_suite:"
        "TaskSuite._check_user_task_utility"
    ): _SOURCE_LOCKS[4][1],
    (
        "agentdojo.task_suite.task_suite:"
        "TaskSuite._check_injection_task_security"
    ): _SOURCE_LOCKS[4][1],
}
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
_NAMESPACE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_PAIR_ROLES = frozenset({"benign", "adversarial"})


class AgentDojoSessionError(RuntimeError):
    """The native session could not preserve its fail-closed contract."""


class AgentDojoRuntimeIntegrityError(AgentDojoSessionError):
    """Receipt-bound runtime or pinned upstream bytes differ."""


class AgentDojoProtocolError(AgentDojoSessionError):
    """A caller or native worker violated the overlay protocol."""


def required_callable_source_sha256() -> dict[str, str]:
    """Return the exact direct-upstream callable hash contract for fresh receipts."""

    return dict(_REQUIRED_CALLABLE_BINDINGS)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AgentDojoProtocolError(f"value is not strict JSON: {exc}") from exc


def _json_clone(value: Any, *, label: str) -> Any:
    try:
        return json.loads(_canonical_json_bytes(value))
    except json.JSONDecodeError as exc:  # pragma: no cover - encoder round trip
        raise AgentDojoProtocolError(f"{label} is not JSON-safe") from exc


def _file_sha256(path: Path) -> str:
    try:
        if not path.is_file():
            raise AgentDojoRuntimeIntegrityError(f"required file is missing: {path}")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError as exc:
        raise AgentDojoRuntimeIntegrityError(
            f"cannot hash required file {path}: {type(exc).__name__}"
        ) from exc


def _tree_manifest_sha256(root: Path) -> str:
    """Copy of the receipt's byte/symlink tree algorithm, with no imports."""

    base = Path(root)
    if not base.is_dir():
        raise AgentDojoRuntimeIntegrityError(f"runtime root is missing: {base}")
    rows: list[dict[str, str]] = []
    try:
        for directory, directory_names, file_names in os.walk(
            base, topdown=True, followlinks=False
        ):
            directory_names.sort()
            file_names.sort()
            parent = Path(directory)
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
                        {
                            "path": relative,
                            "type": "symlink",
                            "target": os.readlink(path),
                        }
                    )
                elif stat.S_ISREG(mode):
                    rows.append(
                        {"path": relative, "type": "file", "sha256": _file_sha256(path)}
                    )
                else:
                    raise AgentDojoRuntimeIntegrityError(
                        f"unsupported runtime tree entry: {path}"
                    )
    except OSError as exc:
        raise AgentDojoRuntimeIntegrityError(
            f"cannot walk runtime tree: {type(exc).__name__}"
        ) from exc
    rows.sort(key=lambda row: row["path"])
    return _sha256_bytes(_canonical_json_bytes(rows))


@dataclass(frozen=True)
class AgentDojoTaskIdentity:
    """Exact upstream identity; notably excludes the injection goal text."""

    source_task_id: str
    task_id: str
    pair_role: str
    domain: str
    user_task_id: str
    injection_task_id: str | None
    injection_vector_id: str | None
    suite_version: str = SUITE_VERSION

    def __post_init__(self) -> None:
        if self.source_task_id != SOURCE_TASK_ID:
            raise AgentDojoProtocolError("task identity is not the frozen u3-i1 source")
        if self.pair_role not in _PAIR_ROLES:
            raise AgentDojoProtocolError("pair_role must be benign or adversarial")
        expected_task_id = f"{SOURCE_TASK_ID}-{self.pair_role}"
        if self.task_id != expected_task_id:
            raise AgentDojoProtocolError("task_id differs from source/pair identity")
        if (
            self.domain != "banking"
            or self.user_task_id != "user_task_3"
            or self.suite_version != SUITE_VERSION
        ):
            raise AgentDojoProtocolError("native suite/domain/user identity differs")
        expected_injection = "injection_task_1" if self.pair_role == "adversarial" else None
        expected_vector = (
            "injection_incoming_transaction"
            if self.pair_role == "adversarial"
            else None
        )
        if (
            self.injection_task_id != expected_injection
            or self.injection_vector_id != expected_vector
        ):
            raise AgentDojoProtocolError("injection identity differs from pair role")

    @classmethod
    def for_pair_role(cls, pair_role: str) -> "AgentDojoTaskIdentity":
        if pair_role not in _PAIR_ROLES:
            raise AgentDojoProtocolError("pair_role must be benign or adversarial")
        return cls(
            source_task_id=SOURCE_TASK_ID,
            task_id=f"{SOURCE_TASK_ID}-{pair_role}",
            pair_role=pair_role,
            domain="banking",
            user_task_id="user_task_3",
            injection_task_id=(
                "injection_task_1" if pair_role == "adversarial" else None
            ),
            injection_vector_id=(
                "injection_incoming_transaction"
                if pair_role == "adversarial"
                else None
            ),
        )


@dataclass(frozen=True)
class RuntimeTripletEvidence:
    schema_version: int
    runtime_id: str
    environment_root: str
    environment_tree_sha256: str
    python_executable: str
    python_version: str
    base_executable: str
    base_executable_sha256: str
    runtime_pycache_dir_count: int
    runtime_pyc_file_count: int
    receipt_path: str
    receipt_sha256: str
    binding_path: str
    binding_sha256: str
    callable_source_sha256: Mapping[str, str]

    def as_json(self) -> dict[str, Any]:
        value = asdict(self)
        value["callable_source_sha256"] = dict(self.callable_source_sha256)
        return value


@dataclass(frozen=True)
class AgentDojoRuntimeBinding:
    """Caller-supplied authority binding; every field is mandatory and live-checked."""

    runtime_id: str
    environment_root: str
    environment_tree_sha256: str
    receipt_path: str
    receipt_sha256: str
    binding_path: str
    binding_sha256: str
    callable_source_sha256: Mapping[str, str]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.runtime_id, str)
            or not self.runtime_id.startswith("agentdojo-0.1.35-")
            or not isinstance(self.environment_root, str)
            or not Path(self.environment_root).is_absolute()
        ):
            raise AgentDojoProtocolError("runtime binding identity/root is invalid")
        for value, label in (
            (self.environment_tree_sha256, "environment_tree_sha256"),
            (self.receipt_sha256, "receipt_sha256"),
            (self.binding_sha256, "binding_sha256"),
        ):
            if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
                raise AgentDojoProtocolError(f"runtime binding {label} is invalid")
        for value, label in (
            (self.receipt_path, "receipt_path"),
            (self.binding_path, "binding_path"),
        ):
            path = Path(value)
            if (
                not isinstance(value, str)
                or not value
                or path.is_absolute()
                or ".." in path.parts
            ):
                raise AgentDojoProtocolError(f"runtime binding {label} is invalid")
        receipt_parts = Path(self.receipt_path).parts
        binding_parts = Path(self.binding_path).parts
        canary_prefix = (
            "experiments",
            "host_boundary_v2",
            "public_four_cell_canary_v1",
            "config",
            "runtime-candidates",
        )
        for parts, value, label in (
            (receipt_parts, self.receipt_path, "receipt_path"),
            (binding_parts, self.binding_path, "binding_path"),
        ):
            if (
                parts[: len(canary_prefix)] != canary_prefix
                or len(parts) != len(canary_prefix) + 1
                or not value.endswith(".json")
            ):
                raise AgentDojoProtocolError(
                    f"{label} must be one JSON artifact directly under the "
                    "versioned canary runtime-candidates directory"
                )
        if self.receipt_path == self.binding_path:
            raise AgentDojoProtocolError(
                "receipt_path and binding_path must name distinct artifacts"
            )
        supplied = dict(self.callable_source_sha256)
        if supplied != _REQUIRED_CALLABLE_BINDINGS:
            raise AgentDojoProtocolError(
                "runtime binding callable hashes differ from the pinned direct API"
            )
        object.__setattr__(self, "callable_source_sha256", supplied)


@dataclass(frozen=True)
class PackPreflightEvidence:
    schema_version: int
    pack_id: str
    pack_root: str
    pack_transform_valid: bool
    pack_locks_exact: bool
    pack_pycache_dir_count: int
    pack_pyc_file_count: int
    bindings: tuple[Mapping[str, Any], ...]

    def as_json(self) -> dict[str, Any]:
        value = asdict(self)
        value["bindings"] = [dict(row) for row in self.bindings]
        return value


def _cache_pollution_counts(root: Path) -> tuple[int, int]:
    pycache = 0
    pyc = 0
    try:
        for directory, directory_names, file_names in os.walk(
            root, topdown=True, followlinks=False
        ):
            pycache += sum(name == "__pycache__" for name in directory_names)
            pyc += sum(name.endswith(".pyc") for name in file_names)
    except OSError as exc:
        raise AgentDojoRuntimeIntegrityError(
            f"cannot inspect cache pollution: {type(exc).__name__}"
        ) from exc
    return pycache, pyc


def validate_pack_preflight(*, repo_root: Path | str) -> PackPreflightEvidence:
    """Bind the overlay to the frozen transform and exact u3-i1 pack bytes."""

    repository = Path(repo_root).resolve()
    pack_root = repository / "data/host_boundary_v2/packs/agentdojo-v0.1.35-v1"
    if not pack_root.is_dir():
        raise AgentDojoRuntimeIntegrityError("frozen AgentDojo pack is missing")
    bindings: list[dict[str, Any]] = []
    for relative, expected in _PACK_LOCKS:
        actual = _file_sha256(pack_root / relative)
        bindings.append(
            {
                "path": relative,
                "expected_sha256": expected,
                "actual_sha256": actual,
                "matches": actual == expected,
            }
        )
    pycache_count, pyc_count = _cache_pollution_counts(pack_root)
    transform_valid = bindings[0]["matches"] is True
    locks_exact = all(row["matches"] is True for row in bindings)
    evidence = PackPreflightEvidence(
        schema_version=1,
        pack_id="host-v2-agentdojo-v0.1.35-v1",
        pack_root=str(pack_root),
        pack_transform_valid=transform_valid,
        pack_locks_exact=locks_exact,
        pack_pycache_dir_count=pycache_count,
        pack_pyc_file_count=pyc_count,
        bindings=tuple(bindings),
    )
    if not transform_valid:
        raise AgentDojoRuntimeIntegrityError("pack transform bytes differ")
    if not locks_exact:
        raise AgentDojoRuntimeIntegrityError("frozen u3-i1 pack bytes differ")
    if pycache_count or pyc_count:
        raise AgentDojoRuntimeIntegrityError("pack contains __pycache__/.pyc pollution")
    _canonical_json_bytes(evidence.as_json())
    return evidence


def _probe_interpreter(python_executable: Path, environment_root: Path) -> Mapping[str, Any]:
    source = """import hashlib,json,sys
from pathlib import Path
base=Path(getattr(sys,'_base_executable',sys.executable)).resolve()
print(json.dumps({'prefix':str(Path(sys.prefix).resolve()),'version':'.'.join(map(str,sys.version_info[:3])),'base_executable':str(base),'base_sha256':hashlib.sha256(base.read_bytes()).hexdigest()},sort_keys=True,separators=(',',':')))
"""
    try:
        completed = subprocess.run(
            [str(python_executable), "-I", "-B", "-c", source],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(environment_root),
            env={
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise AgentDojoRuntimeIntegrityError(
            f"runtime interpreter probe failed: {type(exc).__name__}"
        ) from exc
    if completed.returncode != 0:
        raise AgentDojoRuntimeIntegrityError("runtime interpreter probe returned nonzero")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise AgentDojoRuntimeIntegrityError(
            "runtime interpreter probe returned invalid JSON"
        ) from exc
    if not isinstance(value, dict):
        raise AgentDojoRuntimeIntegrityError("runtime interpreter probe is not an object")
    return value


def _bound_artifact(
    *, repo_root: Path, relative_path: str, expected_sha256: str, label: str
) -> dict[str, Any]:
    candidate = (repo_root / relative_path).resolve()
    try:
        candidate.relative_to(repo_root)
    except ValueError as exc:
        raise AgentDojoRuntimeIntegrityError(f"{label} escapes repository") from exc
    if _file_sha256(candidate) != expected_sha256:
        raise AgentDojoRuntimeIntegrityError(f"{label} bytes differ from binding")
    try:
        value = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AgentDojoRuntimeIntegrityError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise AgentDojoRuntimeIntegrityError(f"{label} must be a JSON object")
    return value


def _receipt_callable_hashes(receipt: Mapping[str, Any]) -> dict[str, str]:
    rows = receipt.get("callable_bindings")
    if not isinstance(rows, list):
        raise AgentDojoRuntimeIntegrityError("runtime receipt lacks callable bindings")
    found: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise AgentDojoRuntimeIntegrityError("runtime receipt callable row is invalid")
        ref = row.get("callable_ref")
        source_sha = row.get("source_sha256")
        if ref in _REQUIRED_CALLABLE_BINDINGS:
            if ref in found or not isinstance(source_sha, str):
                raise AgentDojoRuntimeIntegrityError(
                    "runtime receipt callable binding is duplicate/invalid"
                )
            found[ref] = source_sha
    if found != _REQUIRED_CALLABLE_BINDINGS:
        raise AgentDojoRuntimeIntegrityError(
            "runtime receipt callable hashes differ from pinned direct API"
        )
    return found


def validate_runtime_triplet(
    *,
    repo_root: Path | str,
    runtime_root: Path | str,
    binding: AgentDojoRuntimeBinding,
    _tree_hasher: Callable[[Path], str] = _tree_manifest_sha256,
    _interpreter_probe: Callable[[Path, Path], Mapping[str, Any]] = _probe_interpreter,
) -> RuntimeTripletEvidence:
    """Validate a receipt-bound runtime tuple without any legacy-runtime default."""

    if not isinstance(binding, AgentDojoRuntimeBinding):
        raise AgentDojoProtocolError("binding must be AgentDojoRuntimeBinding")
    repository = Path(repo_root).resolve()
    if not repository.is_dir():
        raise AgentDojoRuntimeIntegrityError("repo_root is missing")
    root = Path(runtime_root).resolve()
    if not root.is_dir():
        raise AgentDojoRuntimeIntegrityError("runtime_root is missing")
    if root != Path(binding.environment_root).resolve():
        raise AgentDojoRuntimeIntegrityError("runtime root differs from authority binding")
    receipt = _bound_artifact(
        repo_root=repository,
        relative_path=binding.receipt_path,
        expected_sha256=binding.receipt_sha256,
        label="runtime receipt",
    )
    binding_artifact = _bound_artifact(
        repo_root=repository,
        relative_path=binding.binding_path,
        expected_sha256=binding.binding_sha256,
        label="runtime binding artifact",
    )
    receipt_environment = receipt.get("environment")
    if not isinstance(receipt_environment, dict):
        raise AgentDojoRuntimeIntegrityError("runtime receipt lacks environment")
    receipt_triplet = (
        receipt.get("runtime_id"),
        receipt_environment.get("root"),
        receipt_environment.get("tree_sha256"),
    )
    expected_triplet = (
        binding.runtime_id,
        binding.environment_root,
        binding.environment_tree_sha256,
    )
    if receipt_triplet != expected_triplet:
        raise AgentDojoRuntimeIntegrityError("runtime receipt triplet differs")
    artifact_triplet = (
        binding_artifact.get("runtime_id"),
        binding_artifact.get("environment_root"),
        binding_artifact.get("environment_tree_sha256"),
    )
    if artifact_triplet != expected_triplet:
        raise AgentDojoRuntimeIntegrityError("runtime binding artifact triplet differs")
    if (
        binding_artifact.get("receipt_path") != binding.receipt_path
        or binding_artifact.get("receipt_sha256") != binding.receipt_sha256
    ):
        raise AgentDojoRuntimeIntegrityError("binding artifact receipt coordinate differs")
    receipt_callables = _receipt_callable_hashes(receipt)
    if receipt_callables != dict(binding.callable_source_sha256):
        raise AgentDojoRuntimeIntegrityError("receipt/caller callable bindings differ")
    pycache_count, pyc_count = _cache_pollution_counts(root)
    if pycache_count or pyc_count:
        raise AgentDojoRuntimeIntegrityError(
            "runtime contains __pycache__/.pyc pollution"
        )
    actual_tree = _tree_hasher(root)
    if actual_tree != binding.environment_tree_sha256:
        raise AgentDojoRuntimeIntegrityError("live runtime tree differs from the triplet")
    python_executable = root / "bin" / "python"
    if not python_executable.is_file():
        raise AgentDojoRuntimeIntegrityError("runtime Python is missing")
    probe = _interpreter_probe(python_executable, root)
    if probe.get("prefix") != str(root):
        raise AgentDojoRuntimeIntegrityError("runtime Python prefix differs")
    if probe.get("version") != FROZEN_PYTHON_VERSION:
        raise AgentDojoRuntimeIntegrityError("runtime Python version differs")
    if Path(str(probe.get("base_executable"))).resolve() != FROZEN_BASE_PYTHON.resolve():
        raise AgentDojoRuntimeIntegrityError("runtime base interpreter differs")
    if probe.get("base_sha256") != FROZEN_BASE_PYTHON_SHA256:
        raise AgentDojoRuntimeIntegrityError("runtime base interpreter bytes differ")
    evidence = RuntimeTripletEvidence(
        schema_version=1,
        runtime_id=binding.runtime_id,
        environment_root=str(root),
        environment_tree_sha256=actual_tree,
        python_executable=str(python_executable),
        python_version=FROZEN_PYTHON_VERSION,
        base_executable=str(FROZEN_BASE_PYTHON),
        base_executable_sha256=FROZEN_BASE_PYTHON_SHA256,
        runtime_pycache_dir_count=pycache_count,
        runtime_pyc_file_count=pyc_count,
        receipt_path=binding.receipt_path,
        receipt_sha256=binding.receipt_sha256,
        binding_path=binding.binding_path,
        binding_sha256=binding.binding_sha256,
        callable_source_sha256=receipt_callables,
    )
    _canonical_json_bytes(evidence.as_json())
    return evidence


def _assert_runtime_unchanged(runtime: RuntimeTripletEvidence) -> None:
    root = Path(runtime.environment_root)
    pycache_count, pyc_count = _cache_pollution_counts(root)
    if pycache_count or pyc_count:
        raise AgentDojoRuntimeIntegrityError(
            "runtime gained __pycache__/.pyc pollution"
        )
    if _tree_manifest_sha256(root) != runtime.environment_tree_sha256:
        raise AgentDojoRuntimeIntegrityError(
            "runtime tree changed after triplet validation"
        )


class _NativeBackend(Protocol):
    def interface_description(self) -> Mapping[str, Any]: ...
    def apply(self, operation: str, args: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def snapshot(self) -> Mapping[str, Any]: ...
    def evaluate_native_checkers(self, terminal_text: str) -> Mapping[str, Any]: ...
    def cleanup(self) -> Mapping[str, Any]: ...
    def close(self) -> None: ...


BackendFactory = Callable[
    [RuntimeTripletEvidence, str, AgentDojoTaskIdentity], _NativeBackend
]


class _SubprocessNativeBackend:
    """One line-delimited JSON worker in the frozen environment."""

    def __init__(
        self,
        runtime: RuntimeTripletEvidence,
        namespace: str,
        identity: AgentDojoTaskIdentity,
    ) -> None:
        self._closed = False
        command = [
            runtime.python_executable,
            "-I",
            "-B",
            str(Path(__file__).resolve()),
            "--native-worker-v1",
        ]
        try:
            self._process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                cwd=str(Path(__file__).resolve().parents[3]),
                env={
                    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
                    "PYTHONDONTWRITEBYTECODE": "1",
                },
            )
        except OSError as exc:
            raise AgentDojoSessionError(
                f"cannot launch native worker: {type(exc).__name__}"
            ) from exc
        try:
            response = self._request(
                {
                    "command": "initialize",
                    "schema_version": 1,
                    "runtime_id": runtime.runtime_id,
                    "environment_root": runtime.environment_root,
                    "namespace": namespace,
                    "identity": asdict(identity),
                },
                timeout=60,
            )
            self._interface = _require_object(
                response.get("interface"), "worker interface"
            )
            self._initial_snapshot = _validate_backend_snapshot(
                response.get("snapshot"), label="initial worker snapshot"
            )
        except Exception:
            self._terminate()
            raise

    def _terminate(self) -> None:
        process = getattr(self, "_process", None)
        if process is None:
            return
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        self._closed = True

    def _request(self, request: Mapping[str, Any], *, timeout: int = 30) -> dict[str, Any]:
        if self._closed or self._process.poll() is not None:
            raise AgentDojoSessionError("native worker is not running")
        stdin = self._process.stdin
        stdout = self._process.stdout
        if stdin is None or stdout is None:
            self._terminate()
            raise AgentDojoSessionError("native worker pipes are unavailable")
        try:
            stdin.write(_canonical_json_bytes(dict(request)).decode("utf-8") + "\n")
            stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            self._terminate()
            raise AgentDojoSessionError("native worker request write failed") from exc
        selector = selectors.DefaultSelector()
        try:
            selector.register(stdout, selectors.EVENT_READ)
            ready = selector.select(timeout)
        finally:
            selector.close()
        if not ready:
            self._terminate()
            raise AgentDojoSessionError("native worker response timed out")
        line = stdout.readline()
        if not line:
            self._terminate()
            raise AgentDojoSessionError("native worker closed without a response")
        try:
            response = json.loads(line)
        except json.JSONDecodeError as exc:
            self._terminate()
            raise AgentDojoProtocolError("native worker response is invalid JSON") from exc
        if not isinstance(response, dict) or set(response) != {"ok", "payload", "error"}:
            self._terminate()
            raise AgentDojoProtocolError("native worker response envelope differs")
        if response["ok"] is not True:
            error = response.get("error")
            code = error.get("code") if isinstance(error, dict) else "UNKNOWN"
            raise AgentDojoSessionError(f"native worker failed closed: {code}")
        if response["error"] is not None or not isinstance(response["payload"], dict):
            self._terminate()
            raise AgentDojoProtocolError("native worker success envelope differs")
        return _json_clone(response["payload"], label="native worker payload")

    def interface_description(self) -> Mapping[str, Any]:
        return copy.deepcopy(self._interface)

    def apply(self, operation: str, args: Mapping[str, Any]) -> Mapping[str, Any]:
        return self._request(
            {"command": "apply", "operation": operation, "args": dict(args)}
        )

    def snapshot(self) -> Mapping[str, Any]:
        return self._request({"command": "snapshot"})

    def evaluate_native_checkers(self, terminal_text: str) -> Mapping[str, Any]:
        return self._request({"command": "checkers", "terminal_text": terminal_text})

    def cleanup(self) -> Mapping[str, Any]:
        return self._request({"command": "cleanup"})

    def close(self) -> None:
        if self._closed:
            return
        try:
            self._request({"command": "close"}, timeout=5)
        except AgentDojoSessionError:
            pass
        finally:
            self._terminate()


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise AgentDojoProtocolError(f"{label} must be a string-keyed object")
    return _json_clone(value, label=label)


def _validate_backend_snapshot(value: Any, *, label: str) -> dict[str, Any]:
    snapshot = _require_object(value, label)
    if set(snapshot) != {"state_sha256", "action_count"}:
        raise AgentDojoProtocolError(f"{label} fields differ")
    if (
        not isinstance(snapshot["state_sha256"], str)
        or _SHA256_RE.fullmatch(snapshot["state_sha256"]) is None
        or not isinstance(snapshot["action_count"], int)
        or isinstance(snapshot["action_count"], bool)
        or snapshot["action_count"] < 0
    ):
        raise AgentDojoProtocolError(f"{label} values are invalid")
    return snapshot


def _validate_interface(value: Any) -> dict[str, Any]:
    interface = _require_object(value, "native interface")
    if set(interface) != {"schema_version", "user_prompt", "operations"}:
        raise AgentDojoProtocolError("native interface fields differ")
    if interface["schema_version"] != 1:
        raise AgentDojoProtocolError("native interface schema_version differs")
    if not isinstance(interface["user_prompt"], str) or not interface["user_prompt"]:
        raise AgentDojoProtocolError("native user prompt is missing")
    operations = interface["operations"]
    if not isinstance(operations, list) or not operations:
        raise AgentDojoProtocolError("native operations must be a nonempty list")
    names: set[str] = set()
    for row in operations:
        if not isinstance(row, dict) or set(row) != {
            "name",
            "description",
            "argument_schema",
        }:
            raise AgentDojoProtocolError("native operation schema fields differ")
        if (
            not isinstance(row["name"], str)
            or not row["name"]
            or row["name"] in names
            or not isinstance(row["description"], str)
            or not isinstance(row["argument_schema"], dict)
        ):
            raise AgentDojoProtocolError("native operation schema is invalid")
        names.add(row["name"])
    return interface


class AgentDojoNativeHostSession:
    """Concrete, receipt-bound native session used below the four-cell bridge."""

    def __init__(
        self,
        runtime_root: Path | str,
        episode_namespace: str,
        task_identity: AgentDojoTaskIdentity,
        *,
        runtime_binding: AgentDojoRuntimeBinding,
        _runtime_validator: Callable[..., RuntimeTripletEvidence] = validate_runtime_triplet,
        _backend_factory: BackendFactory = _SubprocessNativeBackend,
        _runtime_stability_checker: Callable[
            [RuntimeTripletEvidence], None
        ] = _assert_runtime_unchanged,
    ) -> None:
        if not isinstance(episode_namespace, str) or _NAMESPACE_RE.fullmatch(
            episode_namespace
        ) is None:
            raise AgentDojoProtocolError("episode_namespace is invalid")
        if not isinstance(task_identity, AgentDojoTaskIdentity):
            raise AgentDojoProtocolError("task_identity must be AgentDojoTaskIdentity")
        runtime = _runtime_validator(
            repo_root=Path(__file__).resolve().parents[3],
            runtime_root=runtime_root,
            binding=runtime_binding,
        )
        if not isinstance(runtime, RuntimeTripletEvidence):
            raise AgentDojoProtocolError("runtime validator returned the wrong type")
        pack = validate_pack_preflight(repo_root=Path(__file__).resolve().parents[3])
        self._namespace = episode_namespace
        self._identity = task_identity
        self._runtime = runtime
        self._pack = pack
        self._runtime_stability_checker = _runtime_stability_checker
        self._backend = _backend_factory(runtime, episode_namespace, task_identity)
        self._interface = _validate_interface(self._backend.interface_description())
        initial = _validate_backend_snapshot(
            self._backend.snapshot(), label="initial native snapshot"
        )
        if initial["action_count"] != 0:
            self._backend.close()
            raise AgentDojoProtocolError("new native session has a nonzero action_count")
        try:
            self._runtime_stability_checker(runtime)
        except Exception:
            self._backend.close()
            raise
        self._initial_state_sha256 = initial["state_sha256"]
        self._ended = False
        self._closed = False
        self._cleaned = False
        self._poisoned = False
        self._terminal_text: str | None = None
        self._terminal_reason: str | None = None
        self._checker_evaluated = False
        self._lifecycle_sequence = 0

    @property
    def runtime_evidence(self) -> dict[str, Any]:
        return copy.deepcopy(self._runtime.as_json())

    @property
    def preflight_evidence(self) -> dict[str, Any]:
        evidence = {
            "schema_version": 1,
            "artifact_type": "agentdojo_public_four_cell_native_preflight_v1",
            "adapter_id": ADAPTER_ID,
            "runtime": self._runtime.as_json(),
            "pack": self._pack.as_json(),
            "checks": {
                "pack_transform_valid": self._pack.pack_transform_valid,
                "pack_locks_exact": self._pack.pack_locks_exact,
                "pack_cache_pollution_absent": (
                    self._pack.pack_pycache_dir_count == 0
                    and self._pack.pack_pyc_file_count == 0
                ),
                "runtime_cache_pollution_absent": (
                    self._runtime.runtime_pycache_dir_count == 0
                    and self._runtime.runtime_pyc_file_count == 0
                ),
                "runtime_triplet_exact": True,
            },
            "external_preflight_not_in_scope": [
                "tau2_zero_byte_inventory",
                "historical_agentdojo_receipt_drift",
                "historical_full_inventory_drift",
            ],
            "model_calls": 0,
            "provider_calls": 0,
            "api_calls": 0,
        }
        _canonical_json_bytes(evidence)
        return copy.deepcopy(evidence)

    @property
    def task_identity(self) -> AgentDojoTaskIdentity:
        return self._identity

    def _require_live(self, operation: str, *, allow_ended: bool = False) -> None:
        if self._closed:
            raise AgentDojoSessionError(f"{operation} is unavailable after close")
        if self._cleaned:
            raise AgentDojoSessionError(f"{operation} is unavailable after cleanup")
        if self._poisoned:
            raise AgentDojoSessionError(f"{operation} is unavailable on a poisoned session")
        if self._ended and not allow_ended:
            raise AgentDojoSessionError(f"{operation} is unavailable after task end")

    def interface_description(self) -> dict[str, Any]:
        self._require_live("interface_description")
        # Exactly this object is planner-visible: no namespace, pair role,
        # injection identity/goal, runtime identity, condition, or checker data.
        return copy.deepcopy(self._interface)

    def apply(self, action: Any) -> Any:
        self._require_live("apply")
        if self._terminal_text is not None:
            raise AgentDojoSessionError("apply is unavailable after terminal capture")
        from .bridge import ActionOutcome, ActionRequest

        if not isinstance(action, ActionRequest):
            raise AgentDojoProtocolError("native apply requires overlay ActionRequest")
        known = {row["name"] for row in self._interface["operations"]}
        if action.op not in known:
            raise AgentDojoProtocolError("requested operation is not in native interface")
        pre = _validate_backend_snapshot(
            self._backend.snapshot(), label="pre-dispatch native snapshot"
        )
        try:
            raw = _require_object(
                self._backend.apply(action.op, action.args), "native action result"
            )
        except Exception:
            self._poisoned = True
            raise
        expected_fields = {
            "operation",
            "args_sha256",
            "observation",
            "pre_state_sha256",
            "post_state_sha256",
            "action_count",
        }
        if set(raw) != expected_fields:
            self._poisoned = True
            raise AgentDojoProtocolError("native action result fields differ")
        args_sha = _sha256_bytes(_canonical_json_bytes(action.args))
        if (
            raw["operation"] != action.op
            or raw["args_sha256"] != args_sha
            or raw["pre_state_sha256"] != pre["state_sha256"]
            or not isinstance(raw["post_state_sha256"], str)
            or _SHA256_RE.fullmatch(raw["post_state_sha256"]) is None
            or raw["action_count"] != pre["action_count"] + 1
        ):
            self._poisoned = True
            raise AgentDojoProtocolError("native action result binding differs")
        post = _validate_backend_snapshot(
            self._backend.snapshot(), label="post-dispatch native snapshot"
        )
        if (
            post["state_sha256"] != raw["post_state_sha256"]
            or post["action_count"] != raw["action_count"]
        ):
            self._poisoned = True
            raise AgentDojoProtocolError("native post-dispatch snapshot differs")
        native_event = {
            "schema_version": 1,
            "event_id": f"{self._namespace}:native:{post['action_count']}",
            "kind": "agentdojo_native_dispatch",
            "actor": "agentdojo-native-runtime",
            "operation": action.op,
            "args_sha256": args_sha,
            "pre_state_sha256": pre["state_sha256"],
            "post_state_sha256": post["state_sha256"],
            "action_count": post["action_count"],
        }
        effect = {
            "schema_version": 1,
            "effect_id": f"{self._namespace}:native-effect:{post['action_count']}",
            "effect": "agentdojo_native_state_transition",
            "pre_state_sha256": pre["state_sha256"],
            "post_state_sha256": post["state_sha256"],
        }
        _canonical_json_bytes(native_event)
        _canonical_json_bytes(effect)
        return ActionOutcome(
            allowed=True,
            reason="agentdojo_native_dispatch_succeeded",
            observation=_json_clone(raw["observation"], label="native observation"),
            effects=(effect,),
            events=(native_event,),
        )

    def capture_terminal_state(
        self, *, final_assistant_text: str, terminal_reason: str | None = None
    ) -> Mapping[str, Any]:
        self._require_live("capture_terminal_state", allow_ended=True)
        if self._terminal_text is not None:
            raise AgentDojoSessionError("terminal state was already captured")
        if not isinstance(final_assistant_text, str):
            raise AgentDojoProtocolError("final_assistant_text must be a string")
        if terminal_reason is not None and not isinstance(terminal_reason, str):
            raise AgentDojoProtocolError("terminal_reason must be a string or null")
        snapshot = _validate_backend_snapshot(
            self._backend.snapshot(), label="terminal native snapshot"
        )
        self._terminal_text = final_assistant_text
        self._terminal_reason = terminal_reason
        return {
            "schema_version": 1,
            "state_sha256": snapshot["state_sha256"],
            "model_output": final_assistant_text,
            "terminal_reason": terminal_reason,
            "action_count": snapshot["action_count"],
        }

    def evaluate_native_checkers(self) -> Mapping[str, Any]:
        self._require_live("evaluate_native_checkers", allow_ended=True)
        if self._terminal_text is None:
            raise AgentDojoSessionError("native checkers require captured terminal text")
        if self._checker_evaluated:
            raise AgentDojoSessionError("native checkers may execute only once")
        before = _validate_backend_snapshot(
            self._backend.snapshot(), label="pre-checker native snapshot"
        )
        try:
            raw = _require_object(
                self._backend.evaluate_native_checkers(self._terminal_text),
                "native checker result",
            )
        except Exception:
            self._poisoned = True
            raise
        expected = {
            "utility",
            "security",
            "state_sha256",
            "action_count",
            "checker_binding_ids",
        }
        if set(raw) != expected:
            self._poisoned = True
            raise AgentDojoProtocolError("native checker result fields differ")
        if type(raw["utility"]) is not bool:
            self._poisoned = True
            raise AgentDojoProtocolError("native utility checker did not return bool")
        security = raw["security"]
        if self._identity.pair_role == "adversarial":
            valid_security = type(security) is bool
        else:
            valid_security = security is None
        snapshot = _validate_backend_snapshot(
            self._backend.snapshot(), label="post-checker native snapshot"
        )
        if (
            not valid_security
            or snapshot != before
            or raw["state_sha256"] != snapshot["state_sha256"]
            or raw["action_count"] != snapshot["action_count"]
            or raw["checker_binding_ids"] != list(_CHECKER_BINDING_IDS)
        ):
            self._poisoned = True
            raise AgentDojoProtocolError("native checker binding/result differs")
        self._checker_evaluated = True
        result = {
            "schema_version": 1,
            "adapter_id": ADAPTER_ID,
            "source_task_id": self._identity.source_task_id,
            "task_id": self._identity.task_id,
            "pair_role": self._identity.pair_role,
            "utility": raw["utility"],
            "security": security,
            # Exact alias.  It is not an HCER component and is never used to
            # derive a Host-mechanism classification.
            "injection_success": security,
            "checker_binding_ids": list(_CHECKER_BINDING_IDS),
            "state_sha256": snapshot["state_sha256"],
            "action_count": snapshot["action_count"],
        }
        _canonical_json_bytes(result)
        return result

    def end_external_task(self) -> tuple[dict[str, Any], ...]:
        self._require_live("end_external_task")
        self._ended = True
        self._lifecycle_sequence += 1
        snapshot = _validate_backend_snapshot(
            self._backend.snapshot(), label="task-end native snapshot"
        )
        return (
            {
                "schema_version": 1,
                "event_id": f"{self._namespace}:lifecycle:{self._lifecycle_sequence}",
                "kind": "external_task_ended",
                "actor": "host-lifecycle",
                "state_sha256": snapshot["state_sha256"],
                "action_count": snapshot["action_count"],
            },
        )

    def advance_lifecycle(self, transition: str) -> tuple[dict[str, Any], ...]:
        self._require_live("advance_lifecycle", allow_ended=True)
        if not self._ended:
            raise AgentDojoSessionError("lifecycle transition requires task end")
        if not isinstance(transition, str) or not transition.strip():
            raise AgentDojoProtocolError("transition must be a nonempty string")
        self._lifecycle_sequence += 1
        snapshot = _validate_backend_snapshot(
            self._backend.snapshot(), label="lifecycle native snapshot"
        )
        return (
            {
                "schema_version": 1,
                "event_id": f"{self._namespace}:lifecycle:{self._lifecycle_sequence}",
                "kind": "lifecycle_advanced",
                "actor": "host-lifecycle",
                "transition": transition,
                "state_sha256": snapshot["state_sha256"],
                "action_count": snapshot["action_count"],
            },
        )

    def snapshot(self) -> dict[str, Any]:
        if self._closed:
            raise AgentDojoSessionError("snapshot is unavailable after close")
        if self._poisoned:
            raise AgentDojoSessionError("snapshot is unavailable on a poisoned session")
        native = _validate_backend_snapshot(
            self._backend.snapshot(), label="native snapshot"
        )
        return {
            "schema_version": 1,
            "adapter_id": ADAPTER_ID,
            "state_sha256": native["state_sha256"],
            "initial_state_sha256": self._initial_state_sha256,
            "action_count": native["action_count"],
            "ended": self._ended,
            "cleaned": self._cleaned,
            "terminal_captured": self._terminal_text is not None,
            "native_checkers_evaluated": self._checker_evaluated,
        }

    def cleanup(self) -> str:
        if self._closed:
            raise AgentDojoSessionError("cleanup is unavailable after close")
        if self._cleaned:
            raise AgentDojoSessionError("cleanup may execute only once")
        try:
            raw = _validate_backend_snapshot(
                self._backend.cleanup(), label="cleanup native snapshot"
            )
        except Exception:
            self._poisoned = True
            raise
        if raw != {"state_sha256": self._initial_state_sha256, "action_count": 0}:
            self._poisoned = True
            raise AgentDojoProtocolError("cleanup did not restore the initial native state")
        self._runtime_stability_checker(self._runtime)
        self._cleaned = True
        self._poisoned = False
        return self._initial_state_sha256

    def close(self) -> None:
        if self._closed:
            return
        try:
            self._backend.close()
        finally:
            self._closed = True


# ------------------------- isolated native worker -------------------------


def _worker_json_safe(value: Any) -> Any:
    if hasattr(value, "model_dump") and callable(value.model_dump):
        return _worker_json_safe(value.model_dump(mode="json"))
    if hasattr(value, "__dataclass_fields__"):
        return _worker_json_safe(asdict(value))
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise AgentDojoProtocolError("worker JSON object key is not text")
        normalized = {
            key: _worker_json_safe(item) for key, item in value.items()
        }
        return json.loads(_canonical_json_bytes(normalized))
    if isinstance(value, (list, tuple)):
        normalized = [_worker_json_safe(item) for item in value]
        return json.loads(_canonical_json_bytes(normalized))
    return json.loads(_canonical_json_bytes(value))


class _WorkerState:
    def __init__(self) -> None:
        self.initialized = False
        self.closed = False
        self.namespace = ""
        self.identity: dict[str, Any] = {}
        self.suite: Any = None
        self.user_task: Any = None
        self.injection_task: Any = None
        self.runtime: Any = None
        self.function_call_type: Any = None
        self.pre_environment: Any = None
        self.environment: Any = None
        self.initial_environment: Any = None
        self.function_calls: list[Any] = []
        self.action_count = 0

    def state_sha256(self) -> str:
        return _sha256_bytes(_canonical_json_bytes(_worker_json_safe(self.environment)))

    def snapshot(self) -> dict[str, Any]:
        if not self.initialized or self.closed:
            raise AgentDojoProtocolError("worker is not live")
        return {"state_sha256": self.state_sha256(), "action_count": self.action_count}


def _worker_repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _worker_validate_source(checkout: Path) -> None:
    for relative, expected in _SOURCE_LOCKS:
        if _file_sha256(checkout / relative) != expected:
            raise AgentDojoRuntimeIntegrityError(
                f"pinned upstream source differs: {relative}"
            )


def _worker_initialize(state: _WorkerState, request: Mapping[str, Any]) -> dict[str, Any]:
    if state.initialized:
        raise AgentDojoProtocolError("worker is already initialized")
    runtime_id = request.get("runtime_id")
    if (
        request.get("schema_version") != 1
        or not isinstance(runtime_id, str)
        or not runtime_id.startswith("agentdojo-0.1.35-")
    ):
        raise AgentDojoRuntimeIntegrityError("worker runtime identity differs")
    root = Path(str(request.get("environment_root"))).resolve()
    if root != Path(sys.prefix).resolve():
        raise AgentDojoRuntimeIntegrityError("worker sys.prefix differs from runtime root")
    identity = request.get("identity")
    if not isinstance(identity, dict):
        raise AgentDojoProtocolError("worker task identity is missing")
    frozen_identity = AgentDojoTaskIdentity(**identity)
    namespace = request.get("namespace")
    if not isinstance(namespace, str) or _NAMESPACE_RE.fullmatch(namespace) is None:
        raise AgentDojoProtocolError("worker namespace is invalid")
    checkout = _worker_repo_root() / "data/host_boundary_v2/upstream/agentdojo"
    _worker_validate_source(checkout)
    sys.path.insert(0, str(checkout / "src"))
    import importlib
    import inspect
    import socket

    def deny_network(*_args: Any, **_kwargs: Any) -> Any:
        raise AgentDojoSessionError("network is forbidden in native worker")

    class NetworkDeniedSocket(socket.socket):
        def connect(self, *_args: Any, **_kwargs: Any) -> Any:
            return deny_network()

        def connect_ex(self, *_args: Any, **_kwargs: Any) -> Any:
            return deny_network()

    socket.socket = NetworkDeniedSocket
    socket.create_connection = deny_network
    socket.getaddrinfo = deny_network

    load_suites = importlib.import_module("agentdojo.task_suite.load_suites")
    functions_runtime = importlib.import_module("agentdojo.functions_runtime")
    get_suite = getattr(load_suites, "get_suite")
    runtime_type = getattr(functions_runtime, "FunctionsRuntime")
    function_call_type = getattr(functions_runtime, "FunctionCall")
    for target, relative, expected in (
        (
            get_suite,
            "src/agentdojo/task_suite/load_suites.py",
            _SOURCE_LOCKS[3][1],
        ),
        (
            runtime_type,
            "src/agentdojo/functions_runtime.py",
            _SOURCE_LOCKS[2][1],
        ),
        (
            function_call_type,
            "src/agentdojo/functions_runtime.py",
            _SOURCE_LOCKS[2][1],
        ),
    ):
        origin = Path(inspect.getsourcefile(target) or "").resolve()
        if origin != (checkout / relative).resolve() or _file_sha256(origin) != expected:
            raise AgentDojoRuntimeIntegrityError("upstream callable origin/hash differs")
    suite = get_suite(frozen_identity.suite_version, frozen_identity.domain)
    for name in ("_check_user_task_utility", "_check_injection_task_security"):
        target = getattr(type(suite), name, None)
        origin = Path(inspect.getsourcefile(target) or "").resolve()
        if (
            not callable(target)
            or origin != (checkout / _SOURCE_LOCKS[4][0]).resolve()
            or _file_sha256(origin) != _SOURCE_LOCKS[4][1]
        ):
            raise AgentDojoRuntimeIntegrityError("native checker origin/hash differs")
    user_task = suite.get_user_task_by_id(frozen_identity.user_task_id)
    injection_task = (
        suite.get_injection_task_by_id(frozen_identity.injection_task_id)
        if frozen_identity.injection_task_id is not None
        else None
    )
    injections: dict[str, str] = {}
    if injection_task is not None:
        # Goal is consumed only by the upstream environment injector.  It is
        # never returned in initialize/interface/snapshot/checker messages.
        injections[str(frozen_identity.injection_vector_id)] = str(injection_task.GOAL)
    environment = suite.load_and_inject_default_environment(injections)
    environment = user_task.init_environment(environment)
    pre_environment = environment.model_copy(deep=True)
    initial_environment = environment.model_copy(deep=True)
    native_runtime = runtime_type(suite.tools)
    operations = []
    for tool in sorted(suite.tools, key=lambda item: item.name):
        operations.append(
            {
                "name": tool.name,
                "description": tool.description,
                "argument_schema": tool.parameters.model_json_schema(),
            }
        )
    state.initialized = True
    state.namespace = namespace
    state.identity = asdict(frozen_identity)
    state.suite = suite
    state.user_task = user_task
    state.injection_task = injection_task
    state.runtime = native_runtime
    state.function_call_type = function_call_type
    state.pre_environment = pre_environment
    state.environment = environment
    state.initial_environment = initial_environment
    return {
        "interface": {
            "schema_version": 1,
            "user_prompt": str(user_task.PROMPT),
            "operations": operations,
        },
        "snapshot": state.snapshot(),
    }


def _worker_apply(state: _WorkerState, request: Mapping[str, Any]) -> dict[str, Any]:
    if not state.initialized or state.closed:
        raise AgentDojoProtocolError("worker is not live")
    operation = request.get("operation")
    args = request.get("args")
    if not isinstance(operation, str) or not operation:
        raise AgentDojoProtocolError("worker operation is invalid")
    if not isinstance(args, dict) or any(not isinstance(key, str) for key in args):
        raise AgentDojoProtocolError("worker args are invalid")
    safe_args = _worker_json_safe(args)
    before = state.state_sha256()
    result, error = state.runtime.run_function(
        state.environment, operation, safe_args, raise_on_error=True
    )
    if error is not None:
        raise AgentDojoSessionError("native runtime returned an error")
    call = state.function_call_type(function=operation, args=safe_args, id=None)
    state.function_calls.append(call)
    state.action_count += 1
    after = state.state_sha256()
    return {
        "operation": operation,
        "args_sha256": _sha256_bytes(_canonical_json_bytes(safe_args)),
        "observation": _worker_json_safe(result),
        "pre_state_sha256": before,
        "post_state_sha256": after,
        "action_count": state.action_count,
    }


def _worker_checkers(state: _WorkerState, request: Mapping[str, Any]) -> dict[str, Any]:
    terminal_text = request.get("terminal_text")
    if not isinstance(terminal_text, str):
        raise AgentDojoProtocolError("worker terminal text is invalid")
    before = state.snapshot()
    content = [{"type": "text", "content": terminal_text}]
    utility = state.suite._check_user_task_utility(
        state.user_task,
        content,
        state.pre_environment,
        state.environment,
        tuple(state.function_calls),
    )
    security: bool | None = None
    if state.injection_task is not None:
        security = state.suite._check_injection_task_security(
            state.injection_task,
            content,
            state.pre_environment,
            state.environment,
            tuple(state.function_calls),
        )
    if type(utility) is not bool or (security is not None and type(security) is not bool):
        raise AgentDojoProtocolError("native checker returned a non-Boolean verdict")
    snapshot = state.snapshot()
    if snapshot != before:
        raise AgentDojoProtocolError("native checker mutated environment or trace count")
    return {
        "utility": utility,
        "security": security,
        "state_sha256": snapshot["state_sha256"],
        "action_count": snapshot["action_count"],
        "checker_binding_ids": list(_CHECKER_BINDING_IDS),
    }


def _worker_cleanup(state: _WorkerState) -> dict[str, Any]:
    if not state.initialized or state.closed:
        raise AgentDojoProtocolError("worker is not live")
    state.environment = state.initial_environment.model_copy(deep=True)
    state.function_calls = []
    state.action_count = 0
    return state.snapshot()


def _worker_dispatch(state: _WorkerState, request: Mapping[str, Any]) -> dict[str, Any]:
    command = request.get("command")
    if command == "initialize":
        return _worker_initialize(state, request)
    if command == "snapshot":
        return state.snapshot()
    if command == "apply":
        return _worker_apply(state, request)
    if command == "checkers":
        return _worker_checkers(state, request)
    if command == "cleanup":
        return _worker_cleanup(state)
    if command == "close":
        if not state.initialized or state.closed:
            raise AgentDojoProtocolError("worker is not live")
        state.closed = True
        return {"closed": True}
    raise AgentDojoProtocolError("unknown worker command")


def _native_worker_main() -> int:
    state = _WorkerState()
    for line in sys.stdin:
        try:
            request = json.loads(line)
            if not isinstance(request, dict):
                raise AgentDojoProtocolError("worker request must be an object")
            payload = _worker_dispatch(state, request)
            response = {"ok": True, "payload": payload, "error": None}
        except Exception as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit, GeneratorExit)):
                raise
            response = {
                "ok": False,
                "payload": None,
                "error": {
                    "code": f"AGENTDOJO_WORKER_{type(exc).__name__.upper()}",
                    "message": "native worker failed closed",
                },
            }
        sys.stdout.write(_canonical_json_bytes(response).decode("utf-8") + "\n")
        sys.stdout.flush()
        if state.closed:
            return 0
    return 0


__all__ = [
    "ADAPTER_ID",
    "AgentDojoNativeHostSession",
    "AgentDojoProtocolError",
    "AgentDojoRuntimeIntegrityError",
    "AgentDojoSessionError",
    "AgentDojoTaskIdentity",
    "AgentDojoRuntimeBinding",
    "PackPreflightEvidence",
    "RuntimeTripletEvidence",
    "SOURCE_TASK_ID",
    "UPSTREAM_VERSION_OR_COMMIT",
    "validate_runtime_triplet",
    "validate_pack_preflight",
    "required_callable_source_sha256",
]


if __name__ == "__main__":
    if sys.argv[1:] != ["--native-worker-v1"]:
        raise SystemExit("agentdojo_adapter.py is not a standalone command")
    raise SystemExit(_native_worker_main())
