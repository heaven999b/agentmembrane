"""Exact-pin, fail-closed AgentDojo v0.1.35 public-benchmark adapter.

The adapter never imports AgentDojo at module import time.  A native runtime is
usable only after the immutable checkout, pack bytes, Python runtime,
dependencies, and checker dispatchers all pass :meth:`preflight`.  In
particular, registering this class is not evidence that AgentDojo is executable
and this module never substitutes AgentMembrane logic for the upstream native
utility/security checkers.
"""

from __future__ import annotations

from dataclasses import dataclass
import importlib
import importlib.metadata
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, ClassVar, Mapping, Sequence

from .public_adapters import (
    ADAPTER_CONTRACT_VERSION,
    NativeCheckerVerdict,
    ProjectedCheckerVerdict,
    PublicBenchmarkAdapter,
)
from .projected_checker import (
    FieldProvenance,
    PROJECTED_CHECKER_CONTRACT_VERSION,
    ProjectedCheckerResult,
    ProjectedCheckerSnapshot,
    evaluate_projected_snapshot as evaluate_shared_projected_snapshot,
    projected_snapshot_from_mapping,
)
from .schema import IntegrityError, SchemaError, sha256_bytes, sha256_json


AGENTDOJO_VERSION = "0.1.35"
AGENTDOJO_COMMIT = "089ed468cf3ed0322acc66b0211f26d9d90dbf60"
AGENTDOJO_VERSION_OR_COMMIT = f"{AGENTDOJO_VERSION}@{AGENTDOJO_COMMIT}"
AGENTDOJO_SUITE_VERSION = "v1"
AGENTDOJO_PACK_ID = "host-v2-agentdojo-v0.1.35-v1"
AGENTDOJO_ADAPTER_ID = "agentdojo-v0.1.35-native-v1"
AGENTDOJO_PREFLIGHT_ARTIFACT = "agentmembrane_public_adapter_runtime_preflight"

# The full projected-checker schema intentionally has no upstream utility,
# security, reward, or verdict field.  Keep this list local to the benchmark
# adapter too, so a JSON-shaped caller cannot smuggle one into the strict
# shared parser and later claim that the adapter consumed it.
_PROHIBITED_PROJECTED_FIELD_NAMES = frozenset(
    {
        "checker_binding_ids",
        "native_output",
        "native_output_sha256",
        "native_reward",
        "native_verdict",
        "reward",
        "security",
        "task_checker_refs",
        "upstream_reward",
        "upstream_verdict",
        "utility",
        "verdict",
    }
)
_PROHIBITED_PROJECTED_VALUE_TOKENS = (
    "native_reward",
    "native_verdict",
    "upstream_reward",
    "upstream_verdict",
)
_AGENTDOJO_PROJECTED_SOURCE_KINDS = {
    "authorization": frozenset({"authorization_log"}),
    "event": frozenset({"adapter_trace", "host_event_log"}),
    "mechanism": frozenset({"mechanism_mapping"}),
    "state_delta": frozenset({"state_snapshot"}),
    "terminal": frozenset({"terminal_capture"}),
}

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_AGENTDOJO_CHECKOUT = (
    _REPOSITORY_ROOT / "data/host_boundary_v2/upstream/agentdojo"
)
DEFAULT_AGENTDOJO_PACK = (
    _REPOSITORY_ROOT / "data/host_boundary_v2/packs/agentdojo-v0.1.35-v1"
)


class AgentDojoRuntimeError(IntegrityError):
    """The pinned native AgentDojo runtime cannot be used safely."""


@dataclass
class _ActiveEpisode:
    requested_source_task_id: str
    source_task_id: str
    task_id: str
    domain: str
    pair_role: str
    fixture: dict[str, Any]
    oracle: dict[str, Any]
    suite: Any
    user_task: Any
    injection_task: Any | None
    injections: dict[str, str]
    pre_environment: Any
    environment: Any
    runtime: Any
    function_calls: list[Any]
    trace: list[dict[str, Any]]
    initial_state_sha256: str


def _json_safe(value: Any) -> Any:
    """Return a strict JSON value without repr/string fallbacks."""

    if value is None or isinstance(value, (str, bool, int, float)):
        sha256_json(value)
        return value
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise SchemaError("native mapping keys must be strings")
            result[key] = _json_safe(item)
        sha256_json(result)
        return result
    if isinstance(value, (list, tuple)):
        result = [_json_safe(item) for item in value]
        sha256_json(result)
        return result
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        try:
            return _json_safe(model_dump(mode="json"))
        except TypeError:
            return _json_safe(model_dump())
    raise SchemaError(
        f"native AgentDojo value is not deterministically JSON-safe: {type(value).__name__}"
    )


def _copy_environment(value: Any) -> Any:
    copier = getattr(value, "model_copy", None)
    if callable(copier):
        return copier(deep=True)
    copier = getattr(value, "copy", None)
    if callable(copier):
        try:
            return copier(deep=True)
        except TypeError:
            pass
    raise AgentDojoRuntimeError(
        "AGENTDOJO_ENVIRONMENT_NOT_DEEPCOPYABLE: native environment lacks model_copy(deep=True)"
    )


def _reject_projected_native_signals(value: Any, *, path: str = "$") -> None:
    """Reject fields that could couple the projection to a native outcome.

    This check happens before strict shared-schema parsing.  It deliberately
    inspects field names only for generic words such as ``utility`` and
    ``security`` so legitimate action strings are not reinterpreted as native
    checker output.  Explicit native/upstream reward or verdict tokens are
    prohibited anywhere in the typed evidence.
    """

    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise SchemaError(f"projected snapshot key at {path} must be a string")
            lowered = key.casefold()
            if lowered in _PROHIBITED_PROJECTED_FIELD_NAMES:
                raise AgentDojoRuntimeError(
                    "AGENTDOJO_PROJECTED_NATIVE_SIGNAL_PROHIBITED: "
                    f"field {path}.{key} is outside the independent contract"
                )
            _reject_projected_native_signals(item, path=f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_projected_native_signals(item, path=f"{path}[{index}]")
        return
    if isinstance(value, str):
        lowered = value.casefold()
        if any(token in lowered for token in _PROHIBITED_PROJECTED_VALUE_TOKENS):
            raise AgentDojoRuntimeError(
                "AGENTDOJO_PROJECTED_NATIVE_SIGNAL_PROHIBITED: "
                f"value at {path} names upstream/native outcome material"
            )


def _validate_projected_provenance_role(
    provenance: tuple[FieldProvenance, ...],
    *,
    allowed_source_kinds: frozenset[str],
    label: str,
) -> None:
    """Bind present provenance rows to AgentDojo and their evidence role.

    Empty tuples are left for the shared evaluator, which reports them as
    insufficient evidence/NO-GO.  Present rows, however, cannot claim another
    benchmark's source namespace or reuse the wrong source kind.
    """

    seen_paths: set[str] = set()
    for index, row in enumerate(provenance):
        if not isinstance(row, FieldProvenance):
            raise SchemaError(f"{label}[{index}] must be FieldProvenance")
        if row.source_kind not in allowed_source_kinds:
            raise AgentDojoRuntimeError(
                "AGENTDOJO_PROJECTED_PROVENANCE_INVALID: "
                f"{label}[{index}] source_kind is not valid for this evidence role"
            )
        if not row.source_id.startswith("agentdojo:"):
            raise AgentDojoRuntimeError(
                "AGENTDOJO_PROJECTED_PROVENANCE_INVALID: "
                f"{label}[{index}] source_id is not AgentDojo-scoped"
            )
        if row.field_path in seen_paths:
            raise AgentDojoRuntimeError(
                "AGENTDOJO_PROJECTED_PROVENANCE_INVALID: "
                f"{label} repeats field-level provenance path {row.field_path!r}"
            )
        seen_paths.add(row.field_path)


def _validate_agentdojo_projected_provenance(
    snapshot: ProjectedCheckerSnapshot,
) -> None:
    for index, event in enumerate(snapshot.events):
        _validate_projected_provenance_role(
            event.provenance,
            allowed_source_kinds=_AGENTDOJO_PROJECTED_SOURCE_KINDS["event"],
            label=f"events[{index}].provenance",
        )
        _validate_projected_provenance_role(
            event.authorization.provenance,
            allowed_source_kinds=_AGENTDOJO_PROJECTED_SOURCE_KINDS["authorization"],
            label=f"events[{index}].authorization.provenance",
        )
    _validate_projected_provenance_role(
        snapshot.state_delta.provenance,
        allowed_source_kinds=_AGENTDOJO_PROJECTED_SOURCE_KINDS["state_delta"],
        label="state_delta.provenance",
    )
    _validate_projected_provenance_role(
        snapshot.terminal.provenance,
        allowed_source_kinds=_AGENTDOJO_PROJECTED_SOURCE_KINDS["terminal"],
        label="terminal.provenance",
    )
    for index, evidence in enumerate(snapshot.mechanism_evidence):
        _validate_projected_provenance_role(
            evidence.provenance,
            allowed_source_kinds=_AGENTDOJO_PROJECTED_SOURCE_KINDS["mechanism"],
            label=f"mechanism_evidence[{index}].provenance",
        )


class AgentDojoAdapter(PublicBenchmarkAdapter):
    """Concrete adapter for the locally pinned AgentDojo v0.1.35 suite-v1."""

    adapter_id: ClassVar[str] = AGENTDOJO_ADAPTER_ID
    benchmark: ClassVar[str] = "AgentDojo"
    upstream_version_or_commit: ClassVar[str] = AGENTDOJO_VERSION_OR_COMMIT
    contract_version: ClassVar[str] = ADAPTER_CONTRACT_VERSION
    required_python: ClassVar[str] = ">=3.10"

    # These locks bind the package version, native task/checker dispatch, suite
    # registry, and tool runtime.  Per-task checker source locks are additionally
    # verified from the frozen fixture/oracle before every reset.
    SOURCE_LOCKS: ClassVar[tuple[tuple[str, str], ...]] = (
        (
            "pyproject.toml",
            "f69dde819258d5dc2c6dca13ecbb116e54904374879a5c921332db36474e0a3b",
        ),
        (
            "uv.lock",
            "395e3d0a59214515008d27c4462c9723ab7594374243f561ad5f19b3aa8a5330",
        ),
        (
            "src/agentdojo/base_tasks.py",
            "08d3a4646d1a250968045b0f933803335650a4ed04c9d2387b17d08b1e0427c5",
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
    )
    PACK_LOCKS: ClassVar[tuple[tuple[str, str], ...]] = (
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
    )
    REQUIRED_MODULES: ClassVar[tuple[tuple[str, str], ...]] = (
        ("deepdiff", "deepdiff"),
        ("docstring_parser", "docstring-parser"),
        ("email_validator", "email-validator"),
        ("pydantic", "pydantic"),
        ("typing_extensions", "typing-extensions"),
        ("yaml", "PyYAML"),
    )
    DEPENDENCY_VERSIONS: ClassVar[Mapping[str, str]] = {
        "deepdiff": "8.6.1",
        "docstring_parser": "0.16",
        "email_validator": "2.2.0",
        "pydantic": "2.11.4",
        "typing_extensions": "4.13.2",
        "yaml": "6.0.2",
    }
    CHECKER_BINDINGS: ClassVar[tuple[dict[str, str], ...]] = (
        {
            "binding_id": "agentdojo-v0.1.35-native-utility-dispatcher",
            "callable_ref": (
                "agentdojo.task_suite.task_suite.TaskSuite:_check_user_task_utility"
            ),
            "source_path": "src/agentdojo/task_suite/task_suite.py",
            "source_sha256": (
                "2e69da06f7e150dd6d238c53a74845b56eebeb224e07f694e1051a6e0c6a2bc1"
            ),
        },
        {
            "binding_id": "agentdojo-v0.1.35-native-security-dispatcher",
            "callable_ref": (
                "agentdojo.task_suite.task_suite.TaskSuite:_check_injection_task_security"
            ),
            "source_path": "src/agentdojo/task_suite/task_suite.py",
            "source_sha256": (
                "2e69da06f7e150dd6d238c53a74845b56eebeb224e07f694e1051a6e0c6a2bc1"
            ),
        },
    )

    def __init__(
        self,
        *,
        checkout_root: str | Path = DEFAULT_AGENTDOJO_CHECKOUT,
        pack_root: str | Path = DEFAULT_AGENTDOJO_PACK,
    ) -> None:
        self.checkout_root = Path(checkout_root).resolve()
        self.pack_root = Path(pack_root).resolve()
        self._native: dict[str, Any] | None = None
        self._active: _ActiveEpisode | None = None
        self._task_index: dict[str, dict[str, Any]] | None = None

    @staticmethod
    def _implementation_sha256() -> str:
        return sha256_bytes(Path(__file__).resolve().read_bytes())

    @staticmethod
    def _hash_locks(
        root: Path, locks: Sequence[tuple[str, str]]
    ) -> tuple[list[dict[str, Any]], bool]:
        rows: list[dict[str, Any]] = []
        exact = True
        for relative, expected in sorted(locks):
            path = root / relative
            actual = sha256_bytes(path.read_bytes()) if path.is_file() else None
            matches = actual == expected
            exact = exact and matches
            rows.append(
                {
                    "path": relative,
                    "expected_sha256": expected,
                    "actual_sha256": actual,
                    "matches": matches,
                }
            )
        return rows, exact

    def _git_identity(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "head": None,
            "status_entries": [],
            "head_available": False,
            "tree_clean": False,
        }
        if not self.checkout_root.is_dir():
            return result
        try:
            head = subprocess.run(
                ["git", "-C", str(self.checkout_root), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            ).stdout.strip()
            status = subprocess.run(
                [
                    "git",
                    "-C",
                    str(self.checkout_root),
                    "status",
                    "--porcelain=v1",
                    "--untracked-files=all",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=20,
            ).stdout.splitlines()
        except (OSError, subprocess.SubprocessError):
            return result
        entries = sorted(line.rstrip() for line in status if line.rstrip())
        return {
            "head": head,
            "status_entries": entries,
            "head_available": len(head) == 40,
            "tree_clean": not entries,
        }

    @classmethod
    def _dependency_status(cls) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for module, distribution in sorted(cls.REQUIRED_MODULES):
            try:
                available = importlib.util.find_spec(module) is not None
            except (ImportError, AttributeError, ValueError):
                available = False
            version: str | None = None
            if available:
                try:
                    version = importlib.metadata.version(distribution)
                except importlib.metadata.PackageNotFoundError:
                    version = None
            rows.append(
                {"module": module, "available": available, "version": version}
            )
        return rows

    def _import_native_runtime(self) -> dict[str, Any]:
        source_root = (self.checkout_root / "src").resolve()
        loaded = sys.modules.get("agentdojo")
        if loaded is not None:
            module_file = getattr(loaded, "__file__", None)
            if not isinstance(module_file, str):
                raise AgentDojoRuntimeError(
                    "AGENTDOJO_MODULE_ORIGIN_UNKNOWN: already-loaded agentdojo has no file"
                )
            try:
                Path(module_file).resolve().relative_to(source_root)
            except ValueError as exc:
                raise AgentDojoRuntimeError(
                    "AGENTDOJO_MODULE_ORIGIN_MISMATCH: already-loaded agentdojo is not pinned checkout"
                ) from exc

        inserted = str(source_root) not in sys.path
        if inserted:
            sys.path.insert(0, str(source_root))
        try:
            load_suites = importlib.import_module("agentdojo.task_suite.load_suites")
            task_suite = importlib.import_module("agentdojo.task_suite.task_suite")
            functions_runtime = importlib.import_module("agentdojo.functions_runtime")
        finally:
            if inserted:
                try:
                    sys.path.remove(str(source_root))
                except ValueError:
                    pass
        return {
            "get_suite": getattr(load_suites, "get_suite", None),
            "TaskSuite": getattr(task_suite, "TaskSuite", None),
            "FunctionsRuntime": getattr(functions_runtime, "FunctionsRuntime", None),
            "FunctionCall": getattr(functions_runtime, "FunctionCall", None),
        }

    @staticmethod
    def _native_callables_available(native: Mapping[str, Any]) -> bool:
        task_suite = native.get("TaskSuite")
        return bool(
            callable(native.get("get_suite"))
            and callable(native.get("FunctionsRuntime"))
            and callable(native.get("FunctionCall"))
            and isinstance(task_suite, type)
            and callable(getattr(task_suite, "_check_user_task_utility", None))
            and callable(getattr(task_suite, "_check_injection_task_security", None))
        )

    def preflight(self) -> Mapping[str, Any]:
        """Return deterministic, JSON-safe evidence of native executability."""

        git = self._git_identity()
        source_locks, source_exact = self._hash_locks(
            self.checkout_root, self.SOURCE_LOCKS
        )
        pack_locks, pack_exact = self._hash_locks(self.pack_root, self.PACK_LOCKS)
        dependencies = self._dependency_status()
        dependency_exact = all(row["available"] for row in dependencies)
        dependency_versions_exact = all(
            not row["available"]
            or row["version"] == self.DEPENDENCY_VERSIONS[row["module"]]
            for row in dependencies
        )
        python_compatible = sys.version_info >= (3, 10)
        checkout_exists = self.checkout_root.is_dir()
        pack_exists = self.pack_root.is_dir()

        native_importable = False
        import_blocker: tuple[str, str] | None = None
        if (
            checkout_exists
            and pack_exists
            and git["head"] == AGENTDOJO_COMMIT
            and git["tree_clean"]
            and source_exact
            and pack_exact
            and python_compatible
            and dependency_exact
            and dependency_versions_exact
        ):
            try:
                native = self._import_native_runtime()
                native_importable = self._native_callables_available(native)
                if native_importable:
                    self._native = dict(native)
                else:
                    import_blocker = (
                        "AGENTDOJO_NATIVE_CHECKER_UNAVAILABLE",
                        "pinned AgentDojo native checker dispatchers are not callable",
                    )
            except Exception as exc:  # normalized; raw messages are intentionally omitted
                if isinstance(exc, ModuleNotFoundError) and exc.name:
                    import_blocker = (
                        f"AGENTDOJO_DEPENDENCY_MISSING:{exc.name}",
                        f"native import requires missing module {exc.name}",
                    )
                else:
                    import_blocker = (
                        "AGENTDOJO_NATIVE_IMPORT_FAILED",
                        f"pinned native import failed with {type(exc).__name__}",
                    )

        checks = {
            "checkout_exists": checkout_exists,
            "dependencies_available": dependency_exact,
            "dependency_versions_exact": dependency_versions_exact,
            "git_head_exact": git["head"] == AGENTDOJO_COMMIT,
            "git_tree_clean": bool(git["tree_clean"]),
            "native_checker_importable": native_importable,
            "pack_exists": pack_exists,
            "pack_locks_exact": pack_exact,
            "python_compatible": python_compatible,
            "source_locks_exact": source_exact,
        }
        blockers: list[dict[str, str]] = []

        def block(code: str, message: str) -> None:
            blockers.append({"code": code, "message": message})

        if not checkout_exists:
            block("AGENTDOJO_CHECKOUT_MISSING", "pinned AgentDojo checkout is missing")
        if git["head"] != AGENTDOJO_COMMIT:
            block("AGENTDOJO_HEAD_MISMATCH", "AgentDojo checkout HEAD differs from frozen commit")
        if not git["tree_clean"]:
            block("AGENTDOJO_TREE_DIRTY", "AgentDojo checkout is dirty or git status is unavailable")
        if not source_exact:
            block("AGENTDOJO_SOURCE_LOCK_MISMATCH", "one or more AgentDojo source locks differ")
        if not pack_exists:
            block("AGENTDOJO_PACK_MISSING", "frozen AgentDojo task pack is missing")
        if not pack_exact:
            block("AGENTDOJO_PACK_LOCK_MISMATCH", "one or more frozen pack locks differ")
        if not python_compatible:
            block("AGENTDOJO_PYTHON_INCOMPATIBLE", "AgentDojo requires Python >=3.10")
        for row in dependencies:
            if not row["available"]:
                module = str(row["module"])
                block(
                    f"AGENTDOJO_DEPENDENCY_MISSING:{module}",
                    f"required native module {module} is unavailable",
                )
            elif row["version"] != self.DEPENDENCY_VERSIONS[row["module"]]:
                module = str(row["module"])
                block(
                    f"AGENTDOJO_DEPENDENCY_VERSION_MISMATCH:{module}",
                    f"native module {module} differs from the pinned uv.lock version",
                )
        if import_blocker is not None:
            block(*import_blocker)
        elif not native_importable and all(
            checks[name]
            for name in checks
            if name != "native_checker_importable"
        ):
            block(
                "AGENTDOJO_NATIVE_CHECKER_UNAVAILABLE",
                "pinned AgentDojo native checker dispatchers are unavailable",
            )

        blockers = sorted(
            {row["code"] + "\0" + row["message"]: row for row in blockers}.values(),
            key=lambda row: (row["code"], row["message"]),
        )
        executable = bool(self.CHECKER_BINDINGS) and all(checks.values()) and not blockers
        report: dict[str, Any] = {
            "schema_version": 1,
            "artifact_type": AGENTDOJO_PREFLIGHT_ARTIFACT,
            "adapter_id": self.adapter_id,
            "benchmark": self.benchmark,
            "upstream_version_or_commit": self.upstream_version_or_commit,
            "contract_version": self.contract_version,
            "implementation_sha256": self._implementation_sha256(),
            "upstream_checkout_path": str(self.checkout_root),
            "upstream_head": git["head"],
            "python_executable": str(Path(sys.executable).resolve()),
            "python_version": ".".join(str(part) for part in sys.version_info[:3]),
            "required_python": self.required_python,
            "dependencies": dependencies,
            "checker_bindings": [dict(row) for row in self.CHECKER_BINDINGS],
            "checks": checks,
            "blockers": blockers,
            "executable": executable,
        }
        sha256_json(report)
        return report

    def _ensure_executable(self) -> None:
        report = self.preflight()
        if report.get("executable") is True:
            return
        blocker_rows = report.get("blockers")
        codes = [
            str(row.get("code"))
            for row in blocker_rows
            if isinstance(row, Mapping) and isinstance(row.get("code"), str)
        ] if isinstance(blocker_rows, list) else []
        suffix = ",".join(sorted(codes)) or "AGENTDOJO_PREFLIGHT_FAILED"
        raise AgentDojoRuntimeError(f"AgentDojo native runtime is not executable: {suffix}")

    def _get_native_runtime(self) -> Mapping[str, Any]:
        if self._native is None:
            native = self._import_native_runtime()
            if not self._native_callables_available(native):
                raise AgentDojoRuntimeError(
                    "AGENTDOJO_NATIVE_CHECKER_UNAVAILABLE: native checker dispatchers are missing"
                )
            self._native = dict(native)
        return self._native

    def _load_task_index(self) -> dict[str, dict[str, Any]]:
        if self._task_index is not None:
            return self._task_index
        path = self.pack_root / "tasks.jsonl"
        rows: list[dict[str, Any]] = []
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    row = json.loads(line)
                    if not isinstance(row, dict):
                        raise SchemaError("AgentDojo tasks.jsonl row must be an object")
                    rows.append(row)
        except (OSError, json.JSONDecodeError) as exc:
            raise AgentDojoRuntimeError(
                f"AGENTDOJO_TASK_INDEX_INVALID: {type(exc).__name__}"
            ) from exc
        index: dict[str, dict[str, Any]] = {}
        source_rows: dict[str, list[dict[str, Any]]] = {}
        for row in rows:
            task_id = row.get("task_id")
            metadata = row.get("metadata")
            if not isinstance(task_id, str) or not isinstance(metadata, dict):
                raise AgentDojoRuntimeError("AGENTDOJO_TASK_INDEX_INVALID: missing task identity")
            index[task_id] = row
            source_id = metadata.get("source_task_id")
            if isinstance(source_id, str):
                source_rows.setdefault(source_id, []).append(row)
        for source_id, candidates in source_rows.items():
            # A source task represents the official user+injection checker pair;
            # prefer its adversarial fixture.  Exact pack task IDs remain usable
            # when benign-only execution is intended.
            ordered = sorted(
                candidates,
                key=lambda row: (
                    row.get("pair_role") != "adversarial",
                    str(row.get("task_id")),
                ),
            )
            index[source_id] = ordered[0]
        self._task_index = index
        return index

    def _resolve_task(self, source_task_id: str) -> dict[str, Any]:
        if not isinstance(source_task_id, str) or not source_task_id:
            raise SchemaError("source_task_id must be a nonempty string")
        row = self._load_task_index().get(source_task_id)
        if row is None:
            raise AgentDojoRuntimeError(
                f"AGENTDOJO_UNKNOWN_TASK: {source_task_id} is not in the frozen pack"
            )
        return row

    def _load_bound_documents(
        self, row: Mapping[str, Any]
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        fixture_ref = row.get("fixture_ref")
        oracle_ref = row.get("oracle_ref")
        metadata = row.get("metadata")
        if not isinstance(fixture_ref, str) or not isinstance(oracle_ref, str) or not isinstance(metadata, dict):
            raise AgentDojoRuntimeError("AGENTDOJO_TASK_BINDING_INVALID: missing fixture/oracle")
        fixture_path = self.pack_root / fixture_ref
        oracle_path = self.pack_root / oracle_ref
        try:
            fixture_bytes = fixture_path.read_bytes()
            oracle_bytes = oracle_path.read_bytes()
            fixture = json.loads(fixture_bytes)
            oracle = json.loads(oracle_bytes)
        except (OSError, json.JSONDecodeError) as exc:
            raise AgentDojoRuntimeError(
                f"AGENTDOJO_TASK_BINDING_INVALID: {type(exc).__name__}"
            ) from exc
        if (
            sha256_bytes(fixture_bytes) != metadata.get("fixture_sha256")
            or sha256_bytes(oracle_bytes) != metadata.get("oracle_sha256")
        ):
            raise AgentDojoRuntimeError(
                "AGENTDOJO_TASK_BINDING_MISMATCH: fixture/oracle bytes differ from task row"
            )
        if not isinstance(fixture, dict) or not isinstance(oracle, dict):
            raise AgentDojoRuntimeError("AGENTDOJO_TASK_BINDING_INVALID: documents must be objects")
        if (
            fixture.get("benchmark") != "AgentDojo"
            or oracle.get("benchmark") != "AgentDojo"
            or fixture.get("initial_state", {}).get("suite_version")
            != AGENTDOJO_SUITE_VERSION
            or oracle.get("suite_version") != AGENTDOJO_SUITE_VERSION
            or metadata.get("version_or_commit") != AGENTDOJO_VERSION_OR_COMMIT
        ):
            raise AgentDojoRuntimeError(
                "AGENTDOJO_TASK_BINDING_MISMATCH: benchmark/version identity differs"
            )

        def verify_checkout_source(relative: Any, expected: Any, label: str) -> None:
            if not isinstance(relative, str) or not isinstance(expected, str):
                raise AgentDojoRuntimeError(
                    f"AGENTDOJO_TASK_BINDING_INVALID: missing {label} source lock"
                )
            checkout_relative = (
                relative.removeprefix("raw/upstream/")
                if relative.startswith("raw/upstream/")
                else relative
            )
            path = self.checkout_root / checkout_relative
            actual = sha256_bytes(path.read_bytes()) if path.is_file() else None
            if actual != expected:
                raise AgentDojoRuntimeError(
                    f"AGENTDOJO_TASK_SOURCE_MISMATCH: {label} source lock differs"
                )

        pair_role = row.get("pair_role")
        for section in ("user_task", "injection_task"):
            bound = fixture.get(section)
            oracle_bound = oracle.get(section)
            if not isinstance(oracle_bound, dict):
                raise AgentDojoRuntimeError(
                    f"AGENTDOJO_TASK_BINDING_INVALID: missing {section} source lock"
                )
            if section == "injection_task" and pair_role == "benign":
                if bound is not None or fixture.get("injection_enabled") is not False:
                    raise AgentDojoRuntimeError(
                        "AGENTDOJO_TASK_BINDING_MISMATCH: benign fixture enables injection"
                    )
                verify_checkout_source(
                    oracle_bound.get("source_file"),
                    oracle_bound.get("source_sha256"),
                    section,
                )
                continue
            if not isinstance(bound, dict):
                raise AgentDojoRuntimeError(
                    f"AGENTDOJO_TASK_BINDING_INVALID: missing {section} source lock"
                )
            relative = bound.get("source_file")
            expected = bound.get("source_sha256")
            if relative != oracle_bound.get("source_file") or expected != oracle_bound.get("source_sha256"):
                raise AgentDojoRuntimeError(
                    f"AGENTDOJO_TASK_BINDING_MISMATCH: {section} fixture/oracle disagree"
                )
            verify_checkout_source(relative, expected, section)
        initial_state = fixture.get("initial_state")
        vector = fixture.get("injection_vector")
        if not isinstance(initial_state, dict):
            raise AgentDojoRuntimeError(
                "AGENTDOJO_TASK_BINDING_INVALID: missing environment source lock"
            )
        verify_checkout_source(
            initial_state.get("environment_path"),
            initial_state.get("environment_sha256"),
            "environment",
        )
        if pair_role == "adversarial":
            if not isinstance(vector, dict):
                raise AgentDojoRuntimeError(
                    "AGENTDOJO_TASK_BINDING_INVALID: missing injection vector source lock"
                )
            verify_checkout_source(
                vector.get("source_file"), vector.get("source_sha256"), "injection_vector"
            )
        elif vector is not None:
            raise AgentDojoRuntimeError(
                "AGENTDOJO_TASK_BINDING_MISMATCH: benign fixture has injection vector"
            )
        return fixture, oracle

    @staticmethod
    def _state_sha256(environment: Any) -> str:
        return sha256_json(_json_safe(environment))

    def reset(self, source_task_id: str) -> Mapping[str, Any]:
        """Reset the exact frozen suite-v1 task in the pinned native runtime."""

        if self._active is not None:
            raise AgentDojoRuntimeError(
                "AGENTDOJO_EPISODE_ACTIVE: cleanup is required before another reset"
            )
        row = self._resolve_task(source_task_id)
        self._ensure_executable()
        fixture, oracle = self._load_bound_documents(row)
        metadata = row["metadata"]
        domain_id = row.get("domain_id")
        if not isinstance(domain_id, str) or not domain_id.startswith("agentdojo:"):
            raise AgentDojoRuntimeError("AGENTDOJO_TASK_BINDING_INVALID: domain_id")
        domain = domain_id.split(":", 1)[1]
        native = self._get_native_runtime()
        suite = native["get_suite"](AGENTDOJO_SUITE_VERSION, domain)
        user_id = fixture["user_task"].get("id")
        injection_id = oracle["injection_task"].get("id")
        user_task = suite.get_user_task_by_id(user_id)
        pair_role = str(row.get("pair_role"))
        injection_task = (
            suite.get_injection_task_by_id(injection_id)
            if pair_role == "adversarial"
            else None
        )
        vector = fixture.get("injection_vector")
        vector_id = vector.get("id") if isinstance(vector, dict) else None
        injections: dict[str, str] = {}
        if injection_task is not None:
            if not isinstance(vector_id, str) or not vector_id:
                raise AgentDojoRuntimeError(
                    "AGENTDOJO_TASK_BINDING_INVALID: adversarial task lacks injection vector"
                )
            injections[vector_id] = str(injection_task.GOAL)
        environment = suite.load_and_inject_default_environment(injections)
        environment = user_task.init_environment(environment)
        pre_environment = _copy_environment(environment)
        runtime = native["FunctionsRuntime"](suite.tools)
        initial_hash = self._state_sha256(environment)
        bound_source_id = str(metadata.get("source_task_id"))
        active = _ActiveEpisode(
            requested_source_task_id=source_task_id,
            source_task_id=bound_source_id,
            task_id=str(row["task_id"]),
            domain=domain,
            pair_role=pair_role,
            fixture=fixture,
            oracle=oracle,
            suite=suite,
            user_task=user_task,
            injection_task=injection_task,
            injections=injections,
            pre_environment=pre_environment,
            environment=environment,
            runtime=runtime,
            function_calls=[],
            trace=[],
            initial_state_sha256=initial_hash,
        )
        self._active = active
        evidence = {
            "schema_version": 1,
            "adapter_id": self.adapter_id,
            "source_task_id": bound_source_id,
            "task_id": active.task_id,
            "suite_version": AGENTDOJO_SUITE_VERSION,
            "domain": domain,
            "pair_role": pair_role,
            "injection_enabled": injection_task is not None,
            "initial_state_sha256": initial_hash,
            "state_sha256": initial_hash,
        }
        sha256_json(evidence)
        return evidence

    def dispatch_native_action(self, action: Mapping[str, Any]) -> Mapping[str, Any]:
        """Dispatch exactly one validated call through AgentDojo FunctionsRuntime."""

        active = self._active
        if active is None:
            raise AgentDojoRuntimeError("AGENTDOJO_NO_ACTIVE_EPISODE: reset is required")
        if not isinstance(action, Mapping):
            raise SchemaError("native action must be a mapping")
        allowed_keys = {"function", "args", "id"}
        if any(not isinstance(key, str) or key not in allowed_keys for key in action):
            raise SchemaError("native action contains an unsupported field")
        function = action.get("function")
        args = action.get("args")
        call_id = action.get("id")
        if not isinstance(function, str) or not function:
            raise SchemaError("native action.function must be a nonempty string")
        if not isinstance(args, Mapping) or any(not isinstance(key, str) for key in args):
            raise SchemaError("native action.args must be an object with string keys")
        if call_id is not None and not isinstance(call_id, str):
            raise SchemaError("native action.id must be a string or null")
        safe_args = _json_safe(args)
        before = self._state_sha256(active.environment)
        native = self._get_native_runtime()
        function_call = native["FunctionCall"](
            function=function, args=dict(safe_args), id=call_id
        )
        try:
            result, error = active.runtime.run_function(
                active.environment, function, dict(safe_args), raise_on_error=True
            )
        except Exception as exc:
            raise AgentDojoRuntimeError(
                f"AGENTDOJO_NATIVE_ACTION_FAILED:{type(exc).__name__}"
            ) from exc
        if error is not None:
            raise AgentDojoRuntimeError("AGENTDOJO_NATIVE_ACTION_FAILED: runtime returned an error")
        after = self._state_sha256(active.environment)
        row = {
            "schema_version": 1,
            "index": len(active.trace),
            "function": function,
            "args": safe_args,
            "args_sha256": sha256_json(safe_args),
            "result": _json_safe(result),
            "pre_state_sha256": before,
            "post_state_sha256": after,
            "native_success": True,
        }
        sha256_json(row)
        active.function_calls.append(function_call)
        active.trace.append(row)
        return row

    def project_trusted_events(
        self, native_trace: Sequence[Mapping[str, Any]]
    ) -> tuple[Mapping[str, Any], ...]:
        """Project only adapter-recorded successful native calls into Host events."""

        active = self._active
        if active is None:
            raise AgentDojoRuntimeError("AGENTDOJO_NO_ACTIVE_EPISODE: reset is required")
        trace = [_json_safe(row) for row in native_trace]
        if sha256_json(trace) != sha256_json(active.trace):
            raise AgentDojoRuntimeError(
                "AGENTDOJO_TRACE_MISMATCH: only the adapter-recorded native trace is trusted"
            )
        events: list[dict[str, Any]] = []
        for row in trace:
            index = row["index"]
            event = {
                "event_id": (
                    f"agentdojo:{active.task_id}:{index}:"
                    f"{sha256_json(row)[:16]}"
                ),
                "kind": "native_tool_action",
                "op": row["function"],
                "resource": f"agentdojo:{active.domain}:{row['function']}",
                "actor": "external-agent",
                "session_id": active.task_id,
                "allowed": True,
                # Authorization is not an AgentDojo native checker output and
                # is therefore deliberately not inferred by this projection.
                "unauthorized": False,
                "host_mediated": True,
                "native_adapter_id": self.adapter_id,
                "native_trace_sha256": sha256_json(row),
                "authorization_semantics": "not_inferred",
            }
            sha256_json(event)
            events.append(event)
        return tuple(events)

    def capture_terminal_state(
        self,
        *,
        reset_state: Mapping[str, Any],
        native_trace: Sequence[Mapping[str, Any]],
    ) -> Mapping[str, Any]:
        """Capture native state for the shared driver without caller substitution.

        The current shared case schema has no separate terminal text field, so
        the output text is conservatively empty.  A future read-only parity
        corpus that depends on text must extend that case contract explicitly;
        this adapter will not infer model output from tool results.
        """

        del reset_state
        active = self._active
        if active is None:
            raise AgentDojoRuntimeError("AGENTDOJO_NO_ACTIVE_EPISODE: reset is required")
        trace = [_json_safe(row) for row in native_trace]
        if sha256_json(trace) != sha256_json(active.trace):
            raise AgentDojoRuntimeError("AGENTDOJO_TRACE_MISMATCH: terminal trace differs")
        state = {
            "state_sha256": self._state_sha256(active.environment),
            "model_output": "",
        }
        sha256_json(state)
        return state

    def evaluate_native_checkers(
        self,
        *,
        source_task_id: str,
        native_trace: Sequence[Mapping[str, Any]],
        terminal_state: Mapping[str, Any],
    ) -> NativeCheckerVerdict:
        """Invoke the exact upstream suite-v1 utility/security dispatchers."""

        active = self._active
        if active is None:
            raise AgentDojoRuntimeError("AGENTDOJO_NO_ACTIVE_EPISODE: reset is required")
        if source_task_id not in {
            active.requested_source_task_id,
            active.source_task_id,
            active.task_id,
        }:
            raise AgentDojoRuntimeError("AGENTDOJO_TASK_MISMATCH: checker task differs from reset")
        trace = [_json_safe(row) for row in native_trace]
        if sha256_json(trace) != sha256_json(active.trace):
            raise AgentDojoRuntimeError("AGENTDOJO_TRACE_MISMATCH: checker trace differs")
        if not isinstance(terminal_state, Mapping):
            raise SchemaError("terminal_state must be a mapping")
        state_sha = terminal_state.get("state_sha256")
        current_sha = self._state_sha256(active.environment)
        if state_sha != current_sha:
            raise AgentDojoRuntimeError(
                "AGENTDOJO_TERMINAL_STATE_MISMATCH: checker state is not native state"
            )
        model_output = terminal_state.get("model_output", "")
        if not isinstance(model_output, str):
            raise SchemaError("terminal_state.model_output must be a string")
        content = [{"type": "text", "content": model_output}]
        utility = active.suite._check_user_task_utility(
            active.user_task,
            content,
            active.pre_environment,
            active.environment,
            tuple(active.function_calls),
        )
        security: bool | None = None
        task_checker_refs = [str(active.oracle["user_task"]["utility_checker_ref"])]
        if active.injection_task is not None:
            security = active.suite._check_injection_task_security(
                active.injection_task,
                content,
                active.pre_environment,
                active.environment,
                tuple(active.function_calls),
            )
            task_checker_refs.append(
                str(active.oracle["injection_task"]["security_checker_ref"])
            )
        if type(utility) is not bool or (security is not None and type(security) is not bool):
            raise AgentDojoRuntimeError(
                "AGENTDOJO_NATIVE_CHECKER_INVALID: checker did not return bool"
            )
        checker_ids = [row["binding_id"] for row in self.CHECKER_BINDINGS]
        native_output = {
            "source_task_id": active.source_task_id,
            "task_id": active.task_id,
            "utility": utility,
            "security": security,
            "checker_binding_ids": checker_ids,
            "task_checker_refs": task_checker_refs,
            "native_trace_sha256": sha256_json(trace),
            "terminal_state_sha256": current_sha,
        }
        return NativeCheckerVerdict(
            utility=utility,
            security=security,
            checker_binding_ids=tuple(checker_ids),
            native_output_sha256=sha256_json(native_output),
        )

    def build_projected_snapshot(
        self,
        *,
        source_task_id: str,
        trace_id: str,
        trusted_events: Sequence[Mapping[str, Any]],
        pre_state_sha256: str,
        post_state_sha256: str,
        state_delta: Mapping[str, Any],
        terminal: Mapping[str, Any],
        mechanism_evidence: Sequence[Mapping[str, Any]],
    ) -> ProjectedCheckerSnapshot:
        """Build one immutable AgentDojo projection from trusted evidence only.

        The arguments intentionally exclude every upstream checker output.  In
        particular there is no native reward, verdict, utility, security, or
        checker binding parameter.  JSON-shaped inputs are parsed by the exact
        shared schema after an adapter-local prohibited-field check.

        This builder is also independent of an active native episode.  That is
        required for offline synthetic contract tests and prevents reset/task
        execution from becoming an accidental prerequisite for evidence
        validation.  Claim-bearing callers must separately establish that the
        supplied sources are trusted; missing or malformed provenance is
        handled fail-closed by the shared checker.
        """

        if not isinstance(source_task_id, str) or not source_task_id.startswith(
            "agentdojo-"
        ):
            raise AgentDojoRuntimeError(
                "AGENTDOJO_PROJECTED_IDENTITY_INVALID: task_id must be AgentDojo-scoped"
            )
        if not isinstance(trace_id, str) or not trace_id:
            raise SchemaError("trace_id must be a nonempty string")
        snapshot_json: dict[str, Any] = {
            "contract_version": PROJECTED_CHECKER_CONTRACT_VERSION,
            "benchmark": self.benchmark,
            "task_id": source_task_id,
            "trace_id": trace_id,
            "events": list(trusted_events),
            "pre_state_sha256": pre_state_sha256,
            "post_state_sha256": post_state_sha256,
            "state_delta": state_delta,
            "terminal": terminal,
            "mechanism_evidence": list(mechanism_evidence),
        }
        _reject_projected_native_signals(snapshot_json)
        snapshot = projected_snapshot_from_mapping(snapshot_json)
        _validate_agentdojo_projected_provenance(snapshot)
        # Force canonical serialization here so non-JSON values fail at the
        # adapter boundary, before they can be mistaken for checker evidence.
        sha256_json(snapshot.as_json())
        return snapshot

    def evaluate_projected_snapshot(
        self, snapshot: ProjectedCheckerSnapshot
    ) -> ProjectedCheckerResult:
        """Evaluate six Host-action mechanisms without native checker output.

        This is the AgentDojo-specific full-snapshot entrypoint.  It is kept
        separate from the legacy public-parity hook below because that hook has
        no state-delta, terminal, or explicit eligibility/exclusion arguments.
        """

        if not isinstance(snapshot, ProjectedCheckerSnapshot):
            raise TypeError("snapshot must be a ProjectedCheckerSnapshot")
        snapshot_json = snapshot.as_json()
        _reject_projected_native_signals(snapshot_json)
        if (
            snapshot.benchmark != self.benchmark
            or not isinstance(snapshot.task_id, str)
            or not snapshot.task_id.startswith("agentdojo-")
        ):
            raise AgentDojoRuntimeError(
                "AGENTDOJO_PROJECTED_IDENTITY_INVALID: snapshot is not AgentDojo-scoped"
            )
        _validate_agentdojo_projected_provenance(snapshot)
        result = evaluate_shared_projected_snapshot(snapshot)
        if (
            result.benchmark != snapshot.benchmark
            or result.task_id != snapshot.task_id
            or result.trace_id != snapshot.trace_id
            or result.input_sha256 != snapshot.canonical_sha256
            or result.decision != "NO_GO"
        ):
            raise AgentDojoRuntimeError(
                "AGENTDOJO_PROJECTED_RESULT_INVALID: shared result lost its input binding"
            )
        # Canonical output and exact output SHA are established by the shared
        # result.  Recompute here so adapter integration cannot silently accept
        # a mutable or noncanonical result implementation.
        result_json = result.as_json()
        output_sha256 = result_json.pop("output_sha256")
        if output_sha256 != sha256_json(result_json):
            raise AgentDojoRuntimeError(
                "AGENTDOJO_PROJECTED_RESULT_INVALID: output SHA-256 mismatch"
            )
        return result

    def evaluate_projected_checkers(
        self, *, source_task_id: str, trusted_events: Sequence[Mapping[str, Any]]
    ) -> ProjectedCheckerVerdict:
        """Keep the incomplete legacy utility/security projection fail-closed.

        The full independent path is :meth:`evaluate_projected_snapshot`.  This
        legacy signature omits trusted state delta, terminal evidence, and
        explicit mechanism eligibility/exclusions; returning a utility or
        security value here would manufacture an upstream-style verdict.
        """

        del source_task_id, trusted_events
        raise AgentDojoRuntimeError(
            "AGENTDOJO_PROJECTED_CHECKER_INSUFFICIENT_INPUT: use the full typed snapshot contract"
        )

    def cleanup(self) -> str:
        """Rebuild the task environment and prove it matches the reset baseline."""

        active = self._active
        if active is None:
            raise AgentDojoRuntimeError("AGENTDOJO_NO_ACTIVE_EPISODE: reset is required")
        try:
            fresh = active.suite.load_and_inject_default_environment(active.injections)
            fresh = active.user_task.init_environment(fresh)
            cleanup_sha = self._state_sha256(fresh)
            if cleanup_sha != active.initial_state_sha256:
                raise AgentDojoRuntimeError(
                    "AGENTDOJO_CLEANUP_FAILED: reset state differs from episode baseline"
                )
            return cleanup_sha
        finally:
            self._active = None


__all__ = [
    "AGENTDOJO_ADAPTER_ID",
    "AGENTDOJO_COMMIT",
    "AGENTDOJO_PACK_ID",
    "AGENTDOJO_VERSION",
    "AGENTDOJO_VERSION_OR_COMMIT",
    "AgentDojoAdapter",
    "AgentDojoRuntimeError",
    "DEFAULT_AGENTDOJO_CHECKOUT",
    "DEFAULT_AGENTDOJO_PACK",
]
