"""Offline contracts for version-pinned public-benchmark runtime adapters.

Registration proves only inspectable code identity.  It never proves that the
pinned upstream checkout, dependencies, or native checkers are executable.
That second claim requires a bound adapter instance and a validated live
runtime preflight.  Keeping those two facts separate prevents a dotted string
or a registered class from becoming scientific readiness evidence.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
import inspect
from pathlib import Path
from typing import Any, ClassVar, Mapping, Sequence

from .schema import IntegrityError, SchemaError, sha256_bytes


ADAPTER_CONTRACT_VERSION = "agentmembrane.public-adapter.v1"
RUNTIME_PREFLIGHT_SCHEMA_VERSION = 1
RUNTIME_PREFLIGHT_ARTIFACT_TYPE = "agentmembrane_public_adapter_runtime_preflight"


class AdapterRuntimeUnavailable(IntegrityError):
    """Raised when a registered adapter lacks an independently usable runtime."""


@dataclass(frozen=True)
class NativeCheckerBinding:
    """Exact source and callable identity for one pinned upstream checker."""

    binding_id: str
    callable_ref: str
    source_path: str
    source_sha256: str

    def as_json(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class RuntimeDependency:
    """Deterministic import finding recorded by an adapter preflight."""

    module: str
    available: bool
    version: str | None

    def as_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class RuntimeBlocker:
    """One fail-closed reason why native execution is unavailable."""

    code: str
    message: str

    def as_json(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True)
class AdapterRuntimePreflight:
    """Validated live-runtime evidence, distinct from adapter registration."""

    schema_version: int
    artifact_type: str
    adapter_id: str
    benchmark: str
    upstream_version_or_commit: str
    contract_version: str
    implementation_sha256: str
    upstream_checkout_path: str
    upstream_head: str | None
    python_executable: str
    python_version: str
    required_python: str
    dependencies: tuple[RuntimeDependency, ...]
    checker_bindings: tuple[NativeCheckerBinding, ...]
    checks: Mapping[str, bool]
    blockers: tuple[RuntimeBlocker, ...]
    executable: bool

    def as_json(self) -> dict[str, Any]:
        """Return a deterministic JSON-safe representation."""

        return {
            "schema_version": self.schema_version,
            "artifact_type": self.artifact_type,
            "adapter_id": self.adapter_id,
            "benchmark": self.benchmark,
            "upstream_version_or_commit": self.upstream_version_or_commit,
            "contract_version": self.contract_version,
            "implementation_sha256": self.implementation_sha256,
            "upstream_checkout_path": self.upstream_checkout_path,
            "upstream_head": self.upstream_head,
            "python_executable": self.python_executable,
            "python_version": self.python_version,
            "required_python": self.required_python,
            "dependencies": [
                item.as_json() for item in sorted(self.dependencies, key=lambda item: item.module)
            ],
            "checker_bindings": [
                item.as_json()
                for item in sorted(self.checker_bindings, key=lambda item: item.binding_id)
            ],
            "checks": {key: self.checks[key] for key in sorted(self.checks)},
            "blockers": [
                item.as_json()
                for item in sorted(self.blockers, key=lambda item: (item.code, item.message))
            ],
            "executable": self.executable,
        }


@dataclass(frozen=True)
class NativeCheckerVerdict:
    """Native utility/security verdict returned by a pinned upstream checker."""

    utility: bool | None
    security: bool | None
    checker_binding_ids: tuple[str, ...]
    native_output_sha256: str


@dataclass(frozen=True)
class ProjectedCheckerVerdict:
    """Verdict derived only from the adapter's trusted-event projection."""

    utility: bool | None
    security: bool | None
    projected_output_sha256: str


@dataclass(frozen=True)
class AdapterDescriptor:
    """Code identity verified when a concrete adapter class is registered."""

    adapter_id: str
    benchmark: str
    upstream_version_or_commit: str
    contract_version: str
    entrypoint: str
    implementation_path: str
    implementation_sha256: str

    def as_json(self) -> dict[str, str]:
        return asdict(self)


class PublicBenchmarkAdapter(ABC):
    """Minimum executable boundary for a native public benchmark.

    Implementations must reset the frozen native environment, dispatch native
    tools, project resulting state changes into trusted Host events, invoke the
    pinned upstream checkers, and return to a clean reset state.  Inventory
    builders and reference-only oracle documents do not satisfy this contract.
    """

    adapter_id: ClassVar[str]
    benchmark: ClassVar[str]
    upstream_version_or_commit: ClassVar[str]
    contract_version: ClassVar[str] = ADAPTER_CONTRACT_VERSION

    def preflight(self) -> AdapterRuntimePreflight | Mapping[str, Any]:
        """Return deterministic live-runtime evidence.

        The default keeps legacy concrete fixture subclasses compatible while
        ensuring they are never executable merely because they registered.
        """

        descriptor = describe_adapter_type(type(self))
        return AdapterRuntimePreflight(
            schema_version=RUNTIME_PREFLIGHT_SCHEMA_VERSION,
            artifact_type=RUNTIME_PREFLIGHT_ARTIFACT_TYPE,
            adapter_id=descriptor.adapter_id,
            benchmark=descriptor.benchmark,
            upstream_version_or_commit=descriptor.upstream_version_or_commit,
            contract_version=descriptor.contract_version,
            implementation_sha256=descriptor.implementation_sha256,
            upstream_checkout_path="unbound",
            upstream_head=None,
            python_executable="unbound",
            python_version="unbound",
            required_python="unspecified",
            dependencies=(),
            checker_bindings=(),
            checks={"runtime_preflight_implemented": False},
            blockers=(
                RuntimeBlocker(
                    code="RUNTIME_PREFLIGHT_NOT_IMPLEMENTED",
                    message="adapter implements no live native-runtime preflight",
                ),
            ),
            executable=False,
        )

    @abstractmethod
    def reset(self, source_task_id: str) -> Mapping[str, Any]:
        """Reset one frozen source task and return its native state evidence."""

    @abstractmethod
    def dispatch_native_action(self, action: Mapping[str, Any]) -> Mapping[str, Any]:
        """Validate and dispatch one action through the native tool surface."""

    @abstractmethod
    def project_trusted_events(
        self, native_trace: Sequence[Mapping[str, Any]]
    ) -> tuple[Mapping[str, Any], ...]:
        """Project native state/action evidence into trusted Host events."""

    def capture_terminal_state(
        self,
        *,
        reset_state: Mapping[str, Any],
        native_trace: Sequence[Mapping[str, Any]],
    ) -> Mapping[str, Any]:
        """Capture checker input after dispatch without changing legacy adapters.

        Concrete native adapters should override this when a dispatch result is
        not itself a complete terminal-state snapshot.
        """

        return native_trace[-1] if native_trace else reset_state

    @abstractmethod
    def evaluate_native_checkers(
        self,
        *,
        source_task_id: str,
        native_trace: Sequence[Mapping[str, Any]],
        terminal_state: Mapping[str, Any],
    ) -> NativeCheckerVerdict:
        """Run the pinned upstream utility/security checker implementation."""

    def evaluate_projected_checkers(
        self,
        *,
        source_task_id: str,
        trusted_events: Sequence[Mapping[str, Any]],
    ) -> ProjectedCheckerVerdict:
        """Evaluate adapter semantics from trusted events, not native output.

        Native invocation and adapter projection are deliberately separate.
        Implementations that cannot make this independent projection remain
        parity-ineligible rather than copying the native verdict.
        """

        raise AdapterRuntimeUnavailable(
            "adapter does not implement an independent projected checker"
        )

    @abstractmethod
    def cleanup(self) -> str:
        """Reset after the episode and return the cleanup-state SHA-256."""


def _required_class_string(adapter_type: type[PublicBenchmarkAdapter], name: str) -> str:
    value = getattr(adapter_type, name, None)
    if not isinstance(value, str) or not value.strip():
        raise SchemaError(f"public adapter class attribute {name} must be a nonempty string")
    return value


def describe_adapter_type(
    adapter_type: type[PublicBenchmarkAdapter],
) -> AdapterDescriptor:
    """Return a descriptor bound to the concrete implementation file bytes."""

    if not isinstance(adapter_type, type) or not issubclass(
        adapter_type, PublicBenchmarkAdapter
    ):
        raise TypeError("adapter_type must subclass PublicBenchmarkAdapter")
    if inspect.isabstract(adapter_type):
        raise IntegrityError("an abstract public adapter cannot be registered")
    source = inspect.getsourcefile(adapter_type)
    if source is None:
        raise IntegrityError("public adapter implementation has no inspectable source file")
    path = Path(source).resolve()
    if not path.is_file():
        raise IntegrityError(f"public adapter implementation file is missing: {path}")
    try:
        implementation_sha256 = sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise IntegrityError(f"cannot hash public adapter implementation {path}: {exc}") from exc
    return AdapterDescriptor(
        adapter_id=_required_class_string(adapter_type, "adapter_id"),
        benchmark=_required_class_string(adapter_type, "benchmark"),
        upstream_version_or_commit=_required_class_string(
            adapter_type, "upstream_version_or_commit"
        ),
        contract_version=_required_class_string(adapter_type, "contract_version"),
        entrypoint=f"{adapter_type.__module__}:{adapter_type.__qualname__}",
        implementation_path=str(path),
        implementation_sha256=implementation_sha256,
    )


def _nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SchemaError(f"{label} must be a nonempty string")
    return value


def _sha256(value: Any, label: str) -> str:
    text = _nonempty_string(value, label)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise SchemaError(f"{label} must be a lowercase SHA-256")
    return text


def _exact_mapping(value: Any, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SchemaError(f"{label} must be an object")
    missing = sorted(fields - set(value))
    unknown = sorted(set(value) - fields)
    if missing or unknown:
        raise SchemaError(f"{label} fields invalid: missing={missing}, unknown={unknown}")
    return value


_PREFLIGHT_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "adapter_id",
        "benchmark",
        "upstream_version_or_commit",
        "contract_version",
        "implementation_sha256",
        "upstream_checkout_path",
        "upstream_head",
        "python_executable",
        "python_version",
        "required_python",
        "dependencies",
        "checker_bindings",
        "checks",
        "blockers",
        "executable",
    }
)


def normalize_runtime_preflight(
    value: AdapterRuntimePreflight | Mapping[str, Any],
    *,
    descriptor: AdapterDescriptor,
) -> AdapterRuntimePreflight:
    """Validate and normalize a deterministic adapter runtime preflight."""

    raw = value.as_json() if isinstance(value, AdapterRuntimePreflight) else value
    item = _exact_mapping(raw, _PREFLIGHT_FIELDS, "adapter runtime preflight")
    if item["schema_version"] != RUNTIME_PREFLIGHT_SCHEMA_VERSION:
        raise SchemaError("adapter runtime preflight schema_version must equal 1")
    if item["artifact_type"] != RUNTIME_PREFLIGHT_ARTIFACT_TYPE:
        raise SchemaError("invalid adapter runtime preflight artifact_type")
    for field in (
        "adapter_id",
        "benchmark",
        "upstream_version_or_commit",
        "contract_version",
        "implementation_sha256",
    ):
        if item[field] != getattr(descriptor, field):
            raise IntegrityError(f"runtime preflight differs from registered code: {field}")
    _sha256(item["implementation_sha256"], "runtime preflight.implementation_sha256")
    checkout = _nonempty_string(
        item["upstream_checkout_path"], "runtime preflight.upstream_checkout_path"
    )
    upstream_head = item["upstream_head"]
    if upstream_head is not None:
        upstream_head = _nonempty_string(upstream_head, "runtime preflight.upstream_head")
    python_executable = _nonempty_string(
        item["python_executable"], "runtime preflight.python_executable"
    )
    python_version = _nonempty_string(
        item["python_version"], "runtime preflight.python_version"
    )
    required_python = _nonempty_string(
        item["required_python"], "runtime preflight.required_python"
    )

    raw_dependencies = item["dependencies"]
    if not isinstance(raw_dependencies, list):
        raise SchemaError("runtime preflight.dependencies must be a list")
    dependencies: list[RuntimeDependency] = []
    seen_modules: set[str] = set()
    for index, raw_dependency in enumerate(raw_dependencies):
        dependency = _exact_mapping(
            raw_dependency,
            frozenset({"module", "available", "version"}),
            f"runtime preflight.dependencies[{index}]",
        )
        module = _nonempty_string(
            dependency["module"], f"runtime preflight.dependencies[{index}].module"
        )
        if module in seen_modules:
            raise IntegrityError(f"duplicate runtime dependency module: {module}")
        seen_modules.add(module)
        available = dependency["available"]
        if not isinstance(available, bool):
            raise SchemaError(
                f"runtime preflight.dependencies[{index}].available must be boolean"
            )
        version = dependency["version"]
        if version is not None:
            version = _nonempty_string(
                version, f"runtime preflight.dependencies[{index}].version"
            )
        dependencies.append(RuntimeDependency(module, available, version))

    raw_bindings = item["checker_bindings"]
    if not isinstance(raw_bindings, list):
        raise SchemaError("runtime preflight.checker_bindings must be a list")
    bindings: list[NativeCheckerBinding] = []
    seen_binding_ids: set[str] = set()
    for index, raw_binding in enumerate(raw_bindings):
        binding = _exact_mapping(
            raw_binding,
            frozenset({"binding_id", "callable_ref", "source_path", "source_sha256"}),
            f"runtime preflight.checker_bindings[{index}]",
        )
        binding_id = _nonempty_string(
            binding["binding_id"], f"runtime preflight.checker_bindings[{index}].binding_id"
        )
        if binding_id in seen_binding_ids:
            raise IntegrityError(f"duplicate runtime checker binding ID: {binding_id}")
        seen_binding_ids.add(binding_id)
        bindings.append(
            NativeCheckerBinding(
                binding_id=binding_id,
                callable_ref=_nonempty_string(
                    binding["callable_ref"],
                    f"runtime preflight.checker_bindings[{index}].callable_ref",
                ),
                source_path=_nonempty_string(
                    binding["source_path"],
                    f"runtime preflight.checker_bindings[{index}].source_path",
                ),
                source_sha256=_sha256(
                    binding["source_sha256"],
                    f"runtime preflight.checker_bindings[{index}].source_sha256",
                ),
            )
        )

    raw_checks = item["checks"]
    if not isinstance(raw_checks, Mapping) or not raw_checks:
        raise SchemaError("runtime preflight.checks must be a nonempty object")
    checks: dict[str, bool] = {}
    for raw_key, raw_passed in raw_checks.items():
        key = _nonempty_string(raw_key, "runtime preflight.checks key")
        if not isinstance(raw_passed, bool):
            raise SchemaError(f"runtime preflight.checks.{key} must be boolean")
        checks[key] = raw_passed

    raw_blockers = item["blockers"]
    if not isinstance(raw_blockers, list):
        raise SchemaError("runtime preflight.blockers must be a list")
    blockers: list[RuntimeBlocker] = []
    seen_blockers: set[tuple[str, str]] = set()
    for index, raw_blocker in enumerate(raw_blockers):
        blocker = _exact_mapping(
            raw_blocker,
            frozenset({"code", "message"}),
            f"runtime preflight.blockers[{index}]",
        )
        code = _nonempty_string(
            blocker["code"], f"runtime preflight.blockers[{index}].code"
        )
        message = _nonempty_string(
            blocker["message"], f"runtime preflight.blockers[{index}].message"
        )
        identity = (code, message)
        if identity in seen_blockers:
            raise IntegrityError(f"duplicate runtime blocker: {code}")
        seen_blockers.add(identity)
        blockers.append(RuntimeBlocker(code, message))

    executable = item["executable"]
    if not isinstance(executable, bool):
        raise SchemaError("runtime preflight.executable must be boolean")
    derived_executable = (
        bool(bindings)
        and bool(dependencies)
        and all(checks.values())
        and all(dependency.available for dependency in dependencies)
        and not blockers
    )
    if executable != derived_executable:
        raise IntegrityError(
            "runtime preflight executable flag is not derived from "
            "bindings/dependencies/checks/blockers"
        )
    pin_tail = descriptor.upstream_version_or_commit.rpartition("@")[2]
    if executable and upstream_head != pin_tail:
        raise IntegrityError("executable runtime preflight upstream_head differs from exact pin")

    return AdapterRuntimePreflight(
        schema_version=RUNTIME_PREFLIGHT_SCHEMA_VERSION,
        artifact_type=RUNTIME_PREFLIGHT_ARTIFACT_TYPE,
        adapter_id=descriptor.adapter_id,
        benchmark=descriptor.benchmark,
        upstream_version_or_commit=descriptor.upstream_version_or_commit,
        contract_version=descriptor.contract_version,
        implementation_sha256=descriptor.implementation_sha256,
        upstream_checkout_path=checkout,
        upstream_head=upstream_head,
        python_executable=python_executable,
        python_version=python_version,
        required_python=required_python,
        dependencies=tuple(dependencies),
        checker_bindings=tuple(bindings),
        checks=checks,
        blockers=tuple(blockers),
        executable=executable,
    )


class PublicAdapterRegistry:
    """Explicit registry; there is no permissive dotted-import fallback."""

    def __init__(self) -> None:
        self._entries: dict[str, AdapterDescriptor] = {}
        self._runtime_instances: dict[str, PublicBenchmarkAdapter] = {}

    def register(
        self, adapter_type: type[PublicBenchmarkAdapter]
    ) -> AdapterDescriptor:
        descriptor = describe_adapter_type(adapter_type)
        if descriptor.contract_version != ADAPTER_CONTRACT_VERSION:
            raise IntegrityError(
                "unsupported public adapter contract version: "
                f"{descriptor.contract_version!r}"
            )
        prior = self._entries.get(descriptor.adapter_id)
        if prior is not None and prior != descriptor:
            raise IntegrityError(
                f"public adapter_id is already bound to different code: {descriptor.adapter_id}"
            )
        self._entries[descriptor.adapter_id] = descriptor
        return descriptor

    def bind_runtime(self, adapter: PublicBenchmarkAdapter) -> AdapterDescriptor:
        """Bind an instance without treating the binding as executable evidence."""

        if not isinstance(adapter, PublicBenchmarkAdapter):
            raise TypeError("adapter must be a PublicBenchmarkAdapter instance")
        descriptor = describe_adapter_type(type(adapter))
        registered = self._entries.get(descriptor.adapter_id)
        if registered is None:
            raise IntegrityError(
                f"adapter runtime cannot bind before code registration: {descriptor.adapter_id}"
            )
        if registered != descriptor:
            raise IntegrityError(
                f"adapter runtime code differs from registration: {descriptor.adapter_id}"
            )
        prior = self._runtime_instances.get(descriptor.adapter_id)
        if prior is not None and prior is not adapter:
            raise IntegrityError(
                f"adapter runtime is already bound: {descriptor.adapter_id}"
            )
        self._runtime_instances[descriptor.adapter_id] = adapter
        return descriptor

    def get_runtime(self, adapter_id: str) -> PublicBenchmarkAdapter | None:
        return self._runtime_instances.get(adapter_id)

    def runtime_preflight(self, adapter_id: str) -> AdapterRuntimePreflight | None:
        """Run and normalize live preflight for a separately bound instance."""

        descriptor = self._entries.get(adapter_id)
        runtime = self._runtime_instances.get(adapter_id)
        if descriptor is None or runtime is None:
            return None
        return normalize_runtime_preflight(runtime.preflight(), descriptor=descriptor)

    def get(self, adapter_id: str) -> AdapterDescriptor | None:
        return self._entries.get(adapter_id)

    def descriptors(self) -> tuple[AdapterDescriptor, ...]:
        return tuple(self._entries[key] for key in sorted(self._entries))


EMPTY_PUBLIC_ADAPTER_REGISTRY = PublicAdapterRegistry()


__all__ = [
    "ADAPTER_CONTRACT_VERSION",
    "AdapterRuntimePreflight",
    "AdapterRuntimeUnavailable",
    "AdapterDescriptor",
    "EMPTY_PUBLIC_ADAPTER_REGISTRY",
    "NativeCheckerBinding",
    "NativeCheckerVerdict",
    "ProjectedCheckerVerdict",
    "PublicAdapterRegistry",
    "PublicBenchmarkAdapter",
    "RUNTIME_PREFLIGHT_ARTIFACT_TYPE",
    "RUNTIME_PREFLIGHT_SCHEMA_VERSION",
    "RuntimeBlocker",
    "RuntimeDependency",
    "describe_adapter_type",
    "normalize_runtime_preflight",
]
