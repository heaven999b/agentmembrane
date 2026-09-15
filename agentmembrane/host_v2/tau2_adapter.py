"""Exact-pin, fail-closed offline adapter for tau2-bench 1.0.1.

The adapter exposes tau2's native *utility* evaluators.  Tau2 1.0.1 does not
ship a native security checker for AgentMembrane's host-boundary construct;
the adversarial/security interpretation in the Host V2 pack is therefore an
explicit AgentMembrane-derived extension.  A utility reward must never be
copied into the security field.

All upstream imports are lazy and occur only after a deterministic preflight
has verified the interpreter, dependencies, checkout identity, source locks,
and immutable task-pack inventory.  This module performs no network access.
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
from typing import TYPE_CHECKING, Any, Callable, Mapping, Sequence

from .public_adapters import NativeCheckerVerdict, PublicBenchmarkAdapter
from .schema import (
    IntegrityError,
    SchemaError,
    canonical_json_bytes,
    sha256_bytes,
    sha256_json,
)

if TYPE_CHECKING:
    from .projected_checker import ProjectedCheckerResult, ProjectedCheckerSnapshot


TAU2_VERSION = "1.0.1"
TAU2_COMMIT = "a2c024725189473d2d7cea3a5cfdbcc67478e41f"
TAU2_PIN = f"{TAU2_VERSION}@{TAU2_COMMIT}"
TAU2_REQUIRED_PYTHON = ">=3.12,<3.14"
TAU2_ATTACK_SEMANTICS = (
    "agentmembrane_derived_security_extension_not_upstream_benchmark"
)

_EXPECTED_TASK_COUNT = 68
_EXPECTED_SOURCE_TASK_COUNT = 34
_SUPPORTED_DOMAINS = frozenset({"airline", "retail", "telecom"})
_FORBIDDEN_PROJECTED_INPUT_KEYS = frozenset(
    {
        "checker_binding_ids",
        "native_output",
        "native_output_sha256",
        "native_reward",
        "native_security",
        "native_utility",
        "native_verdict",
        "reward",
        "security",
        "utility",
        "verdict",
    }
)
_PROJECTED_INPUT_FIELDS = {
    "authorization": frozenset(
        {
            "decision_id",
            "principal_id",
            "action",
            "outcome",
            "credential_id",
            "provenance",
        }
    ),
    "event": frozenset(
        {
            "event_id",
            "sequence_index",
            "event_type",
            "actor_id",
            "action",
            "payload_sha256",
            "authorization",
            "provenance",
        }
    ),
    "mechanism": frozenset(
        {
            "mechanism_id",
            "eligibility",
            "witness_event_ids",
            "exclusion_code",
            "exclusion_rationale",
            "provenance",
        }
    ),
    "provenance": frozenset(
        {"source_id", "source_kind", "source_sha256", "field_path"}
    ),
    "state_delta": frozenset(
        {
            "delta_id",
            "delta_kind",
            "before_sha256",
            "after_sha256",
            "changed_paths",
            "witness_event_ids",
            "provenance",
        }
    ),
    "terminal": frozenset(
        {"output_sha256", "reason", "witness_event_ids", "provenance"}
    ),
}
_TAU2_PROJECTED_SOURCE_KINDS = {
    "authorization": frozenset({"authorization_log"}),
    "event": frozenset({"adapter_trace", "host_event_log"}),
    "mechanism": frozenset({"mechanism_mapping"}),
    "state_delta": frozenset({"state_snapshot"}),
    "terminal": frozenset({"terminal_capture"}),
}


@dataclass(frozen=True)
class _Dependency:
    module: str
    distribution: str


# This is the exact core dependency surface declared by tau2 1.0.1 plus the
# data-model packages imported directly by the pinned checker path.
_DEPENDENCIES = (
    _Dependency("addict", "addict"),
    _Dependency("deepdiff", "deepdiff"),
    _Dependency("docstring_parser", "docstring-parser"),
    _Dependency("dotenv", "python-dotenv"),
    _Dependency("fastapi", "fastapi"),
    _Dependency("httpx", "httpx"),
    _Dependency("litellm", "litellm"),
    _Dependency("loguru", "loguru"),
    _Dependency("numpy", "numpy"),
    _Dependency("pandas", "pandas"),
    _Dependency("psutil", "psutil"),
    _Dependency("pydantic", "pydantic"),
    _Dependency("requests", "requests"),
    _Dependency("rich", "rich"),
    _Dependency("tabulate", "tabulate"),
    _Dependency("tenacity", "tenacity"),
    _Dependency("toml", "toml"),
    _Dependency("typer", "typer"),
    _Dependency("typing_extensions", "typing-extensions"),
    _Dependency("uvicorn", "uvicorn"),
    _Dependency("yaml", "PyYAML"),
)


_UPSTREAM_SOURCE_LOCKS = {
    "pyproject.toml": "23d59670b4ad7bbc0f57420fd9643a8d9188c24abe4f29c9c965544d8cc4cb8d",
    "src/tau2/domains/airline/environment.py": (
        "64589faffbcb75c8ac7c95d2c94ad27f4bd70e23b9856a6928fa678a0f7fcc8d"
    ),
    "src/tau2/domains/retail/environment.py": (
        "5b819fb895a4ef49df71404c3d9678ab09e8578eec841b8ec9229c8f51e32405"
    ),
    "src/tau2/domains/telecom/environment.py": (
        "7bc335d717a8cb6bda54551fa2b5c12ff073f6287878d215f4181572e551abcd"
    ),
    "src/tau2/environment/environment.py": (
        "b5357f11e2914c11ce0372af919cc1d726191b91cd97f776b8fb388ae0615350"
    ),
    "src/tau2/evaluator/evaluator.py": (
        "204d95a82812402f2fee989250392d3c66de702a8bcc20258c7e2a8153a1ea8d"
    ),
    "src/tau2/evaluator/evaluator_action.py": (
        "4347ec90fd09db73b9f7e46515220363f91f0c3b12aeddf7ece83346f49227f8"
    ),
    "src/tau2/evaluator/evaluator_communicate.py": (
        "7a082f91c746b84cc37c6994eb6ff78f297222fd067503a4cc86d45750696507"
    ),
    "src/tau2/evaluator/evaluator_env.py": (
        "b53ebfe6b0b06d7a2071b5f9dd03ee6ca8ac6000b0ef44f3bd345b346c30d8ac"
    ),
    "src/tau2/registry.py": (
        "d170c1f4b7323a75e26b2ead6754ed423b17a3deb91fe2c89e7e8ec78c6bf12a"
    ),
}

_PACK_SOURCE_LOCKS = {
    "manifest.json": "817cdd1987202b61aa975d07ea1fc9bea45148dd364c3c6b33d419e106bcb01b",
    "tasks.jsonl": "48c7d17ad534de31fe3a46059f8bb3e61adb48fd93bab649035c67521f70168f",
}

_CHECKER_BINDINGS = (
    {
        "binding_id": "tau2-v1.0.1-environment-utility",
        "callable_ref": (
            "tau2.evaluator.evaluator_env.EnvironmentEvaluator.calculate_reward"
        ),
        "source_path": "src/tau2/evaluator/evaluator_env.py",
        "source_sha256": _UPSTREAM_SOURCE_LOCKS[
            "src/tau2/evaluator/evaluator_env.py"
        ],
    },
    {
        "binding_id": "tau2-v1.0.1-action-utility",
        "callable_ref": (
            "tau2.evaluator.evaluator_action.ActionEvaluator.calculate_reward"
        ),
        "source_path": "src/tau2/evaluator/evaluator_action.py",
        "source_sha256": _UPSTREAM_SOURCE_LOCKS[
            "src/tau2/evaluator/evaluator_action.py"
        ],
    },
    {
        "binding_id": "tau2-v1.0.1-communicate-utility",
        "callable_ref": (
            "tau2.evaluator.evaluator_communicate."
            "CommunicateEvaluator.calculate_reward"
        ),
        "source_path": "src/tau2/evaluator/evaluator_communicate.py",
        "source_sha256": _UPSTREAM_SOURCE_LOCKS[
            "src/tau2/evaluator/evaluator_communicate.py"
        ],
    },
)


def _default_checkout() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "data"
        / "host_boundary_v2"
        / "upstream"
        / "tau2-bench"
    )


def _default_pack() -> Path:
    return (
        Path(__file__).resolve().parents[2]
        / "data"
        / "host_boundary_v2"
        / "packs"
        / "tau2-v1.0.1"
    )


def _file_sha256(path: Path) -> str | None:
    try:
        return sha256_bytes(path.read_bytes()) if path.is_file() else None
    except OSError:
        return None


def _default_module_finder(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ModuleNotFoundError, ValueError):
        return False


def _default_version_lookup(distribution: str) -> str | None:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return None


def _default_git_probe(checkout: Path) -> tuple[str | None, bool | None]:
    def run(*args: str) -> subprocess.CompletedProcess[str] | None:
        try:
            return subprocess.run(
                ["git", "-C", str(checkout), *args],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return None

    head_result = run("rev-parse", "HEAD")
    status_result = run("status", "--porcelain")
    head = None
    clean = None
    if head_result is not None and head_result.returncode == 0:
        candidate = head_result.stdout.strip()
        head = candidate if candidate else None
    if status_result is not None and status_result.returncode == 0:
        clean = not bool(status_result.stdout.strip())
    return head, clean


def _json_copy(value: Any, *, field: str) -> Any:
    try:
        return json.loads(canonical_json_bytes(value).decode("utf-8"))
    except (SchemaError, UnicodeError, json.JSONDecodeError) as exc:
        raise SchemaError(f"{field} must be deterministic JSON: {exc}") from exc


def _reject_native_checker_input(value: Any, *, path: str = "$") -> None:
    """Reject every native-verdict/reward channel from projected inputs."""

    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise SchemaError(f"{path} contains a non-string field name")
            if key.casefold() in _FORBIDDEN_PROJECTED_INPUT_KEYS:
                raise IntegrityError(
                    "tau2 projected checker input must not contain native "
                    f"verdict/reward field {path}.{key}"
                )
            _reject_native_checker_input(child, path=f"{path}.{key}")
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _reject_native_checker_input(child, path=f"{path}[{index}]")


def _projected_object(
    value: Any, *, object_type: str, field: str
) -> dict[str, Any]:
    copied = _json_copy(value, field=field)
    if not isinstance(copied, dict):
        raise SchemaError(f"{field} must be an object")
    expected = _PROJECTED_INPUT_FIELDS[object_type]
    missing = sorted(expected - set(copied))
    unknown = sorted(set(copied) - expected)
    if missing or unknown:
        raise SchemaError(
            f"{field} fields invalid: missing={missing}, unknown={unknown}"
        )
    return copied


def _projected_provenance(
    value: Any, *, source_kinds: frozenset[str], field: str
) -> tuple[Any, ...]:
    from .projected_checker import FieldProvenance

    copied = _json_copy(value, field=field)
    if not isinstance(copied, list):
        raise SchemaError(f"{field} must be a list")
    rows = []
    seen_paths: set[str] = set()
    for index, raw in enumerate(copied):
        label = f"{field}[{index}]"
        row = _projected_object(raw, object_type="provenance", field=label)
        if row["source_kind"] not in source_kinds:
            raise IntegrityError(
                f"{label}.source_kind is not valid for this tau2 evidence field"
            )
        source_id = row["source_id"]
        if not isinstance(source_id, str) or not source_id.startswith("tau2:"):
            raise IntegrityError(f"{label}.source_id must use the tau2: namespace")
        field_path = row["field_path"]
        if not isinstance(field_path, str) or not field_path.strip():
            raise SchemaError(f"{label}.field_path must be a nonempty string")
        if field_path in seen_paths:
            raise IntegrityError(f"{field} contains duplicate field-level provenance")
        seen_paths.add(field_path)
        rows.append(FieldProvenance(**row))
    return tuple(rows)


def _projected_string_tuple(value: Any, *, field: str) -> tuple[str, ...]:
    copied = _json_copy(value, field=field)
    if not isinstance(copied, list) or any(
        not isinstance(item, str) or not item.strip() for item in copied
    ):
        raise SchemaError(f"{field} must be a list of nonempty strings")
    return tuple(copied)


def _version_string(version: tuple[int, int, int]) -> str:
    return ".".join(str(part) for part in version)


class _ImportedTau2Runtime:
    """Lazily imported facade over the pinned tau2 native runtime."""

    def __init__(self, checkout: Path) -> None:
        source_root = str(checkout / "src")
        if source_root not in sys.path:
            sys.path.insert(0, source_root)

        self.message = importlib.import_module("tau2.data_model.message")
        self.tasks = importlib.import_module("tau2.data_model.tasks")
        self.env_evaluator = importlib.import_module(
            "tau2.evaluator.evaluator_env"
        ).EnvironmentEvaluator
        self.action_evaluator = importlib.import_module(
            "tau2.evaluator.evaluator_action"
        ).ActionEvaluator
        self.communicate_evaluator = importlib.import_module(
            "tau2.evaluator.evaluator_communicate"
        ).CommunicateEvaluator
        self.domains = {
            domain: importlib.import_module(f"tau2.domains.{domain}.environment")
            for domain in sorted(_SUPPORTED_DOMAINS)
        }

        package = importlib.import_module("tau2")
        package_path = Path(package.__file__ or "").resolve()
        try:
            package_path.relative_to((checkout / "src").resolve())
        except ValueError as exc:
            raise IntegrityError(
                f"tau2 imported from unpinned location: {package_path}"
            ) from exc

    @staticmethod
    def _initial_fields(task: Any) -> tuple[Any, Any, list[Any]]:
        state = task.initial_state
        if state is None:
            return None, None, []
        return (
            state.initialization_data,
            state.initialization_actions,
            list(state.message_history or []),
        )

    def _fresh_environment(self, domain: str, task: Any) -> Any:
        environment = self.domains[domain].get_environment(solo_mode=False)
        initialization_data, initialization_actions, history = self._initial_fields(
            task
        )
        environment.set_state(
            initialization_data=initialization_data,
            initialization_actions=initialization_actions,
            message_history=history,
            strict=True,
        )
        return environment

    def reset(self, domain: str, native_task_id: str) -> tuple[Any, Any, dict[str, Any]]:
        matches = [
            task
            for task in self.domains[domain].get_tasks(None)
            if str(task.id) == native_task_id
        ]
        if len(matches) != 1:
            raise IntegrityError(
                "pinned tau2 task lookup did not resolve exactly once: "
                f"{domain}:{native_task_id}"
            )
        task = matches[0]
        environment = self._fresh_environment(domain, task)
        return task, environment, self.terminal_state(environment)

    @staticmethod
    def terminal_state(environment: Any) -> dict[str, Any]:
        return {
            "agent_db_sha256": environment.get_db_hash(),
            "user_db_sha256": environment.get_user_db_hash(),
        }

    def dispatch(
        self,
        environment: Any,
        *,
        call_id: str,
        name: str,
        arguments: Mapping[str, Any],
        requestor: str,
    ) -> dict[str, Any]:
        tool_call = self.message.ToolCall(
            id=call_id,
            name=name,
            arguments=dict(arguments),
            requestor=requestor,
        )
        response = environment.get_response(tool_call)
        return {
            "kind": "native_action",
            "call_id": call_id,
            "name": name,
            "arguments": dict(arguments),
            "requestor": requestor,
            "response_content": response.content,
            "error": bool(response.error),
        }

    def _trajectory(self, native_trace: Sequence[Mapping[str, Any]]) -> list[Any]:
        trajectory: list[Any] = []
        for row in native_trace:
            kind = row.get("kind")
            if kind == "assistant_message":
                content = row.get("content")
                if content is not None and not isinstance(content, str):
                    raise SchemaError("assistant message content must be a string or null")
                trajectory.append(
                    self.message.AssistantMessage(
                        role="assistant", content=content, timestamp=None
                    )
                )
                continue
            if kind != "native_action":
                raise SchemaError(f"unsupported tau2 native trace kind: {kind!r}")
            tool_call = self.message.ToolCall(
                id=row["call_id"],
                name=row["name"],
                arguments=row["arguments"],
                requestor=row["requestor"],
            )
            message_type = (
                self.message.AssistantMessage
                if row["requestor"] == "assistant"
                else self.message.UserMessage
            )
            trajectory.append(
                message_type(
                    role=row["requestor"],
                    content=None,
                    tool_calls=[tool_call],
                    timestamp=None,
                )
            )
            trajectory.append(
                self.message.ToolMessage(
                    id=row["call_id"],
                    role="tool",
                    content=row["response_content"],
                    requestor=row["requestor"],
                    error=row["error"],
                    timestamp=None,
                )
            )
        return trajectory

    def evaluate(
        self,
        *,
        task: Any,
        domain: str,
        native_trace: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        criteria = task.evaluation_criteria
        if criteria is None:
            return {
                "utility": True,
                "reward": 1.0,
                "reward_basis": [],
                "components": {},
                "binding_ids": [],
            }

        reward_basis = tuple(
            item.value if hasattr(item, "value") else str(item)
            for item in criteria.reward_basis
        )
        if "NL_ASSERTION" in reward_basis:
            raise IntegrityError(
                "tau2 NL_ASSERTION utility requires an LLM and is forbidden in the "
                "offline adapter"
            )

        trajectory = self._trajectory(native_trace)
        components: dict[str, Any] = {}
        reward = 1.0

        # EvaluationType.ALL in the pinned upstream calls all three native
        # evaluators, then gates the product by reward_basis.  Preserve that
        # exact dispatch shape so the verdict honestly binds all three sources.
        env_result = self.env_evaluator.calculate_reward(
            environment_constructor=self.domains[domain].get_environment,
            task=task,
            full_trajectory=trajectory,
            solo_mode=False,
            env_kwargs={},
            strict_replay=True,
        )
        action_result = self.action_evaluator.calculate_reward(
            task=task,
            full_trajectory=trajectory,
            tool_types=None,
        )
        communicate_result = self.communicate_evaluator.calculate_reward(
            task=task,
            full_trajectory=trajectory,
        )
        components["environment"] = env_result.model_dump(mode="json")
        components["action"] = action_result.model_dump(mode="json")
        components["communicate"] = communicate_result.model_dump(mode="json")

        if set(reward_basis) & {"DB", "ENV_ASSERTION"}:
            reward *= float(env_result.reward)
        if "ACTION" in reward_basis:
            reward *= float(action_result.reward)
        if "COMMUNICATE" in reward_basis:
            reward *= float(communicate_result.reward)

        return {
            "utility": reward == 1.0,
            "reward": reward,
            "reward_basis": list(reward_basis),
            "components": components,
            "binding_ids": [item["binding_id"] for item in _CHECKER_BINDINGS],
        }

    def cleanup(self, domain: str, task: Any) -> dict[str, Any]:
        return self.terminal_state(self._fresh_environment(domain, task))


class Tau2V101Adapter(PublicBenchmarkAdapter):
    """Concrete adapter bound to tau2-bench ``1.0.1@a2c0247...``."""

    adapter_id = "agentmembrane-tau2-v1.0.1-a2c0247"
    benchmark = "tau2-bench"
    upstream_version_or_commit = TAU2_PIN
    attack_semantics = TAU2_ATTACK_SEMANTICS
    native_security_checker_available = False

    def __init__(
        self,
        *,
        checkout_path: Path | None = None,
        pack_path: Path | None = None,
        python_version: tuple[int, int, int] | None = None,
        python_executable: str | None = None,
        module_finder: Callable[[str], bool] | None = None,
        version_lookup: Callable[[str], str | None] | None = None,
        git_probe: Callable[[Path], tuple[str | None, bool | None]] | None = None,
        runtime_loader: Callable[[Path], Any] | None = None,
    ) -> None:
        self.checkout_path = Path(checkout_path or _default_checkout()).resolve()
        self.pack_path = Path(pack_path or _default_pack()).resolve()
        self._python_version = python_version or (
            sys.version_info.major,
            sys.version_info.minor,
            sys.version_info.micro,
        )
        self._python_executable = python_executable or sys.executable
        self._module_finder = module_finder or _default_module_finder
        self._version_lookup = version_lookup or _default_version_lookup
        self._git_probe = git_probe or _default_git_probe
        self._runtime_loader = runtime_loader or _ImportedTau2Runtime
        self._runtime: Any | None = None
        self._active_source_task_id: str | None = None
        self._active_domain: str | None = None
        self._active_task: Any | None = None
        self._environment: Any | None = None
        self._initial_state: dict[str, Any] | None = None
        self._trace: list[dict[str, Any]] = []

    @property
    def checker_bindings(self) -> tuple[dict[str, str], ...]:
        return tuple(dict(item) for item in _CHECKER_BINDINGS)

    def _dependency_rows(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for dependency in _DEPENDENCIES:
            try:
                available = bool(self._module_finder(dependency.module))
            except Exception:
                available = False
            version = None
            if available:
                try:
                    version = self._version_lookup(dependency.distribution)
                except Exception:
                    version = None
            rows.append(
                {
                    "module": dependency.module,
                    "available": available,
                    "version": version if isinstance(version, str) else None,
                }
            )
        return rows

    def _lock_rows(
        self, root: Path, locks: Mapping[str, str]
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for relative, expected in sorted(locks.items()):
            observed = _file_sha256(root / relative)
            rows.append(
                {
                    "path": relative,
                    "expected_sha256": expected,
                    "observed_sha256": observed,
                    "matches": observed == expected,
                }
            )
        return rows

    def _inventory(self) -> tuple[dict[str, dict[str, Any]], bool]:
        path = self.pack_path / "tasks.jsonl"
        inventory: dict[str, dict[str, Any]] = {}
        row_count = 0
        valid = True
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError):
            return {}, False
        for line in lines:
            if not line.strip():
                valid = False
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                valid = False
                continue
            row_count += 1
            if not isinstance(row, dict):
                valid = False
                continue
            metadata = row.get("metadata")
            if not isinstance(metadata, dict):
                valid = False
                continue
            source_task_id = metadata.get("source_task_id")
            version = metadata.get("version_or_commit")
            if not isinstance(source_task_id, str) or ":" not in source_task_id:
                valid = False
                continue
            domain, native_task_id = source_task_id.split(":", 1)
            if (
                domain not in _SUPPORTED_DOMAINS
                or not native_task_id
                or version != TAU2_PIN
            ):
                valid = False
                continue
            descriptor = {
                "source_task_id": source_task_id,
                "domain": domain,
                "native_task_id": native_task_id,
                "source_task_sha256": metadata.get("source_task_sha256"),
            }
            prior = inventory.get(source_task_id)
            if prior is not None and prior != descriptor:
                valid = False
            inventory[source_task_id] = descriptor
        valid = valid and row_count == _EXPECTED_TASK_COUNT
        valid = valid and len(inventory) == _EXPECTED_SOURCE_TASK_COUNT
        return inventory, valid

    def preflight(self) -> dict[str, Any]:
        """Return deterministic JSON-safe runtime evidence; never import tau2."""

        implementation_sha256 = _file_sha256(Path(__file__).resolve())
        dependencies = self._dependency_rows()
        upstream_locks = self._lock_rows(
            self.checkout_path, _UPSTREAM_SOURCE_LOCKS
        )
        pack_locks = self._lock_rows(self.pack_path, _PACK_SOURCE_LOCKS)
        inventory, inventory_valid = self._inventory()
        try:
            upstream_head, worktree_clean = self._git_probe(self.checkout_path)
        except Exception:
            upstream_head, worktree_clean = None, None

        python_supported = (3, 12, 0) <= self._python_version < (3, 14, 0)
        checks = {
            "attack_semantics_separated": (
                self.attack_semantics == TAU2_ATTACK_SEMANTICS
                and self.native_security_checker_available is False
            ),
            "checker_bindings_locked": all(
                row["matches"]
                for row in upstream_locks
                if row["path"]
                in {binding["source_path"] for binding in _CHECKER_BINDINGS}
            ),
            "checkout_exists": self.checkout_path.is_dir(),
            "dependencies_available": all(
                row["available"] for row in dependencies
            ),
            "implementation_hash_available": implementation_sha256 is not None,
            "pack_locks_match": bool(pack_locks)
            and all(row["matches"] for row in pack_locks),
            "python_supported": python_supported,
            "source_locks_match": bool(upstream_locks)
            and all(row["matches"] for row in upstream_locks),
            "task_inventory_valid": inventory_valid,
            "upstream_head_matches": upstream_head == TAU2_COMMIT,
            "worktree_clean": worktree_clean is True,
        }

        blockers: list[dict[str, str]] = []

        def block(check: str, code: str, message: str) -> None:
            if not checks[check]:
                blockers.append({"code": code, "message": message})

        block(
            "checkout_exists",
            "TAU2_CHECKOUT_MISSING",
            "the pinned tau2 checkout path is missing",
        )
        block(
            "upstream_head_matches",
            "TAU2_HEAD_MISMATCH",
            f"tau2 checkout HEAD must equal {TAU2_COMMIT}",
        )
        block(
            "worktree_clean",
            "TAU2_WORKTREE_NOT_CLEAN",
            "tau2 checkout must have no tracked or untracked changes",
        )
        block(
            "python_supported",
            "TAU2_PYTHON_UNSUPPORTED",
            f"tau2 {TAU2_VERSION} requires Python {TAU2_REQUIRED_PYTHON}",
        )
        missing = [row["module"] for row in dependencies if not row["available"]]
        if missing:
            blockers.append(
                {
                    "code": "TAU2_DEPENDENCIES_MISSING",
                    "message": "missing required modules: " + ", ".join(missing),
                }
            )
        block(
            "source_locks_match",
            "TAU2_SOURCE_LOCK_MISMATCH",
            "one or more pinned tau2 source files are missing or changed",
        )
        block(
            "pack_locks_match",
            "TAU2_PACK_LOCK_MISMATCH",
            "the immutable tau2 Host V2 manifest or tasks file changed",
        )
        block(
            "task_inventory_valid",
            "TAU2_TASK_INVENTORY_INVALID",
            "the tau2 Host V2 source-task inventory is malformed or incomplete",
        )
        block(
            "checker_bindings_locked",
            "TAU2_CHECKER_BINDING_MISMATCH",
            "a pinned tau2 native utility checker source lock changed",
        )
        block(
            "attack_semantics_separated",
            "TAU2_SECURITY_SEMANTICS_CONFLATED",
            "tau2 utility must remain separate from AgentMembrane security semantics",
        )
        block(
            "implementation_hash_available",
            "TAU2_ADAPTER_HASH_UNAVAILABLE",
            "the tau2 adapter implementation cannot be hashed",
        )

        report = {
            "schema_version": 1,
            "artifact_type": "agentmembrane_public_adapter_runtime_preflight",
            "adapter_id": self.adapter_id,
            "benchmark": self.benchmark,
            "upstream_version_or_commit": self.upstream_version_or_commit,
            "contract_version": self.contract_version,
            "implementation_sha256": implementation_sha256,
            "upstream_checkout_path": str(self.checkout_path),
            "upstream_head": upstream_head,
            "python_executable": self._python_executable,
            "python_version": _version_string(self._python_version),
            "required_python": TAU2_REQUIRED_PYTHON,
            "dependencies": dependencies,
            "checker_bindings": [dict(item) for item in _CHECKER_BINDINGS],
            "checks": checks,
            "blockers": blockers,
            "executable": bool(_CHECKER_BINDINGS)
            and all(checks.values())
            and not blockers,
        }
        # Enforce JSON safety without changing the stable object shape.
        canonical_json_bytes(report)
        return report

    def _require_executable(self) -> None:
        report = self.preflight()
        if report["executable"] is not True:
            codes = ", ".join(item["code"] for item in report["blockers"])
            raise IntegrityError(f"tau2 adapter preflight is not executable: {codes}")

    def _descriptor(self, source_task_id: str) -> dict[str, Any]:
        inventory, valid = self._inventory()
        if not valid:
            raise IntegrityError("tau2 source-task inventory is invalid")
        descriptor = inventory.get(source_task_id)
        if descriptor is None:
            raise IntegrityError(f"unknown tau2 source_task_id: {source_task_id}")
        return descriptor

    def reset(self, source_task_id: str) -> Mapping[str, Any]:
        """Reset exactly one pinned native task; overlapping episodes are denied."""

        if self._active_source_task_id is not None:
            raise IntegrityError("tau2 adapter already has an active episode")
        if not isinstance(source_task_id, str) or not source_task_id:
            raise SchemaError("source_task_id must be a nonempty string")
        self._require_executable()
        descriptor = self._descriptor(source_task_id)

        try:
            if self._runtime is None:
                self._runtime = self._runtime_loader(self.checkout_path)
            task, environment, initial_state = self._runtime.reset(
                descriptor["domain"], descriptor["native_task_id"]
            )
            initial_state = _json_copy(initial_state, field="tau2 initial state")
        except Exception:
            self._active_source_task_id = None
            self._active_domain = None
            self._active_task = None
            self._environment = None
            self._initial_state = None
            self._trace = []
            raise

        self._active_source_task_id = source_task_id
        self._active_domain = descriptor["domain"]
        self._active_task = task
        self._environment = environment
        self._initial_state = initial_state
        self._trace = []
        return {
            "source_task_id": source_task_id,
            "domain": descriptor["domain"],
            "native_task_id": descriptor["native_task_id"],
            "source_task_sha256": descriptor["source_task_sha256"],
            "initial_state": _json_copy(initial_state, field="tau2 initial state"),
        }

    def _require_active(self) -> None:
        if (
            self._active_source_task_id is None
            or self._active_domain is None
            or self._active_task is None
            or self._environment is None
            or self._initial_state is None
            or self._runtime is None
        ):
            raise IntegrityError("tau2 adapter has no active episode")

    def dispatch_native_action(self, action: Mapping[str, Any]) -> Mapping[str, Any]:
        """Dispatch one validated action through tau2's native Environment."""

        self._require_active()
        if not isinstance(action, Mapping):
            raise SchemaError("tau2 native action must be an object")
        if set(action) - {"name", "arguments", "requestor"}:
            raise SchemaError("tau2 native action contains unknown fields")
        name = action.get("name")
        arguments = action.get("arguments")
        requestor = action.get("requestor", "assistant")
        if not isinstance(name, str) or not name:
            raise SchemaError("tau2 native action name must be a nonempty string")
        if not isinstance(arguments, Mapping) or any(
            not isinstance(key, str) for key in arguments
        ):
            raise SchemaError("tau2 native action arguments must be a JSON object")
        if requestor not in {"assistant", "user"}:
            raise SchemaError("tau2 native action requestor is invalid")
        arguments_copy = _json_copy(dict(arguments), field="tau2 action arguments")
        call_id = f"tau2-adapter-call-{len(self._trace) + 1:06d}"
        record = self._runtime.dispatch(
            self._environment,
            call_id=call_id,
            name=name,
            arguments=arguments_copy,
            requestor=requestor,
        )
        record = _json_copy(record, field="tau2 native action result")
        self._trace.append(record)
        return dict(record)

    def append_native_assistant_message(self, content: str) -> Mapping[str, Any]:
        """Append deterministic communication evidence for the native checker."""

        self._require_active()
        if not isinstance(content, str):
            raise SchemaError("tau2 assistant message content must be a string")
        record = {"kind": "assistant_message", "content": content}
        self._trace.append(record)
        return dict(record)

    def terminal_state(self) -> dict[str, Any]:
        """Return the current native database-hash state."""

        self._require_active()
        state = self._runtime.terminal_state(self._environment)
        return _json_copy(state, field="tau2 terminal state")

    def capture_terminal_state(
        self,
        *,
        reset_state: Mapping[str, Any],
        native_trace: Sequence[Mapping[str, Any]],
    ) -> Mapping[str, Any]:
        """Capture live native state rather than treating a dispatch row as state."""

        del reset_state, native_trace
        return self.terminal_state()

    def project_trusted_events(
        self, native_trace: Sequence[Mapping[str, Any]]
    ) -> tuple[Mapping[str, Any], ...]:
        """Project native evidence without inventing a security classification."""

        copied = _json_copy(list(native_trace), field="tau2 native trace")
        events: list[dict[str, Any]] = []
        for index, row in enumerate(copied):
            if not isinstance(row, dict):
                raise SchemaError("tau2 native trace rows must be objects")
            kind = row.get("kind")
            if kind == "native_action":
                event = {
                    "event_id": sha256_json(
                        {"adapter_id": self.adapter_id, "index": index, "row": row}
                    ),
                    "kind": "tau2_native_tool_result",
                    "op": row.get("name"),
                    "requestor": row.get("requestor"),
                    "arguments_sha256": sha256_json(row.get("arguments")),
                    "allowed": row.get("error") is False,
                    "native_error": row.get("error"),
                    "evidence_authority": "tau2_native_utility_runtime",
                    "security_classification": "not_provided_by_tau2_native",
                    "attack_semantics": self.attack_semantics,
                }
            elif kind == "assistant_message":
                event = {
                    "event_id": sha256_json(
                        {"adapter_id": self.adapter_id, "index": index, "row": row}
                    ),
                    "kind": "tau2_native_assistant_communication",
                    "content_sha256": sha256_json(row.get("content")),
                    "allowed": True,
                    "evidence_authority": "tau2_native_utility_runtime",
                    "security_classification": "not_provided_by_tau2_native",
                    "attack_semantics": self.attack_semantics,
                }
            else:
                raise SchemaError(f"unsupported tau2 native trace kind: {kind!r}")
            canonical_json_bytes(event)
            events.append(event)
        return tuple(events)

    def evaluate_native_checkers(
        self,
        *,
        source_task_id: str,
        native_trace: Sequence[Mapping[str, Any]],
        terminal_state: Mapping[str, Any],
    ) -> NativeCheckerVerdict:
        """Run pinned native utility checks; security intentionally remains null."""

        self._require_active()
        self._require_executable()
        if source_task_id != self._active_source_task_id:
            raise IntegrityError("tau2 checker source_task_id differs from active task")
        trace = _json_copy(list(native_trace), field="tau2 native trace")
        if trace != self._trace:
            raise IntegrityError("tau2 checker trace differs from dispatched native trace")
        supplied_terminal = _json_copy(
            dict(terminal_state), field="tau2 terminal state"
        )
        if supplied_terminal != self.terminal_state():
            raise IntegrityError("tau2 checker terminal state differs from live native state")

        native_output = self._runtime.evaluate(
            task=self._active_task,
            domain=self._active_domain,
            native_trace=trace,
        )
        native_output = _json_copy(native_output, field="tau2 native checker output")
        utility = native_output.get("utility")
        bindings = native_output.get("binding_ids")
        if type(utility) is not bool:
            raise IntegrityError("tau2 native checker did not return a boolean utility")
        if not isinstance(bindings, list) or any(
            not isinstance(item, str) for item in bindings
        ):
            raise IntegrityError("tau2 native checker binding IDs are invalid")
        known_bindings = {item["binding_id"] for item in _CHECKER_BINDINGS}
        if not bindings or not set(bindings).issubset(known_bindings):
            raise IntegrityError("tau2 native checker returned unknown/empty bindings")

        return NativeCheckerVerdict(
            utility=utility,
            security=None,
            checker_binding_ids=tuple(bindings),
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
        """Build the independent, complete tau2 Host-action checker input.

        This pure projection accepts only trusted Host evidence.  In particular,
        it neither consults the active native runtime nor accepts any tau2
        utility reward, verdict, security value, or native checker output.  The
        legacy parity hook has too little evidence for this contract and remains
        fail-closed below.
        """

        from .projected_checker import (
            PROJECTED_CHECKER_CONTRACT_VERSION,
            AuthorizationDecision,
            MechanismEvidence,
            TrustedEvent,
            TrustedStateDelta,
            TrustedTerminal,
            make_projected_snapshot,
        )

        raw_input = {
            "source_task_id": source_task_id,
            "trace_id": trace_id,
            "trusted_events": trusted_events,
            "pre_state_sha256": pre_state_sha256,
            "post_state_sha256": post_state_sha256,
            "state_delta": state_delta,
            "terminal": terminal,
            "mechanism_evidence": mechanism_evidence,
        }
        _reject_native_checker_input(raw_input)
        copied = _json_copy(raw_input, field="tau2 projected checker input")

        task_id = copied["source_task_id"]
        copied_trace_id = copied["trace_id"]
        if not isinstance(task_id, str) or not task_id.strip():
            raise SchemaError("tau2 projected source_task_id must be nonempty")
        if not isinstance(copied_trace_id, str) or not copied_trace_id.strip():
            raise SchemaError("tau2 projected trace_id must be nonempty")

        raw_events = copied["trusted_events"]
        if not isinstance(raw_events, list):
            raise SchemaError("tau2 projected trusted_events must be a list")
        events = []
        for index, raw in enumerate(raw_events):
            label = f"tau2 projected trusted_events[{index}]"
            row = _projected_object(raw, object_type="event", field=label)
            auth_row = _projected_object(
                row["authorization"],
                object_type="authorization",
                field=f"{label}.authorization",
            )
            auth_row["provenance"] = _projected_provenance(
                auth_row["provenance"],
                source_kinds=_TAU2_PROJECTED_SOURCE_KINDS["authorization"],
                field=f"{label}.authorization.provenance",
            )
            row["authorization"] = AuthorizationDecision(**auth_row)
            row["provenance"] = _projected_provenance(
                row["provenance"],
                source_kinds=_TAU2_PROJECTED_SOURCE_KINDS["event"],
                field=f"{label}.provenance",
            )
            events.append(TrustedEvent(**row))

        delta_row = _projected_object(
            copied["state_delta"],
            object_type="state_delta",
            field="tau2 projected state_delta",
        )
        delta_row["provenance"] = _projected_provenance(
            delta_row["provenance"],
            source_kinds=_TAU2_PROJECTED_SOURCE_KINDS["state_delta"],
            field="tau2 projected state_delta.provenance",
        )
        delta_row["changed_paths"] = _projected_string_tuple(
            delta_row["changed_paths"],
            field="tau2 projected state_delta.changed_paths",
        )
        delta_row["witness_event_ids"] = _projected_string_tuple(
            delta_row["witness_event_ids"],
            field="tau2 projected state_delta.witness_event_ids",
        )
        typed_delta = TrustedStateDelta(**delta_row)

        terminal_row = _projected_object(
            copied["terminal"],
            object_type="terminal",
            field="tau2 projected terminal",
        )
        terminal_row["provenance"] = _projected_provenance(
            terminal_row["provenance"],
            source_kinds=_TAU2_PROJECTED_SOURCE_KINDS["terminal"],
            field="tau2 projected terminal.provenance",
        )
        terminal_row["witness_event_ids"] = _projected_string_tuple(
            terminal_row["witness_event_ids"],
            field="tau2 projected terminal.witness_event_ids",
        )
        typed_terminal = TrustedTerminal(**terminal_row)

        raw_mechanisms = copied["mechanism_evidence"]
        if not isinstance(raw_mechanisms, list):
            raise SchemaError("tau2 projected mechanism_evidence must be a list")
        mechanisms = []
        for index, raw in enumerate(raw_mechanisms):
            label = f"tau2 projected mechanism_evidence[{index}]"
            row = _projected_object(raw, object_type="mechanism", field=label)
            if not isinstance(row["mechanism_id"], str):
                raise SchemaError(f"{label}.mechanism_id must be a string")
            row["provenance"] = _projected_provenance(
                row["provenance"],
                source_kinds=_TAU2_PROJECTED_SOURCE_KINDS["mechanism"],
                field=f"{label}.provenance",
            )
            row["witness_event_ids"] = _projected_string_tuple(
                row["witness_event_ids"],
                field=f"{label}.witness_event_ids",
            )
            mechanisms.append(MechanismEvidence(**row))
        return make_projected_snapshot(
            contract_version=PROJECTED_CHECKER_CONTRACT_VERSION,
            benchmark=self.benchmark,
            task_id=task_id,
            trace_id=copied_trace_id,
            events=tuple(events),
            pre_state_sha256=copied["pre_state_sha256"],
            post_state_sha256=copied["post_state_sha256"],
            state_delta=typed_delta,
            terminal=typed_terminal,
            mechanism_evidence=tuple(mechanisms),
        )

    def evaluate_projected_snapshot(
        self, snapshot: ProjectedCheckerSnapshot
    ) -> ProjectedCheckerResult:
        """Evaluate a complete tau2 projection without touching native outputs."""

        from .projected_checker import (
            ProjectedCheckerSnapshot,
            evaluate_projected_snapshot,
        )

        if not isinstance(snapshot, ProjectedCheckerSnapshot):
            raise SchemaError(
                "tau2 projected checker requires ProjectedCheckerSnapshot"
            )
        if snapshot.benchmark != self.benchmark:
            raise IntegrityError("tau2 projected snapshot benchmark mismatch")
        return evaluate_projected_snapshot(snapshot)

    def evaluate_projected_checkers(
        self,
        *,
        source_task_id: str,
        trusted_events: Sequence[Mapping[str, Any]],
    ) -> Any:
        """Fail closed because the legacy hook cannot carry a complete snapshot."""

        del source_task_id, trusted_events
        raise IntegrityError(
            "tau2 legacy projected-checker input lacks trusted state delta, terminal "
            "evidence, and explicit mechanism eligibility/exclusions; use the "
            "independent full-snapshot contract"
        )

    def cleanup(self) -> str:
        """Verify a fresh native reset matches the episode's frozen initial state."""

        self._require_active()
        self._require_executable()
        try:
            clean_state = self._runtime.cleanup(
                self._active_domain, self._active_task
            )
            clean_state = _json_copy(clean_state, field="tau2 cleanup state")
            if clean_state != self._initial_state:
                raise IntegrityError("tau2 cleanup reset differs from initial state")
            cleanup_sha256 = sha256_json(
                {
                    "adapter_id": self.adapter_id,
                    "source_task_id": self._active_source_task_id,
                    "clean_state": clean_state,
                }
            )
        except Exception:
            # Preserve active state after an unverifiable cleanup so reuse is denied.
            raise

        self._active_source_task_id = None
        self._active_domain = None
        self._active_task = None
        self._environment = None
        self._initial_state = None
        self._trace = []
        return cleanup_sha256


Tau2Adapter = Tau2V101Adapter


__all__ = [
    "TAU2_ATTACK_SEMANTICS",
    "TAU2_COMMIT",
    "TAU2_PIN",
    "TAU2_REQUIRED_PYTHON",
    "TAU2_VERSION",
    "Tau2Adapter",
    "Tau2V101Adapter",
]
