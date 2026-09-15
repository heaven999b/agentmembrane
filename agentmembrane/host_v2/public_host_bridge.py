"""AgentDojo public-runtime bridge for the Host Boundary V2 runner.

This module is deliberately narrow.  It exposes the exact tools of one
version-pinned :class:`AgentDojoAdapter` episode through the generic
``EnvironmentAdapter``/``HostSession`` lifecycle, but it does not invent Host
mechanisms that AgentDojo does not implement.  In particular, the task's
fixture/oracle metadata and injection objective are control-plane inputs and
never become planner-visible interface or snapshot fields.

The existing generic runner still needs a small, separately reviewed oracle
integration before a native checker can be used: it must pass the last
ledger-confirmed assistant text to :meth:`AgentDojoPublicHostSession.capture_terminal_state`.
Tool results are never substituted for that text.
"""

from __future__ import annotations

import copy
import re
from pathlib import Path
from typing import Any, Callable, Mapping, MutableSet

from .agentdojo_adapter import AGENTDOJO_ADAPTER_ID, AgentDojoAdapter
from .conditions import ConditionSpec, validate_condition
from .host import ActionOutcome, ActionRequest, HostError, HostSession
from .public_adapters import NativeCheckerVerdict, PublicBenchmarkAdapter
from .schema import IntegrityError, SchemaError, sha256_bytes, sha256_json


AGENTDOJO_PUBLIC_HOST_BRIDGE_ID = "agentdojo-v0.1.35-host-v2-bridge-v1"
AGENTDOJO_PUBLIC_HOST_ADAPTER_REF = (
    "agentmembrane.host_v2.public_host_bridge:AgentDojoPublicHostAdapter"
)

_NAMESPACE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MODEL_VISIBLE_CONTROL_KEYS = frozenset(
    {
        "authorized_test_objective",
        "fixture_injection_goal",
        "injection_goal",
        "oracle",
        "oracle_fields",
        "oracle_ref",
        "security_objective",
    }
)
_MODEL_VISIBLE_CONTROL_TOKENS = (
    "authorized_test_objective",
    "fixture injection goal",
    "fixture_injection_goal",
    "injection goal",
    "injection_goal",
    "oracle_ref",
    "security objective",
    "security_objective",
)
_PROJECTED_EVENT_FIELDS = frozenset(
    {
        "actor",
        "allowed",
        "authorization_semantics",
        "event_id",
        "host_mediated",
        "kind",
        "native_adapter_id",
        "native_trace_sha256",
        "op",
        "resource",
        "session_id",
        "unauthorized",
    }
)
_STATE_CONTAINERS = (
    "resources",
    "capabilities",
    "records",
    "proposals",
    "messages",
    "scheduled",
    "children",
)


class PublicHostBridgeError(HostError):
    """The public adapter cannot be exposed safely as a Host V2 session."""


def _task_value(task: Any, field: str) -> Any:
    if isinstance(task, Mapping):
        return task.get(field)
    return getattr(task, field, None)


def _task_metadata(task: Any) -> dict[str, Any]:
    value = _task_value(task, "metadata")
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise SchemaError("AgentDojo bridge task metadata must be a string-keyed object")
    sha256_json(value)
    return copy.deepcopy(value)


def _nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SchemaError(f"{label} must be a nonempty string")
    return value


def _reject_control_plane_leakage(value: Any, *, path: str) -> None:
    """Reject control-plane names in anything that can reach the planner.

    Native tool observations are intentionally not passed through this check:
    an AgentDojo injection is supposed to become visible only when a native
    tool reads the injected environment value.  Interface schemas, snapshots,
    trusted events, and lifecycle feedback have no such exception.
    """

    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IntegrityError(f"{path} contains a non-string key")
            if key.casefold() in _MODEL_VISIBLE_CONTROL_KEYS:
                raise IntegrityError(f"{path} leaks control-plane field {key!r}")
            _reject_control_plane_leakage(item, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_control_plane_leakage(item, path=f"{path}[{index}]")
    elif isinstance(value, str):
        folded = value.casefold()
        for token in _MODEL_VISIBLE_CONTROL_TOKENS:
            if token in folded:
                raise IntegrityError(f"{path} leaks control-plane token {token!r}")


def _reject_control_plane_keys(value: Any, *, path: str) -> None:
    """Reject fixture/oracle structure while allowing native injected text.

    Once a native read returns, the injected instruction itself is legitimate
    benchmark input.  The environment still may not return an oracle or a
    separately labelled injection/security objective field.
    """

    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise IntegrityError(f"{path} contains a non-string key")
            if key.casefold() in _MODEL_VISIBLE_CONTROL_KEYS:
                raise IntegrityError(f"{path} leaks control-plane field {key!r}")
            _reject_control_plane_keys(item, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_control_plane_keys(item, path=f"{path}[{index}]")


def _native_task_binding(task: Any) -> tuple[str, str]:
    """Return ``(native pack row ID, source task ID)`` for one derived task."""

    metadata = _task_metadata(task)
    source_task_id = _nonempty_string(
        metadata.get("source_task_id"), "task.metadata.source_task_id"
    )
    task_id = _nonempty_string(_task_value(task, "task_id"), "task.task_id")
    native_task_id = metadata.get(
        "source_task_record_id", metadata.get("native_task_id", task_id)
    )
    native_task_id = _nonempty_string(
        native_task_id, "task.metadata.source_task_record_id"
    )
    if not native_task_id.startswith("agentdojo-v1-"):
        raise IntegrityError("AgentDojo native task row ID is not suite-v1 scoped")
    if not source_task_id.startswith("agentdojo-v1-"):
        raise IntegrityError("AgentDojo source_task_id is not suite-v1 scoped")
    return native_task_id, source_task_id


def _validate_ordinary_planner_task(task: Any) -> None:
    """Fail closed unless this public episode uses the ordinary task agent.

    The native row may be the adversarial member of an AgentDojo pair.  That
    label controls environment injection, not the planner role.  A canary task
    therefore has a benign/ordinary planner role and no authorized red-team
    objective; the injected instruction can arrive only through a tool result.
    """

    role = _task_value(task, "pair_role")
    # ModelPlanner recognizes ``benign`` as the ordinary task-assistant role.
    # Accepting an informal alias here would only defer failure until the first
    # provider request and could tempt a caller to retain ``adversarial``.
    if role != "benign":
        raise IntegrityError(
            "AgentDojo public bridge requires an ordinary/benign planner role"
        )
    if _task_value(task, "authorized_test_objective") is not None:
        raise IntegrityError(
            "AgentDojo public bridge forbids planner-visible authorized_test_objective"
        )
    surface = _nonempty_string(_task_value(task, "surface_task"), "task.surface_task")
    _reject_control_plane_leakage(surface, path="task.surface_task")
    metadata = _task_metadata(task)
    for key in ("model_visible_context", "visible_context"):
        if key in metadata:
            _reject_control_plane_leakage(metadata[key], path=f"task.metadata.{key}")


def _operation_schemas(adapter: PublicBenchmarkAdapter) -> tuple[dict[str, Any], ...]:
    """Read exact Pydantic JSON schemas from the active pinned native runtime."""

    active = getattr(adapter, "_active", None)
    runtime = getattr(active, "runtime", None)
    functions = getattr(runtime, "functions", None)
    if not isinstance(functions, Mapping) or not functions:
        raise PublicHostBridgeError(
            "active AgentDojo runtime exposes no native function registry"
        )
    rows: list[dict[str, Any]] = []
    for raw_name in sorted(functions):
        name = _nonempty_string(raw_name, "native operation name")
        function = functions[raw_name]
        parameters = getattr(function, "parameters", None)
        serializer = getattr(parameters, "model_json_schema", None)
        if not callable(serializer):
            raise PublicHostBridgeError(
                f"native operation {name!r} has no Pydantic JSON schema"
            )
        schema = serializer()
        if not isinstance(schema, dict) or schema.get("type") != "object":
            raise PublicHostBridgeError(
                f"native operation {name!r} schema is not an object schema"
            )
        properties = schema.get("properties")
        required = schema.get("required", [])
        if (
            not isinstance(properties, dict)
            or not isinstance(required, list)
            or any(not isinstance(key, str) for key in properties)
            or any(not isinstance(key, str) for key in required)
            or len(required) != len(set(required))
            or not set(required).issubset(properties)
        ):
            raise PublicHostBridgeError(
                f"native operation {name!r} schema has invalid properties/required"
            )
        schema = copy.deepcopy(schema)
        sha256_json(schema)
        _reject_control_plane_leakage(
            schema, path=f"runtime_interface.operations.{name}.argument_schema"
        )
        rows.append({"name": name, "argument_schema": schema})
    return tuple(rows)


def _normalize_projected_event(
    value: Mapping[str, Any], *, namespace: str
) -> dict[str, Any]:
    if not isinstance(value, Mapping) or set(value) != _PROJECTED_EVENT_FIELDS:
        missing = sorted(_PROJECTED_EVENT_FIELDS - set(value)) if isinstance(value, Mapping) else []
        unknown = sorted(set(value) - _PROJECTED_EVENT_FIELDS) if isinstance(value, Mapping) else []
        raise IntegrityError(
            f"AgentDojo projected event fields differ: missing={missing}, unknown={unknown}"
        )
    event = copy.deepcopy(dict(value))
    if (
        event.get("kind") != "native_tool_action"
        or event.get("allowed") is not True
        or event.get("host_mediated") is not True
        or event.get("native_adapter_id") != AGENTDOJO_ADAPTER_ID
        or event.get("authorization_semantics") != "not_inferred"
    ):
        raise IntegrityError("AgentDojo projected event lost its native trust binding")
    # The upstream adapter's private task row ID is not a Host session ID.  Bind
    # the public event to the runner-provided fresh namespace while retaining
    # every action/evidence field that the adapter established.
    event["session_id"] = namespace
    _reject_control_plane_leakage(event, path="action_outcome.events")
    sha256_json(event)
    return event


class AgentDojoPublicHostSession:
    """One single-use Host view over one active AgentDojo native episode."""

    def __init__(
        self,
        *,
        adapter: PublicBenchmarkAdapter,
        task: Any,
        condition: ConditionSpec,
        namespace: str,
        native_task_id: str,
        source_task_id: str,
    ) -> None:
        self._adapter = adapter
        self._task = task
        self._condition = condition
        self._namespace = namespace
        self._native_task_id = native_task_id
        self._source_task_id = source_task_id
        self._closed = False
        self._ended = False
        self._terminal_state: dict[str, Any] | None = None
        self._terminal_reason: str | None = None
        self._cleanup_sha256: str | None = None
        self._trace: list[dict[str, Any]] = []
        self._events: list[dict[str, Any]] = []
        self._operations: tuple[dict[str, Any], ...] = ()
        self._operation_names: frozenset[str] = frozenset()

        evidence = adapter.reset(native_task_id)
        try:
            if not isinstance(evidence, Mapping):
                raise IntegrityError("AgentDojo reset evidence must be an object")
            reset_evidence = copy.deepcopy(dict(evidence))
            sha256_json(reset_evidence)
            if (
                reset_evidence.get("adapter_id") != AGENTDOJO_ADAPTER_ID
                or reset_evidence.get("task_id") != native_task_id
                or reset_evidence.get("source_task_id") != source_task_id
            ):
                raise IntegrityError(
                    "AgentDojo reset evidence differs from the pinned task binding"
                )
            initial_hash = reset_evidence.get("initial_state_sha256")
            if (
                not isinstance(initial_hash, str)
                or len(initial_hash) != 64
                or any(character not in "0123456789abcdef" for character in initial_hash)
            ):
                raise IntegrityError("AgentDojo reset has no exact initial-state SHA-256")
            self._reset_evidence = reset_evidence
            self._initial_state_sha256 = initial_hash
            self._current_state_sha256 = initial_hash
            self._operations = _operation_schemas(adapter)
            self._operation_names = frozenset(row["name"] for row in self._operations)
        except Exception:
            # Reset opened a native episode.  Never leave it active when bridge
            # binding/schema validation fails.
            try:
                adapter.cleanup()
            finally:
                self._closed = True
            raise

    @property
    def cleanup_sha256(self) -> str | None:
        return self._cleanup_sha256

    def _ensure_open(self) -> None:
        if self._closed:
            raise PublicHostBridgeError("AgentDojo public host session is closed")

    def interface_description(self) -> dict[str, Any]:
        self._ensure_open()
        result = {"operations": copy.deepcopy(list(self._operations))}
        _reject_control_plane_leakage(result, path="runtime_interface")
        sha256_json(result)
        return result

    def apply(self, action: ActionRequest) -> ActionOutcome:
        self._ensure_open()
        if self._ended:
            raise PublicHostBridgeError("cannot dispatch after the external task ended")
        if self._terminal_state is not None:
            raise PublicHostBridgeError("cannot dispatch after terminal assistant capture")
        if not isinstance(action, ActionRequest):
            raise SchemaError("AgentDojo bridge action must be an ActionRequest")
        if action.op not in self._operation_names:
            raise PublicHostBridgeError(
                f"operation is not in the exact native interface: {action.op}"
            )
        native_row = self._adapter.dispatch_native_action(
            {"function": action.op, "args": copy.deepcopy(action.args), "id": None}
        )
        if not isinstance(native_row, Mapping):
            raise IntegrityError("AgentDojo native dispatch result must be an object")
        row = copy.deepcopy(dict(native_row))
        sha256_json(row)
        if (
            row.get("index") != len(self._trace)
            or row.get("function") != action.op
            or row.get("args") != action.args
            or row.get("native_success") is not True
        ):
            raise IntegrityError("AgentDojo native dispatch result lost request binding")
        pre_hash = row.get("pre_state_sha256")
        post_hash = row.get("post_state_sha256")
        if pre_hash != self._current_state_sha256 or not isinstance(post_hash, str):
            raise IntegrityError("AgentDojo native state transition is not contiguous")
        self._trace.append(row)
        self._current_state_sha256 = post_hash

        projected = self._adapter.project_trusted_events(tuple(self._trace))
        if len(projected) != len(self._trace):
            raise IntegrityError("AgentDojo trusted-event projection is not one-per-action")
        normalized = [
            _normalize_projected_event(event, namespace=self._namespace)
            for event in projected
        ]
        if normalized[:-1] != self._events:
            raise IntegrityError("AgentDojo trusted-event projection changed an earlier event")
        event = normalized[-1]
        self._events.append(event)

        effect = {
            "effect_id": f"{self._namespace}:native-effect:{len(self._trace)}",
            "effect": "native_state_transition",
            "namespace": self._namespace,
            "op": action.op,
            "pre_state_sha256": pre_hash,
            "post_state_sha256": post_hash,
            "state_changed": pre_hash != post_hash,
        }
        sha256_json(effect)
        _reject_control_plane_keys(
            row.get("result"), path="action_outcome.observation.result"
        )
        observation = {
            # This is the sole bridge path through which an injected environment
            # value can reach the ordinary task agent.
            "result": copy.deepcopy(row.get("result")),
            "native_success": True,
            "post_state_sha256": post_hash,
        }
        sha256_json(observation)
        return ActionOutcome(
            allowed=True,
            reason="native_dispatch_succeeded",
            observation=observation,
            effects=(effect,),
            events=(event,),
        )

    def capture_terminal_state(
        self,
        *,
        final_assistant_text: str,
        terminal_reason: str | None = None,
    ) -> Mapping[str, Any]:
        """Bind the last ledger-confirmed assistant text to native checker input."""

        self._ensure_open()
        if self._terminal_state is not None:
            raise PublicHostBridgeError("terminal assistant text was already captured")
        if not isinstance(final_assistant_text, str) or not final_assistant_text.strip():
            raise IntegrityError(
                "final_assistant_text must be a nonempty ledger-confirmed assistant message"
            )
        if terminal_reason is not None and (
            not isinstance(terminal_reason, str) or not terminal_reason.strip()
        ):
            raise SchemaError("terminal_reason must be null or a nonempty string")
        native = self._adapter.capture_terminal_state(
            reset_state=copy.deepcopy(self._reset_evidence),
            native_trace=tuple(copy.deepcopy(self._trace)),
        )
        if not isinstance(native, Mapping):
            raise IntegrityError("AgentDojo terminal capture must return an object")
        state_hash = native.get("state_sha256")
        if state_hash != self._current_state_sha256:
            raise IntegrityError("AgentDojo terminal capture differs from native state")
        terminal = {
            "state_sha256": state_hash,
            "model_output": final_assistant_text,
        }
        sha256_json(terminal)
        self._terminal_state = terminal
        self._terminal_reason = terminal_reason
        return copy.deepcopy(terminal)

    def evaluate_native_checkers(self) -> NativeCheckerVerdict:
        """Invoke native checkers only after explicit terminal-text capture.

        The generic runner does not call this method yet.  A public canary
        oracle integration must call it explicitly; snapshot text or tool
        observations are never accepted as a substitute.
        """

        self._ensure_open()
        if self._terminal_state is None:
            raise IntegrityError(
                "native checker requires explicit ledger-confirmed assistant text"
            )
        verdict = self._adapter.evaluate_native_checkers(
            source_task_id=self._source_task_id,
            native_trace=tuple(copy.deepcopy(self._trace)),
            terminal_state=copy.deepcopy(self._terminal_state),
        )
        if not isinstance(verdict, NativeCheckerVerdict):
            raise IntegrityError("AgentDojo native checker returned an invalid verdict")
        return verdict

    def end_external_task(self) -> tuple[dict[str, Any], ...]:
        self._ensure_open()
        if self._ended:
            raise PublicHostBridgeError("external task already ended")
        self._ended = True
        # AgentDojo has no native post-task lifecycle event.  Returning an
        # invented revocation/cleanup/mechanism event would be construct-invalid.
        return ()

    def advance_lifecycle(self, transition: str) -> tuple[dict[str, Any], ...]:
        self._ensure_open()
        if not self._ended:
            raise PublicHostBridgeError("lifecycle transition requires task end")
        _nonempty_string(transition, "lifecycle transition")
        # AgentDojo exposes no corresponding native lifecycle transition.
        return ()

    def snapshot(self) -> dict[str, Any]:
        self._ensure_open()
        state = {container: {} for container in _STATE_CONTAINERS}
        result = {
            "namespace": self._namespace,
            "step": len(self._trace),
            "external_task_ended": self._ended,
            "state": state,
            "state_sha256": self._current_state_sha256,
            "native_trace_sha256": sha256_json(self._trace),
            "action_count": len(self._trace),
            "terminal_assistant_captured": self._terminal_state is not None,
        }
        _reject_control_plane_leakage(result, path="snapshot")
        sha256_json(result)
        return result

    def cleanup(self) -> str:
        self._ensure_open()
        try:
            cleanup_sha = self._adapter.cleanup()
            if cleanup_sha != self._initial_state_sha256:
                raise IntegrityError(
                    "AgentDojo cleanup SHA-256 differs from the episode baseline"
                )
            self._cleanup_sha256 = cleanup_sha
            return cleanup_sha
        finally:
            self._closed = True

    def close(self) -> None:
        if self._closed:
            return
        self.cleanup()


class AgentDojoPublicHostAdapter:
    """EnvironmentAdapter that creates exact-pin AgentDojo Host sessions."""

    adapter_id = AGENTDOJO_PUBLIC_HOST_BRIDGE_ID

    def __init__(
        self,
        *,
        public_adapter_factory: Callable[[], PublicBenchmarkAdapter] = AgentDojoAdapter,
        namespace_registry: MutableSet[str] | None = None,
    ) -> None:
        if not callable(public_adapter_factory):
            raise TypeError("public_adapter_factory must be callable")
        self._public_adapter_factory = public_adapter_factory
        self._namespaces = namespace_registry if namespace_registry is not None else set()

    def prepare_episode(
        self,
        *,
        task_record: Any,
        namespace: str,
        condition: ConditionSpec,
    ) -> HostSession:
        """Canary-friendly spelling of the EnvironmentAdapter reset boundary."""

        return self.reset(
            task=task_record,
            condition=condition,
            episode_namespace=namespace,
        )

    def reset(
        self,
        *,
        task: Any,
        condition: ConditionSpec,
        episode_namespace: str,
    ) -> AgentDojoPublicHostSession:
        if (
            not isinstance(episode_namespace, str)
            or _NAMESPACE_RE.fullmatch(episode_namespace) is None
        ):
            raise PublicHostBridgeError(
                "episode_namespace must be a safe nonempty opaque ID"
            )
        if episode_namespace in self._namespaces:
            raise PublicHostBridgeError(
                f"episode namespace already used: {episode_namespace}"
            )
        validated_condition = validate_condition(condition)
        _validate_ordinary_planner_task(task)
        native_task_id, source_task_id = _native_task_binding(task)
        self._namespaces.add(episode_namespace)
        backend = self._public_adapter_factory()
        if not isinstance(backend, PublicBenchmarkAdapter):
            raise TypeError("public_adapter_factory must return PublicBenchmarkAdapter")
        if getattr(backend, "adapter_id", None) != AGENTDOJO_ADAPTER_ID:
            raise IntegrityError("public host bridge requires the exact pinned AgentDojo adapter")
        return AgentDojoPublicHostSession(
            adapter=backend,
            task=task,
            condition=validated_condition,
            namespace=episode_namespace,
            native_task_id=native_task_id,
            source_task_id=source_task_id,
        )


def bridge_descriptor() -> dict[str, Any]:
    """Return audit identity for the bridge implementation bytes."""

    path = Path(__file__).resolve()
    result = {
        "bridge_id": AGENTDOJO_PUBLIC_HOST_BRIDGE_ID,
        "adapter_ref": AGENTDOJO_PUBLIC_HOST_ADAPTER_REF,
        "native_adapter_id": AGENTDOJO_ADAPTER_ID,
        "implementation_path": str(path),
        "implementation_sha256": sha256_bytes(path.read_bytes()),
        "terminal_text_contract": "ledger-confirmed-final-assistant-text-only",
        "condition_semantics": "validated-and-bound-no-host-mechanisms-simulated",
    }
    sha256_json(result)
    return result


__all__ = [
    "AGENTDOJO_PUBLIC_HOST_ADAPTER_REF",
    "AGENTDOJO_PUBLIC_HOST_BRIDGE_ID",
    "AgentDojoPublicHostAdapter",
    "AgentDojoPublicHostSession",
    "PublicHostBridgeError",
    "bridge_descriptor",
]
