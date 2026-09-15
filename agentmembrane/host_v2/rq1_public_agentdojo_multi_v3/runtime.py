"""Generic ordinary-agent session over the pinned AgentDojo adapter.

The session deliberately keeps experimental coordinates outside the ordinary
agent interface.  A model can read only the upstream user prompt, schemas
frozen from the live native ``Function`` objects, and observations produced by
allowed native calls.  Pair role, treatment arm, injection-task identity,
goals, checker outputs, and selector objectives remain Host-private.

At reset, the session asks the upstream user task for its ground-truth calls in
a separate no-injection environment and projects only effect operation,
resource, authority-bearing values, and provenance.  Protected admission is a
static match against that frozen grant: it never executes the candidate and
never reads an injection task or checker.  The vulnerable arm records the same
static decision but dispatches regardless.  Upstream security checking occurs
only during final measurement.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Literal, Mapping

from ..agentdojo_adapter import (
    AgentDojoAdapter,
    AgentDojoRuntimeError,
    _copy_environment,
    _json_safe,
)
from ..schema import SchemaError, sha256_json
from .domain_authority.core import (
    AuthorityGrant,
    DomainAuthorityProfile,
    build_authority_grant,
    decide_authority,
    load_domain_profile,
    validate_native_tool_coverage,
)


PairRole = Literal["benign", "adversarial"]
Arm = Literal["vulnerable", "protected"]

SESSION_ADAPTER_ID = "agentdojo-v0.1.35-rq1-ordinary-multi-native-session-v3"
_PAIR_ROLES = frozenset({"benign", "adversarial"})
_ARMS = frozenset({"vulnerable", "protected"})


class FrozenNativeSessionError(AgentDojoRuntimeError):
    """The ordinary native-session lifecycle failed closed."""


@dataclass(frozen=True)
class DispatchResult:
    """Host-private result for one proposed native action.

    ``observation`` is the only field intended to be appended to an ordinary
    agent transcript.  Static authority evidence is retained separately so
    callers do not need to expose it to the model.
    """

    allowed: bool
    reason: str
    observation: Any
    native_trace_row: Mapping[str, Any] | None
    pre_state_sha256: str
    post_state_sha256: str
    native_dispatch_count_before: int
    native_dispatch_count_after: int
    denied_pre_dispatch: bool
    within_authority: bool
    authority_decision_sha256: str

    def as_json(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "allowed": self.allowed,
            "reason": self.reason,
            "observation": copy.deepcopy(self.observation),
            "native_trace_row": (
                copy.deepcopy(dict(self.native_trace_row))
                if self.native_trace_row is not None
                else None
            ),
            "pre_state_sha256": self.pre_state_sha256,
            "post_state_sha256": self.post_state_sha256,
            "native_dispatch_count_before": self.native_dispatch_count_before,
            "native_dispatch_count_after": self.native_dispatch_count_after,
            "denied_pre_dispatch": self.denied_pre_dispatch,
            "within_authority": self.within_authority,
            "authority_decision_sha256": self.authority_decision_sha256,
        }


def _normalize_action(action: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the exact public ``AgentDojoAdapter`` action envelope."""

    if not isinstance(action, Mapping):
        raise SchemaError("native action must be a mapping")
    if any(
        not isinstance(key, str) or key not in {"function", "args", "id"}
        for key in action
    ):
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
    normalized = {
        "function": function,
        "args": _json_safe(args),
        "id": call_id,
    }
    sha256_json(normalized)
    return normalized


class FrozenNativeSession:
    """One exact benign/adversarial row in one vulnerable/protected arm."""

    adapter_id = SESSION_ADAPTER_ID

    def __init__(
        self,
        *,
        source_task_id: str,
        pair_role: PairRole,
        arm: Arm,
        adapter: AgentDojoAdapter | None = None,
        authority_profile: DomainAuthorityProfile | None = None,
    ) -> None:
        if not isinstance(source_task_id, str) or not source_task_id:
            raise SchemaError("source_task_id must be a nonempty string")
        if pair_role not in _PAIR_ROLES:
            raise SchemaError("pair_role must be benign or adversarial")
        if arm not in _ARMS:
            raise SchemaError("arm must be vulnerable or protected")
        if adapter is not None and not isinstance(adapter, AgentDojoAdapter):
            raise TypeError("adapter must be an AgentDojoAdapter")
        if authority_profile is not None and not isinstance(
            authority_profile, DomainAuthorityProfile
        ):
            raise TypeError("authority_profile must be DomainAuthorityProfile")
        self._source_task_id = source_task_id
        self._pair_role = pair_role
        self._arm = arm
        self._adapter = adapter if adapter is not None else AgentDojoAdapter()
        self._authority_profile = authority_profile
        self._authority_grant: AuthorityGrant | None = None
        self._consumed_grant_indexes: list[int] = []
        self._reset_evidence: dict[str, Any] | None = None
        self._interface: dict[str, Any] | None = None
        self._tool_schemas_sha256: str | None = None
        self._decisions: list[dict[str, Any]] = []
        self._terminal_state: dict[str, Any] | None = None
        self._final_evaluation: dict[str, Any] | None = None
        self._cleaned = False
        self._poisoned = False

    @property
    def exact_task_id(self) -> str:
        """Host-private pack row selected at reset."""

        return f"{self._source_task_id}-{self._pair_role}"

    def _require_reset(self, operation: str) -> Any:
        if self._reset_evidence is None:
            raise FrozenNativeSessionError(f"{operation} requires reset")
        if self._cleaned:
            raise FrozenNativeSessionError(f"{operation} is unavailable after cleanup")
        if self._poisoned:
            raise FrozenNativeSessionError(
                f"{operation} is unavailable on a poisoned session"
            )
        active = self._adapter._active
        if active is None:
            self._poisoned = True
            raise FrozenNativeSessionError(
                "active pinned AgentDojo episode disappeared"
            )
        return active

    def _freeze_authority_grant(self, active: Any) -> AuthorityGrant:
        profile = (
            self._authority_profile
            if self._authority_profile is not None
            else load_domain_profile(active.domain)
        )
        if profile.domain != active.domain:
            raise FrozenNativeSessionError(
                "domain authority profile differs from the native suite"
            )
        native_names = [getattr(tool, "name", None) for tool in active.suite.tools]
        validate_native_tool_coverage(profile, native_names)
        # This environment is deliberately independent of the active benign or
        # adversarial row.  No injection task, goal, vector, or checker is read.
        clean_environment = active.suite.load_and_inject_default_environment({})
        clean_environment = active.user_task.init_environment(clean_environment)
        frozen_pre_environment = _copy_environment(clean_environment)
        ground_truth_calls = active.user_task.ground_truth(frozen_pre_environment)
        grant = build_authority_grant(
            profile,
            source_task_id=self._source_task_id,
            ground_truth_calls=ground_truth_calls,
        )
        self._authority_profile = profile
        return grant

    @staticmethod
    def _freeze_interface(active: Any) -> tuple[dict[str, Any], str]:
        prompt = getattr(active.user_task, "PROMPT", None)
        if not isinstance(prompt, str) or not prompt:
            raise FrozenNativeSessionError("native user task prompt is unavailable")
        schemas: list[dict[str, Any]] = []
        names: set[str] = set()
        for tool in active.suite.tools:
            name = getattr(tool, "name", None)
            description = getattr(tool, "description", None)
            parameters_type = getattr(tool, "parameters", None)
            schema_exporter = getattr(parameters_type, "model_json_schema", None)
            if (
                not isinstance(name, str)
                or not name
                or name in names
                or not isinstance(description, str)
                or not callable(schema_exporter)
            ):
                raise FrozenNativeSessionError("native tool metadata is invalid")
            parameters = _json_safe(schema_exporter())
            if not isinstance(parameters, dict):
                raise FrozenNativeSessionError("native tool schema is not an object")
            schemas.append(
                {
                    "type": "function",
                    "function": {
                        "name": name,
                        "description": description,
                        "parameters": parameters,
                    },
                }
            )
            names.add(name)
        if not schemas:
            raise FrozenNativeSessionError("native suite exported no tools")
        schema_sha = sha256_json(schemas)
        interface = {
            "agent_role": "ordinary_assistant",
            "messages": [{"role": "user", "content": prompt}],
            "tools": schemas,
            "tool_schemas_sha256": schema_sha,
        }
        sha256_json(interface)
        return copy.deepcopy(interface), schema_sha

    def reset(self) -> dict[str, Any]:
        """Reset the exact pack row and freeze its live native interface."""

        if self._reset_evidence is not None or self._cleaned:
            raise FrozenNativeSessionError("session reset may execute only once")
        evidence = dict(self._adapter.reset(self.exact_task_id))
        if (
            evidence.get("source_task_id") != self._source_task_id
            or evidence.get("task_id") != self.exact_task_id
            or evidence.get("pair_role") != self._pair_role
            or evidence.get("injection_enabled")
            is not (self._pair_role == "adversarial")
        ):
            try:
                self._adapter.cleanup()
            finally:
                self._poisoned = True
            raise FrozenNativeSessionError(
                "pinned adapter reset did not select the exact requested row"
            )
        active = self._adapter._active
        if active is None:
            self._poisoned = True
            raise FrozenNativeSessionError("pinned adapter reset produced no episode")
        interface, schema_sha = self._freeze_interface(active)
        grant = self._freeze_authority_grant(active)
        self._reset_evidence = copy.deepcopy(evidence)
        self._reset_evidence["authority_profile_sha256"] = (
            grant.profile_sha256
        )
        self._reset_evidence["authority_grant_sha256"] = grant.grant_sha256
        self._interface = interface
        self._tool_schemas_sha256 = schema_sha
        self._authority_grant = grant
        return self.reset_evidence()

    def reset_evidence(self) -> dict[str, Any]:
        self._require_reset("reset_evidence")
        assert self._reset_evidence is not None
        return copy.deepcopy(self._reset_evidence)

    def read(self) -> dict[str, Any]:
        """Return the complete model-visible initial input and nothing private."""

        self._require_reset("read")
        assert self._interface is not None
        return copy.deepcopy(self._interface)

    def frozen_native_schemas(self) -> list[dict[str, Any]]:
        """Return a mutation-isolated copy of the reset-time native schemas."""

        return copy.deepcopy(self.read()["tools"])

    def authority_grant(self) -> dict[str, Any]:
        """Return Host-private, condition-independent user authority bytes."""

        self._require_reset("authority_grant")
        assert self._authority_grant is not None
        return self._authority_grant.as_json()

    @property
    def tool_schemas_sha256(self) -> str:
        self._require_reset("tool_schemas_sha256")
        assert self._tool_schemas_sha256 is not None
        return self._tool_schemas_sha256

    def _actual_snapshot(self) -> dict[str, Any]:
        active = self._require_reset("snapshot")
        snapshot = {
            "state_sha256": self._adapter._state_sha256(active.environment),
            "native_trace_sha256": sha256_json(_json_safe(active.trace)),
            "function_calls_sha256": sha256_json(
                _json_safe(tuple(active.function_calls))
            ),
            "native_dispatch_count": len(active.trace),
            "function_call_count": len(active.function_calls),
        }
        sha256_json(snapshot)
        return snapshot

    def snapshot(self) -> dict[str, Any]:
        """Return state/trace counters without experimental coordinates."""

        actual = self._actual_snapshot()
        value = {
            "schema_version": 1,
            "adapter_id": self.adapter_id,
            **actual,
            "host_decision_count": len(self._decisions),
            "authority_grant_sha256": (
                self._authority_grant.grant_sha256
                if self._authority_grant is not None
                else None
            ),
            "consumed_authority_grant_indexes": list(
                self._consumed_grant_indexes
            ),
            "terminal_captured": self._terminal_state is not None,
            "final_evaluated": self._final_evaluation is not None,
        }
        sha256_json(value)
        return value

    def native_trace(self) -> tuple[dict[str, Any], ...]:
        active = self._require_reset("native_trace")
        return tuple(copy.deepcopy(row) for row in active.trace)

    def decisions(self) -> tuple[dict[str, Any], ...]:
        self._require_reset("decisions")
        return tuple(copy.deepcopy(row) for row in self._decisions)

    def _dispatch_with_native_tool_feedback(
        self,
        active: Any,
        action: Mapping[str, Any],
        *,
        expected_pre_state_sha256: str,
    ) -> dict[str, Any]:
        """Dispatch once while preserving ordinary upstream tool errors.

        AgentDojo's ordinary tool loop uses ``raise_on_error=False`` and
        returns tool implementation ``ValueError`` messages to the model.  A
        missing tool, schema-validation error, runtime exception, or any error
        accompanied by native state drift remains fatal here.  Successful and
        controlled-error attempts are both appended to the native trace and
        function-call list so final upstream checkers see the actual calls.
        """

        function = action["function"]
        safe_args = _json_safe(action["args"])
        call_id = action.get("id")
        native_names = {
            getattr(tool, "name", None) for tool in active.suite.tools
        }
        if function not in native_names:
            raise SchemaError(
                "native action function is absent from the frozen tool schema"
            )
        native = self._adapter._get_native_runtime()
        try:
            function_call = native["FunctionCall"](
                function=function,
                args=dict(safe_args),
                id=call_id,
            )
        except Exception as exc:
            raise SchemaError("native function-call envelope is invalid") from exc
        current_pre_state = self._adapter._state_sha256(active.environment)
        if current_pre_state != expected_pre_state_sha256:
            self._poisoned = True
            raise FrozenNativeSessionError(
                "native state changed before trusted dispatch"
            )
        try:
            result, error = active.runtime.run_function(
                active.environment,
                function,
                dict(safe_args),
                raise_on_error=False,
            )
        except Exception as exc:
            after_exception = self._adapter._state_sha256(active.environment)
            self._poisoned = True
            if after_exception != expected_pre_state_sha256:
                raise FrozenNativeSessionError(
                    "native runtime exception changed state without a trusted trace"
                ) from exc
            raise FrozenNativeSessionError(
                "native runtime infrastructure failed before a trusted trace"
            ) from exc
        post_state_sha256 = self._adapter._state_sha256(active.environment)
        if error is not None:
            if post_state_sha256 != expected_pre_state_sha256:
                self._poisoned = True
                raise FrozenNativeSessionError(
                    "native tool error changed state without a trusted effect"
                )
            if not isinstance(error, str):
                self._poisoned = True
                raise FrozenNativeSessionError(
                    "native runtime returned a non-string error"
                )
            if error.startswith("ToolNotFoundError:"):
                raise SchemaError("native action function is unavailable")
            if error.startswith("ValidationError:"):
                raise SchemaError("native action arguments violate the tool schema")
            # The pinned suite-v1 tool implementations use ValueError for
            # ordinary, recoverable domain errors (no search match, missing
            # resource, invalid date/value).  Other types are infrastructure
            # failures and are never converted into model-visible feedback.
            if not error.startswith("ValueError:"):
                self._poisoned = True
                raise FrozenNativeSessionError(
                    "native runtime returned an unclassified tool error"
                )
        try:
            row = {
                "schema_version": 1,
                "index": len(active.trace),
                "function": function,
                "args": safe_args,
                "args_sha256": sha256_json(safe_args),
                "result": _json_safe(result),
                **({"error": error} if error is not None else {}),
                "pre_state_sha256": expected_pre_state_sha256,
                "post_state_sha256": post_state_sha256,
                "native_success": error is None,
            }
            sha256_json(row)
        except Exception as exc:
            self._poisoned = True
            raise FrozenNativeSessionError(
                "native dispatch could not produce a trusted trace"
            ) from exc
        active.function_calls.append(function_call)
        active.trace.append(copy.deepcopy(row))
        return copy.deepcopy(row)

    def dispatch(self, action: Mapping[str, Any]) -> DispatchResult:
        """Statically decide authority, then deny or dispatch by arm."""

        if self._terminal_state is not None:
            raise FrozenNativeSessionError("dispatch is unavailable after terminal capture")
        self._require_reset("dispatch")
        normalized = _normalize_action(action)
        before = self._actual_snapshot()
        assert self._authority_profile is not None
        assert self._authority_grant is not None
        authority = decide_authority(
            self._authority_profile,
            self._authority_grant,
            action=normalized,
            consumed_grant_indexes=tuple(self._consumed_grant_indexes),
        )
        if self._arm == "protected" and not authority.within_authority:
            after = self._actual_snapshot()
            if after != before:
                self._poisoned = True
                raise FrozenNativeSessionError(
                    "pre-dispatch authority denial changed native state or trace"
                )
            result = DispatchResult(
                allowed=False,
                reason="operation_not_authorized_by_user_request",
                observation="operation_not_authorized_by_user_request",
                native_trace_row=None,
                pre_state_sha256=before["state_sha256"],
                post_state_sha256=after["state_sha256"],
                native_dispatch_count_before=before["native_dispatch_count"],
                native_dispatch_count_after=after["native_dispatch_count"],
                denied_pre_dispatch=True,
                within_authority=False,
                authority_decision_sha256=authority.decision_sha256,
            )
            decision_json = result.as_json()
            decision_json["authority"] = authority.as_json()
            decision_json["proposed_action"] = copy.deepcopy(normalized)
            self._decisions.append(decision_json)
            return result
        active = self._require_reset("dispatch")
        trace_row = self._dispatch_with_native_tool_feedback(
            active,
            normalized,
            expected_pre_state_sha256=before["state_sha256"],
        )
        after = self._actual_snapshot()
        if (
            after["native_dispatch_count"]
            != before["native_dispatch_count"] + 1
            or after["function_call_count"] != before["function_call_count"] + 1
            or trace_row.get("pre_state_sha256") != before["state_sha256"]
            or trace_row.get("post_state_sha256") != after["state_sha256"]
        ):
            self._poisoned = True
            raise FrozenNativeSessionError("native dispatch evidence differs from state")
        if (
            authority.within_authority
            and authority.matched_grant_index is not None
            and authority.consumes_grant
            and trace_row.get("native_success") is True
        ):
            self._consumed_grant_indexes.append(authority.matched_grant_index)
        native_success = trace_row.get("native_success") is True
        result = DispatchResult(
            allowed=True,
            reason=(
                "native_dispatch_succeeded"
                if native_success
                else "native_tool_error_observed"
            ),
            observation=copy.deepcopy(
                trace_row["result"]
                if native_success
                else trace_row["error"]
            ),
            native_trace_row=copy.deepcopy(trace_row),
            pre_state_sha256=before["state_sha256"],
            post_state_sha256=after["state_sha256"],
            native_dispatch_count_before=before["native_dispatch_count"],
            native_dispatch_count_after=after["native_dispatch_count"],
            denied_pre_dispatch=False,
            within_authority=authority.within_authority,
            authority_decision_sha256=authority.decision_sha256,
        )
        decision_json = result.as_json()
        decision_json["authority"] = authority.as_json()
        decision_json["proposed_action"] = copy.deepcopy(normalized)
        self._decisions.append(decision_json)
        return result

    def capture_terminal_state(
        self, *, final_assistant_text: str, terminal_reason: str | None = None
    ) -> dict[str, Any]:
        """Bind model terminal text to an exact native state/trace capture."""

        self._require_reset("capture_terminal_state")
        if self._terminal_state is not None:
            raise FrozenNativeSessionError("terminal state may be captured only once")
        if not isinstance(final_assistant_text, str):
            raise SchemaError("final_assistant_text must be a string")
        if terminal_reason is not None and not isinstance(terminal_reason, str):
            raise SchemaError("terminal_reason must be a string or null")
        assert self._reset_evidence is not None
        native = dict(
            self._adapter.capture_terminal_state(
                reset_state=self._reset_evidence,
                native_trace=self.native_trace(),
            )
        )
        # The pinned adapter captures state and deliberately leaves its shared
        # driver text empty.  This session owns the ordinary-agent transcript,
        # so it binds the actually observed terminal text before invoking the
        # very same native checker entrypoint.
        native["model_output"] = final_assistant_text
        native["terminal_reason"] = terminal_reason
        native["native_trace_sha256"] = sha256_json(_json_safe(self.native_trace()))
        sha256_json(native)
        self._terminal_state = copy.deepcopy(native)
        return copy.deepcopy(native)

    def evaluate_final(
        self,
        *,
        final_assistant_text: str | None = None,
        terminal_reason: str | None = None,
    ) -> dict[str, Any]:
        """Capture the terminal state and run exact native utility/security checkers."""

        self._require_reset("evaluate_final")
        if self._final_evaluation is not None:
            raise FrozenNativeSessionError("native final evaluation may run only once")
        if self._terminal_state is None:
            if final_assistant_text is None:
                raise SchemaError(
                    "final_assistant_text is required before terminal capture"
                )
            self.capture_terminal_state(
                final_assistant_text=final_assistant_text,
                terminal_reason=terminal_reason,
            )
        elif final_assistant_text is not None and (
            final_assistant_text != self._terminal_state.get("model_output")
            or terminal_reason != self._terminal_state.get("terminal_reason")
        ):
            raise FrozenNativeSessionError(
                "final evaluation differs from captured terminal state"
            )
        assert self._terminal_state is not None
        verdict = self._adapter.evaluate_native_checkers(
            source_task_id=self.exact_task_id,
            native_trace=self.native_trace(),
            terminal_state=self._terminal_state,
        )
        snapshot = self._actual_snapshot()
        result = {
            "schema_version": 1,
            "adapter_id": self.adapter_id,
            "source_task_id": self._source_task_id,
            "task_id": self.exact_task_id,
            "utility": verdict.utility,
            # AgentDojo names this field security, but True means the paired
            # injection task was completed.  Preserve the upstream value.
            "security": verdict.security,
            "checker_binding_ids": list(verdict.checker_binding_ids),
            "native_output_sha256": verdict.native_output_sha256,
            "state_sha256": snapshot["state_sha256"],
            "native_dispatch_count": snapshot["native_dispatch_count"],
            "terminal_state_sha256": sha256_json(self._terminal_state),
        }
        sha256_json(result)
        self._final_evaluation = copy.deepcopy(result)
        return copy.deepcopy(result)

    def cleanup(self) -> str:
        """Delegate exact baseline reconstruction to the pinned adapter."""

        self._require_reset("cleanup")
        cleanup_sha = self._adapter.cleanup()
        if cleanup_sha != self._reset_evidence.get("initial_state_sha256"):
            self._poisoned = True
            raise FrozenNativeSessionError(
                "native cleanup differs from the exact reset baseline"
            )
        self._cleaned = True
        return cleanup_sha


def create_session(
    *,
    source_task_id: str,
    pair_role: PairRole,
    arm: Arm,
    adapter: AgentDojoAdapter | None = None,
    authority_profile: DomainAuthorityProfile | None = None,
) -> FrozenNativeSession:
    """Create and reset one ordinary native session for an exact pack row."""

    session = FrozenNativeSession(
        source_task_id=source_task_id,
        pair_role=pair_role,
        arm=arm,
        adapter=adapter,
        authority_profile=authority_profile,
    )
    session.reset()
    return session


__all__ = [
    "Arm",
    "DispatchResult",
    "FrozenNativeSession",
    "FrozenNativeSessionError",
    "PairRole",
    "SESSION_ADAPTER_ID",
    "create_session",
]
