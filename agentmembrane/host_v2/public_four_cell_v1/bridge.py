"""Versioned resource-binding wrapper for the public four-cell candidate.

This module is deliberately an *unadjudicated generic Host-policy candidate*.
It wraps an already-reset native public Host session and places one host-owned
decision point immediately before ``delegate.apply``.  The vulnerable arm
passes through the same decision point with the single enforcement toggle
disabled; the protected arm denies an out-of-scope ``send_money.recipient``
before the native session is called.

The wrapper never reads pair-role, injection, oracle, checker, or outcome data
to construct authority.  Its authorization manifest is derived only from an
exact substring and offsets in the user's prompt.  It does not authorize a
model/API experiment and it makes no canonical six-mechanism or HCER claim.
"""

from __future__ import annotations

import copy
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping, Protocol, runtime_checkable

from .contracts import (
    AuthorizationManifest,
    ConstructStatus,
    DecisionKind,
    FOUR_CELLS,
    PairRole,
    PreDispatchDecision,
    SOURCE_TASK_ID,
    TreatmentArm,
    validate_authorization_manifest,
    validate_pre_dispatch_decision,
)


PUBLIC_FOUR_CELL_BRIDGE_ID = "agentdojo-v0.1.35-public-four-cell-host-bridge-v1"
PUBLIC_FOUR_CELL_SESSION_WRAPPER_REF = (
    "agentmembrane.host_v2.public_four_cell_v1.bridge:FourCellPublicHostSession"
)
BRIDGE_CONSTRUCT_STATUS = "generic_host_policy_candidate_unadjudicated"
RESOURCE_BINDING_MECHANISM = "resource_binding"
HOST_POLICY_ACTOR = "host-policy-kernel"
EXTERNAL_PRINCIPAL = "external-agent"
NATIVE_RUNTIME_ACTOR = "agentdojo-native-runtime"
HOST_OWNED_TERMINAL_ROUTE = "four-cell-wrapper-before-native-dispatch"

_EVENT_KINDS = frozenset(
    {
        "request_received",
        "policy_evaluated",
        "policy_denied",
        "native_dispatch_started",
        "native_dispatch_completed",
    }
)
_FORBIDDEN_AUTHORITY_TOKENS = (
    "pair_role",
    "injection",
    "oracle",
    "checker",
    "outcome",
)
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class FourCellBridgeError(RuntimeError):
    """The public four-cell wrapper cannot preserve its frozen contract."""


class IntegrityError(FourCellBridgeError):
    """A trusted binding or ordering invariant was violated."""


class SchemaError(FourCellBridgeError):
    """An overlay-local public bridge value has an invalid schema."""


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SchemaError(f"value is not strict JSON: {exc}") from exc


def sha256_bytes(value: bytes) -> str:
    if not isinstance(value, bytes):
        raise TypeError("sha256_bytes requires bytes")
    return hashlib.sha256(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256_bytes(_canonical_json_bytes(value))


def _json_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise SchemaError(f"{label} must be a string-keyed object")
    sha256_json(value)
    return copy.deepcopy(value)


@dataclass(frozen=True)
class ActionRequest:
    """Overlay-local request contract; no active Host import required."""

    op: str
    args: dict[str, Any]

    def __post_init__(self) -> None:
        if not isinstance(self.op, str) or not self.op.strip():
            raise SchemaError("action op must be a nonempty string")
        object.__setattr__(self, "args", _json_object(self.args, "action args"))


@dataclass(frozen=True)
class ActionOutcome:
    """Overlay-local outcome contract for wrapper/executor integration."""

    allowed: bool
    reason: str
    observation: Any
    effects: tuple[dict[str, Any], ...]
    events: tuple[dict[str, Any], ...]

    def __post_init__(self) -> None:
        if type(self.allowed) is not bool or not isinstance(self.reason, str):
            raise SchemaError("invalid action outcome")
        sha256_json(self.observation)
        object.__setattr__(self, "observation", copy.deepcopy(self.observation))
        object.__setattr__(
            self, "effects", tuple(_json_object(row, "effect") for row in self.effects)
        )
        object.__setattr__(
            self, "events", tuple(_json_object(row, "event") for row in self.events)
        )


@runtime_checkable
class NativeHostSession(Protocol):
    """Minimal session capability copied into the isolated overlay."""

    def interface_description(self) -> dict[str, Any]: ...
    def apply(self, action: ActionRequest) -> ActionOutcome: ...
    def end_external_task(self) -> tuple[dict[str, Any], ...]: ...
    def advance_lifecycle(self, transition: str) -> tuple[dict[str, Any], ...]: ...
    def snapshot(self) -> dict[str, Any]: ...
    def close(self) -> None: ...


def _enum_value(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value


def _dataclass_mapping(value: Any) -> dict[str, Any]:
    result = asdict(value)
    return {key: _enum_value(item) for key, item in result.items()}


def _manifest_contract_mapping(manifest: AuthorizationManifest) -> dict[str, Any]:
    """Return enum-preserving input suitable for the frozen validator."""

    return asdict(manifest)


def _decision_contract_mapping(decision: PreDispatchDecision) -> dict[str, Any]:
    """Return enum-preserving input suitable for the frozen validator."""

    return asdict(decision)


def _validate_prompt_binding(
    manifest: AuthorizationManifest, *, user_prompt: str
) -> None:
    if not isinstance(user_prompt, str) or not user_prompt:
        raise SchemaError("user_prompt must be a nonempty string")
    prompt_bytes = user_prompt.encode("utf-8")
    if sha256_bytes(prompt_bytes) != manifest.user_prompt_sha256:
        raise IntegrityError("authorization manifest user-prompt SHA differs")
    if manifest.substring_end > len(user_prompt):
        raise IntegrityError("authorization manifest substring exceeds user prompt")
    if (
        user_prompt[manifest.substring_start : manifest.substring_end]
        != manifest.authorized_value
    ):
        raise IntegrityError("authorization manifest substring/offset binding differs")
    if user_prompt.count(manifest.authorized_value) != 1:
        raise IntegrityError("authorized prompt substring must occur exactly once")


def build_authorization_manifest(
    *,
    user_prompt: str,
    user_prompt_path: str,
    authorized_value: str,
    substring_start: int,
    substring_end: int,
) -> AuthorizationManifest:
    """Build authority solely from an exact prompt substring and its offsets.

    The narrow signature is intentional: callers cannot supply a pair role,
    condition, injection target, oracle, checker, or observed outcome.  A
    deterministic manifest ID is derived from the same prompt binding.
    """

    if not isinstance(user_prompt_path, str) or not user_prompt_path.strip():
        raise SchemaError("user_prompt_path must be a nonempty string")
    if not isinstance(authorized_value, str) or not authorized_value:
        raise SchemaError("authorized_value must be a nonempty string")
    if (
        not isinstance(substring_start, int)
        or isinstance(substring_start, bool)
        or not isinstance(substring_end, int)
        or isinstance(substring_end, bool)
    ):
        raise SchemaError("authorization offsets must be integers")
    prompt_sha256 = sha256_bytes(user_prompt.encode("utf-8"))
    identity = {
        "source_task_id": SOURCE_TASK_ID,
        "user_prompt_path": user_prompt_path,
        "user_prompt_sha256": prompt_sha256,
        "authorized_operation": "send_money",
        "authorized_argument": "recipient",
        "authorized_value": authorized_value,
        "substring_start": substring_start,
        "substring_end": substring_end,
        "derivation_method": "exact_user_prompt_substring_only",
    }
    manifest = AuthorizationManifest(
        schema_version=1,
        manifest_id=f"prompt-resource-binding:{sha256_json(identity)}",
        **identity,
    )
    manifest = validate_authorization_manifest(_manifest_contract_mapping(manifest))
    _validate_prompt_binding(manifest, user_prompt=user_prompt)
    serialized = _dataclass_mapping(manifest)
    if any(
        token in key.casefold()
        for key in serialized
        for token in _FORBIDDEN_AUTHORITY_TOKENS
    ):
        raise IntegrityError("authorization manifest contains a forbidden control field")
    return manifest


def authorization_manifest_sha256(manifest: AuthorizationManifest) -> str:
    validated = validate_authorization_manifest(_manifest_contract_mapping(manifest))
    return sha256_json(_dataclass_mapping(validated))


def _cell_for(*, treatment_arm: TreatmentArm, pair_role: PairRole):
    matches = [
        cell
        for cell in FOUR_CELLS
        if cell.treatment_arm is treatment_arm and cell.pair_role is pair_role
    ]
    if len(matches) != 1:
        raise IntegrityError("arm/role does not resolve to exactly one frozen cell")
    return matches[0]


def _snapshot_facts(session: NativeHostSession) -> tuple[str, int]:
    value = session.snapshot()
    if not isinstance(value, Mapping):
        raise IntegrityError("native session snapshot must be an object")
    state_sha = value.get("state_sha256")
    count = value.get("action_count")
    if (
        not isinstance(state_sha, str)
        or _SHA256_RE.fullmatch(state_sha) is None
    ):
        raise IntegrityError("native snapshot lacks a lowercase state SHA-256")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise IntegrityError("native snapshot lacks a nonnegative action_count")
    return state_sha, count


class FourCellPublicHostSession:
    """Host-owned, pre-dispatch resource-binding wrapper for one frozen cell."""

    def __init__(
        self,
        *,
        delegate: NativeHostSession,
        treatment_arm: TreatmentArm | str,
        pair_role: PairRole | str,
        condition_id: str,
        episode_namespace: str,
        authorization_manifest: AuthorizationManifest,
        user_prompt: str,
    ) -> None:
        if not isinstance(delegate, NativeHostSession):
            raise TypeError("delegate must implement the overlay NativeHostSession")
        try:
            self._arm = TreatmentArm(treatment_arm)
            self._role = PairRole(pair_role)
        except ValueError as exc:
            raise SchemaError("invalid public four-cell arm or pair role") from exc
        self._cell = _cell_for(treatment_arm=self._arm, pair_role=self._role)
        if condition_id != self._cell.condition_id:
            raise IntegrityError("public condition ID differs from the frozen cell")
        if not isinstance(episode_namespace, str) or not episode_namespace.strip():
            raise SchemaError("episode_namespace must be a nonempty string")
        manifest = validate_authorization_manifest(
            _manifest_contract_mapping(authorization_manifest)
        )
        _validate_prompt_binding(manifest, user_prompt=user_prompt)

        self._delegate = delegate
        self._namespace = episode_namespace
        self._manifest = manifest
        self._manifest_sha256 = authorization_manifest_sha256(manifest)
        self._enforcement_enabled = self._arm is TreatmentArm.PROTECTED
        self._event_seq = 0
        self._request_seq = 0
        self._event_log: list[dict[str, Any]] = []
        self._decisions: list[dict[str, Any]] = []
        self._initial_state_sha256, self._initial_dispatch_count = _snapshot_facts(delegate)

    @property
    def authorization_manifest(self) -> dict[str, Any]:
        return copy.deepcopy(_dataclass_mapping(self._manifest))

    @property
    def authorization_manifest_sha256(self) -> str:
        return self._manifest_sha256

    @property
    def enforcement_enabled(self) -> bool:
        return self._enforcement_enabled

    def interface_description(self) -> dict[str, Any]:
        # Exact passthrough is the treatment-blinding boundary.  Never add arm,
        # condition, authority, or policy fields to the planner-visible schema.
        interface = self._delegate.interface_description()
        if not isinstance(interface, dict):
            raise IntegrityError("native interface description must be an object")
        sha256_json(interface)
        return copy.deepcopy(interface)

    def _emit(
        self,
        *,
        kind: str,
        actor: str,
        request_id: str,
        request_sha256: str,
        policy_input_sha256: str,
        decision_sha256: str | None,
        decision_kind: str | None,
        direct_authority_witness: bool,
        pre_state_sha256: str,
        post_state_sha256: str,
        dispatch_count_before: int,
        dispatch_count_after: int,
    ) -> dict[str, Any]:
        if kind not in _EVENT_KINDS:
            raise IntegrityError("unknown four-cell trusted event kind")
        self._event_seq += 1
        event = {
            "schema_version": 1,
            "event_id": f"{self._namespace}:host-policy:{self._event_seq}",
            "event_seq": self._event_seq,
            "kind": kind,
            "trusted": True,
            "actor": actor,
            "external_principal": EXTERNAL_PRINCIPAL,
            "episode_namespace": self._namespace,
            "cell_id": self._cell.cell_id,
            "condition_id": self._cell.condition_id,
            "treatment_arm": self._arm.value,
            "pair_role": self._role.value,
            "request_id": request_id,
            "request_sha256": request_sha256,
            "authorization_manifest_sha256": self._manifest_sha256,
            "policy_input_sha256": policy_input_sha256,
            "decision_sha256": decision_sha256,
            "decision_kind": decision_kind,
            "direct_authority_witness": direct_authority_witness,
            "host_owned_route_witness": True,
            "host_owned_terminal_route": HOST_OWNED_TERMINAL_ROUTE,
            "resource_binding_enforced": self._enforcement_enabled,
            "pre_state_sha256": pre_state_sha256,
            "post_state_sha256": post_state_sha256,
            "native_dispatch_count_before": dispatch_count_before,
            "native_dispatch_count_after": dispatch_count_after,
            "execution_authorized": False,
            "construct_status": BRIDGE_CONSTRUCT_STATUS,
            "claim_eligible": False,
        }
        sha256_json(event)
        self._event_log.append(copy.deepcopy(event))
        return event

    def _make_decision(
        self,
        *,
        action: ActionRequest,
        request_id: str,
        request_sha256: str,
        decision_event_id: str,
        decision_event_sequence: int,
        direct_authority: bool,
        decision_kind: DecisionKind,
        reason_code: str,
    ) -> PreDispatchDecision:
        resource = action.args.get(self._manifest.authorized_argument)
        if not isinstance(resource, str) or not resource:
            resource = "<not-applicable>"
        decision = PreDispatchDecision(
            schema_version=1,
            decision_id=f"{request_id}:decision",
            event_id=decision_event_id,
            episode_namespace=self._namespace,
            cell_id=self._cell.cell_id,
            condition_id=self._cell.condition_id,
            treatment_arm=self._arm,
            pair_role=self._role,
            request_sha256=request_sha256,
            authorization_manifest_sha256=self._manifest_sha256,
            operation=action.op,
            resource_argument=self._manifest.authorized_argument,
            requested_resource=resource,
            direct_authority_witness=direct_authority,
            host_owned_route_witness=True,
            decision_kind=decision_kind,
            reason_code=reason_code,
            pre_dispatch_sequence=decision_event_sequence,
            native_dispatch_authorized=(
                decision_kind is DecisionKind.ALLOW_NATIVE_DISPATCH
            ),
            native_dispatch_observed=False,
            execution_authorized=False,
            construct_status=ConstructStatus.UNADJUDICATED,
            claim_eligible=False,
        )
        return validate_pre_dispatch_decision(_decision_contract_mapping(decision))

    def apply(self, action: ActionRequest) -> ActionOutcome:
        if not isinstance(action, ActionRequest):
            raise SchemaError("four-cell action must be an ActionRequest")
        self._request_seq += 1
        request = {"op": action.op, "args": copy.deepcopy(action.args)}
        request_sha = sha256_json(request)
        request_id = f"{self._namespace}:request:{self._request_seq}:{request_sha[:16]}"
        pre_state, pre_count = _snapshot_facts(self._delegate)

        is_bound_operation = action.op == self._manifest.authorized_operation
        requested = action.args.get(self._manifest.authorized_argument)
        if is_bound_operation and (not isinstance(requested, str) or not requested):
            raise FourCellBridgeError(
                "send_money request lacks a nonempty recipient; refusing before dispatch"
            )
        direct_authority = bool(
            is_bound_operation and requested == self._manifest.authorized_value
        )
        deny = self._enforcement_enabled and is_bound_operation and not direct_authority
        if deny:
            decision_kind = DecisionKind.DENY_BEFORE_NATIVE_DISPATCH
            reason_code = "resource_binding_denied_pre_dispatch"
        elif not is_bound_operation:
            decision_kind = DecisionKind.ALLOW_NATIVE_DISPATCH
            reason_code = "resource_binding_not_applicable"
        elif direct_authority:
            decision_kind = DecisionKind.ALLOW_NATIVE_DISPATCH
            reason_code = "exact_direct_user_authority"
        else:
            decision_kind = DecisionKind.ALLOW_NATIVE_DISPATCH
            reason_code = "vulnerable_resource_binding_toggle_disabled"

        policy_input = {
            "request_sha256": request_sha,
            "authorization_manifest_sha256": self._manifest_sha256,
            "resource_binding_enforced": self._enforcement_enabled,
        }
        policy_input_sha = sha256_json(policy_input)
        decision_event_sequence = self._event_seq + 2
        decision_event_id = (
            f"{self._namespace}:host-policy:{decision_event_sequence}"
        )
        decision = self._make_decision(
            action=action,
            request_id=request_id,
            request_sha256=request_sha,
            decision_event_id=decision_event_id,
            decision_event_sequence=decision_event_sequence,
            direct_authority=direct_authority,
            decision_kind=decision_kind,
            reason_code=reason_code,
        )
        decision_row = _dataclass_mapping(decision)
        decision_sha = sha256_json(decision_row)
        self._decisions.append(copy.deepcopy(decision_row))

        request_event = self._emit(
            kind="request_received",
            actor=EXTERNAL_PRINCIPAL,
            request_id=request_id,
            request_sha256=request_sha,
            policy_input_sha256=policy_input_sha,
            decision_sha256=None,
            decision_kind=None,
            direct_authority_witness=direct_authority,
            pre_state_sha256=pre_state,
            post_state_sha256=pre_state,
            dispatch_count_before=pre_count,
            dispatch_count_after=pre_count,
        )
        evaluated_event = self._emit(
            kind="policy_evaluated",
            actor=HOST_POLICY_ACTOR,
            request_id=request_id,
            request_sha256=request_sha,
            policy_input_sha256=policy_input_sha,
            decision_sha256=decision_sha,
            decision_kind=decision_kind.value,
            direct_authority_witness=direct_authority,
            pre_state_sha256=pre_state,
            post_state_sha256=pre_state,
            dispatch_count_before=pre_count,
            dispatch_count_after=pre_count,
        )
        if evaluated_event["event_id"] != decision.event_id:
            raise IntegrityError("pre-dispatch decision event binding differs")

        if deny:
            post_state, post_count = _snapshot_facts(self._delegate)
            if post_state != pre_state or post_count != pre_count:
                raise IntegrityError("pre-dispatch denial changed native state or count")
            denial_event = self._emit(
                kind="policy_denied",
                actor=HOST_POLICY_ACTOR,
                request_id=request_id,
                request_sha256=request_sha,
                policy_input_sha256=policy_input_sha,
                decision_sha256=decision_sha,
                decision_kind=decision_kind.value,
                direct_authority_witness=False,
                pre_state_sha256=pre_state,
                post_state_sha256=post_state,
                dispatch_count_before=pre_count,
                dispatch_count_after=post_count,
            )
            return ActionOutcome(
                allowed=False,
                reason=reason_code,
                observation={
                    "error": reason_code,
                    "native_dispatch_observed": False,
                    "state_sha256": post_state,
                },
                effects=(),
                events=(request_event, evaluated_event, denial_event),
            )

        started_event = self._emit(
            kind="native_dispatch_started",
            actor=HOST_POLICY_ACTOR,
            request_id=request_id,
            request_sha256=request_sha,
            policy_input_sha256=policy_input_sha,
            decision_sha256=decision_sha,
            decision_kind=decision_kind.value,
            direct_authority_witness=direct_authority,
            pre_state_sha256=pre_state,
            post_state_sha256=pre_state,
            dispatch_count_before=pre_count,
            dispatch_count_after=pre_count,
        )
        native = self._delegate.apply(action)
        if not isinstance(native, ActionOutcome) or native.allowed is not True:
            raise IntegrityError("authorized native dispatch did not return allowed=true")
        post_state, post_count = _snapshot_facts(self._delegate)
        if post_count != pre_count + 1:
            raise IntegrityError("native dispatch count did not increment exactly once")
        completed_event = self._emit(
            kind="native_dispatch_completed",
            actor=NATIVE_RUNTIME_ACTOR,
            request_id=request_id,
            request_sha256=request_sha,
            policy_input_sha256=policy_input_sha,
            decision_sha256=decision_sha,
            decision_kind=decision_kind.value,
            direct_authority_witness=direct_authority,
            pre_state_sha256=pre_state,
            post_state_sha256=post_state,
            dispatch_count_before=pre_count,
            dispatch_count_after=post_count,
        )
        return ActionOutcome(
            allowed=True,
            reason=native.reason,
            observation=copy.deepcopy(native.observation),
            effects=tuple(copy.deepcopy(native.effects)),
            events=(
                request_event,
                evaluated_event,
                started_event,
                *tuple(copy.deepcopy(native.events)),
                completed_event,
            ),
        )

    def treatment_evidence(self) -> dict[str, Any]:
        current_state, current_count = _snapshot_facts(self._delegate)
        evidence = {
            "schema_version": 1,
            "bridge_id": PUBLIC_FOUR_CELL_BRIDGE_ID,
            "construct_status": BRIDGE_CONSTRUCT_STATUS,
            "cell_id": self._cell.cell_id,
            "condition_id": self._cell.condition_id,
            "treatment_arm": self._arm.value,
            "pair_role": self._role.value,
            "atomic_mechanism": RESOURCE_BINDING_MECHANISM,
            "resource_binding_enforced": self._enforcement_enabled,
            "authorization_manifest": self.authorization_manifest,
            "authorization_manifest_sha256": self._manifest_sha256,
            "host_owned_terminal_route": HOST_OWNED_TERMINAL_ROUTE,
            "initial_state_sha256": self._initial_state_sha256,
            "current_state_sha256": current_state,
            "initial_native_dispatch_count": self._initial_dispatch_count,
            "native_dispatch_count": current_count,
            "pre_dispatch_decisions": copy.deepcopy(self._decisions),
            "trusted_event_log": copy.deepcopy(self._event_log),
            "trusted_event_log_sha256": sha256_json(self._event_log),
            "execution_authorized": False,
            "claim_eligible": False,
            "canonical_six_mechanism_claim_eligible": False,
            "hcer_claim_eligible": False,
        }
        sha256_json(evidence)
        return evidence

    def capture_terminal_state(
        self, *, final_assistant_text: str, terminal_reason: str | None = None
    ) -> Mapping[str, Any]:
        method = getattr(self._delegate, "capture_terminal_state", None)
        if not callable(method):
            raise FourCellBridgeError("native session lacks terminal-state capture")
        return method(
            final_assistant_text=final_assistant_text,
            terminal_reason=terminal_reason,
        )

    def evaluate_native_checkers(self) -> Any:
        method = getattr(self._delegate, "evaluate_native_checkers", None)
        if not callable(method):
            raise FourCellBridgeError("native session lacks native checker evaluation")
        return method()

    def end_external_task(self) -> tuple[dict[str, Any], ...]:
        return self._delegate.end_external_task()

    def advance_lifecycle(self, transition: str) -> tuple[dict[str, Any], ...]:
        return self._delegate.advance_lifecycle(transition)

    def snapshot(self) -> dict[str, Any]:
        # Preserve the native snapshot exactly; treatment evidence is available
        # only through the trusted, non-model-facing accessor above.
        return copy.deepcopy(self._delegate.snapshot())

    def cleanup(self) -> Any:
        method = getattr(self._delegate, "cleanup", None)
        if not callable(method):
            raise FourCellBridgeError("native session lacks exact cleanup")
        return method()

    def close(self) -> None:
        self._delegate.close()


def bridge_descriptor() -> dict[str, Any]:
    path = Path(__file__).resolve()
    descriptor = {
        "bridge_id": PUBLIC_FOUR_CELL_BRIDGE_ID,
        "session_wrapper_ref": PUBLIC_FOUR_CELL_SESSION_WRAPPER_REF,
        "implementation_path": str(path),
        "implementation_sha256": sha256_bytes(path.read_bytes()),
        "construct_status": BRIDGE_CONSTRUCT_STATUS,
        "treatment": "single-atomic-resource-binding-toggle",
        "protected_enforcement_point": "before-native-dispatch",
        "vulnerable_mediation_layer_installed": True,
        "planner_visible_schema_modified": False,
        "authorization_derivation": "exact_user_prompt_substring_only",
        "execution_authorized": False,
        "claim_eligible": False,
        "canonical_six_mechanism_claim_eligible": False,
        "hcer_claim_eligible": False,
    }
    sha256_json(descriptor)
    return descriptor


__all__ = [
    "BRIDGE_CONSTRUCT_STATUS",
    "FourCellBridgeError",
    "FourCellPublicHostSession",
    "PUBLIC_FOUR_CELL_BRIDGE_ID",
    "PUBLIC_FOUR_CELL_SESSION_WRAPPER_REF",
    "authorization_manifest_sha256",
    "bridge_descriptor",
    "build_authorization_manifest",
]
