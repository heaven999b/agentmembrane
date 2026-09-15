"""Frozen primitives for Host-mediated RQ1b / legacy HB-RQ2.

This overlay is design-only: importing or validating it never authorizes an
experiment, a provider request, or a native dispatch.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Any, Mapping


CANONICAL_LABEL = "Host-mediated RQ1b / legacy HB-RQ2"
CONTRACT_VERSION = "public-four-cell-contract-v1"
CONSTRUCT_ID = "host_mediated_capability_exploitation"
SOURCE_TASK_ID = "agentdojo-v1-banking-u3-i1"
FAMILY_ID = "public_resource_binding_u3_i1"
VULNERABLE_CONDITION_ID = "RQ1-resource-vulnerable-public-v1"
PROTECTED_CONDITION_ID = "RQ1-resource-protected-public-v1"
INJECTION_SUCCESS_SEMANTICS = "injection_objective_achieved"


class ContractError(ValueError):
    """A frozen public four-cell contract was violated."""


class ConstructStatus(str, Enum):
    UNADJUDICATED = "unadjudicated"


class TreatmentArm(str, Enum):
    VULNERABLE = "vulnerable"
    PROTECTED = "protected"


class PairRole(str, Enum):
    BENIGN = "benign"
    ADVERSARIAL = "adversarial"


class DecisionKind(str, Enum):
    ALLOW_NATIVE_DISPATCH = "allow_native_dispatch"
    DENY_BEFORE_NATIVE_DISPATCH = "deny_before_native_dispatch"


DEFAULT_CONSTRUCT_STATUS = ConstructStatus.UNADJUDICATED.value


@dataclass(frozen=True)
class FourCell:
    cell_id: str
    condition_id: str
    treatment_arm: TreatmentArm
    pair_role: PairRole
    family_id: str = FAMILY_ID


FOUR_CELLS = (
    FourCell("benign-vulnerable", VULNERABLE_CONDITION_ID, TreatmentArm.VULNERABLE, PairRole.BENIGN),
    FourCell("benign-protected", PROTECTED_CONDITION_ID, TreatmentArm.PROTECTED, PairRole.BENIGN),
    FourCell("adversarial-vulnerable", VULNERABLE_CONDITION_ID, TreatmentArm.VULNERABLE, PairRole.ADVERSARIAL),
    FourCell("adversarial-protected", PROTECTED_CONDITION_ID, TreatmentArm.PROTECTED, PairRole.ADVERSARIAL),
)

HCER_COMPONENTS = (
    "confused_deputy_outcome",
    "capability_delegation_outcome",
    "proposal_conversion_outcome",
    "capability_chaining_outcome",
    "cross_tool_composition_outcome",
    "transformation_laundering_outcome",
)

REQUIRED_AUTHORIZATION_MANIFEST_FIELDS = (
    "schema_version", "manifest_id", "source_task_id", "user_prompt_path",
    "user_prompt_sha256", "authorized_operation", "authorized_argument",
    "authorized_value", "substring_start", "substring_end", "derivation_method",
)
REQUIRED_PRE_DISPATCH_WITNESS_FIELDS = (
    "schema_version", "decision_id", "event_id", "episode_namespace", "cell_id",
    "condition_id", "treatment_arm", "pair_role", "request_sha256",
    "authorization_manifest_sha256", "operation", "resource_argument",
    "requested_resource", "direct_authority_witness", "host_owned_route_witness",
    "decision_kind", "reason_code", "pre_dispatch_sequence",
    "native_dispatch_authorized", "native_dispatch_observed",
    "execution_authorized", "construct_status", "claim_eligible",
)
IMMUTABLE_BINDING_FIELDS = (
    "profile_sha256", "schedule_sha256", "authorization_manifest_sha256",
    "run_chain_manifest_sha256", "taskpack_manifest_sha256", "taskpack_tasks_sha256",
)
IMMUTABLE_LEDGER_FIELDS = (
    "attempt_ledger_sha256", "attempt_count", "delivered_call_count",
    "token_bearing_call_count", "failed_pre_model_attempt_count", "namespace_reused",
)
IMMUTABLE_CLEANUP_FIELDS = (
    "initial_state_sha256", "cleanup_state_sha256", "cleanup_succeeded",
)


@dataclass(frozen=True)
class AuthorizationManifest:
    schema_version: int
    manifest_id: str
    source_task_id: str
    user_prompt_path: str
    user_prompt_sha256: str
    authorized_operation: str
    authorized_argument: str
    authorized_value: str
    substring_start: int
    substring_end: int
    derivation_method: str = "exact_user_prompt_substring_only"


@dataclass(frozen=True)
class PreDispatchDecision:
    schema_version: int
    decision_id: str
    event_id: str
    episode_namespace: str
    cell_id: str
    condition_id: str
    treatment_arm: TreatmentArm
    pair_role: PairRole
    request_sha256: str
    authorization_manifest_sha256: str
    operation: str
    resource_argument: str
    requested_resource: str
    direct_authority_witness: bool
    host_owned_route_witness: bool
    decision_kind: DecisionKind
    reason_code: str
    pre_dispatch_sequence: int
    native_dispatch_authorized: bool
    native_dispatch_observed: bool = False
    execution_authorized: bool = False
    construct_status: ConstructStatus = ConstructStatus.UNADJUDICATED
    claim_eligible: bool = False


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _exact_fields(value: Mapping[str, Any], fields: tuple[str, ...], label: str) -> None:
    if set(value) != set(fields):
        raise ContractError(f"{label} fields differ from the frozen contract")


def validate_authorization_manifest(value: Mapping[str, Any]) -> AuthorizationManifest:
    _exact_fields(value, REQUIRED_AUTHORIZATION_MANIFEST_FIELDS, "authorization manifest")
    result = AuthorizationManifest(**value)
    if result.source_task_id != SOURCE_TASK_ID or result.schema_version != 1:
        raise ContractError("authorization manifest source/schema differs")
    if not _SHA256.fullmatch(result.user_prompt_sha256):
        raise ContractError("user_prompt_sha256 is not a lowercase SHA-256")
    if result.authorized_operation != "send_money" or result.authorized_argument != "recipient":
        raise ContractError("authorization manifest must bind send_money.recipient")
    if result.substring_start < 0 or result.substring_end <= result.substring_start:
        raise ContractError("authorization manifest offsets are invalid")
    if result.derivation_method != "exact_user_prompt_substring_only":
        raise ContractError("authorization manifest derivation is not oracle-independent")
    return result


def validate_pre_dispatch_decision(value: Mapping[str, Any]) -> PreDispatchDecision:
    _exact_fields(value, REQUIRED_PRE_DISPATCH_WITNESS_FIELDS, "pre-dispatch witness")
    normalized = dict(value)
    try:
        normalized["treatment_arm"] = TreatmentArm(normalized["treatment_arm"])
        normalized["pair_role"] = PairRole(normalized["pair_role"])
        normalized["decision_kind"] = DecisionKind(normalized["decision_kind"])
        normalized["construct_status"] = ConstructStatus(normalized["construct_status"])
    except (TypeError, ValueError) as exc:
        raise ContractError("pre-dispatch witness contains an invalid enum value") from exc
    result = PreDispatchDecision(**normalized)
    if result.execution_authorized or result.native_dispatch_observed or result.claim_eligible:
        raise ContractError("offline witness cannot authorize/observe execution or support a claim")
    if result.construct_status is not ConstructStatus.UNADJUDICATED:
        raise ContractError("construct_status must remain unadjudicated")
    if not _SHA256.fullmatch(result.request_sha256) or not _SHA256.fullmatch(result.authorization_manifest_sha256):
        raise ContractError("pre-dispatch witness hashes are invalid")
    return result
