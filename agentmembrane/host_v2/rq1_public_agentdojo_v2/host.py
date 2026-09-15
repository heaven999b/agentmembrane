"""Condition-blind admission and non-throwing action decisions for RQ1 v2."""

from __future__ import annotations

import copy
from dataclasses import asdict, dataclass
from typing import Any, Mapping

from ..schema import IntegrityError, SchemaError, sha256_json
from .contracts import (
    AUTHORIZED_TARGET,
    AUTHORIZED_VALUE_SHA256,
    OVERLAY_ID,
    READ_RESOURCE,
    RESOURCE,
    SOURCE_TASK_ID,
    live_tool_schemas,
)


class RQ1OrdinaryHostError(IntegrityError):
    """A private Host lifecycle invariant failed."""


def admission_request() -> dict[str, Any]:
    """Return the prompt-derived authority request for the send side effect."""

    return {
        "request_type": "request_admission",
        "overlay_id": OVERLAY_ID,
        "source_task_id": SOURCE_TASK_ID,
        "op": "send_money",
        "resource": RESOURCE,
        "authorized_value": AUTHORIZED_TARGET,
        "authorized_value_sha256": AUTHORIZED_VALUE_SHA256,
        "authority_source": "exact_user_prompt_substring",
    }


@dataclass(frozen=True)
class AdmissionGrant:
    admission_id: str
    op: str
    resource: str
    authorized_value: str
    authorized_value_sha256: str
    authority_source: str
    tool_schemas_sha256: str

    def as_json(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ActionDecision:
    decision_id: str
    sequence: int
    action_name: str | None
    resource: str | None
    value_sha256: str | None
    schema_valid: bool
    within_admission: bool | None
    enforcement_enabled: bool
    allowed: bool
    denial_kind: str | None
    reason: str
    native_dispatch_count_before: int
    normalized_action: Mapping[str, Any] | None

    def as_json(self) -> dict[str, Any]:
        value = asdict(self)
        value["normalized_action"] = (
            None
            if self.normalized_action is None
            else copy.deepcopy(dict(self.normalized_action))
        )
        return value


def _normalize_action(
    action: Any,
) -> tuple[dict[str, Any] | None, str | None]:
    if not isinstance(action, Mapping) or any(
        not isinstance(key, str) for key in action
    ):
        return None, "action_must_be_object"
    if set(action) != {"name", "arguments"}:
        return None, "action_envelope_keys_differ"
    name = action.get("name")
    raw_arguments = action.get("arguments")
    if not isinstance(name, str) or not name:
        return None, "tool_name_must_be_nonempty_string"
    if not isinstance(raw_arguments, Mapping) or any(
        not isinstance(key, str) for key in raw_arguments
    ):
        return None, "tool_arguments_must_be_object"
    try:
        arguments = copy.deepcopy(dict(raw_arguments))
    except Exception:
        return None, "tool_arguments_not_copyable"
    if name == "get_most_recent_transactions":
        if any(key != "n" for key in arguments):
            return None, "read_arguments_unknown_field"
        if "n" in arguments and (
            isinstance(arguments["n"], bool)
            or not isinstance(arguments["n"], int)
        ):
            return None, "read_n_must_be_integer"
    elif name == "send_money":
        required = {"recipient", "amount", "subject", "date"}
        if not required.issubset(arguments):
            return None, "send_required_argument_missing"
        if not isinstance(arguments["recipient"], str):
            return None, "send_recipient_must_be_string"
        if (
            isinstance(arguments["amount"], bool)
            or not isinstance(arguments["amount"], (int, float))
        ):
            return None, "send_amount_must_be_number"
        if not isinstance(arguments["subject"], str):
            return None, "send_subject_must_be_string"
        if not isinstance(arguments["date"], str):
            return None, "send_date_must_be_string"
    else:
        return None, "unknown_tool"
    normalized = {"name": name, "arguments": arguments}
    try:
        sha256_json(normalized)
    except SchemaError:
        return None, "action_not_json_safe"
    return normalized, None


class RQ1OrdinaryHostGate:
    """One admission followed by multiple reads and at most one terminal send."""

    def __init__(self, *, arm: str) -> None:
        if arm not in {"vulnerable", "protected"}:
            raise SchemaError("arm must be vulnerable or protected")
        self._arm = arm
        self._grant: AdmissionGrant | None = None
        self._decisions: list[ActionDecision] = []
        self._terminal = False

    def request_admission(self, request: Mapping[str, Any]) -> AdmissionGrant:
        if self._grant is not None or self._decisions:
            raise RQ1OrdinaryHostError("request_admission must be first")
        if not isinstance(request, Mapping) or dict(request) != admission_request():
            raise RQ1OrdinaryHostError("admission request differs")
        public_payload = {
            "op": "send_money",
            "resource": RESOURCE,
            "authorized_value": AUTHORIZED_TARGET,
            "authorized_value_sha256": AUTHORIZED_VALUE_SHA256,
            "authority_source": "exact_user_prompt_substring",
            "tool_schemas_sha256": sha256_json(live_tool_schemas()),
        }
        self._grant = AdmissionGrant(
            admission_id="admission-v2-" + sha256_json(public_payload)[:20],
            **public_payload,
        )
        return self._grant

    def decide(
        self, action: Any, *, native_dispatch_count_before: int
    ) -> ActionDecision:
        if self._grant is None:
            raise RQ1OrdinaryHostError("request_admission is required")
        if self._terminal:
            raise RQ1OrdinaryHostError("episode already reached a terminal decision")
        if (
            isinstance(native_dispatch_count_before, bool)
            or not isinstance(native_dispatch_count_before, int)
            or native_dispatch_count_before < 0
        ):
            raise SchemaError("native_dispatch_count_before must be nonnegative")
        normalized, schema_reason = _normalize_action(action)
        enforcement = self._arm == "protected"
        if normalized is None:
            name = action.get("name") if isinstance(action, Mapping) else None
            payload = {
                "sequence": len(self._decisions) + 1,
                "action_name": name if isinstance(name, str) else None,
                "resource": None,
                "value_sha256": None,
                "schema_valid": False,
                "within_admission": None,
                "enforcement_enabled": enforcement,
                "allowed": False,
                "denial_kind": "invalid_schema",
                "reason": str(schema_reason),
                "native_dispatch_count_before": native_dispatch_count_before,
                "normalized_action": None,
            }
            self._terminal = True
        elif normalized["name"] == "get_most_recent_transactions":
            payload = {
                "sequence": len(self._decisions) + 1,
                "action_name": normalized["name"],
                "resource": READ_RESOURCE,
                "value_sha256": None,
                "schema_valid": True,
                "within_admission": True,
                "enforcement_enabled": enforcement,
                "allowed": True,
                "denial_kind": None,
                "reason": "read_only_tool_allowed",
                "native_dispatch_count_before": native_dispatch_count_before,
                "normalized_action": normalized,
            }
        else:
            recipient = normalized["arguments"]["recipient"]
            value_sha = sha256_json(recipient)
            within = value_sha == self._grant.authorized_value_sha256
            allowed = within or not enforcement
            payload = {
                "sequence": len(self._decisions) + 1,
                "action_name": normalized["name"],
                "resource": RESOURCE,
                "value_sha256": value_sha,
                "schema_valid": True,
                "within_admission": within,
                "enforcement_enabled": enforcement,
                "allowed": allowed,
                "denial_kind": None if allowed else "policy_denial",
                "reason": (
                    "admitted_exact_resource"
                    if within
                    else (
                        "vulnerable_enforcement_disabled"
                        if not enforcement
                        else "protected_exact_resource_mismatch"
                    )
                ),
                "native_dispatch_count_before": native_dispatch_count_before,
                "normalized_action": normalized,
            }
            self._terminal = True
        decision = ActionDecision(
            decision_id="decision-v2-" + sha256_json(payload)[:20],
            **payload,
        )
        self._decisions.append(decision)
        return decision

    def decisions(self) -> tuple[dict[str, Any], ...]:
        return tuple(row.as_json() for row in self._decisions)


__all__ = [
    "ActionDecision",
    "AdmissionGrant",
    "RQ1OrdinaryHostError",
    "RQ1OrdinaryHostGate",
    "admission_request",
]
