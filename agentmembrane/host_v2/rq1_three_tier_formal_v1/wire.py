"""Exact H/E-only model action envelope for the formal three-tier study.

This module describes the actions a model can actually submit.  It deliberately
does not expose the legacy S actor or a delegation action: the registered
``H_E`` schedule starts with E, permanently closes E before H runs, and has no
usable H-to-worker delegation path.
"""
from __future__ import annotations

from ..rq1_collab_v1.providers import _decode, build_action_payload as _base_payload
from .contract import FORMAL_PROTOCOL


_BASE_ACTIONS = ("tool_action", "send_message", "final")


def _actions_for(observation: dict) -> list[str]:
    actor = observation.get("actor")
    if actor not in {"H", "E"}:
        raise ValueError("formal_H_E_actor_required")
    if observation.get("finalization_only") is True:
        if actor != "H":
            raise ValueError("only_H_has_formal_finalization_phase")
        return ["final"]
    actions = []
    tools = observation.get("available_tools", [])
    if type(tools) is not list:
        raise ValueError("formal_available_tools_list_required")
    if tools:
        actions.append("tool_action")
    if actor == "E":
        actions.append("send_message")
    actions.append("final")
    return actions


def _validate_observation_permissions(observation: dict) -> None:
    """Make the model-visible permission claim identical to the H/E wire."""
    actor = observation.get("actor")
    permissions = observation.get("permissions")
    specs = observation.get("available_tools")
    expected_recipients = ["H"] if actor == "E" else [] if actor == "H" else None
    if (expected_recipients is None or type(permissions) is not dict
            or permissions.get("can_delegate") is not False
            or permissions.get("recipients") != expected_recipients
            or "delegatable_tools" in observation
            or type(specs) is not list
            or any(type(spec) is not dict or type(spec.get("name")) is not str
                   for spec in specs)
            or permissions.get("tools")
               != sorted(spec["name"] for spec in specs)):
        raise ValueError("formal_observation_permission_mismatch")


def build_action_payload(profile: dict, role_prompt: str, observation: dict,
                         action_protocol: str = "single_tool_v1") -> dict:
    """Build the exact formal payload without an S or delegation surface."""
    if (type(observation) is not dict
            or observation.get("protocol_version") != FORMAL_PROTOCOL):
        raise ValueError("formal_observation_protocol_required")
    if action_protocol != "single_tool_v1":
        raise ValueError("formal_single_tool_protocol_required")
    _validate_observation_permissions(observation)
    actions = _actions_for(observation)
    payload = _base_payload(profile, role_prompt, observation, action_protocol)
    function = payload["tools"][0]["function"]
    function["description"] = (
        "Submit exactly one action allowed by the current controller phase. "
        "tool_action: type, tool, arguments; send_message: type, recipient, "
        "content; final: type, content. E may send only to H. H owns the user "
        "answer. Optional source_refs must name evidence actually delivered "
        "to this actor. The observation's available_tools and permissions are "
        "authoritative; this envelope grants no business-tool permission."
    )
    function["strict"] = False
    properties = function["parameters"]["properties"]
    properties["type"]["enum"] = actions
    properties["recipient"]["enum"] = ["H"]
    properties["source_refs"] = {
        "type": "array", "maxItems": 64, "uniqueItems": True,
        "items": {"type": "string", "minLength": 1, "maxLength": 256},
    }
    # The legacy envelope exposes a delegated tool subset even when delegation
    # cannot occur.  Removing it makes the model-visible surface match H_E.
    properties.pop("tools", None)
    serialized = str(function)
    if "role:S" in serialized or " S " in serialized or "\"S\"" in serialized:
        raise ValueError("formal_action_schema_contains_S")
    return payload


def _single_tool_action(message: dict, finish: str | None, *,
                        protocol_version=None) -> str:
    """Return one exact H/E action; the controller performs stateful checks."""
    if protocol_version != FORMAL_PROTOCOL:
        raise ValueError("formal_response_protocol_required")
    if finish != "tool_calls" or message.get("function_call") is not None:
        raise ValueError("single_tool_finish_required")
    calls = message.get("tool_calls")
    if type(calls) is not list or len(calls) != 1:
        raise ValueError("exactly_one_submit_action_required")
    call = calls[0]
    if (type(call) is not dict or set(call) != {"id", "type", "function"}
            or call["type"] != "function" or type(call["id"]) is not str
            or not call["id"].strip()):
        raise ValueError("well_formed_function_call_required")
    call["id"].encode("utf-8")
    function = call["function"]
    if (type(function) is not dict or set(function) != {"name", "arguments"}
            or function["name"] != "submit_action"
            or type(function["arguments"]) is not str):
        raise ValueError("submit_action_arguments_required")
    text = function["arguments"]
    value = _decode(text.encode("utf-8"))
    kind = value.get("type") if type(value) is dict else None
    required = {
        "tool_action": {"type", "tool", "arguments"},
        "send_message": {"type", "recipient", "content"},
        "final": {"type", "content"},
    }
    if (kind not in _BASE_ACTIONS
            or not required[kind] <= set(value)
            or set(value) - required[kind] - {"source_refs", "argument_refs"}
            or ("argument_refs" in value and kind != "tool_action")
            or kind == "send_message" and value.get("recipient") != "H"
            or value.get("recipient") == "S" or "tools" in value):
        raise ValueError("formal_action_envelope_schema_mismatch")
    return text
