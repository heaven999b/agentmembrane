"""The v6 three-actor Chat Completions action envelope.

This is transport syntax, not native-tool authorization.  Runtime permissions
still mediate every tool name, argument, recipient, and delegated subset.
"""
from __future__ import annotations

from ..rq1_collab_v1.providers import (
    _decode,
    build_action_payload as _base_build_action_payload,
)
from .contract import PROTOCOL


def build_action_payload(profile: dict, role_prompt: str, observation: dict,
                         action_protocol: str = "single_tool_v1") -> dict:
    """Build the exact /6 wire payload sent by the model driver and hash check."""
    if type(observation) is not dict or observation.get("protocol_version") != PROTOCOL:
        raise ValueError("v6_observation_protocol_required")
    if action_protocol != "single_tool_v1":
        raise ValueError("v6_single_tool_protocol_required")
    payload = _base_build_action_payload(profile, role_prompt, observation, action_protocol)
    function = payload["tools"][0]["function"]
    function["description"] = (
        "Submit exactly one action. tool_action: type, tool, arguments; "
        "send_message: type, recipient, content; final: type, content; "
        "delegate: type, recipient (S or E), content, tools. "
        "Optional source_refs must name evidence actually delivered to you. "
        "Only H can delegate. E final hands off to H; S final returns to H. "
        "The observation's available_tools and permissions specify native scope; "
        "this envelope grants none. Runtime validates every field."
    )
    function["strict"] = False  # Dynamic native argument objects are non-strict.
    properties = function["parameters"]["properties"]
    properties["type"]["enum"] = ["tool_action", "send_message", "delegate", "final"]
    properties["recipient"]["enum"] = ["H", "S", "E"]
    properties["tools"] = {"type": "array", "maxItems": 64, "uniqueItems": True,
                           "items": {"type": "string", "minLength": 1, "maxLength": 256}}
    properties["source_refs"] = {"type": "array", "maxItems": 64, "uniqueItems": True,
                                 "items": {"type": "string", "minLength": 1, "maxLength": 256}}
    return payload


def _single_tool_action(message: dict, finish: str | None, *, protocol_version=None) -> str:
    """Return exact model arguments; runtime performs type-specific validation."""
    if protocol_version != PROTOCOL:
        raise ValueError("v6_response_protocol_required")
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
            or function["name"] != "submit_action" or type(function["arguments"]) is not str):
        raise ValueError("submit_action_arguments_required")
    text = function["arguments"]
    value = _decode(text.encode("utf-8"))  # Reject duplicate keys and nonfinite JSON.
    if type(value) is not dict or value.get("type") not in {
            "tool_action", "send_message", "delegate", "final"}:
        raise ValueError("action_envelope_schema_mismatch")
    return text
