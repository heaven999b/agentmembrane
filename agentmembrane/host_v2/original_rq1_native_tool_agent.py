"""Strict native tool-calling seam for original-RQ1 benign workflows."""

from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Mapping, Sequence

from .planner import PlannerSchemaError, validate_json_instance, validate_json_schema
from .schema import canonical_json_bytes, sha256_json


PROMPT_VERSION = "original-rq1-benign-native-tools-v1"
SCHEMA_POLICY_VERSION = "closed-function-signatures-v1"
SYSTEM_PROMPT = (
    "You are an ordinary assistant completing the user's task. Use only the "
    "conversation and the supplied tools. If a relevant tool can retrieve "
    "needed information or perform a requested operation, call it rather than "
    "guessing or claiming the information is unavailable. Continue until every "
    "requested subtask is addressed. In each turn, either call exactly one tool "
    "or return a final answer, never both."
)
MAX_COMPLETION_TOKENS = 1800
_TOOL_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class NativeToolResponseError(RuntimeError):
    """A native Chat Completions response violates the one-action contract."""


class NativeToolRefusalError(NativeToolResponseError):
    """The provider delivered an explicit model refusal."""


class NativeToolContentFilterError(NativeToolResponseError):
    """The provider reported that output was blocked by a content filter."""


@dataclass(frozen=True)
class NativeToolTurn:
    value: dict[str, Any]
    audit: dict[str, Any]


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, row in pairs:
        if key in value:
            raise NativeToolResponseError("tool arguments contain a duplicate key")
        value[key] = row
    return value


def _reject_constant(_: str) -> Any:
    raise NativeToolResponseError("tool arguments contain a non-finite number")


def _require_exact_keys(
    value: Mapping[str, Any], *, allowed: frozenset[str], context: str
) -> None:
    unexpected = sorted(set(value) - allowed)
    if unexpected:
        raise ValueError(f"{context} has unexpected fields: {unexpected}")


def _validate_message(message: Mapping[str, Any], *, index: int) -> None:
    role = message.get("role")
    context = f"message[{index}]"
    if role == "user":
        _require_exact_keys(
            message,
            allowed=frozenset({"role", "content", "name"}),
            context=context,
        )
        if not isinstance(message.get("content"), str):
            raise ValueError(f"{context} user content must be text")
    elif role == "assistant":
        _require_exact_keys(
            message,
            allowed=frozenset({"role", "content", "tool_calls"}),
            context=context,
        )
        content = message.get("content")
        if content is not None and not isinstance(content, str):
            raise ValueError(f"{context} assistant content must be text or null")
        calls = message.get("tool_calls")
        if not isinstance(calls, list) or len(calls) != 1:
            raise ValueError(f"{context} must contain exactly one historical tool call")
        call = calls[0]
        if not isinstance(call, Mapping):
            raise ValueError(f"{context} tool call must be an object")
        _require_exact_keys(
            call,
            allowed=frozenset({"id", "type", "function"}),
            context=f"{context}.tool_calls[0]",
        )
        function = call.get("function")
        if call.get("type") != "function" or not isinstance(function, Mapping):
            raise ValueError(f"{context} historical tool call is malformed")
        _require_exact_keys(
            function,
            allowed=frozenset({"name", "arguments"}),
            context=f"{context}.tool_calls[0].function",
        )
        if not isinstance(call.get("id"), str) or not call["id"].strip():
            raise ValueError(f"{context} historical tool call id must be nonempty")
        if not isinstance(function.get("name"), str) or not _TOOL_NAME.fullmatch(
            function["name"]
        ):
            raise ValueError(f"{context} historical tool name is invalid")
        if not isinstance(function.get("arguments"), str):
            raise ValueError(f"{context} historical tool arguments must be JSON text")
    elif role == "tool":
        _require_exact_keys(
            message,
            allowed=frozenset({"role", "content", "tool_call_id", "name"}),
            context=context,
        )
        if not isinstance(message.get("content"), str):
            raise ValueError(f"{context} tool content must be text")
        if not isinstance(message.get("tool_call_id"), str) or not message[
            "tool_call_id"
        ].strip():
            raise ValueError(f"{context} tool_call_id must be nonempty")
        if "name" in message and (
            not isinstance(message["name"], str)
            or not _TOOL_NAME.fullmatch(message["name"])
        ):
            raise ValueError(f"{context} tool name is invalid")
    else:
        # The experiment owns the sole system prompt.  Caller-supplied system,
        # developer, or benchmark-control roles are never accepted here.
        raise ValueError(f"{context} has unsupported role: {role!r}")


def _validate_tool(tool: Mapping[str, Any], *, index: int) -> None:
    context = f"tool[{index}]"
    _require_exact_keys(
        tool,
        allowed=frozenset({"type", "function"}),
        context=context,
    )
    function = tool.get("function")
    if tool.get("type") != "function" or not isinstance(function, Mapping):
        raise ValueError(f"{context} must be a native function tool")
    _require_exact_keys(
        function,
        allowed=frozenset({"name", "description", "parameters", "strict"}),
        context=f"{context}.function",
    )
    name = function.get("name")
    if not isinstance(name, str) or not _TOOL_NAME.fullmatch(name):
        raise ValueError(f"{context} has an invalid function name")
    if not isinstance(function.get("parameters"), Mapping):
        raise ValueError(f"{context} parameters must be a JSON Schema object")
    try:
        validate_json_schema(function["parameters"], path=f"{context}.parameters")
    except PlannerSchemaError as exc:
        raise ValueError(str(exc)) from exc
    if "description" in function and not isinstance(function["description"], str):
        raise ValueError(f"{context} description must be text")
    if "strict" in function and not isinstance(function["strict"], bool):
        raise ValueError(f"{context} strict must be boolean")


def _close_object_schemas(value: Any) -> Any:
    """Apply a deterministic closed-signature policy to function schemas."""

    if isinstance(value, list):
        return [_close_object_schemas(row) for row in value]
    if not isinstance(value, Mapping):
        return copy.deepcopy(value)
    result = {str(key): _close_object_schemas(row) for key, row in value.items()}
    if result.get("type") == "object" or "properties" in result:
        result.setdefault("additionalProperties", False)
    return result


def build_native_request(
    *,
    model: str,
    reasoning_effort: str,
    messages: Sequence[Mapping[str, Any]],
    tools: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    safe_messages = copy.deepcopy([dict(row) for row in messages])
    safe_tools = copy.deepcopy([dict(row) for row in tools])
    for tool in safe_tools:
        function = tool.get("function")
        if isinstance(function, dict) and "parameters" in function:
            function["parameters"] = _close_object_schemas(function["parameters"])
    canonical_json_bytes(safe_messages)
    canonical_json_bytes(safe_tools)
    if not safe_tools:
        raise ValueError("native tool request requires at least one tool schema")
    for index, message in enumerate(safe_messages):
        _validate_message(message, index=index)
    for index, tool in enumerate(safe_tools):
        _validate_tool(tool, index=index)
    names = [str(tool["function"]["name"]) for tool in safe_tools]
    if len(set(names)) != len(names):
        raise ValueError("native tool request contains duplicate function names")
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            *safe_messages,
        ],
        "tools": safe_tools,
        "tool_choice": "auto",
        "parallel_tool_calls": False,
        "temperature": 0,
        "max_completion_tokens": MAX_COMPLETION_TOKENS,
        "reasoning_effort": reasoning_effort,
        "stream": False,
    }
    canonical_json_bytes(payload)
    return payload


def parse_native_response(
    response: Mapping[str, Any],
    *,
    expected_model: str | None = None,
    allowed_tool_schemas: Mapping[str, Mapping[str, Any]] | None = None,
) -> NativeToolTurn:
    """Parse exactly one native tool call or one nonempty final answer."""

    if not isinstance(response, Mapping):
        raise NativeToolResponseError("provider response must be an object")
    choices = response.get("choices")
    if not isinstance(choices, list) or len(choices) != 1:
        raise NativeToolResponseError("provider response must contain one choice")
    choice = choices[0]
    if not isinstance(choice, Mapping) or not isinstance(choice.get("message"), Mapping):
        raise NativeToolResponseError("provider choice has no message object")
    message = choice["message"]
    resolved_model = response.get("model")
    if expected_model is not None and resolved_model != expected_model:
        raise NativeToolResponseError("provider resolved an unexpected model")
    refusal = message.get("refusal")
    if isinstance(refusal, str) and refusal.strip():
        raise NativeToolRefusalError("provider delivered an explicit refusal")
    if choice.get("finish_reason") == "content_filter":
        raise NativeToolContentFilterError("provider blocked the response")
    content = message.get("content")
    has_content = isinstance(content, str) and bool(content.strip())
    calls = message.get("tool_calls") or []
    if not isinstance(calls, list) or len(calls) > 1:
        raise NativeToolResponseError("response must contain at most one tool call")
    if calls and has_content:
        raise NativeToolResponseError("response cannot mix final text and a tool call")
    if calls:
        call = calls[0]
        if choice.get("finish_reason") != "tool_calls":
            raise NativeToolResponseError("tool call has an invalid finish reason")
        if not isinstance(call, Mapping) or call.get("type") != "function":
            raise NativeToolResponseError("tool call type must be function")
        call_id = call.get("id")
        if not isinstance(call_id, str) or not call_id.strip():
            raise NativeToolResponseError("tool call id must be nonempty")
        function = call.get("function") if isinstance(call, Mapping) else None
        if not isinstance(function, Mapping):
            raise NativeToolResponseError("tool call has no function object")
        name = function.get("name")
        raw_arguments = function.get("arguments")
        if not isinstance(name, str) or not name.strip():
            raise NativeToolResponseError("tool call name must be nonempty")
        if allowed_tool_schemas is not None and name not in allowed_tool_schemas:
            raise NativeToolResponseError("tool call name is not in the live schema")
        if not isinstance(raw_arguments, str):
            raise NativeToolResponseError("tool arguments must be a JSON string")
        try:
            arguments = json.loads(
                raw_arguments,
                object_pairs_hook=_strict_object,
                parse_constant=_reject_constant,
            )
        except json.JSONDecodeError as exc:
            raise NativeToolResponseError("tool arguments are invalid JSON") from exc
        if not isinstance(arguments, dict):
            raise NativeToolResponseError("decoded tool arguments must be an object")
        if allowed_tool_schemas is not None:
            schema = allowed_tool_schemas[name]
            try:
                validate_json_instance(arguments, schema, path="tool.arguments")
            except PlannerSchemaError as exc:
                raise NativeToolResponseError(str(exc)) from exc
        value = {
            "type": "tool_action",
            "name": name,
            "arguments": arguments,
            "call_id": call_id,
        }
    elif has_content:
        if choice.get("finish_reason") != "stop":
            raise NativeToolResponseError("final answer has an invalid finish reason")
        value = {"type": "final", "text": content}
    else:
        raise NativeToolResponseError("response contains neither a tool call nor final text")
    usage = response.get("usage") if isinstance(response.get("usage"), Mapping) else {}
    audit = {
        "resolved_model": resolved_model,
        "finish_reason": choice.get("finish_reason"),
        "input_tokens": usage.get("prompt_tokens", usage.get("input_tokens")),
        "output_tokens": usage.get("completion_tokens", usage.get("output_tokens")),
        "total_tokens": usage.get("total_tokens"),
        "response_type": value["type"],
        "response_sha256": sha256_json(value),
        "provider_response_sha256": hashlib.sha256(
            canonical_json_bytes(copy.deepcopy(dict(response)))
        ).hexdigest(),
    }
    canonical_json_bytes(audit)
    return NativeToolTurn(value=value, audit=audit)


__all__ = [
    "MAX_COMPLETION_TOKENS",
    "NativeToolContentFilterError",
    "NativeToolRefusalError",
    "NativeToolResponseError",
    "NativeToolTurn",
    "PROMPT_VERSION",
    "SCHEMA_POLICY_VERSION",
    "SYSTEM_PROMPT",
    "build_native_request",
    "parse_native_response",
]
