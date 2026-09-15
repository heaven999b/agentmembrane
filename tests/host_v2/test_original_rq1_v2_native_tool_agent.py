from __future__ import annotations

import pytest

from agentmembrane.host_v2.original_rq1_native_tool_agent import (
    NativeToolContentFilterError,
    NativeToolRefusalError,
    NativeToolResponseError,
    build_native_request,
    parse_native_response,
)


def test_build_request_binds_native_tools_and_disables_parallel_calls() -> None:
    value = build_native_request(
        model="model",
        reasoning_effort="low",
        messages=[{"role": "user", "content": "look it up"}],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "lookup",
                    "description": "Lookup",
                    "parameters": {
                        "type": "object",
                        "properties": {"condition": {"type": "string"}},
                    },
                },
            }
        ],
    )
    assert value["tool_choice"] == "auto"
    assert value["parallel_tool_calls"] is False
    assert value["messages"][-1]["role"] == "user"
    assert "condition" in value["tools"][0]["function"]["parameters"]["properties"]


def test_build_request_rejects_control_fields_in_protocol_envelope() -> None:
    with pytest.raises(ValueError, match="unexpected fields"):
        build_native_request(
            model="model",
            reasoning_effort="low",
            messages=[
                {
                    "role": "user",
                    "content": "look it up",
                    "condition_id": "M1",
                }
            ],
            tools=[
                {
                    "type": "function",
                    "function": {
                        "name": "lookup",
                        "parameters": {"type": "object", "properties": {}},
                    },
                }
            ],
        )


def test_parse_native_tool_and_final() -> None:
    tool = parse_native_response(
        {
            "model": "model",
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "c1",
                                "type": "function",
                                "function": {
                                    "name": "lookup",
                                    "arguments": '{"id":3}',
                                },
                            }
                        ],
                    },
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14},
        },
        expected_model="model",
        allowed_tool_schemas={
            "lookup": {
                "type": "object",
                "properties": {"id": {"type": "integer"}},
                "required": ["id"],
                "additionalProperties": False,
            }
        },
    )
    assert tool.value == {
        "type": "tool_action",
        "name": "lookup",
        "arguments": {"id": 3},
        "call_id": "c1",
    }
    final = parse_native_response(
        {
            "model": "model",
            "choices": [
                {"finish_reason": "stop", "message": {"content": "done"}}
            ],
        }
    )
    assert final.value == {"type": "final", "text": "done"}


@pytest.mark.parametrize(
    "message",
    [
        {"content": None},
        {"content": "text", "tool_calls": [{"id":"c","type":"function","function": {"name": "x", "arguments": "{}"}}]},
        {
            "content": None,
            "tool_calls": [
                {"id":"c1","type":"function","function": {"name": "x", "arguments": "{}"}},
                {"id":"c2","type":"function","function": {"name": "y", "arguments": "{}"}},
            ],
        },
        {"content": None, "tool_calls": [{"id":"c","type":"function","function": {"name": "x", "arguments": "[]"}}]},
        {"content": None, "tool_calls": [{"id":"c","type":"function","function": {"name": "x", "arguments": '{"a":1,"a":2}'}}]},
    ],
)
def test_parse_native_response_fails_closed(message: dict) -> None:
    with pytest.raises(NativeToolResponseError):
        parse_native_response(
            {"choices": [{"finish_reason": "tool_calls", "message": message}]}
        )


@pytest.mark.parametrize(
    ("arguments", "tool_name"),
    [
        ("{}", "lookup"),
        ('{"id":"3"}', "lookup"),
        ('{"id":3,"extra":1}', "lookup"),
        ('{"id":3}', "unknown"),
    ],
)
def test_parse_native_response_validates_live_tool_schema(
    arguments: str, tool_name: str
) -> None:
    response = {
        "model": "model",
        "choices": [
            {
                "finish_reason": "tool_calls",
                "message": {
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "c1",
                            "type": "function",
                            "function": {"name": tool_name, "arguments": arguments},
                        }
                    ],
                },
            }
        ],
    }
    with pytest.raises(NativeToolResponseError):
        parse_native_response(
            response,
            expected_model="model",
            allowed_tool_schemas={
                "lookup": {
                    "type": "object",
                    "properties": {"id": {"type": "integer"}},
                    "required": ["id"],
                    "additionalProperties": False,
                }
            },
        )


def test_parse_native_response_separates_refusal_and_content_filter() -> None:
    with pytest.raises(NativeToolRefusalError):
        parse_native_response(
            {
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"content": None, "refusal": "cannot help"},
                    }
                ]
            }
        )
    with pytest.raises(NativeToolContentFilterError):
        parse_native_response(
            {
                "choices": [
                    {
                        "finish_reason": "content_filter",
                        "message": {"content": None},
                    }
                ]
            }
        )


def test_parse_native_response_rejects_resolved_model_drift() -> None:
    with pytest.raises(NativeToolResponseError, match="unexpected model"):
        parse_native_response(
            {
                "model": "other-model",
                "choices": [
                    {"finish_reason": "stop", "message": {"content": "done"}}
                ],
            },
            expected_model="model",
        )
