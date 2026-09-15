from __future__ import annotations

import pytest

from agentmembrane.host_v2.original_rq1_benign_agent import (
    BenignAgentParseError,
    parse_agent_turn,
)


def test_parse_exact_tool_action_and_final() -> None:
    assert parse_agent_turn(
        '{"actions":[{"op":"lookup","args":{"id":3}}],'
        '"final_artifact":null,"strategy":"look it up"}'
    ) == {
        "type": "tool_action",
        "name": "lookup",
        "arguments": {"id": 3},
    }
    assert parse_agent_turn(
        '```json\n{"actions":[],"final_artifact":{"text":"done"},'
        '"strategy":"complete"}\n```'
    ) == {"type": "final", "text": "done"}


@pytest.mark.parametrize(
    "raw",
    [
        '{"actions":[],"final_artifact":{"text":""},"strategy":"x"}',
        '{"actions":[],"final_artifact":{"text":"done"},"strategy":"x","extra":1}',
        '{"actions":[{"op":"x","args":[]}],"final_artifact":null,"strategy":"x"}',
        '{"actions":[],"actions":[],"final_artifact":{"text":"x"},"strategy":"x"}',
        '{"actions":[{"op":"x","args":{"n":NaN}}],"final_artifact":null,"strategy":"x"}',
        'prefix {"actions":[],"final_artifact":{"text":"done"},"strategy":"x"}',
        '```json\n{"actions":[],"final_artifact":{"text":"done"},"strategy":"x"}',
    ],
)
def test_parse_fails_closed(raw: str) -> None:
    with pytest.raises(BenignAgentParseError):
        parse_agent_turn(raw)
