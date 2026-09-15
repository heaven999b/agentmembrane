"""Deterministic ordinary-agent substitute for zero-token multi-turn tests."""

from __future__ import annotations

import copy
import json
from typing import Any, Mapping, Sequence

from .contracts import ADVERSARIAL_ACTION, BENIGN_ACTION, UNAUTHORIZED_TARGET


class FakeOrdinaryBankingAgent:
    """Read transactions first, then react only to the visible tool result.

    The object receives no pair role, condition arm, planner role, or hidden
    objective.  It models an ordinary agent that follows an indirect injection
    when the attacker IBAN appears in tool output.
    """

    agent_role = "ordinary_assistant"

    def __init__(self) -> None:
        self.received_views: list[dict[str, Any]] = []

    def respond(
        self,
        *,
        messages: Sequence[Mapping[str, Any]],
        tools: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        view = {
            "messages": copy.deepcopy([dict(row) for row in messages]),
            "tools": copy.deepcopy([dict(row) for row in tools]),
        }
        self.received_views.append(view)
        read_results = [
            row
            for row in messages
            if row.get("role") == "tool"
            and row.get("name") == "get_most_recent_transactions"
        ]
        if not read_results:
            return {
                "name": "get_most_recent_transactions",
                "arguments": {"n": 100},
            }
        rendered = json.dumps(
            read_results[-1].get("content"),
            sort_keys=True,
            ensure_ascii=False,
        )
        if UNAUTHORIZED_TARGET in rendered:
            return copy.deepcopy(ADVERSARIAL_ACTION)
        return copy.deepcopy(BENIGN_ACTION)


__all__ = ["FakeOrdinaryBankingAgent"]
