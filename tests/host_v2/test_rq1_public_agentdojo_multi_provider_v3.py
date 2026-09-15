from __future__ import annotations

import copy
import inspect
import json
import unittest
from typing import Any

from agentmembrane.host_v2.rq1_public_agentdojo_multi_v3.provider_agent import (
    MAX_COMPLETION_TOKENS,
    MODEL_ID,
    REASONING_EFFORT,
    REQUEST_RETRIES,
    ProviderBackedOrdinaryAgent,
    ProviderBackedOrdinaryMultiSourceAgent,
    ProviderCallError,
    ProviderInputError,
    ProviderResponseContractError,
    ProviderResponseParseError,
    SYSTEM_PROMPT,
)
from agentmembrane.host_v2.rq1_smoke import ExactRQ1SolMaxClient
from agentmembrane.proxy import Completion


MESSAGES = [
    {"role": "user", "content": "Find the file and tell me its title."},
    {
        "role": "tool",
        "name": "search_files",
        "content": [{"id": "file-1", "title": "Quarterly plan"}],
    },
]
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "search_files",
            "description": "Search native drive data.",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    },
    {
        "name": "send_email",
        "description": "Native mail tool schema from another source.",
        "parameters": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "body": {"type": "string"},
            },
        },
    },
]


def _completion(text: str, *, model: str = MODEL_ID) -> Completion:
    return Completion(
        text=text,
        model=model,
        latency_ms=17,
        input_tokens=31,
        output_tokens=7,
        total_tokens=38,
    )


class _FakeExactClient:
    def __init__(self, steps: list[Completion | Exception | object]) -> None:
        self.steps = list(steps)
        self.calls: list[dict[str, Any]] = []

    def complete(
        self,
        *,
        model: str,
        system: str,
        user: str,
        max_completion_tokens: int,
        retries: int,
        reasoning_effort: str | None,
    ) -> Completion:
        self.calls.append(
            copy.deepcopy(
                {
                    "model": model,
                    "system": system,
                    "user": user,
                    "max_completion_tokens": max_completion_tokens,
                    "retries": retries,
                    "reasoning_effort": reasoning_effort,
                }
            )
        )
        step = self.steps.pop(0)
        if isinstance(step, Exception):
            raise step
        return step  # type: ignore[return-value]


class RQ1PublicAgentDojoMultiProviderV3Tests(unittest.TestCase):
    def test_one_exact_small_request_contains_only_ordinary_multi_source_view(
        self,
    ) -> None:
        expected = {
            "type": "tool_action",
            "name": "search_files",
            "arguments": {"query": "Quarterly plan"},
        }
        client = _FakeExactClient(
            [_completion(json.dumps(expected, separators=(",", ":")))]
        )
        messages = copy.deepcopy(MESSAGES)
        tools = copy.deepcopy(TOOLS)
        agent = ProviderBackedOrdinaryMultiSourceAgent(client)

        self.assertEqual(agent.respond(messages=messages, tools=tools), expected)
        self.assertEqual(messages, MESSAGES)
        self.assertEqual(tools, TOOLS)
        self.assertEqual(len(client.calls), 1)
        call = client.calls[0]
        self.assertEqual(
            set(call),
            {
                "model",
                "system",
                "user",
                "max_completion_tokens",
                "retries",
                "reasoning_effort",
            },
        )
        self.assertEqual(call["model"], MODEL_ID)
        self.assertEqual(call["system"], SYSTEM_PROMPT)
        self.assertEqual(call["max_completion_tokens"], MAX_COMPLETION_TOKENS)
        self.assertEqual(call["retries"], REQUEST_RETRIES)
        self.assertEqual(call["reasoning_effort"], REASONING_EFFORT)
        payload = json.loads(call["user"])
        self.assertEqual(set(payload), {"messages", "tools"})
        self.assertEqual(payload, {"messages": MESSAGES, "tools": TOOLS})
        rendered = json.dumps(payload, sort_keys=True).casefold()
        for hidden in (
            "pair_role",
            "planner_role",
            "arm",
            "condition_id",
            "injection_enabled",
            "authorized_test_objective",
            "expected_outcome",
            "oracle_direction",
        ):
            self.assertNotIn(hidden, rendered)

        self.assertEqual(agent.request_count, 1)
        record = agent.request_records[0]
        self.assertEqual(record["status"], "parsed_tool_action")
        self.assertIsNone(record["failure_class"])
        self.assertFalse(record["hidden_key_present"])
        self.assertEqual(record["completion_finish_status"], "returned")
        self.assertEqual(record["raw_parse_status"], "parsed_exact_union")
        self.assertEqual(record["response_type"], "tool_action")
        self.assertEqual(
            record["completion_usage"],
            {
                "model": MODEL_ID,
                "latency_ms": 17,
                "input_tokens": 31,
                "output_tokens": 7,
                "total_tokens": 38,
            },
        )
        self.assertNotIn("user", record)
        self.assertIn("request_sha256", record)

    def test_final_text_union_member_is_supported_and_usage_none_is_recorded(
        self,
    ) -> None:
        final = {"type": "final", "text": "The title is Quarterly plan."}
        completion = Completion(
            text=json.dumps(final),
            model=MODEL_ID,
            latency_ms=3,
            input_tokens=None,
            output_tokens=None,
            total_tokens=None,
        )
        client = _FakeExactClient([completion])
        agent = ProviderBackedOrdinaryAgent(client)

        self.assertEqual(agent.respond(messages=MESSAGES, tools=TOOLS), final)
        record = agent.request_records[0]
        self.assertEqual(record["status"], "parsed_final")
        self.assertEqual(record["completion_finish_status"], "returned")
        self.assertEqual(record["raw_parse_status"], "parsed_exact_union")
        self.assertEqual(record["response_type"], "final")
        self.assertEqual(
            record["completion_usage"],
            {
                "model": MODEL_ID,
                "latency_ms": 3,
                "input_tokens": None,
                "output_tokens": None,
                "total_tokens": None,
            },
        )

    def test_hidden_keys_fail_before_client_call(self) -> None:
        mutations = (
            (
                [{"role": "user", "content": {"pair_role": "adversarial"}}],
                TOOLS,
            ),
            (
                [{"role": "user", "content": {"EXPECTED_OUTCOME": "win"}}],
                TOOLS,
            ),
            (
                MESSAGES,
                [{"name": "unsafe", "parameters": {"condition_id": {}}}],
            ),
        )
        for messages, tools in mutations:
            with self.subTest(messages=messages, tools=tools):
                client = _FakeExactClient([_completion("unused")])
                agent = ProviderBackedOrdinaryAgent(client)
                with self.assertRaises(ProviderInputError) as raised:
                    agent.respond(messages=messages, tools=tools)
                self.assertEqual(
                    raised.exception.failure_class, "input_boundary_failure"
                )
                self.assertEqual(client.calls, [])
                self.assertEqual(agent.request_count, 0)
                self.assertEqual(agent.request_records, [])

    def test_each_turn_is_one_independent_completion_request(self) -> None:
        first = {
            "type": "tool_action",
            "name": "search_files",
            "arguments": {"query": "plan"},
        }
        second = {"type": "final", "text": "Quarterly plan"}
        client = _FakeExactClient(
            [_completion(json.dumps(first)), _completion(json.dumps(second))]
        )
        agent = ProviderBackedOrdinaryAgent(client)

        self.assertEqual(agent.respond(messages=MESSAGES[:1], tools=TOOLS), first)
        next_messages = [
            *MESSAGES[:1],
            {"role": "assistant", "tool_call": first},
            MESSAGES[1],
        ]
        self.assertEqual(
            agent.respond(messages=next_messages, tools=TOOLS),
            second,
        )
        self.assertEqual(agent.request_count, 2)
        self.assertEqual(len(client.calls), 2)
        self.assertEqual(len(agent.request_records), 2)
        self.assertEqual(
            [row["request_index"] for row in agent.request_records], [1, 2]
        )
        self.assertNotEqual(client.calls[0]["user"], client.calls[1]["user"])
        for call in client.calls:
            self.assertEqual(call["retries"], 0)
            self.assertEqual(call["max_completion_tokens"], 1100)

    def test_one_optional_strict_fence_preserves_exact_union_semantics(self) -> None:
        cases = (
            (
                "json-tool-action",
                "```json\n"
                '{"type":"tool_action","name":"search_files",'
                '"arguments":{"query":"plan"}}\n'
                "```",
                {
                    "type": "tool_action",
                    "name": "search_files",
                    "arguments": {"query": "plan"},
                },
            ),
            (
                "plain-fence-final",
                "  \n  ```  \n"
                '{"type":"final","text":"Quarterly plan"}\n'
                "  ```  \n ",
                {"type": "final", "text": "Quarterly plan"},
            ),
        )
        for label, raw, expected in cases:
            with self.subTest(label=label):
                client = _FakeExactClient([_completion(raw)])
                agent = ProviderBackedOrdinaryAgent(client)
                self.assertEqual(
                    agent.respond(messages=MESSAGES, tools=TOOLS), expected
                )
                self.assertEqual(len(client.calls), 1)
                self.assertEqual(agent.request_count, 1)
                self.assertEqual(
                    agent.request_records[0]["raw_parse_status"],
                    "parsed_exact_union",
                )
                self.assertEqual(
                    agent.request_records[0]["status"],
                    f"parsed_{expected['type']}",
                )
        self.assertIn("one strict Markdown code fence", SYSTEM_PROMPT)

    def test_repairs_exactly_one_trailing_brace_with_distinct_audit_status(
        self,
    ) -> None:
        tool_action = {
            "type": "tool_action",
            "name": "search_hotels",
            "arguments": {
                "hotel_names": ["Montmartre Suites"],
            },
        }
        final = {"type": "final", "text": "Montmartre Suites"}
        exact = json.dumps(tool_action, separators=(",", ":"))
        cases = (
            ("plain", exact + "}", tool_action),
            ("plain-whitespace", exact + "}  \n", tool_action),
            ("fenced", "```json\n" + exact + "}\n```", tool_action),
            ("fenced-plain", "```\n" + exact + "}\n```", tool_action),
            (
                "final-union-member",
                json.dumps(final, separators=(",", ":")) + "}",
                final,
            ),
        )
        for label, raw, expected in cases:
            with self.subTest(label=label):
                client = _FakeExactClient([_completion(raw)])
                agent = ProviderBackedOrdinaryAgent(client)
                self.assertEqual(
                    agent.respond(messages=MESSAGES, tools=TOOLS), expected
                )
                self.assertEqual(len(client.calls), 1)
                self.assertEqual(agent.request_count, 1)
                record = agent.request_records[0]
                self.assertEqual(record["status"], f"parsed_{expected['type']}")
                self.assertEqual(
                    record["raw_parse_status"],
                    "parsed_single_trailing_brace_repair",
                )
                self.assertEqual(record["completion_usage"]["total_tokens"], 38)

    def test_strict_union_allows_only_one_narrow_repair_without_retry_or_fallback(
        self,
    ) -> None:
        invalid = (
            (
                "prose-before-fence",
                "Here is the result:\n"
                "```json\n{\"type\":\"final\",\"text\":\"hello\"}\n```",
                ProviderResponseParseError,
                "response_parse_error",
                "response_parse_failure",
            ),
            (
                "prose-after-fence",
                "```json\n{\"type\":\"final\",\"text\":\"hello\"}\n```\nDone.",
                ProviderResponseParseError,
                "response_parse_error",
                "response_parse_failure",
            ),
            (
                "wrong-fence-language",
                "```javascript\n{\"type\":\"final\",\"text\":\"hello\"}\n```",
                ProviderResponseParseError,
                "response_parse_error",
                "response_parse_failure",
            ),
            (
                "inline-fence",
                "```json {\"type\":\"final\",\"text\":\"hello\"}```",
                ProviderResponseParseError,
                "response_parse_error",
                "response_parse_failure",
            ),
            (
                "two-objects-in-fence",
                "```json\n"
                '{"type":"final","text":"first"}\n'
                '{"type":"final","text":"second"}\n'
                "```",
                ProviderResponseParseError,
                "response_parse_error",
                "response_parse_failure",
            ),
            (
                "two-fences",
                "```json\n{\"type\":\"final\",\"text\":\"first\"}\n```\n"
                "```json\n{\"type\":\"final\",\"text\":\"second\"}\n```",
                ProviderResponseParseError,
                "response_parse_error",
                "response_parse_failure",
            ),
            (
                "prose-inside-fence",
                "```json\nHere is the result:\n"
                "{\"type\":\"final\",\"text\":\"hello\"}\n```",
                ProviderResponseParseError,
                "response_parse_error",
                "response_parse_failure",
            ),
            (
                "duplicate",
                '{"type":"final","type":"final","text":"hello"}',
                ProviderResponseParseError,
                "response_parse_error",
                "response_parse_failure",
            ),
            (
                "duplicate-inside-fence",
                "```json\n"
                '{"type":"final","type":"final","text":"hello"}\n'
                "```",
                ProviderResponseParseError,
                "response_parse_error",
                "response_parse_failure",
            ),
            (
                "two-extra-trailing-braces",
                '{"type":"final","text":"hello"}}}',
                ProviderResponseParseError,
                "response_parse_error",
                "response_parse_failure",
            ),
            (
                "four-closing-braces",
                '{"type":"tool_action","name":"search_files",'
                '"arguments":{}}}}',
                ProviderResponseParseError,
                "response_parse_error",
                "response_parse_failure",
            ),
            (
                "prose-ending-in-brace",
                'Result: {"type":"final","text":"hello"}}',
                ProviderResponseParseError,
                "response_parse_error",
                "response_parse_failure",
            ),
            (
                "two-objects-plus-brace",
                '{"type":"final","text":"first"}'
                '{"type":"final","text":"second"}}',
                ProviderResponseParseError,
                "response_parse_error",
                "response_parse_failure",
            ),
            (
                "missing-closing-brace",
                '{"type":"final","text":"hello"',
                ProviderResponseParseError,
                "response_parse_error",
                "response_parse_failure",
            ),
            (
                "internal-json-error-plus-brace",
                '{"type":"final",,"text":"hello"}}',
                ProviderResponseParseError,
                "response_parse_error",
                "response_parse_failure",
            ),
            (
                "duplicate-plus-brace",
                '{"type":"final","type":"final","text":"hello"}}',
                ProviderResponseParseError,
                "response_parse_error",
                "response_parse_failure",
            ),
            (
                "nan-plus-brace",
                '{"type":"tool_action","name":"search_files",'
                '"arguments":{"n":NaN}}}',
                ProviderResponseParseError,
                "response_parse_error",
                "response_parse_failure",
            ),
            (
                "repaired-array-is-not-union",
                '[{"type":"final","text":"hello"}]}',
                ProviderResponseContractError,
                "response_contract_error",
                "response_contract_failure",
            ),
            (
                "repaired-nonexact-union",
                '{"type":"final","text":"hello","extra":true}}',
                ProviderResponseContractError,
                "response_contract_error",
                "response_contract_failure",
            ),
            (
                "extra",
                '{"type":"final","text":"hello","name":"tool"}',
                ProviderResponseContractError,
                "response_contract_error",
                "response_contract_failure",
            ),
            (
                "legacy-v2",
                '{"name":"search_files","arguments":{}}',
                ProviderResponseContractError,
                "response_contract_error",
                "response_contract_failure",
            ),
            (
                "empty-final",
                '{"type":"final","text":""}',
                ProviderResponseContractError,
                "response_contract_error",
                "response_contract_failure",
            ),
        )
        repair_parse_failures = {
            "two-objects-in-fence",
            "prose-inside-fence",
            "duplicate",
            "duplicate-inside-fence",
            "two-extra-trailing-braces",
            "four-closing-braces",
            "prose-ending-in-brace",
            "two-objects-plus-brace",
            "internal-json-error-plus-brace",
            "duplicate-plus-brace",
            "nan-plus-brace",
        }
        repaired_contract_failures = {
            "repaired-array-is-not-union",
            "repaired-nonexact-union",
        }
        for label, text, error_type, status, failure_class in invalid:
            with self.subTest(label=label):
                client = _FakeExactClient([_completion(text)])
                agent = ProviderBackedOrdinaryAgent(client)
                with self.assertRaises(error_type) as raised:
                    agent.respond(messages=MESSAGES, tools=TOOLS)
                self.assertEqual(len(client.calls), 1)
                self.assertEqual(agent.request_count, 1)
                self.assertEqual(len(agent.request_records), 1)
                record = agent.request_records[0]
                self.assertEqual(record["status"], status)
                self.assertEqual(record["failure_class"], failure_class)
                self.assertEqual(raised.exception.failure_class, failure_class)
                self.assertEqual(record["completion_finish_status"], "returned")
                self.assertEqual(
                    record["raw_parse_status"],
                    (
                        "json_parse_failed_after_single_trailing_brace_repair"
                        if label in repair_parse_failures
                        else (
                            "union_contract_failed_after_single_trailing_brace_repair"
                            if label in repaired_contract_failures
                            else (
                                "json_parse_failed"
                                if failure_class == "response_parse_failure"
                                else "union_contract_failed"
                            )
                        )
                    ),
                )
                self.assertEqual(
                    record["completion_usage"]["total_tokens"], 38
                )

    def test_provider_and_noncompletion_failures_have_stable_classes(self) -> None:
        cases = (
            (
                RuntimeError("offline synthetic provider failure"),
                ProviderCallError,
                "provider_error",
                "provider_failure",
            ),
            (
                {"text": '{"type":"final","text":"wrong object"}'},
                ProviderResponseContractError,
                "response_contract_error",
                "response_contract_failure",
            ),
        )
        for step, error_type, status, failure_class in cases:
            with self.subTest(step_type=type(step).__name__):
                client = _FakeExactClient([step])
                agent = ProviderBackedOrdinaryAgent(client)
                with self.assertRaises(error_type) as raised:
                    agent.respond(messages=MESSAGES, tools=TOOLS)
                self.assertEqual(len(client.calls), 1)
                record = agent.request_records[0]
                self.assertEqual(record["status"], status)
                self.assertEqual(record["failure_class"], failure_class)
                self.assertEqual(raised.exception.failure_class, failure_class)
                if failure_class == "provider_failure":
                    self.assertEqual(
                        record["completion_finish_status"], "not_returned"
                    )
                    self.assertEqual(record["raw_parse_status"], "not_attempted")
                else:
                    self.assertEqual(
                        record["completion_finish_status"],
                        "invalid_completion_type",
                    )
                    self.assertEqual(record["raw_parse_status"], "not_attempted")

    def test_complete_kwargs_are_directly_exact_client_compatible(self) -> None:
        expected = {
            "model",
            "system",
            "user",
            "max_completion_tokens",
            "retries",
            "reasoning_effort",
        }
        exact = inspect.signature(ExactRQ1SolMaxClient.complete)
        fake = inspect.signature(_FakeExactClient.complete)
        self.assertEqual(set(exact.parameters) - {"self"}, expected)
        self.assertEqual(set(fake.parameters) - {"self"}, expected)
        self.assertTrue(
            all(
                parameter.kind is inspect.Parameter.KEYWORD_ONLY
                for name, parameter in exact.parameters.items()
                if name != "self"
            )
        )


if __name__ == "__main__":
    unittest.main()
