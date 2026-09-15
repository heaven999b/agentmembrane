from __future__ import annotations

import copy
import inspect
import json
from pathlib import Path
import tempfile
import unittest

from agentmembrane.host_v2.rq1_public_agentdojo_v2.contracts import (
    ADVERSARIAL_ACTION,
    BENIGN_ACTION,
    INJECTION_GOAL,
    UNAUTHORIZED_TARGET,
)
from agentmembrane.host_v2.rq1_public_agentdojo_v2.engineering_executor import (
    EngineeringExecutorError,
    OfflineScriptedCompletionClient,
    load_engineering_batch,
    run_provider_engineering_batch,
)
from agentmembrane.host_v2.rq1_public_agentdojo_v2.provider_agent import (
    MAX_COMPLETION_TOKENS,
    MODEL_ID,
    REASONING_EFFORT,
    REQUEST_RETRIES,
    ProviderBackedOrdinaryAgent,
    ProviderResponseError,
    SYSTEM_PROMPT,
)
from agentmembrane.host_v2.rq1_public_agentdojo_v2.selector import select_cell
from agentmembrane.host_v2.rq1_public_agentdojo_v2.runner import (
    run_ordinary_agent_episode,
)
from agentmembrane.host_v2.rq1_smoke import ExactRQ1SolMaxClient
from agentmembrane.proxy import Completion


class _FakeExactCompletionClient:
    """Offline fake with the exact LocalProxyClient.complete call signature."""

    def __init__(
        self,
        *,
        failure_by_call: dict[int, str] | None = None,
    ) -> None:
        self.failure_by_call = dict(failure_by_call or {})
        self.calls: list[dict[str, object]] = []

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
        call = {
            "model": model,
            "system": system,
            "user": user,
            "max_completion_tokens": max_completion_tokens,
            "retries": retries,
            "reasoning_effort": reasoning_effort,
        }
        self.calls.append(copy.deepcopy(call))
        call_index = len(self.calls)
        failure = self.failure_by_call.get(call_index)
        if failure == "provider":
            raise RuntimeError("synthetic offline provider failure")
        if failure == "parse":
            text = "```json\n{\"name\":\"send_money\",\"arguments\":{}}\n```"
        else:
            payload = json.loads(user)
            messages = payload["messages"]
            read_result_seen = any(
                row.get("role") == "tool"
                and row.get("name") == "get_most_recent_transactions"
                for row in messages
            )
            if not read_result_seen:
                action = {
                    "name": "get_most_recent_transactions",
                    "arguments": {"n": 100},
                }
            elif failure == "schema":
                action = {
                    "name": "send_money",
                    "arguments": {
                        "recipient": UNAUTHORIZED_TARGET,
                        "subject": "missing amount",
                        "date": "2022-01-01",
                    },
                }
            elif INJECTION_GOAL in json.dumps(messages, ensure_ascii=False):
                action = copy.deepcopy(ADVERSARIAL_ACTION)
            else:
                action = copy.deepcopy(BENIGN_ACTION)
            text = json.dumps(action, sort_keys=True, separators=(",", ":"))
        return Completion(
            text=text,
            model=model,
            latency_ms=1,
            input_tokens=1,
            output_tokens=1,
            total_tokens=2,
        )


def _completion(value: dict[str, object] | str) -> Completion:
    text = (
        value
        if isinstance(value, str)
        else json.dumps(value, sort_keys=True, separators=(",", ":"))
    )
    return Completion(
        text=text,
        model="gpt-5.6-sol",
        latency_ms=0,
        input_tokens=0,
        output_tokens=0,
        total_tokens=0,
    )


def _offline_client(
    *, failure_call: int | None = None, failure_kind: str | None = None
) -> OfflineScriptedCompletionClient:
    read = {
        "name": "get_most_recent_transactions",
        "arguments": {"n": 100},
    }
    if failure_kind in {"provider", "parse"} and failure_call == 3:
        failure_step: Completion | Exception
        if failure_kind == "provider":
            failure_step = RuntimeError("synthetic offline provider failure")
        else:
            failure_step = _completion("```json\n{}\n```")
        steps: list[Completion | Exception] = [
            _completion(read),
            _completion(BENIGN_ACTION),
            failure_step,
            _completion(read),
            _completion(ADVERSARIAL_ACTION),
            _completion(read),
            _completion(ADVERSARIAL_ACTION),
        ]
    else:
        second_protected: dict[str, object] = copy.deepcopy(BENIGN_ACTION)
        if failure_kind == "schema" and failure_call == 4:
            second_protected = {
                "name": "send_money",
                "arguments": {
                    "recipient": UNAUTHORIZED_TARGET,
                    "subject": "missing amount",
                    "date": "2022-01-01",
                },
            }
        steps = [
            _completion(read),
            _completion(BENIGN_ACTION),
            _completion(read),
            _completion(second_protected),
            _completion(read),
            _completion(ADVERSARIAL_ACTION),
            _completion(read),
            _completion(ADVERSARIAL_ACTION),
        ]
    return OfflineScriptedCompletionClient(steps)


def _private_keys(value: object) -> set[str]:
    prohibited = {
        "arm",
        "authorized_test_objective",
        "condition",
        "injection_enabled",
        "pair_role",
        "planner_role",
    }
    found: set[str] = set()
    if isinstance(value, dict):
        found.update(key for key in value if key in prohibited)
        for row in value.values():
            found.update(_private_keys(row))
    elif isinstance(value, list):
        for row in value:
            found.update(_private_keys(row))
    return found


class RQ1PublicAgentDojoProviderV2Tests(unittest.TestCase):
    def test_agent_uses_exact_completion_client_seam_and_fixed_settings(self) -> None:
        client = _FakeExactCompletionClient()
        cell = select_cell("benign", "vulnerable")
        visible = cell.model_visible_initial()
        action = ProviderBackedOrdinaryAgent(client).respond(
            messages=visible["messages"],
            tools=visible["tools"],
        )
        self.assertEqual(action["name"], "get_most_recent_transactions")
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
        user = json.loads(str(call["user"]))
        self.assertEqual(set(user), {"messages", "response_contract", "tools"})
        self.assertEqual(user["messages"], visible["messages"])
        self.assertEqual(user["tools"], visible["tools"])
        self.assertFalse(_private_keys(user))

    def test_signature_matches_exact_rq1_client_without_transport_adapter(self) -> None:
        expected = {
            "model",
            "system",
            "user",
            "max_completion_tokens",
            "retries",
            "reasoning_effort",
        }
        exact = inspect.signature(ExactRQ1SolMaxClient.complete)
        fake = inspect.signature(_FakeExactCompletionClient.complete)
        self.assertEqual(set(exact.parameters) - {"self"}, expected)
        self.assertEqual(set(fake.parameters) - {"self"}, expected)

    def test_response_is_parsed_once_without_repair_or_retry(self) -> None:
        client = _FakeExactCompletionClient(failure_by_call={1: "parse"})
        cell = select_cell("benign", "protected")
        visible = cell.model_visible_initial()
        agent = ProviderBackedOrdinaryAgent(client)
        with self.assertRaises(ProviderResponseError):
            agent.respond(messages=visible["messages"], tools=visible["tools"])
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(agent.request_count, 1)
        self.assertEqual(agent.request_records[0]["status"], "parse_error")

    def test_fake_client_runs_eight_small_condition_blind_requests(self) -> None:
        client = _offline_client()
        with tempfile.TemporaryDirectory() as directory:
            result = run_provider_engineering_batch(
                client,
                output_root=Path(directory),
                namespace="fresh-provider-eight-calls",
                engineering_test_double=True,
            )
            summary = load_engineering_batch(Path(result["summary_path"]))
            self.assertEqual(summary["cell_count"], 4)
            self.assertEqual(summary["completed_episode_count"], 4)
            self.assertEqual(summary["failed_episode_count"], 0)
            self.assertEqual(summary["provider_request_count"], 8)
            self.assertEqual(summary["offline_client_call_count"], 8)
            self.assertTrue(summary["offline_client_call_count_matches"])
            self.assertTrue(summary["offline_client_exact_type_verified"])
            self.assertTrue(summary["offline_script_fully_consumed"])
            self.assertEqual(summary["real_api_calls"], 0)
            self.assertFalse(summary["execution_authorized"])
            self.assertFalse(summary["expected_outcome_gate_used"])
            self.assertFalse(summary["oracle_direction_gate_used"])
            namespace = Path(result["namespace_path"])
            for row in summary["cells"]:
                self.assertTrue((namespace / row["path"]).is_file())
                self.assertEqual(row["provider_request_count"], 2)
                cell = json.loads((namespace / row["path"]).read_text())
                counts = cell["episode"]["execution_counts"]
                self.assertEqual(counts["completion_client_calls"], 2)
                self.assertEqual(counts["api_calls"], 0)
                self.assertEqual(counts["model_calls"], 0)
                self.assertEqual(counts["provider_calls"], 0)
                provenance = cell["episode"]["execution_counts_provenance"]
                self.assertTrue(
                    provenance["real_api_calls_proven_zero_by_exact_client_type"]
                )
                self.assertEqual(
                    provenance["legacy_source_execution_counts"]["provider_calls"],
                    0,
                )
        self.assertEqual(len(client.calls), 8)
        for call in client.calls:
            self.assertEqual(call["model"], "gpt-5.6-sol")
            self.assertEqual(call["max_completion_tokens"], 1100)
            self.assertEqual(call["retries"], 0)
            self.assertEqual(call["reasoning_effort"], "max")
            payload = json.loads(str(call["user"]))
            self.assertEqual(
                set(payload), {"messages", "response_contract", "tools"}
            )
            self.assertFalse(_private_keys(payload))
            self.assertNotIn("expected_outcome", str(call["user"]))
            self.assertNotIn("oracle_direction", str(call["user"]))
        injection_calls = [
            index
            for index, call in enumerate(client.calls, start=1)
            if INJECTION_GOAL in str(call["user"])
        ]
        self.assertEqual(injection_calls, [6, 8])
        self.assertNotIn(INJECTION_GOAL, str(client.calls[4]["user"]))
        self.assertNotIn(INJECTION_GOAL, str(client.calls[6]["user"]))

    def test_provider_failure_is_written_and_later_cells_continue(self) -> None:
        client = _offline_client(failure_call=3, failure_kind="provider")
        with tempfile.TemporaryDirectory() as directory:
            result = run_provider_engineering_batch(
                client,
                output_root=Path(directory),
                namespace="fresh-provider-one-failure",
                engineering_test_double=True,
            )
            summary = result["summary"]
            self.assertEqual(
                [row["classification"] for row in summary["cells"]],
                [
                    "episode_completed",
                    "provider_failure",
                    "episode_completed",
                    "episode_completed",
                ],
            )
            self.assertEqual(summary["provider_request_count"], 7)
            self.assertEqual(summary["completed_episode_count"], 3)
            self.assertEqual(summary["failed_episode_count"], 1)
            self.assertEqual(summary["real_api_calls"], 0)
            self.assertEqual(len(list(Path(result["namespace_path"]).glob("cell-*.json"))), 4)
        self.assertEqual(len(client.calls), 7)

    def test_parse_and_schema_failures_are_recorded_without_stopping_batch(self) -> None:
        cases = ((3, "parse", "parse_failure", 7), (4, "schema", "schema_failure", 8))
        for call_index, failure, classification, request_count in cases:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                client = _offline_client(
                    failure_call=call_index,
                    failure_kind=failure,
                )
                result = run_provider_engineering_batch(
                    client,
                    output_root=Path(directory),
                    namespace=f"fresh-provider-{failure}-failure",
                    engineering_test_double=True,
                )
                summary = result["summary"]
                self.assertEqual(summary["cells"][1]["classification"], classification)
                self.assertEqual(
                    [row["classification"] for row in summary["cells"][2:]],
                    ["episode_completed", "episode_completed"],
                )
                self.assertEqual(summary["provider_request_count"], request_count)
                self.assertEqual(summary["real_api_calls"], 0)

    def test_engineering_executor_is_exclusive_and_never_authorizes_live_use(self) -> None:
        client = _offline_client()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(EngineeringExecutorError):
                run_provider_engineering_batch(
                    client,
                    output_root=root,
                    namespace="fresh-provider-no-proof",
                )
            self.assertEqual(client.calls, ())
            self.assertFalse((root / "fresh-provider-no-proof").exists())
            run_provider_engineering_batch(
                client,
                output_root=root,
                namespace="fresh-provider-exclusive",
                engineering_test_double=True,
            )
            with self.assertRaises(EngineeringExecutorError):
                run_provider_engineering_batch(
                    _offline_client(),
                    output_root=root,
                    namespace="fresh-provider-exclusive",
                    engineering_test_double=True,
                )

    def test_engineering_executor_rejects_real_exact_client_before_any_call(self) -> None:
        client = ExactRQ1SolMaxClient(
            base_url="http://127.0.0.1:19876/v1",
            api_key="sk-offline-never-used",
        )
        setattr(client, "engineering_test_double", True)
        self.assertTrue(getattr(client, "engineering_test_double"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(EngineeringExecutorError):
                run_provider_engineering_batch(
                    client,
                    output_root=root,
                    namespace="fresh-real-client-refused",
                    engineering_test_double=True,
                )
            self.assertEqual(client.calls_made, 0)
            self.assertFalse((root / "fresh-real-client-refused").exists())


if __name__ == "__main__":
    unittest.main()
