from __future__ import annotations

import ast
import copy
import json
from pathlib import Path
import tempfile
import unittest

from agentmembrane.host_v2.public_four_cell_v1.budget import build_run_chain_budget
from agentmembrane.host_v2.public_four_cell_v1.executor import (
    CheckerTextCapability,
    ImmutablePlannerFailure,
)
from agentmembrane.host_v2.public_four_cell_v1.sol_planner import (
    DeliveredResponseCaps,
    SOL_MODEL_ID,
    SOL_REASONING_EFFORT,
    SOL_RETRIES,
    SOL_TEMPERATURE,
    SUBMIT_TOOL_NAME,
    SolAttemptStore,
    SolPlanner,
    SolPlannerError,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_TASK_ID = "agentdojo-v1-banking-u3-i1"
CELL_IDS = (
    "benign-vulnerable",
    "benign-protected",
    "adversarial-vulnerable",
    "adversarial-protected",
)


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _caps(*, each: int = 2, total: int = 8) -> DeliveredResponseCaps:
    return DeliveredResponseCaps(
        per_cell={cell_id: each for cell_id in CELL_IDS}, total=total
    )


def _budget(root: Path, *, name: str, cap: int = 8, predecessors=()):
    return build_run_chain_budget(
        repo_root=root,
        chain_id=f"chain-{name}",
        cap=cap,
        predecessor_attempt_paths=predecessors,
        fresh_namespaces={
            "output": f"runs/{name}/output",
            "cache": f"runs/{name}/cache",
            "native": f"runs/{name}/native",
        },
    )


def _response(
    *,
    content: str = "I will submit the authorized structured turn.",
    argument_text: str | None = None,
    model: str = SOL_MODEL_ID,
    input_tokens: int = 11,
    output_tokens: int = 7,
) -> str:
    arguments = {
        "status": "complete",
        "explicit_abstention": False,
        "actions": [
            {
                "operation": "send_money",
                "arguments": {"recipient": "GB29NWBK60161331926819", "amount": 5},
            }
        ],
        "final_artifact": None,
        "strategy": "perform the user-authorized transfer",
        "confirmed_assistant_text": content if argument_text is None else argument_text,
    }
    return _canonical(
        {
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": content,
                        "tool_calls": [
                            {
                                "id": "call_submit_1",
                                "type": "function",
                                "function": {
                                    "name": SUBMIT_TOOL_NAME,
                                    "arguments": _canonical(arguments),
                                },
                            }
                        ],
                    },
                }
            ],
            "usage": {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens,
            },
        }
    )


class _FakeTransport:
    def __init__(self, responses: list[str | Exception]) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, object]] = []

    def invoke(self, request):
        self.requests.append(copy.deepcopy(dict(request)))
        if not self.responses:
            raise AssertionError("unexpected fake transport call")
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def _capability() -> CheckerTextCapability:
    return CheckerTextCapability(
        source_task_id=SOURCE_TASK_ID,
        checker_binding_id="state-checker-v1",
        reads_terminal_text=False,
        raw_response_envelope_compatible=False,
    )


def _planner(root: Path, *, name: str, transport, caps=None, budget=None) -> SolPlanner:
    chosen_budget = budget or _budget(root, name=name)
    return SolPlanner(
        repo_root=root,
        transport=transport,
        attempt_store=SolAttemptStore(
            repo_root=root,
            run_dir=root / chosen_budget.fresh_namespaces["cache"],
        ),
        run_chain_budget=chosen_budget,
        delivered_caps=caps or _caps(),
    )


def _plan(planner: SolPlanner, root: Path, *, cell_id: str = CELL_IDS[0]):
    return planner.plan(
        cell_id=cell_id,
        interface_description="send_money(recipient: str, amount: number)",
        messages=[{"role": "user", "content": "Send 5 to my authorized recipient."}],
        failure_record_path=root / "failures" / f"{cell_id}.json",
        checker_binding_ids=["state-checker-v1"],
        checker_capabilities=[_capability()],
    )


class PublicFourCellSolPlannerV1Tests(unittest.TestCase):
    def test_exact_route_forced_tool_and_confirmed_text(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            transport = _FakeTransport([_response()])
            result = _plan(_planner(root, name="exact", transport=transport), root)

            self.assertEqual(len(transport.requests), 1)
            request = transport.requests[0]
            self.assertEqual(
                {
                    "model": request["model"],
                    "reasoning_effort": request["reasoning_effort"],
                    "temperature": request["temperature"],
                    "retries": request["retries"],
                },
                {
                    "model": "gpt-5.6-sol",
                    "reasoning_effort": "max",
                    "temperature": 0,
                    "retries": 0,
                },
            )
            self.assertEqual(
                request["tool_choice"],
                {"type": "function", "function": {"name": SUBMIT_TOOL_NAME}},
            )
            self.assertTrue(request["tools"][0]["function"]["strict"])
            self.assertIn("send_money(recipient", request["messages"][0]["content"])
            self.assertEqual(result.turn.status, "complete")
            self.assertEqual(result.turn.actions[0].operation, "send_money")
            self.assertEqual(
                result.resolution.terminal_text,
                "I will submit the authorized structured turn.",
            )
            self.assertEqual(result.attempt_counters.client_attempts, 1)
            self.assertEqual(result.attempt_counters.delivered_model_responses, 1)
            self.assertEqual(result.budget_snapshot.consumed, 1)
            self.assertEqual(len(result.attempt_records), 1)
            self.assertEqual(len(result.attempt_ledger_sha256), 64)
            self.assertEqual(len(result.attempt_sha256), 64)
            self.assertEqual(
                result.attempt_records[0]["run_chain_manifest_sha256"],
                result.run_chain_manifest_sha256,
            )

    def test_transport_failure_publishes_attempt_then_failure_without_retry(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            transport = _FakeTransport([ConnectionError("offline")])
            planner = _planner(root, name="transport-fail", transport=transport)
            failure_path = root / "failures" / "failure.json"
            with self.assertRaises(ImmutablePlannerFailure) as raised:
                planner.plan(
                    cell_id=CELL_IDS[0],
                    interface_description="send_money(recipient: str, amount: number)",
                    messages=[{"role": "user", "content": "request"}],
                    failure_record_path=failure_path,
                    checker_binding_ids=[],  # Failure ordering precedes checker validation.
                    checker_capabilities=[],
                )
            self.assertEqual(len(transport.requests), 1)
            self.assertTrue(failure_path.is_file())
            failure = json.loads(failure_path.read_text(encoding="utf-8"))
            self.assertEqual(failure["failure_class"], "transport_failure")
            self.assertEqual(failure["ledger_status"], "verified")
            self.assertFalse(failure["terminal_text_extraction_attempted"])
            self.assertEqual(failure["native_checker_invocation_count"], 0)
            self.assertEqual(raised.exception.record_path, failure_path)
            terminal_path = root / failure["terminal_attempt"]["path"]
            self.assertTrue(terminal_path.is_file())
            attempt = json.loads(terminal_path.read_text(encoding="utf-8"))
            self.assertEqual(attempt["planner_status"], "failed")
            self.assertIsNone(attempt["raw_response"])
            self.assertEqual(planner.budget_snapshot.consumed, 1)
            self.assertEqual(planner.budget_snapshot.counters.delivered_model_responses, 0)

    def test_text_mismatch_is_delivered_failure_and_consumes_cell_cap(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            transport = _FakeTransport(
                [_response(content="visible", argument_text="different")]
            )
            caps = _caps(each=1, total=4)
            planner = _planner(root, name="mismatch", transport=transport, caps=caps)
            with self.assertRaises(ImmutablePlannerFailure):
                _plan(planner, root)
            per_cell, total = planner.delivered_counts
            self.assertEqual(per_cell[CELL_IDS[0]], 1)
            self.assertEqual(total, 1)
            self.assertEqual(planner.budget_snapshot.counters.delivered_model_responses, 1)
            with self.assertRaisesRegex(SolPlannerError, "cap exhausted"):
                _plan(planner, root)
            self.assertEqual(len(transport.requests), 1)

    def test_wrong_model_fails_closed_after_one_delivered_attempt(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            transport = _FakeTransport([_response(model="gpt-5.6-terra")])
            planner = _planner(root, name="wrong-model", transport=transport)
            with self.assertRaises(ImmutablePlannerFailure):
                _plan(planner, root)
            failure = json.loads(
                (root / "failures" / f"{CELL_IDS[0]}.json").read_text(encoding="utf-8")
            )
            self.assertEqual(failure["failure_class"], "response_contract_failure")
            self.assertEqual(failure["attempt_counters"]["delivered_model_responses"], 1)
            self.assertEqual(len(transport.requests), 1)

    def test_caps_are_injected_immutable_and_global_at_most_24(self) -> None:
        source = {cell_id: 2 for cell_id in CELL_IDS}
        caps = DeliveredResponseCaps(per_cell=source, total=8)
        source[CELL_IDS[0]] = 99
        self.assertEqual(caps.per_cell[CELL_IDS[0]], 2)
        with self.assertRaisesRegex(SolPlannerError, "exceeds 24"):
            DeliveredResponseCaps(per_cell={cell_id: 1 for cell_id in CELL_IDS}, total=25)
        with self.assertRaisesRegex(SolPlannerError, "cover the frozen four cells"):
            DeliveredResponseCaps(per_cell={CELL_IDS[0]: 1}, total=1)
        with self.assertRaisesRegex(SolPlannerError, "per-cell.*exceeds"):
            DeliveredResponseCaps(
                per_cell={cell_id: 2 for cell_id in CELL_IDS}, total=1
            )

    def test_immutable_predecessor_counts_against_new_caps(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            first = _planner(
                root,
                name="prior",
                transport=_FakeTransport([_response()]),
                caps=_caps(each=1, total=1),
            )
            prior = _plan(first, root)
            second_budget = _budget(
                root,
                name="resume",
                predecessors=[prior.attempt_path],
                cap=4,
            )
            second_transport = _FakeTransport([_response()])
            resumed = _planner(
                root,
                name="resume",
                transport=second_transport,
                caps=_caps(each=1, total=1),
                budget=second_budget,
            )
            with self.assertRaisesRegex(SolPlannerError, "total.*cap exhausted"):
                _plan(resumed, root)
            self.assertEqual(second_transport.requests, [])

    def test_predecessor_byte_drift_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            prior = _plan(
                _planner(
                    root,
                    name="drift-prior",
                    transport=_FakeTransport([_response()]),
                ),
                root,
            )
            budget = _budget(
                root, name="drift-resume", predecessors=[prior.attempt_path]
            )
            path = root / prior.attempt_path
            value = json.loads(path.read_text(encoding="utf-8"))
            value["error_metadata"]["tampered"] = True
            path.write_text(_canonical(value), encoding="utf-8")
            with self.assertRaisesRegex(SolPlannerError, "drifted"):
                _planner(
                    root,
                    name="drift-resume",
                    transport=_FakeTransport([]),
                    budget=budget,
                )

    def test_source_imports_only_stdlib_and_overlay_local_modules(self) -> None:
        source_path = (
            REPO_ROOT
            / "agentmembrane/host_v2/public_four_cell_v1/sol_planner.py"
        )
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        forbidden = {
            "planner", "runner", "cache", "prompts", "public_canary",
            "public_host_bridge", "proxy", "oracle",
        }
        violations: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("agentmembrane"):
                        violations.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and (node.module or "").startswith("agentmembrane"):
                    violations.append(node.module or "")
                if node.level > 0 and any(
                    part in forbidden for part in (node.module or "").split(".")
                ):
                    violations.append(node.module or "")
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
