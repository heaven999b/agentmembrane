from __future__ import annotations

import ast
import base64
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from agentmembrane.host_v2.public_four_cell_v1.budget import build_run_chain_budget
from agentmembrane.host_v2.public_four_cell_v1.contracts import SOURCE_TASK_ID
from agentmembrane.host_v2.public_four_cell_v1.executor import (
    CheckerTextCapability,
    ImmutablePlannerFailure,
    TEXT_CAPABILITY_CONTRACT,
)
from agentmembrane.host_v2.public_four_cell_v1.sol_planner_wire_v2 import (
    DISCOVERY_PHASE,
    POST_OBSERVATION_PHASE,
    WIRE_SOL_LOCAL_RETRIES,
    WIRE_SOL_MAX_COMPLETION_TOKENS,
    WIRE_SOL_MODEL_ID,
    WIRE_SOL_TOTAL_DELIVERED_CAP,
    WIRE_SUBMIT_TOOL_NAME,
    WireSolAttemptStore,
    WireSolPlanner,
    WireSolPlannerError,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _arguments(*, discovery: bool, content: str = "confirmed") -> dict[str, object]:
    action = (
        {"operation": "get_most_recent_transactions", "arguments": {"n": 100}}
        if discovery
        else {
            "operation": "send_money",
            "arguments": {"amount": 5, "recipient": "GB29NWBK60161331926819"},
        }
    )
    return {
        "status": "complete",
        "explicit_abstention": False,
        "actions": [action],
        "final_artifact": None,
        "strategy": "frozen two-turn trace",
        "confirmed_assistant_text": content,
    }


def _assistant(
    *, discovery: bool, content: str = "confirmed", call_id: str = "call_provider_1"
) -> dict[str, object]:
    return {
        "role": "assistant",
        "content": content,
        "tool_calls": [
            {
                "id": call_id,
                "type": "function",
                "function": {
                    "name": WIRE_SUBMIT_TOOL_NAME,
                    "arguments": _canonical(_arguments(discovery=discovery, content=content)),
                },
            }
        ],
    }


def _response(
    *,
    discovery: bool,
    content: str = "confirmed",
    call_id: str = "call_provider_1",
    model: str = WIRE_SOL_MODEL_ID,
    prompt_tokens: int = 11,
    completion_tokens: int = 7,
    response_extra: dict[str, object] | None = None,
    usage_extra: dict[str, object] | None = None,
    assistant_override: dict[str, object] | None = None,
) -> bytes:
    usage: dict[str, object] = {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": prompt_tokens + completion_tokens,
    }
    usage.update(usage_extra or {})
    response: dict[str, object] = {
        "id": "chatcmpl-real-shape",
        "object": "chat.completion",
        "created": 1788100000,
        "model": model,
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "logprobs": None,
                "message": assistant_override
                or _assistant(discovery=discovery, content=content, call_id=call_id),
            }
        ],
        "usage": usage,
        "system_fingerprint": None,
        "service_tier": "default",
    }
    response.update(response_extra or {})
    return _canonical(response).encode("utf-8")


class _FakeBytesTransport:
    def __init__(self, responses: list[bytes | Exception]) -> None:
        self.responses = list(responses)
        self.request_wires: list[bytes] = []

    def invoke(self, request_wire: bytes) -> bytes:
        self.request_wires.append(request_wire)
        if not self.responses:
            raise AssertionError("unexpected transport call")
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def _budget(root: Path, *, name: str, predecessors=()):
    return build_run_chain_budget(
        repo_root=root,
        chain_id=f"wire-{name}",
        cap=WIRE_SOL_TOTAL_DELIVERED_CAP,
        predecessor_attempt_paths=predecessors,
        fresh_namespaces={
            "output": f"runs/{name}/output",
            "cache": f"runs/{name}/cache",
            "native": f"runs/{name}/native",
        },
    )


def _planner(root: Path, *, name: str, transport, budget=None) -> WireSolPlanner:
    chosen = budget or _budget(root, name=name)
    return WireSolPlanner(
        repo_root=root,
        transport=transport,
        attempt_store=WireSolAttemptStore(
            repo_root=root, run_dir=root / chosen.fresh_namespaces["cache"]
        ),
        run_chain_budget=chosen,
    )


def _state_capability() -> CheckerTextCapability:
    return CheckerTextCapability(
        source_task_id=SOURCE_TASK_ID,
        checker_binding_id="native-state-checker",
        reads_terminal_text=False,
        raw_response_envelope_compatible=False,
    )


def _discovery(planner: WireSolPlanner, root: Path, *, trace: str = "benign"):
    return planner.plan(
        planner_trace_id=trace,
        phase=DISCOVERY_PHASE,
        interface_description="get_most_recent_transactions(n: integer); send_money(recipient, amount)",
        messages=[{"role": "user", "content": "Complete the banking task."}],
        failure_record_path=root / "failures" / f"{trace}-discovery.json",
    )


def _post(
    planner: WireSolPlanner,
    root: Path,
    discovery_result,
    *,
    trace: str = "benign",
    capabilities=None,
    checker_ids=("native-state-checker",),
):
    observation = _canonical({"transactions": [{"amount": 5, "recipient": "Alice"}]})
    return planner.plan(
        planner_trace_id=trace,
        phase=POST_OBSERVATION_PHASE,
        interface_description="get_most_recent_transactions(n: integer); send_money(recipient, amount)",
        messages=[
            {"role": "user", "content": "Complete the banking task."},
            discovery_result.assistant_message,
            {
                "role": "tool",
                "tool_call_id": discovery_result.tool_call_id,
                "content": observation,
            },
        ],
        failure_record_path=root / "failures" / f"{trace}-post.json",
        checker_binding_ids=checker_ids,
        checker_capabilities=capabilities or [_state_capability()],
    )


class PublicFourCellSolPlannerWireV2Tests(unittest.TestCase):
    def test_exact_cli_proxy_wire_and_raw_byte_evidence(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            raw = b'  ' + _response(discovery=True) + b'\n'
            transport = _FakeBytesTransport([raw])
            result = _discovery(_planner(root, name="wire", transport=transport), root)

            self.assertEqual(len(transport.request_wires), 1)
            request_wire = transport.request_wires[0]
            request = json.loads(request_wire)
            self.assertEqual(
                set(request),
                {
                    "model", "reasoning_effort", "temperature", "stream",
                    "max_completion_tokens", "messages", "tools", "tool_choice",
                },
            )
            self.assertEqual(request["model"], "gpt-5.6-sol")
            self.assertEqual(request["reasoning_effort"], "max")
            self.assertEqual(request["temperature"], 0)
            self.assertIs(request["stream"], False)
            self.assertEqual(request["max_completion_tokens"], 1100)
            self.assertNotIn("retries", request)
            self.assertEqual(WIRE_SOL_LOCAL_RETRIES, 0)
            self.assertEqual(request_wire, _canonical(request).encode("utf-8"))
            self.assertEqual(len(request["tools"]), 1)
            self.assertTrue(request["tools"][0]["function"]["strict"])
            self.assertEqual(
                request["tool_choice"],
                {"type": "function", "function": {"name": WIRE_SUBMIT_TOOL_NAME}},
            )

            attempt = dict(result.attempt_records[0])
            self.assertEqual(base64.b64decode(attempt["request_wire_bytes_base64"]), request_wire)
            self.assertEqual(base64.b64decode(attempt["raw_response_bytes_base64"]), raw)
            self.assertEqual(attempt["request_wire_sha256"], hashlib.sha256(request_wire).hexdigest())
            self.assertEqual(attempt["raw_response_sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(attempt["resolved_model_id"], WIRE_SOL_MODEL_ID)
            self.assertEqual(attempt["provider_usage"], {
                "prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18,
            })
            self.assertEqual(attempt["usage"], {
                "input_tokens": 11, "output_tokens": 7, "total_tokens": 18,
            })
            self.assertEqual(result.attempt_counters.total_tokens, 18)
            self.assertIsNone(result.resolution)

    def test_paired_trace_two_turn_transcript_and_projection(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            transport = _FakeBytesTransport([
                _response(discovery=True, call_id="correlation-random-a"),
                _response(discovery=False, call_id="correlation-random-b"),
            ])
            planner = _planner(root, name="paired", transport=transport)
            first = _discovery(planner, root)
            second = _post(planner, root, first)

            request2 = json.loads(transport.request_wires[1])
            self.assertEqual([row["role"] for row in request2["messages"]], [
                "system", "user", "assistant", "tool",
            ])
            self.assertEqual(request2["messages"][2], first.assistant_message)
            self.assertEqual(request2["messages"][3]["tool_call_id"], first.tool_call_id)
            self.assertEqual(first.tool_call_id, "correlation-random-a")
            projection = json.loads(first.assistant_semantic_projection_json)
            self.assertNotIn("id", projection["tool_calls"][0])
            raw_message = first.assistant_message
            expected = copy.deepcopy(raw_message)
            expected["tool_calls"][0].pop("id")
            self.assertEqual(projection, expected)
            self.assertEqual(
                first.assistant_semantic_projection_sha256,
                hashlib.sha256(first.assistant_semantic_projection_json.encode()).hexdigest(),
            )
            self.assertIsNotNone(second.resolution)
            self.assertEqual(second.resolution.terminal_text, "confirmed")
            counts, total = planner.delivered_counts
            self.assertEqual(dict(counts), {"benign": 2, "adversarial": 0})
            self.assertEqual(total, 2)
            self.assertEqual(dict(planner.delivered_caps.per_trace), {
                "benign": 2, "adversarial": 2,
            })
            self.assertEqual(planner.delivered_caps.total, 4)

    def test_request_message_and_interface_hashes_come_from_wire(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            transport = _FakeBytesTransport([_response(discovery=True)])
            result = _discovery(_planner(root, name="hashes", transport=transport), root)
            request = json.loads(transport.request_wires[0])
            messages_json = _canonical(request["messages"])
            attempt = dict(result.attempt_records[0])
            self.assertEqual(result.request_messages_json, messages_json)
            self.assertEqual(result.request_messages_sha256, hashlib.sha256(messages_json.encode()).hexdigest())
            self.assertEqual(result.system_message_sha256, hashlib.sha256(_canonical(request["messages"][0]).encode()).hexdigest())
            self.assertEqual(result.user_message_sha256, hashlib.sha256(_canonical(request["messages"][1]).encode()).hexdigest())
            self.assertEqual(
                result.interface_description_sha256,
                hashlib.sha256(
                    b"get_most_recent_transactions(n: integer); send_money(recipient, amount)"
                ).hexdigest(),
            )
            for field in (
                "request_messages_json", "request_messages_sha256", "system_message_sha256",
                "user_message_sha256", "interface_description_sha256",
            ):
                self.assertEqual(attempt[field], getattr(result, field))

    def test_usage_mismatch_and_extra_usage_field_fail_closed(self) -> None:
        cases = [
            _response(discovery=True, usage_extra={"total_tokens": 999}),
            _response(discovery=True, usage_extra={"surprise_tokens": 1}),
            _response(
                discovery=True,
                usage_extra={"input_tokens": 11},
            ),
        ]
        for index, raw in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
                root = Path(temporary)
                planner = _planner(root, name=f"usage-{index}", transport=_FakeBytesTransport([raw]))
                with self.assertRaises(ImmutablePlannerFailure):
                    _discovery(planner, root)
                attempt_paths = list((root / f"runs/usage-{index}/cache/attempts").glob("*/*.json"))
                attempt = json.loads(attempt_paths[0].read_text())
                self.assertEqual(attempt["planner_status"], "failed")
                self.assertEqual(attempt["failure_class"], "response_contract_failure")
                self.assertEqual(attempt["usage"], {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0})
                self.assertIsNotNone(attempt["raw_response_sha256"])

    def test_known_actual_usage_detail_fields_are_preserved_not_counted_twice(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            raw = _response(
                discovery=True,
                usage_extra={
                    "prompt_tokens_details": {"cached_tokens": 3},
                    "completion_tokens_details": {"reasoning_tokens": 4},
                },
            )
            result = _discovery(
                _planner(root, name="usage-details", transport=_FakeBytesTransport([raw])),
                root,
            )
            attempt = dict(result.attempt_records[0])
            self.assertEqual(attempt["provider_usage"]["prompt_tokens_details"], {"cached_tokens": 3})
            self.assertEqual(attempt["provider_usage"]["completion_tokens_details"], {"reasoning_tokens": 4})
            self.assertEqual(attempt["usage"], {
                "input_tokens": 11, "output_tokens": 7, "total_tokens": 18,
            })
            self.assertEqual(result.attempt_counters.total_tokens, 18)

    def test_unexpected_response_field_and_wrong_model_fail_closed(self) -> None:
        raws = [
            _response(discovery=True, response_extra={"surprise": True}),
            _response(discovery=True, model="gpt-5.6-terra"),
        ]
        for index, raw in enumerate(raws):
            with self.subTest(index=index), tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
                root = Path(temporary)
                planner = _planner(root, name=f"envelope-{index}", transport=_FakeBytesTransport([raw]))
                with self.assertRaises(ImmutablePlannerFailure):
                    _discovery(planner, root)
                self.assertEqual(planner.budget_snapshot.counters.delivered_model_responses, 1)

    def test_transport_failure_is_charged_published_and_never_retried(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            transport = _FakeBytesTransport([ConnectionError("offline"), _response(discovery=True)])
            planner = _planner(root, name="transport", transport=transport)
            with self.assertRaises(ImmutablePlannerFailure):
                _discovery(planner, root)
            self.assertEqual(len(transport.request_wires), 1)
            self.assertEqual(planner.budget_snapshot.consumed, 1)
            self.assertEqual(planner.budget_snapshot.counters.delivered_model_responses, 0)
            with self.assertRaisesRegex(WireSolPlannerError, "no-retry"):
                _discovery(planner, root)
            self.assertEqual(len(transport.request_wires), 1)

    def test_transport_must_return_bytes_not_rewritten_text(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            transport = _FakeBytesTransport([])
            transport.responses = [_response(discovery=True).decode("utf-8")]  # type: ignore[list-item]
            planner = _planner(root, name="not-bytes", transport=transport)
            with self.assertRaises(ImmutablePlannerFailure):
                _discovery(planner, root)
            self.assertEqual(planner.budget_snapshot.counters.delivered_model_responses, 0)

    def test_discovery_action_is_exact_and_post_cannot_repeat_it(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            wrong_args = _assistant(discovery=True)
            args = json.loads(wrong_args["tool_calls"][0]["function"]["arguments"])
            args["actions"][0]["arguments"] = {"n": 99}
            wrong_args["tool_calls"][0]["function"]["arguments"] = _canonical(args)
            planner = _planner(
                root, name="wrong-discovery",
                transport=_FakeBytesTransport([_response(discovery=True, assistant_override=wrong_args)]),
            )
            with self.assertRaises(ImmutablePlannerFailure):
                _discovery(planner, root)

        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            planner = _planner(
                root, name="repeat-discovery",
                transport=_FakeBytesTransport([
                    _response(discovery=True), _response(discovery=True, call_id="call2")
                ]),
            )
            first = _discovery(planner, root)
            with self.assertRaises(ImmutablePlannerFailure):
                _post(planner, root, first)

    def test_post_transcript_rejects_wrong_id_noncanonical_tool_and_extra_fields(self) -> None:
        mutations = [
            lambda messages: messages[2].update(tool_call_id="wrong"),
            lambda messages: messages[2].update(content='{ "transactions": [] }'),
            lambda messages: messages[2].update(name="submit"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
                root = Path(temporary)
                transport = _FakeBytesTransport([_response(discovery=True)])
                planner = _planner(root, name=f"transcript-{index}", transport=transport)
                first = _discovery(planner, root)
                messages = [
                    {"role": "user", "content": "Complete the banking task."},
                    first.assistant_message,
                    {"role": "tool", "tool_call_id": first.tool_call_id, "content": "{\"transactions\":[]}"},
                ]
                mutate(messages)
                with self.assertRaises(WireSolPlannerError):
                    planner.plan(
                        planner_trace_id="adversarial",
                        phase=POST_OBSERVATION_PHASE,
                        interface_description="interface",
                        messages=messages,
                        failure_record_path=root / "unused.json",
                    )
                self.assertEqual(len(transport.request_wires), 1)

    def test_out_of_protocol_refusal_and_confirmed_text_mismatch_fail_closed(self) -> None:
        refusal = _assistant(discovery=True)
        refusal["refusal"] = "I refuse"
        mismatch = _assistant(discovery=True, content="visible")
        mismatch_args = json.loads(mismatch["tool_calls"][0]["function"]["arguments"])
        mismatch_args["confirmed_assistant_text"] = "different"
        mismatch["tool_calls"][0]["function"]["arguments"] = _canonical(mismatch_args)
        for index, assistant in enumerate((refusal, mismatch)):
            with self.subTest(index=index), tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
                root = Path(temporary)
                planner = _planner(
                    root, name=f"text-{index}",
                    transport=_FakeBytesTransport([
                        _response(discovery=True, assistant_override=assistant)
                    ]),
                )
                with self.assertRaises(ImmutablePlannerFailure):
                    _discovery(planner, root)

    def test_text_sensitive_checker_uses_confirmed_assistant_text(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            evidence = root / "evidence.json"
            evidence.write_text("{}", encoding="utf-8")
            capability = CheckerTextCapability(
                source_task_id=SOURCE_TASK_ID,
                checker_binding_id="text-checker",
                reads_terminal_text=True,
                raw_response_envelope_compatible=True,
                compatibility_contract=TEXT_CAPABILITY_CONTRACT,
                evidence_path=evidence.relative_to(root).as_posix(),
                evidence_sha256=hashlib.sha256(evidence.read_bytes()).hexdigest(),
            )
            transport = _FakeBytesTransport([
                _response(discovery=True, content="discovery text"),
                _response(discovery=False, content="final exact text", call_id="final-call"),
            ])
            planner = _planner(root, name="text-checker", transport=transport)
            first = _discovery(planner, root)
            result = _post(
                planner, root, first,
                capabilities=[capability], checker_ids=("text-checker",),
            )
            self.assertEqual(result.resolution.terminal_text, "final exact text")

    def test_caps_are_two_per_trace_four_total_and_hard_below_24(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            transport = _FakeBytesTransport([
                _response(discovery=True, call_id="b1"),
                _response(discovery=False, call_id="b2"),
                _response(discovery=True, call_id="a1"),
                _response(discovery=False, call_id="a2"),
            ])
            planner = _planner(root, name="all-four", transport=transport)
            benign = _discovery(planner, root, trace="benign")
            _post(planner, root, benign, trace="benign")
            adversarial = _discovery(planner, root, trace="adversarial")
            _post(planner, root, adversarial, trace="adversarial")
            counts, total = planner.delivered_counts
            self.assertEqual(dict(counts), {"benign": 2, "adversarial": 2})
            self.assertEqual(total, 4)
            self.assertEqual(planner.budget_snapshot.consumed, 4)
            self.assertLessEqual(planner.budget_snapshot.cap, 24)
            self.assertEqual(len(transport.request_wires), 4)

    def test_predecessor_resume_preserves_trace_no_retry_and_byte_hash(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            first_planner = _planner(
                root, name="predecessor", transport=_FakeBytesTransport([_response(discovery=True)])
            )
            first = _discovery(first_planner, root)
            resumed_budget = _budget(root, name="resumed", predecessors=[first.attempt_path])
            resumed_transport = _FakeBytesTransport([])
            resumed = _planner(root, name="resumed", transport=resumed_transport, budget=resumed_budget)
            with self.assertRaisesRegex(WireSolPlannerError, "no-retry"):
                _discovery(resumed, root)
            self.assertEqual(resumed_transport.request_wires, [])
            self.assertEqual(resumed.delivered_counts[1], 1)

    def test_source_imports_only_stdlib_and_overlay_owned_modules(self) -> None:
        source = REPO_ROOT / "agentmembrane/host_v2/public_four_cell_v1/sol_planner_wire_v2.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        forbidden = {
            "planner", "runner", "cache", "prompts", "public_canary",
            "public_host_bridge", "proxy", "oracle", "sol_planner",
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
