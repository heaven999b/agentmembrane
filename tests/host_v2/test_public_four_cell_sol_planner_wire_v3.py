from __future__ import annotations

import base64
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
)
from agentmembrane.host_v2.public_four_cell_v1.sol_planner_wire_v3 import (
    DISCOVERY_PHASE,
    POST_OBSERVATION_PHASE,
    WIRE_SOL_LOCAL_RETRIES,
    WIRE_SOL_MODEL_ID,
    WIRE_SOL_PLANNER_ID,
    WIRE_SOL_TOTAL_DELIVERED_CAP,
    WIRE_SUBMIT_TOOL_NAME,
    WireSolAttemptStore,
    WireSolPlanner,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _submit_arguments(
    *,
    discovery: bool,
    confirmed: str = "confirmed",
    final_artifact: dict[str, object] | None = None,
) -> dict[str, object]:
    action = (
        {
            "operation": "get_most_recent_transactions",
            "arguments_json": _canonical({"n": 100}),
        }
        if discovery
        else {
            "operation": "send_money",
            "arguments_json": _canonical(
                {"amount": 5, "recipient": "GB29NWBK60161331926819"}
            ),
        }
    )
    return {
        "status": "complete",
        "explicit_abstention": False,
        "actions": [] if final_artifact is not None else [action],
        "final_artifact_json": (
            _canonical(final_artifact) if final_artifact is not None else None
        ),
        "strategy": "frozen two-turn trace",
        "confirmed_assistant_text": confirmed,
    }


def _assistant(
    *,
    discovery: bool,
    content: str | None = None,
    confirmed: str = "confirmed",
    arguments_override: dict[str, object] | None = None,
    call_id: str = "call_v3_provider_1",
) -> dict[str, object]:
    arguments = arguments_override or _submit_arguments(
        discovery=discovery, confirmed=confirmed
    )
    return {
        "role": "assistant",
        "content": content,
        "tool_calls": [
            {
                "id": call_id,
                "type": "function",
                "function": {
                    "name": WIRE_SUBMIT_TOOL_NAME,
                    "arguments": _canonical(arguments),
                },
            }
        ],
    }


def _response(
    *,
    discovery: bool,
    assistant_override: dict[str, object] | None = None,
    prompt_tokens: int = 11,
    completion_tokens: int = 7,
) -> bytes:
    return _canonical(
        {
            "id": "chatcmpl-v3-shape",
            "object": "chat.completion",
            "created": 1788100000,
            "model": WIRE_SOL_MODEL_ID,
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "tool_calls",
                    "logprobs": None,
                    "message": assistant_override
                    or _assistant(discovery=discovery),
                }
            ],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
            "system_fingerprint": None,
            "service_tier": "default",
        }
    ).encode("utf-8")


class _FakeBytesTransport:
    def __init__(self, responses: list[bytes | Exception]) -> None:
        self.responses = list(responses)
        self.request_wires: list[bytes] = []

    def invoke(self, request_wire: bytes) -> bytes:
        self.request_wires.append(request_wire)
        if not self.responses:
            raise AssertionError("unexpected transport call")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class _SimulatedHTTP400(RuntimeError):
    def __init__(self, body: bytes) -> None:
        super().__init__(
            _canonical(
                {
                    "error_body_length": len(body),
                    "error_body_sha256": hashlib.sha256(body).hexdigest(),
                    "error_body_truncated": False,
                    "http_status": 400,
                }
            )
        )
        self.body = body

    def to_attempt_error_evidence(self) -> dict[str, object]:
        return {
            "error_body_bytes_base64": base64.b64encode(self.body).decode("ascii"),
            "error_body_length": len(self.body),
            "error_body_redacted": False,
            "error_body_sha256": hashlib.sha256(self.body).hexdigest(),
            "error_body_truncated": False,
            "http_status": 400,
        }


def _budget(root: Path, *, name: str, predecessors=()):
    return build_run_chain_budget(
        repo_root=root,
        chain_id=f"wire-v3-{name}",
        cap=WIRE_SOL_TOTAL_DELIVERED_CAP,
        predecessor_attempt_paths=predecessors,
        fresh_namespaces={
            "output": f"runs/{name}/output",
            "cache": f"runs/{name}/cache",
            "native": f"runs/{name}/native",
        },
    )


def _planner(root: Path, *, name: str, transport: _FakeBytesTransport):
    budget = _budget(root, name=name)
    return WireSolPlanner(
        repo_root=root,
        transport=transport,
        attempt_store=WireSolAttemptStore(
            repo_root=root, run_dir=root / budget.fresh_namespaces["cache"]
        ),
        run_chain_budget=budget,
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
        interface_description=(
            "get_most_recent_transactions(n: integer); "
            "send_money(recipient, amount)"
        ),
        messages=[{"role": "user", "content": "Complete the banking task."}],
        failure_record_path=root / "failures" / f"{trace}-discovery.json",
    )


class PublicFourCellSolPlannerWireV3Tests(unittest.TestCase):
    def _assert_strict_objects(self, schema: object, *, path: str = "$") -> None:
        if isinstance(schema, dict):
            node_type = schema.get("type")
            is_object = node_type == "object" or (
                isinstance(node_type, list) and "object" in node_type
            )
            if is_object:
                self.assertIs(
                    schema.get("additionalProperties"),
                    False,
                    msg=f"open object at {path}",
                )
                properties = schema.get("properties")
                required = schema.get("required")
                self.assertIsInstance(properties, dict, msg=path)
                self.assertIsInstance(required, list, msg=path)
                self.assertEqual(set(required), set(properties), msg=path)
                self.assertEqual(len(required), len(set(required)), msg=path)
            for key, value in schema.items():
                self._assert_strict_objects(value, path=f"{path}.{key}")
        elif isinstance(schema, list):
            for index, value in enumerate(schema):
                self._assert_strict_objects(value, path=f"{path}[{index}]")

    def test_provider_schema_is_recursively_closed_and_has_no_arbitrary_object(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            transport = _FakeBytesTransport([_response(discovery=True)])
            result = _discovery(_planner(root, name="schema", transport=transport), root)

            request = json.loads(transport.request_wires[0])
            parameters = request["tools"][0]["function"]["parameters"]
            self._assert_strict_objects(parameters)
            action_properties = parameters["properties"]["actions"]["items"][
                "properties"
            ]
            self.assertEqual(set(action_properties), {"operation", "arguments_json"})
            self.assertEqual(action_properties["arguments_json"], {"type": "string"})
            self.assertNotIn("arguments", action_properties)
            self.assertEqual(
                parameters["properties"]["final_artifact_json"],
                {"type": ["string", "null"]},
            )
            self.assertNotIn("final_artifact", parameters["properties"])
            self.assertTrue(request["tools"][0]["function"]["strict"])
            self.assertIs(request["parallel_tool_calls"], False)
            self.assertEqual(result.turn.actions[0].operation, "get_most_recent_transactions")

    def test_exact_wire_and_decoded_discovery_action_are_runner_compatible(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            raw = b"  " + _response(discovery=True) + b"\n"
            transport = _FakeBytesTransport([raw])
            result = _discovery(_planner(root, name="decode", transport=transport), root)

            request_wire = transport.request_wires[0]
            request = json.loads(request_wire)
            self.assertEqual(request_wire, _canonical(request).encode("utf-8"))
            self.assertEqual(request["model"], "gpt-5.6-sol")
            self.assertEqual(request["reasoning_effort"], "max")
            self.assertEqual(request["temperature"], 0)
            self.assertIs(request["parallel_tool_calls"], False)
            self.assertNotIn("retries", request)
            self.assertEqual(WIRE_SOL_LOCAL_RETRIES, 0)
            self.assertEqual(len(result.turn.actions), 1)
            self.assertEqual(
                dict(result.turn.actions[0].arguments), {"n": 100}
            )
            self.assertIsNone(result.turn.final_artifact)
            attempt = dict(result.attempt_records[0])
            self.assertEqual(attempt["planner_id"], WIRE_SOL_PLANNER_ID)
            self.assertEqual(attempt["schema_version"], 3)
            self.assertNotIn("provider_wire_contract", attempt)
            self.assertEqual(
                attempt["client_requested_wire_contract"]["parallel_tool_calls"],
                False,
            )
            self.assertEqual(
                set(attempt["effective_provider_contract"].values()),
                {"unknown_pending_route_enforcement_audit"},
            )
            self.assertEqual(
                base64.b64decode(attempt["request_wire_bytes_base64"]),
                request_wire,
            )
            self.assertEqual(
                base64.b64decode(attempt["raw_response_bytes_base64"]), raw
            )
            self.assertEqual(result.attempt_counters.client_attempts, 1)
            self.assertEqual(result.attempt_counters.provider_accepted_requests, 1)
            self.assertEqual(result.attempt_counters.delivered_model_responses, 1)
            self.assertEqual(result.attempt_counters.total_tokens, 18)

    def test_null_assistant_content_uses_confirmed_tool_argument_authoritatively(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            transport = _FakeBytesTransport([_response(discovery=True)])
            result = _discovery(_planner(root, name="null-content", transport=transport), root)

            self.assertIsNone(result.assistant_message["content"])
            self.assertEqual(result.turn.confirmed_assistant_text, "confirmed")

    def test_non_null_assistant_content_must_exactly_match_confirmation(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            response = _response(
                discovery=True,
                assistant_override=_assistant(
                    discovery=True, content="different", confirmed="confirmed"
                ),
            )
            transport = _FakeBytesTransport([response])
            with self.assertRaises(ImmutablePlannerFailure):
                _discovery(_planner(root, name="content-mismatch", transport=transport), root)

            attempt = json.loads(next(root.glob("runs/*/cache/attempts/*/1.json")).read_text())
            self.assertEqual(attempt["failure_class"], "response_contract_failure")
            self.assertEqual(attempt["usage"]["total_tokens"], 18)

    def test_phase_two_decodes_native_action_and_preserves_correlation(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            transport = _FakeBytesTransport(
                [
                    _response(
                        discovery=True,
                        assistant_override=_assistant(
                            discovery=True, call_id="correlation-v3-a"
                        ),
                    ),
                    _response(
                        discovery=False,
                        assistant_override=_assistant(
                            discovery=False, call_id="correlation-v3-b"
                        ),
                    ),
                ]
            )
            planner = _planner(root, name="post", transport=transport)
            first = _discovery(planner, root)
            observation = _canonical(
                {"transactions": [{"amount": 5, "recipient": "Alice"}]}
            )
            second = planner.plan(
                planner_trace_id="benign",
                phase=POST_OBSERVATION_PHASE,
                interface_description=(
                    "get_most_recent_transactions(n: integer); "
                    "send_money(recipient, amount)"
                ),
                messages=[
                    {"role": "user", "content": "Complete the banking task."},
                    first.assistant_message,
                    {
                        "role": "tool",
                        "tool_call_id": first.tool_call_id,
                        "content": observation,
                    },
                ],
                failure_record_path=root / "failures" / "benign-post.json",
                checker_binding_ids=("native-state-checker",),
                checker_capabilities=(_state_capability(),),
            )

            request2 = json.loads(transport.request_wires[1])
            self.assertEqual(request2["messages"][2], first.assistant_message)
            self.assertEqual(
                request2["messages"][3]["tool_call_id"], "correlation-v3-a"
            )
            self.assertEqual(second.turn.actions[0].operation, "send_money")
            self.assertEqual(
                dict(second.turn.actions[0].arguments),
                {"amount": 5, "recipient": "GB29NWBK60161331926819"},
            )
            self.assertIsNotNone(second.resolution)

    def test_final_artifact_json_is_decoded_to_mapping(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            first_response = _response(discovery=True)
            final = {"answer": "done", "nested": {"ok": True}}
            second_arguments = _submit_arguments(
                discovery=False, final_artifact=final
            )
            second_response = _response(
                discovery=False,
                assistant_override=_assistant(
                    discovery=False, arguments_override=second_arguments
                ),
            )
            transport = _FakeBytesTransport([first_response, second_response])
            planner = _planner(root, name="artifact", transport=transport)
            first = _discovery(planner, root)
            second = planner.plan(
                planner_trace_id="benign",
                phase=POST_OBSERVATION_PHASE,
                interface_description="get_most_recent_transactions(n); send_money(a,b)",
                messages=[
                    {"role": "user", "content": "Complete the banking task."},
                    first.assistant_message,
                    {
                        "role": "tool",
                        "tool_call_id": first.tool_call_id,
                        "content": _canonical({"transactions": []}),
                    },
                ],
                failure_record_path=root / "failures" / "artifact.json",
                checker_binding_ids=("native-state-checker",),
                checker_capabilities=(_state_capability(),),
            )
            self.assertEqual(dict(second.turn.final_artifact or {}), final)

    def test_non_object_arguments_json_fails_after_one_delivered_response(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            arguments = _submit_arguments(discovery=True)
            actions = arguments["actions"]
            assert isinstance(actions, list)
            actions[0]["arguments_json"] = "[]"  # type: ignore[index]
            transport = _FakeBytesTransport(
                [
                    _response(
                        discovery=True,
                        assistant_override=_assistant(
                            discovery=True, arguments_override=arguments
                        ),
                    )
                ]
            )
            with self.assertRaises(ImmutablePlannerFailure):
                _discovery(_planner(root, name="bad-json", transport=transport), root)
            attempt = json.loads(next(root.glob("runs/*/cache/attempts/*/1.json")).read_text())
            self.assertEqual(attempt["failure_class"], "response_contract_failure")
            self.assertEqual(
                {
                    key: attempt[key]
                    for key in ("planner_status", "resolved_model_id")
                },
                {"planner_status": "failed", "resolved_model_id": WIRE_SOL_MODEL_ID},
            )
            self.assertEqual(attempt["usage"]["total_tokens"], 18)

    def test_duplicate_keys_in_arguments_json_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            arguments = _submit_arguments(discovery=True)
            actions = arguments["actions"]
            assert isinstance(actions, list)
            actions[0]["arguments_json"] = '{"n":100,"n":99}'  # type: ignore[index]
            transport = _FakeBytesTransport(
                [
                    _response(
                        discovery=True,
                        assistant_override=_assistant(
                            discovery=True, arguments_override=arguments
                        ),
                    )
                ]
            )
            with self.assertRaises(ImmutablePlannerFailure):
                _discovery(
                    _planner(root, name="duplicate-json", transport=transport), root
                )
            attempt = json.loads(
                next(root.glob("runs/*/cache/attempts/*/1.json")).read_text()
            )
            self.assertEqual(attempt["failure_class"], "response_contract_failure")
            self.assertIn("arguments_json is not strict JSON", attempt["error"])
            self.assertEqual(attempt["usage"]["total_tokens"], 18)

    def test_simulated_http_400_body_is_offline_and_counted_as_pre_delivery(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            body = _canonical(
                {
                    "error": {
                        "code": "invalid_function_parameters",
                        "message": "strict schema rejected",
                    }
                }
            ).encode("utf-8")
            transport = _FakeBytesTransport([_SimulatedHTTP400(body)])
            with self.assertRaises(ImmutablePlannerFailure):
                _discovery(_planner(root, name="http400", transport=transport), root)

            # The fake seam proves this test never opens a network client: it
            # receives exactly one local byte request and raises its fixture.
            self.assertEqual(len(transport.request_wires), 1)
            attempt = json.loads(next(root.glob("runs/*/cache/attempts/*/1.json")).read_text())
            self.assertEqual(attempt["failure_class"], "transport_failure")
            self.assertEqual(attempt["planner_id"], WIRE_SOL_PLANNER_ID)
            self.assertIsNone(attempt["raw_response"])
            self.assertIsNone(attempt["raw_response_bytes_base64"])
            self.assertIsNone(attempt["resolved_model_id"])
            self.assertEqual(
                attempt["usage"],
                {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
            )
            evidence = attempt["transport_error_evidence"]
            self.assertEqual(evidence["http_status"], 400)
            self.assertEqual(
                base64.b64decode(evidence["error_body_bytes_base64"]), body
            )
            failure = json.loads((root / "failures" / "benign-discovery.json").read_text())
            self.assertEqual(
                failure["attempt_counters"],
                {
                    "client_attempts": 1,
                    "provider_accepted_requests": 0,
                    "delivered_model_responses": 0,
                    "token_bearing_calls": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                },
            )
            self.assertEqual(
                failure["error_metadata"]["transport_error_evidence"], evidence
            )

    def test_caps_remain_two_per_trace_four_total_and_no_retry(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            transport = _FakeBytesTransport([_response(discovery=True)])
            planner = _planner(root, name="caps", transport=transport)
            first = _discovery(planner, root)
            self.assertEqual(dict(planner.delivered_caps.per_trace), {
                "benign": 2,
                "adversarial": 2,
            })
            self.assertEqual(planner.delivered_caps.total, 4)
            self.assertEqual(planner.budget_snapshot.consumed, 1)
            with self.assertRaisesRegex(Exception, "no-retry"):
                _discovery(planner, root)
            self.assertEqual(len(transport.request_wires), 1)
            self.assertEqual(first.attempt_counters.client_attempts, 1)

    def test_v3_predecessor_resume_preserves_counter_and_trace_phase(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            first_transport = _FakeBytesTransport([_response(discovery=True)])
            first = _discovery(
                _planner(root, name="predecessor-first", transport=first_transport),
                root,
            )
            resumed_budget = _budget(
                root,
                name="predecessor-resumed",
                predecessors=(first.attempt_path,),
            )
            resumed_transport = _FakeBytesTransport([_response(discovery=False)])
            resumed = WireSolPlanner(
                repo_root=root,
                transport=resumed_transport,
                attempt_store=WireSolAttemptStore(
                    repo_root=root,
                    run_dir=root / resumed_budget.fresh_namespaces["cache"],
                ),
                run_chain_budget=resumed_budget,
            )
            second = resumed.plan(
                planner_trace_id="benign",
                phase=POST_OBSERVATION_PHASE,
                interface_description=(
                    "get_most_recent_transactions(n: integer); "
                    "send_money(recipient, amount)"
                ),
                messages=[
                    {"role": "user", "content": "Complete the banking task."},
                    first.assistant_message,
                    {
                        "role": "tool",
                        "tool_call_id": first.tool_call_id,
                        "content": _canonical({"transactions": []}),
                    },
                ],
                failure_record_path=root / "failures" / "resumed-post.json",
                checker_binding_ids=("native-state-checker",),
                checker_capabilities=(_state_capability(),),
            )
            self.assertEqual(second.budget_snapshot.consumed, 2)
            self.assertEqual(second.budget_snapshot.counters.client_attempts, 2)
            self.assertEqual(second.budget_snapshot.counters.delivered_model_responses, 2)
            self.assertEqual(dict(resumed.delivered_counts[0])["benign"], 2)
            self.assertEqual(resumed.delivered_counts[1], 2)


if __name__ == "__main__":
    unittest.main()
