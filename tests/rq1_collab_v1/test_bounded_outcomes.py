"""Collector/metric unit fixtures only; never public data or model experiments."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from agentmembrane.host_v2.rq1_collab_v1.audit import EventCollector
from agentmembrane.host_v2.rq1_collab_v1.bounded_outcomes import _hash, _ever_goal_value, joint_outcome, verify_bounded_outcomes
from agentmembrane.host_v2.rq1_collab_v1.integration import _write
from agentmembrane.host_v2.rq1_collab_v1.providers import HTTPReply, ModelDriver


class BoundedOutcomesTests(unittest.TestCase):
    def fixture(self, directory, *, value=0, initial=0, edit=None, actor="H", decisions=1):
        prompts = {"H": "public host instructions", "E": "public external instructions"}
        arm = "H_ONLY" if actor == "H" else "PLAIN"
        goal = {"goal_id": "injection_task_1", "goal": "fixture goal"}
        item = {"episode_id": "unit-only", "assignment_id": "unit-assignment", "pair_id": "unit-pair",
                "regime": "reference" if arm == "H_ONLY" else "attack", "goal_id": goal["goal_id"],
                "repetition": 0, "public_goal_record": goal, "role_prompts": prompts,
                "role_prompts_sha256": _hash(prompts), "arm": arm, "level": "A4",
                "suite": "workspace", "task_id": "user_task_8"}
        code = {x: "unit-fixture" for x in ("native.py", "native_goals.py", "process_backend.py")}
        contract = {"kind": "public_original_paired_diagnostic", "paired_protocol": "public_goal_external_agent/1",
                    "schedule": [item], "code_hashes": code,
                    "selection": [{"suite": "workspace", "task_id": "user_task_8", "initial_state_sha256": _hash({})}]}
        collector = EventCollector(directory, item["episode_id"])
        self.addCleanup(collector.abort)
        profile = {"model": "unit-no-network", "max_completion_tokens": 100}
        action = '{"type":"final","content":"unit fixture"}'
        reply = {"model": profile["model"], "choices": [{"index": 0, "finish_reason": "tool_calls",
            "message": {"role": "assistant", "content": None, "tool_calls": [{"id": "unit-call",
                "type": "function", "function": {"name": "submit_action", "arguments": action}}]}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}
        applied = {"H": prompts["H"]} if arm == "H_ONLY" else prompts
        driver = ModelDriver(profile, applied, collector, lambda _: HTTPReply(200, json.dumps(reply).encode()),
                             request_limit=decisions, action_protocol="single_tool_v1")
        bindings = []
        for n in range(decisions):
            observation = {"actor": actor, "history": [{"role": "observation", "content": {
                "status": "tool_result", "call_id": "earlier-call", "result": {"public": "same"}}}], "tools": []}
            raw = driver.next_action(actor, observation)
            binding = driver.last_completion_binding(actor)
            collector.emit("model_decision_response", {"raw": raw, "provider_binding": binding}, actor=actor)
            bindings.append({"actor": actor, "decision_id": "decision-" + str(n), "provider_binding": binding})
        fields = ("assignment_id", "episode_id", "pair_id", "regime", "goal_id", "repetition", "public_goal_record", "role_prompts_sha256")
        evidence = {"protocol_hash": _hash(contract), "episode_id": item["episode_id"],
            "execution_mode": "remote_text_mediated_diagnostic",
            "config": {"episode_id": item["episode_id"], "arm": arm, "level": "A4", "action_protocol": "single_tool_v1"},
            "paired_assignment": {k: item[k] for k in fields}, "model_role_prompts": applied,
            "initial_snapshot": {}, "initial_snapshot_hash": _hash({}), "terminal_snapshot": {}, "final_text": "unit fixture",
            "native_calls": [], "model_decisions": bindings,
            "native_attack": {"value": value, "initial_goal_value": initial, "goal_record": goal,
                "initial_snapshot_hash": _hash({}), "terminal_snapshot_hash": _hash({}), "final_text_hash": _hash("unit fixture"),
                "checker_file_hashes": code, "transitions": []},
            "termination": "host_final", "driver_failures": [], "unknown_reasons": [],
            "drain": {"status": "settled", "inflight": []},
            "system_terminal_snapshot": {"episode": {"status": "closed"}},
            "post_close_probe": {"fresh_reader": {"snapshot_matches": True}, "old_leases_accepted": {"H": False}},
            "utility": {"value": 0}}
        if edit:
            edit(evidence)
        _write(directory / "private_evaluation/evidence.json", evidence)
        _write(directory / "manifest.json", {"code_hashes": code})
        seal = collector.seal({"kind": "unit_fixture_not_research_sample"})
        return dict(expected_seal_hash=seal["seal_hash"], expected_contract=contract, expected_assignment=item)

    def test_both_goal_outcomes_and_task_failure_are_retained(self):
        for value in (0, 1):
            with self.subTest(value=value), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp) / "episode"
                kwargs = self.fixture(directory, value=value)
                result = verify_bounded_outcomes(directory, **kwargs)
                self.assertTrue(result["verified"], result)
                self.assertEqual(result["native_attack_success"], value)
                self.assertTrue(result["joint_outcome"].startswith("task_failure_"))
                self.assertFalse(result["full_rq1_risk_certified"])

    def test_unknown_bool_and_initially_true_never_negative_certificates(self):
        for value, initial in ((None, 0), (False, 0), (True, 0), (0, 1), (1, None)):
            with self.subTest(value=value, initial=initial), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp) / "episode"
                result = verify_bounded_outcomes(directory, **self.fixture(directory, value=value, initial=initial))
                self.assertIsNone(result["native_attack_success"])

    def test_incomplete_task_not_false_safe(self):
        for edit in (lambda e: e.update(termination="timeout"),
                     lambda e: e.update(driver_failures=[{"kind": "transport"}]),
                     lambda e: e["post_close_probe"].update(old_leases_accepted={"H": True})):
            with tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp) / "episode"
                result = verify_bounded_outcomes(directory, **self.fixture(directory, edit=edit))
                self.assertIsNone(result["native_attack_success"])
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "episode"
            result = verify_bounded_outcomes(directory, **self.fixture(directory, value=1,
                edit=lambda e: e.update(termination="timeout")))
            self.assertFalse(result["verified"])
            self.assertEqual(result["native_attack_success"], 1)
            self.assertEqual(result["observed_goal_ever_achieved"], 1)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "episode"
            result = verify_bounded_outcomes(directory, **self.fixture(directory, value=1,
                edit=lambda e: e.update(driver_failures=[{"kind": "transport_error"}])))
            self.assertFalse(result["verified"])
            self.assertEqual(result["native_attack_success"], 1)
            self.assertEqual(result["observed_goal_ever_achieved"], 1)

    def test_binding_tamper_and_asserted_complete_cannot_certify(self):
        for edit in (lambda e: e["native_attack"].update(terminal_snapshot_hash="wrong"),
                     lambda e: e["model_role_prompts"].update(H="different"),
                     lambda e: e.update(native_calls=[{"claimed": "unrecorded"}]),
                     lambda e: e.update(execution_mode="engineering_offline_native_only")):
            with tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp) / "episode"
                result = verify_bounded_outcomes(directory, **self.fixture(directory, edit=edit))
                self.assertFalse(result["verified"])
                self.assertIsNone(result["native_attack_success"])
        with tempfile.TemporaryDirectory() as tmp:
            result = verify_bounded_outcomes(Path(tmp), expected_seal_hash="fake",
                expected_contract={"observation_complete": True}, expected_assignment={})
            self.assertIsNone(result["native_attack_success"])

    def test_external_delivery_deduplicates_history_not_new_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "episode"
            result = verify_bounded_outcomes(directory, **self.fixture(directory, actor="E", decisions=2))
            self.assertTrue(result["verified"], result)
            info = result["external_information"]
            self.assertEqual(len(info["requests"]), 2)
            self.assertEqual(len(info["unique_tool_returns"]), 1)
            self.assertFalse(info["is_exact_secret_leakage"])

    def test_joint_four_cells_and_unknown(self):
        self.assertEqual(len({joint_outcome(u, r) for u in (0, 1) for r in (0, 1)}), 4)
        self.assertEqual(joint_outcome(None, 0), "not_determined")
        self.assertEqual(joint_outcome(1, False), "not_determined")

    def test_transient_effect_not_erased_and_unknown_not_zero(self):
        calls = [{"call_id": "a", "actor": "E", "status": "committed"},
                 {"call_id": "b", "actor": "H", "status": "committed"}]
        transient = [{**calls[0], "before": 0, "after": 1}, {**calls[1], "before": 1, "after": 0}]
        self.assertEqual(_ever_goal_value(0, calls, transient), 1)
        zero = [{**c, "before": 0, "after": 0} for c in calls]
        self.assertEqual(_ever_goal_value(0, calls, zero), 0)
        zero[0]["after"] = None
        self.assertIsNone(_ever_goal_value(0, calls, zero))
        zero[1]["before"] = 1
        self.assertEqual(_ever_goal_value(0, calls, zero), 1)
        with self.assertRaises(ValueError):
            _ever_goal_value(0, calls, [])
        swapped = copy.deepcopy(transient)
        swapped[0]["actor"] = "H"
        with self.assertRaises(ValueError):
            _ever_goal_value(0, calls, swapped)


if __name__ == "__main__":
    unittest.main()
