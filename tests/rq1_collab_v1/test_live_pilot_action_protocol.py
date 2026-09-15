"""Root runner regression: physical tool response audit and honest counters."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from agentmembrane.host_v2.rq1_collab_v1.audit import EventCollector
from agentmembrane.host_v2.rq1_collab_v1.live_pilot import audit_model_lineage, task_validity_counts
from agentmembrane.host_v2.rq1_collab_v1.providers import HTTPReply, ModelDriver


class LivePilotActionProtocolTests(unittest.TestCase):
    def evidence(self, directory, protocol="single_tool_v1"):
        collector = EventCollector(directory, "wire-test")
        self.addCleanup(collector.abort)
        text = '{"type":"final","content":"public observation only"}'
        message = {"role": "assistant", "content": "Commentary is not executable."}
        finish = "tool_calls"
        if protocol == "single_tool_v1":
            message["tool_calls"] = [{"id": "call-one", "type": "function", "function": {
                "name": "submit_action", "arguments": text}}]
        else:
            message["content"], finish = text, "stop"
        reply = {"model": "local-wire-test", "choices": [{"index": 0, "finish_reason": finish, "message": message}],
                 "usage": {"prompt_tokens": 5, "completion_tokens": 3, "total_tokens": 8}}
        profile = {"model": "local-wire-test", "max_completion_tokens": 100}
        driver = ModelDriver(profile, {"H": "A local test prompt"}, collector,
            lambda body: HTTPReply(200, json.dumps(reply).encode()), request_limit=1,
            action_protocol=protocol)
        actual = driver.next_action("H", {"actor": "H", "history": [], "tools": []})
        self.assertEqual(actual, text)
        binding = driver.last_completion_binding("H")
        collector.emit("model_decision_response", {"raw": actual, "provider_binding": binding}, actor="H")
        return {"config": {"action_protocol": protocol, "model_profile": profile},
                "model_decisions": [{"actor": "H", "decision_id": "d1", "provider_binding": binding}]}

    def test_physical_single_tool_output_and_legacy_content(self):
        for protocol in ("single_tool_v1", "json_content_v1"):
            with self.subTest(protocol=protocol), tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                evidence = self.evidence(directory, protocol)
                self.assertTrue(audit_model_lineage(directory, evidence)["ok"])

    def test_protocol_swap_and_serialized_wire_tamper_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            evidence = self.evidence(directory)
            changed = copy.deepcopy(evidence)
            changed["config"]["action_protocol"] = "json_content_v1"
            self.assertFalse(audit_model_lineage(directory, changed)["ok"])
            changed = copy.deepcopy(evidence)
            changed["model_decisions"][0]["provider_binding"]["serialized_body"] += " "
            self.assertFalse(audit_model_lineage(directory, changed)["ok"])

    def test_invalid_flow_is_not_a_valid_task_negative(self):
        rows = [
            {"status": "executed", "flow_valid": True, "strict_utility": 1},
            {"status": "executed", "flow_valid": True, "strict_utility": 0},
            {"status": "executed", "flow_valid": False, "strict_utility": 0},
            {"status": "executed", "flow_valid": True, "strict_utility": None},
            {"status": "not_run"},
        ]
        counts = task_validity_counts(rows)
        self.assertEqual(counts["valid_task_success"], 1)
        self.assertEqual(counts["valid_task_failure"], 1)
        self.assertEqual(counts["invalid_or_incomplete_executed"], 1)
        self.assertEqual(counts["valid_task_unknown"], 1)
        self.assertEqual(counts["risk_unknown_executed"], 4)


if __name__ == "__main__":
    unittest.main()
