"""Native side-effect controls for four Workspace calendar D diagnostics."""
from __future__ import annotations

import copy
import unittest
from pathlib import Path

from agentmembrane.host_v2.rq1_collab_v1.process_backend import ProcessNativeTask
from agentmembrane.host_v2.rq1_collab_v6.workspace_qid_calendar_effect import (
    calendar_damage_contract, calendar_write_rule, observe_calendar_damage,
)


ROOT = Path(__file__).resolve().parents[2]
PYTHON = ROOT / "experiments/host_boundary_v2/runtime_envs/agentdojo-0.1.35-py3123-lock-395e3d0a5921-rq1v4/bin/python"
SOURCE = ROOT / "data/host_boundary_v2/upstream/agentdojo"


class WorkspaceCalendarDamageTests(unittest.TestCase):
    def real_case(self, task_id):
        native = ProcessNativeTask(str(PYTHON), str(SOURCE), "workspace", f"user_task_{task_id}")
        try:
            record, prompt, initial = native.record, native.prompt, native.snapshot()
            rule = calendar_write_rule(record, prompt, initial)
            participants = [p for p in rule["participants"] if p != rule["owner"]]
            if task_id in {9, 21}:
                participants = list(rule["participants"])
            result = native.call("create_calendar_event", {
                "title": rule["title"], "start_time": rule["start_time"][:16].replace("T", " "),
                "end_time": rule["end_time"][:16].replace("T", " "),
                "description": rule["description"], "participants": participants,
                "location": None})
        finally:
            native.shutdown()
        call = {**result, "call_id": f"calendar-{task_id}", "tool": "create_calendar_event",
                "arguments": {}, "record_origin": "trusted_native_adapter"}
        data = {"episode_id": f"calendar-D-{task_id}", "native_record": record,
                "task": {"suite": "workspace", "task_id": f"user_task_{task_id}", "prompt": prompt},
                "initial_snapshot": initial, "terminal_snapshot": result["after"],
                "native_calls": [call], "decisions": []}
        contract = calendar_damage_contract(record, prompt, initial)
        return data, contract

    def positives(self, result):
        return {row["unit_id"]: row for row in result["observations"] if row["affected"] == 1}

    def test_all_four_exact_native_event_and_invitation_effects_are_allowed(self):
        for task_id in (6, 9, 12, 21):
            with self.subTest(task=task_id):
                data, contract = self.real_case(task_id)
                result = observe_calendar_damage(data, contract)
                self.assertFalse(result["scope_incomplete"])
                self.assertEqual(self.positives(result), {})

    def test_unexpected_invitation_recipient_is_damage(self):
        data, contract = self.real_case(9)
        after = copy.deepcopy(data["terminal_snapshot"])
        new_mail = next(mail for key, mail in after["inbox"]["emails"].items()
                        if key not in data["initial_snapshot"]["inbox"]["emails"])
        new_mail["recipients"].append("outsider@example.com")
        data["native_calls"][0]["after"] = after
        data["terminal_snapshot"] = after
        positives = self.positives(observe_calendar_damage(data, contract))
        self.assertIn("D:inbox/new_objects", positives)

    def test_wrong_or_duplicate_event_is_damage(self):
        data, contract = self.real_case(6)
        after = copy.deepcopy(data["terminal_snapshot"])
        new_event = next(event for key, event in after["calendar"]["events"].items()
                         if key not in data["initial_snapshot"]["calendar"]["events"])
        duplicate = copy.deepcopy(new_event)
        duplicate["id_"] = "999"
        after["calendar"]["events"]["999"] = duplicate
        data["native_calls"][0]["after"] = after
        data["terminal_snapshot"] = after
        positives = self.positives(observe_calendar_damage(data, contract))
        self.assertIn("D:calendar/new_objects", positives)

    def test_original_mutation_and_unconfirmed_commit_are_not_declared_safe(self):
        data, contract = self.real_case(12)
        changed = copy.deepcopy(data["terminal_snapshot"])
        changed["calendar"]["events"]["1"]["title"] = "tampered"
        data["native_calls"][0]["after"] = changed
        data["terminal_snapshot"] = changed
        positives = self.positives(observe_calendar_damage(data, contract))
        self.assertIn("D:calendar/1", positives)
        unknown_data, contract = self.real_case(12)
        unknown_data["native_calls"][0]["after"] = None
        unknown_data["native_calls"][0]["evidence_quality"]["commit_status"] = "unknown"
        result = observe_calendar_damage(unknown_data, contract)
        self.assertTrue(result["scope_incomplete"])
        self.assertTrue(any(row["affected"] is None for row in result["observations"] if row["severity_lower"] == 0))

    def test_bad_source_or_contract_binding_rejected(self):
        data, contract = self.real_case(21)
        bad = copy.deepcopy(contract)
        bad["units"].pop()
        with self.assertRaisesRegex(ValueError, "contract_mismatch"):
            observe_calendar_damage(data, bad)
        wrong_record = copy.deepcopy(data["native_record"])
        wrong_record["prompt_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "source_binding_mismatch"):
            calendar_damage_contract(wrong_record, data["task"]["prompt"], data["initial_snapshot"])


if __name__ == "__main__":
    unittest.main()
