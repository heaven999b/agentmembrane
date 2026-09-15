"""Workspace source-bound, no-model read-only D diagnostic controls."""
from __future__ import annotations

import copy
import unittest
from pathlib import Path

from agentmembrane.host_v2.rq1_collab_v1.process_backend import ProcessNativeTask
from agentmembrane.host_v2.rq1_collab_v6.workspace_qid_readonly import (
    observe_readonly_damage, readonly_damage_contract, source_bound_readonly_draft,
)


ROOT = Path(__file__).resolve().parents[2]
PYTHON = ROOT / "experiments/host_boundary_v2/runtime_envs/agentdojo-0.1.35-py3123-lock-395e3d0a5921-rq1v4/bin/python"
SOURCE = ROOT / "data/host_boundary_v2/upstream/agentdojo"


class WorkspaceReadOnlyDamageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native = ProcessNativeTask(str(PYTHON), str(SOURCE), "workspace", "user_task_2")
        try:
            cls.record = native.record
            cls.prompt = native.prompt
            cls.initial = native.snapshot()
        finally:
            native.shutdown()
        cls.contract = readonly_damage_contract(cls.record, cls.prompt, cls.initial)

    def data(self, *, calls=None, terminal=None):
        return {"episode_id": "test-workspace-readonly",
                "native_record": self.record,
                "task": {"suite": "workspace", "task_id": "user_task_2", "prompt": self.prompt},
                "initial_snapshot": self.initial,
                "terminal_snapshot": self.initial if terminal is None else terminal,
                "native_calls": [] if calls is None else calls,
                "decisions": []}

    def confirmed(self, call_id, before, after):
        return {"call_id": call_id, "before": before, "after": after,
                "record_origin": "trusted_native_adapter",
                "evidence_quality": {"backend_entered": True, "commit_status": "confirmed"}}

    def test_all_readonly_drafts_compile_against_real_original_source(self):
        task_ids = (0, 1, 2, 3, 5, 10, 11, 14, 16, 17, 22, 27, 28, 30)
        for task_id in task_ids:
            with self.subTest(task_id=task_id):
                native = ProcessNativeTask(str(PYTHON), str(SOURCE), "workspace", f"user_task_{task_id}")
                try:
                    contract = readonly_damage_contract(native.record, native.prompt, native.snapshot())
                finally:
                    native.shutdown()
                self.assertEqual(len(contract["units"]), 86)
                self.assertEqual(contract["status"], "diagnostic_only_not_formal_QID_registration")

    def test_four_calendar_writing_tasks_are_rejected(self):
        for task_id in (6, 9, 12, 21):
            with self.subTest(task_id=task_id):
                native = ProcessNativeTask(str(PYTHON), str(SOURCE), "workspace", f"user_task_{task_id}")
                try:
                    with self.assertRaisesRegex(ValueError, "needs_effect_observer"):
                        source_bound_readonly_draft(native.record, native.prompt, native.snapshot())
                finally:
                    native.shutdown()

    def test_source_prompt_world_and_contract_tamper_rejected(self):
        with self.assertRaisesRegex(ValueError, "prompt_or_world_mismatch"):
            readonly_damage_contract(self.record, self.prompt + "!", self.initial)
        altered = copy.deepcopy(self.initial)
        altered["calendar"]["events"]["1"]["title"] = "changed"
        with self.assertRaisesRegex(ValueError, "prompt_or_world_mismatch"):
            readonly_damage_contract(self.record, self.prompt, altered)
        bad = copy.deepcopy(self.contract)
        bad["units"].pop()
        with self.assertRaisesRegex(ValueError, "contract_mismatch"):
            observe_readonly_damage(self.data(), bad)

    def test_intact_terminal_is_known_safe(self):
        result = observe_readonly_damage(self.data(), self.contract)
        self.assertFalse(result["scope_incomplete"])
        self.assertEqual(len(result["observations"]), 86)
        self.assertTrue(all(row["affected"] == 0 for row in result["observations"]))

    def test_committed_mutation_retained_after_recovery(self):
        changed = copy.deepcopy(self.initial)
        changed["calendar"]["events"]["1"]["title"] = "tampered"
        calls = [self.confirmed("c1", self.initial, changed),
                 self.confirmed("c2", changed, self.initial)]
        result = observe_readonly_damage(self.data(calls=calls), self.contract)
        row = next(row for row in result["observations"] if row["unit_id"] == "D:calendar/1")
        self.assertFalse(result["scope_incomplete"])
        self.assertEqual(row["affected"], 1)
        self.assertEqual(row["severity_lower"], 2)
        self.assertIn("c1", row["evidence_ids"])

    def test_committed_creation_and_deletion_count_as_damage(self):
        changed = copy.deepcopy(self.initial)
        changed["calendar"]["events"].pop("1")
        changed["calendar"]["events"]["new"] = {"title": "unauthorized"}
        result = observe_readonly_damage(self.data(
            calls=[self.confirmed("c1", self.initial, changed)], terminal=changed), self.contract)
        rows = {row["unit_id"]: row for row in result["observations"]}
        self.assertEqual(rows["D:calendar/1"]["severity_lower"], 3)
        self.assertEqual(rows["D:calendar/new_objects"]["severity_lower"], 2)

    def test_unconfirmed_transition_stays_unknown(self):
        call = {"call_id": "c1", "before": self.initial, "after": None,
                "record_origin": "trusted_native_adapter",
                "evidence_quality": {"backend_entered": True, "commit_status": "unknown"}}
        result = observe_readonly_damage(self.data(calls=[call]), self.contract)
        row = next(row for row in result["observations"] if row["unit_id"] == "D:calendar/1")
        self.assertTrue(result["scope_incomplete"])
        self.assertIsNone(row["affected"])

    def test_rejected_call_is_not_realized_damage(self):
        call = {"call_id": "c1", "before": self.initial, "after": None,
                "record_origin": "trusted_native_adapter",
                "evidence_quality": {"backend_entered": False, "commit_status": "not_entered"}}
        result = observe_readonly_damage(self.data(calls=[call]), self.contract)
        self.assertFalse(result["scope_incomplete"])
        self.assertTrue(all(row["affected"] == 0 for row in result["observations"]))


if __name__ == "__main__":
    unittest.main()
