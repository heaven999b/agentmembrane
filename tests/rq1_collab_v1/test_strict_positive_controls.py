"""No-model, private evaluator qualification of complete original-task controls."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest

from agentmembrane.host_v2.rq1_collab_v1.strict_positive_controls import audit_positive_controls


SOURCE = Path(__file__).resolve().parents[2] / "data/host_boundary_v2/upstream/agentdojo"


@unittest.skipUnless(importlib.util.find_spec("pydantic"), "locked native runtime required")
class StrictPositiveControls(unittest.TestCase):
    def test_every_supported_original_task_has_private_reachable_positive(self):
        report = audit_positive_controls(str(SOURCE))
        self.assertEqual(report["source_task_count"], 97)
        self.assertGreaterEqual(report["supported_task_count"], 46)
        self.assertEqual(report["reached_one_count"], report["supported_task_count"])
        self.assertTrue(report["all_supported_reached_one"])
        self.assertEqual(report["model_calls"], 0)
        self.assertFalse(report["formal_admission"])
        self.assertEqual(report["proof_scope"], "strict_checker_positive_reachability_not_independent_second_oracle")
        self.assertEqual(set(report["code_sha256"]), {"strict_positive_controls.py", "pilot_checkers.py", "native.py"})
        self.assertTrue(all(len(value) == 64 for value in report["code_sha256"].values()))
        sensitive = {"answer", "prompt", "initial_snapshot", "terminal_snapshot", "private_facts", "control_sha256"}
        self.assertTrue(all(not sensitive.intersection(row) for row in report["rows"]))
        corrected = {(row["suite"], row["task_id"]) for row in report["rows"]
                     if row.get("control_origin") == "independent_complete_answer_with_original_native_state"}
        self.assertGreaterEqual(corrected, {
            ("slack", "user_task_0"), ("travel", "user_task_0"), ("travel", "user_task_2"),
            ("workspace", "user_task_0"), ("workspace", "user_task_1"),
            ("workspace", "user_task_24"), ("workspace", "user_task_26"), ("workspace", "user_task_30"),
        })


if __name__ == "__main__":
    unittest.main()
