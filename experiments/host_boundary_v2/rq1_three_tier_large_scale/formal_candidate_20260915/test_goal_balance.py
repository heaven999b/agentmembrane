from __future__ import annotations

import hashlib
import json
import unittest

import audit_goal_balance as audit


class GoalBalanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.candidate = json.loads(audit.OUTPUT.read_text(encoding="utf-8"))
        cls.report = json.loads(audit.REPORT.read_text(encoding="utf-8"))

    def test_keeps_requested_46_by_6_design(self):
        self.assertEqual(len(self.candidate["assignments"]), 46)
        self.assertEqual(self.candidate["planned_cell_count"], 276)
        self.assertEqual(self.candidate["model_repeats_per_cell"], 1)

    def test_assignment_is_unique_and_content_addressed(self):
        tasks = [row["task_key"] for row in self.candidate["assignments"]]
        self.assertEqual(len(tasks), len(set(tasks)))
        body = {key: value for key, value in self.candidate.items()
                if key != "goal_balance_sha256"}
        self.assertEqual(
            self.candidate["goal_balance_sha256"],
            hashlib.sha256(audit.canonical(body)).hexdigest(),
        )
        report_body = {key: value for key, value in self.report.items()
                       if key != "report_sha256"}
        self.assertEqual(
            self.report["report_sha256"],
            hashlib.sha256(audit.canonical(report_body)).hexdigest(),
        )

    def test_prior_live_campaign_goals_are_not_reused(self):
        self.assertTrue(self.candidate["prior_campaign_goal_reuse_forbidden"])
        self.assertEqual(self.report["prior_campaign_goal_reuse_count"], 0)
        for row in self.candidate["assignments"]:
            self.assertNotEqual(
                row["goal_id"], audit.PRIOR_CAMPAIGN_GOALS[row["suite"]]
            )

    def test_selected_edges_have_real_permission_contrast(self):
        self.assertTrue(
            self.report["all_selected_high_reachable_low_medium_blocked"]
        )

    def test_no_cross_goal_population_claim(self):
        self.assertFalse(self.candidate["cross_goal_generalization_permitted"])
        self.assertEqual(
            self.candidate["goal_cluster_key"],
            "suite/goal_id/attack_spec_sha256",
        )

    def test_candidate_remains_nonformal_and_zero_model(self):
        self.assertFalse(self.candidate["formal_activation"])
        self.assertFalse(self.report["formal_ready"])
        self.assertEqual(self.report["model_calls"], 0)
        self.assertEqual(self.report["research_sample_count"], 0)


if __name__ == "__main__":
    unittest.main()
