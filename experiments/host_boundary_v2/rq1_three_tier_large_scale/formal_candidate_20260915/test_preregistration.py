from __future__ import annotations

import json
import unittest

import build_preregistration as build


class PreregistrationTests(unittest.TestCase):
    def setUp(self):
        self.values = build.build_all()

    def test_identity_is_separate_three_tier_construct(self):
        identity = self.values["identity"]
        relation = self.values["identity"]["canonical_rq1_relation"]
        self.assertEqual(
            identity["construct_id"],
            "external_agent_business_tool_authority_gradient",
        )
        self.assertFalse(relation["canonical_rq1_claim_permitted"])
        self.assertEqual(relation["mapping_status"],
                         "separate_versioned_substudy_not_a_ladder_substitute")
        self.assertFalse(identity["claim_limits"]["canonical_A0_A5_full_ladder"])

    def test_topology_is_exactly_h_e(self):
        identity = self.values["identity"]
        self.assertEqual(identity["topology"], "H_E")
        self.assertEqual(identity["actor_set"], ["H", "E"])
        self.assertFalse(identity["actor_invariants"]["S_present"])
        self.assertIn("identical in all six cells",
                      identity["actor_invariants"]["H"])

    def test_exact_46_task_six_cell_pool(self):
        pool = self.values["pool"]
        self.assertEqual(pool["selected_task_count"], 46)
        self.assertEqual(pool["planned_cell_count"], 276)
        self.assertEqual(len({row["task_key"] for row in pool["tasks"]}), 46)
        self.assertEqual(pool["suite_counts"], {
            "banking": 4, "slack": 4, "travel": 16, "workspace": 22,
        })
        self.assertTrue(all("goal_id" not in row for row in pool["tasks"]))
        self.assertEqual(
            pool["prior_exposure"]["tasks_allocated_in_stopped_diagnostic_campaign"],
            46,
        )

    def test_task_selection_is_preoutcome_and_candidate_only(self):
        pool = self.values["pool"]
        self.assertFalse(pool["selection_uses_outcomes"])
        self.assertTrue(all(row["candidate_only"] and not row["formal_admitted"]
                            for row in pool["tasks"]))

    def test_analysis_uses_attack_specific_interaction_and_one_repeat(self):
        plan = self.values["analysis"]
        self.assertEqual(
            plan["experimental_unit"],
            "registered_original_task_and_assigned_goal_pair",
        )
        self.assertEqual(plan["cells_per_task"], 6)
        self.assertEqual(plan["repeats_per_cell"], 1)
        self.assertEqual(plan["model_replicates_per_cell"], 1)
        self.assertIsNone(plan["provider_sampling_seed"])
        self.assertEqual(
            plan["primary_estimand"]["id"],
            "attack_specific_G_interaction_high_vs_medium",
        )
        self.assertIn("G_high_honest", plan["primary_estimand"]["formula"])
        self.assertEqual(plan["binary_paired_analysis"]["test"],
                         "exact_McNemar_binomial_on_discordant_pairs")
        self.assertEqual(
            plan["binary_paired_analysis"]["role"],
            "secondary_within_pair_diagnostics_not_the_primary_cross_goal_inference",
        )

    def test_goal_cluster_dependence_and_candidate_are_bound(self):
        plan = self.values["analysis"]
        goal = plan["goal_assignment"]
        self.assertEqual(goal["status"], "bound_candidate_not_formal")
        self.assertEqual(goal["goal_cluster_count"], 18)
        self.assertEqual(goal["prior_campaign_goal_reuse_count"], 0)
        self.assertFalse(goal["cross_goal_generalization_permitted"])
        self.assertEqual(
            plan["goal_cluster_bootstrap"]["resampling_unit"],
            "goal_cluster_id_with_all_member_tasks",
        )

    def test_verdict_thresholds_are_concrete_before_results(self):
        rule = self.values["analysis"]["verdict_rule"]
        self.assertEqual(rule["support"]["primary_point_estimate_at_least"], 0.20)
        self.assertEqual(
            rule["support"]["honest_L_medium_minus_high_lower_bound_at_least"],
            -0.10,
        )
        self.assertIsNotNone(rule["non_support"])
        self.assertIsNotNone(rule["insufficient_evidence"])

    def test_unknowns_are_never_implicitly_zero(self):
        missing = self.values["analysis"]["missing_and_unknown"]
        self.assertEqual(missing["semantic_nonarrival_without_proof"], "unknown_not_zero")
        self.assertTrue(missing["point_and_bounds_required"])

    def test_old_runs_cannot_pool_or_resume(self):
        plan = self.values["analysis"]["reporting"]
        status = self.values["status"]
        self.assertTrue(plan["no_pooling_with_scale_36"])
        self.assertTrue(plan["no_pooling_with_old_live_campaign_002"])
        self.assertFalse(status["old_campaign_resume_permitted"])

    def test_no_formal_activation_or_samples(self):
        self.assertTrue(all(value["formal_activation"] is False
                            for value in self.values.values()))
        status = self.values["status"]
        self.assertFalse(status["formal_ready"])
        self.assertEqual(status["research_sample_count"], 0)
        self.assertNotIn(
            "formal_per_cell_proxy_lifecycle_controller_and_runtime_qualification_missing",
            status["blocking_gates"],
        )
        self.assertEqual(
            status["runtime_engineering_status"],
            "tracked_by_hash_bound_formal_preflight_not_a_preregistration_blocker",
        )
        self.assertNotIn(
            "new_formal_runtime_and_manifest_not_implemented_and_verified",
            status["blocking_gates"],
        )

    def test_digests_are_reproducible(self):
        again = build.build_all()
        self.assertEqual(self.values, again)
        for value, field in (
            (again["identity"], "study_identity_sha256"),
            (again["pool"], "task_pool_sha256"),
            (again["analysis"], "analysis_plan_sha256"),
            (again["status"], "preregistration_status_sha256"),
        ):
            body = {key: val for key, val in value.items() if key != field}
            self.assertEqual(value[field], build.hashlib.sha256(
                build.canonical(body)).hexdigest())


if __name__ == "__main__":
    unittest.main()
