"""Statistical identity regressions; synthetic contracts, never research data."""
import copy
import unittest

from agentmembrane.host_v2.rq1_collab_v1.campaign import plan_panel, validate_tasks
from agentmembrane.host_v2.rq1_collab_v1.statistics import (
    condition_decision, paired_utility_bounds, simultaneous_risk,
)


HAZARDS = ("H_MEM", "H_TOOL", "H_XAG", "H_CAP", "H_CTRL", "union")


def original_task(*, source="AgentDojo", suite="workspace", original_id="user_task_8", alias="local-task"):
    return {"task_id": alias, "source": source, "suite": suite, "original_id": original_id,
            "group_id": "unit-group", "world_id": "unit-world", "admission_status": "admitted",
            "task_bundle_hash": "a" * 64, "initial_state_hash": "b" * 64,
            "task_authorization_hash": "c" * 64,
            "eligible_goals": [{"goal_id": "unit-public-goal", "public_goal_hash": "d" * 64,
                                "eligibility_status": "admitted", "target_exists": True,
                                "initially_satisfied": False, "conflicts_with_user_intent": True}]}


def planned(n=6, tasks=None):
    return plan_panel(tasks or [original_task()], n=n, master_seeds=[11, 22, 33],
                      protocol_hash="e" * 64, campaign_id="identity-unit-plan")


def rows(plan, arm, level, regime, value):
    return [{**copy.deepcopy(row), "value": value} for row in plan["rows"]
            if (row["arm"], row["level"], row["regime"]) == (arm, level, regime)]


class StatisticalIdentityTests(unittest.TestCase):
    def setUp(self):
        self.plan = planned()
        self.ref = rows(self.plan, "PLAIN", "A4", "clean", 1)
        self.con = rows(self.plan, "CAP", "A0", "clean", 1)
        self.attack = rows(self.plan, "CAP", "A0", "attack", 0)

    def test_original_minimal_missing_assignment_retry_rejected(self):
        # Independent reviewer DS-01: used to yield n=2, identity_validated=True.
        payload = [{"execution_id": "attempt-one", "pair_id": "same-assigned-pair", "value": 0},
                   {"execution_id": "attempt-two", "pair_id": "same-assigned-pair", "value": 0}]
        with self.assertRaises(ValueError):
            simultaneous_risk(payload)

    def test_real_planner_rows_are_accepted_and_math_values_stay_unvalidated(self):
        result = simultaneous_risk(self.attack)
        self.assertEqual(result["n"], self.plan["paired_draw_count"])
        self.assertTrue(result["identity_validated"])
        self.assertIn("not_execution_authentication", result["identity_validation_scope"])
        self.assertFalse(simultaneous_risk([0, None, 1])["identity_validated"])
        self.assertEqual(simultaneous_risk([0, None, 1])["unknown"], 1)
        self.assertEqual(len({row["assignment_id"] for row in self.plan["rows"]}), self.plan["planned_episode_count"])

    def test_missing_empty_and_nonstring_stable_identity_rejected(self):
        for key in ("execution_id", "assignment_id", "pair_id", "source", "suite", "original_id", "protocol_hash"):
            for replacement in (None, "", 1, []):
                changed = copy.deepcopy(self.attack)
                changed[0][key] = replacement
                with self.subTest(key=key, value=replacement), self.assertRaises(ValueError):
                    simultaneous_risk(changed)

    def test_new_execution_or_renamed_pair_cannot_turn_retry_into_new_draw(self):
        for copied_field in ("execution_id", "assignment_id", "pair_id", "replication"):
            changed = copy.deepcopy(self.attack)
            changed[1][copied_field] = changed[0][copied_field]
            with self.subTest(field=copied_field), self.assertRaises(ValueError):
                simultaneous_risk(changed)
        retry = {**self.attack[0], "execution_id": "new-attempt", "assignment_id": "forged-new-assignment", "pair_id": "forged-new-pair"}
        with self.assertRaises(ValueError):
            simultaneous_risk([self.attack[0], retry])

    def test_repeated_original_task_draws_are_legitimate_not_deduplicated(self):
        self.assertEqual(len({row["original_id"] for row in self.attack}), 1)
        self.assertEqual(simultaneous_risk(self.attack)["n"], 6)

    def test_risk_series_cannot_mix_conditions_or_seed_batch_mapping(self):
        for key, replacement in (("arm", "PLAIN"), ("level", "A4"), ("regime", "clean"),
                                 ("panel", "U"), ("protocol_hash", "different"), ("model_profile", "another-model")):
            changed = copy.deepcopy(self.attack)
            changed[1][key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                simultaneous_risk(changed)
        changed = copy.deepcopy(self.attack)
        changed[3]["master_seed"] += 1
        with self.assertRaises(ValueError):
            simultaneous_risk(changed)

    def test_pair_alignment_requires_same_draw_not_only_same_pair_string(self):
        self.assertTrue(paired_utility_bounds(self.ref, self.con)["identity_validated"])
        for key, replacement in (("source", "other-source"), ("original_id", "other-task"), ("world_id", "other-world"),
                                 ("initial_state_hash", "f" * 64), ("task_authorization_hash", "f" * 64),
                                 ("goal_id", "other-goal"), ("seed", 123456789), ("replication", 9999)):
            changed = copy.deepcopy(self.con)
            changed[0][key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                paired_utility_bounds(self.ref, changed)
        with self.assertRaises(ValueError):
            paired_utility_bounds(self.ref, list(reversed(self.con)))

    def test_same_reference_condition_can_compare_to_itself_not_conflicting_copy(self):
        self.assertTrue(paired_utility_bounds(self.ref, copy.deepcopy(self.ref))["identity_validated"])
        contradictory = copy.deepcopy(self.ref)
        contradictory[0]["value"] = 0
        with self.assertRaises(ValueError):
            paired_utility_bounds(self.ref, contradictory)
        swapped = copy.deepcopy(self.con)
        swapped[0]["execution_id"] = self.ref[1]["execution_id"]
        with self.assertRaises(ValueError):
            paired_utility_bounds(self.ref, swapped)

    def test_primary_clean_utility_and_attack_risk_pairing_accepted(self):
        hazards = {hazard: copy.deepcopy(self.attack) for hazard in HAZARDS}
        result = condition_decision(self.ref, self.con, hazards)
        self.assertTrue(result["utility"]["identity_validated"])
        self.assertTrue(all(item["identity_validated"] for item in result["hazards"].values()))
        self.assertNotEqual(self.con[0]["assignment_id"], self.attack[0]["assignment_id"])
        self.assertNotEqual(self.con[0]["execution_id"], self.attack[0]["execution_id"])

    def test_wrong_arm_or_level_hazard_rows_cannot_pass_primary_gate(self):
        # Complete rows from the real planner reproduce the DS-03 join problem.
        wrong = rows(self.plan, "PLAIN", "A4", "attack", 0)
        with self.assertRaises(ValueError):
            condition_decision(self.ref, self.con, {hazard: copy.deepcopy(wrong) for hazard in HAZARDS})
        wrong_clean = rows(self.plan, "CAP", "A0", "clean", 0)
        with self.assertRaises(ValueError):
            condition_decision(self.ref, self.con, {hazard: copy.deepcopy(wrong_clean) for hazard in HAZARDS})

    def test_hazard_families_and_union_require_identical_attack_execution(self):
        for key in ("assignment_id", "execution_id"):
            hazards = {hazard: copy.deepcopy(self.attack) for hazard in HAZARDS}
            hazards["H_TOOL"][0][key] = "different-resolved-attempt"
            with self.subTest(key=key), self.assertRaises(ValueError):
                condition_decision(self.ref, self.con, hazards)

    def test_optional_model_family_locks_cannot_be_dropped_or_mixed(self):
        hazards = {hazard: copy.deepcopy(self.attack) for hazard in HAZARDS}
        for series in hazards.values():
            for row in series:
                row["family_hash"] = "wrong-family"
        with self.assertRaises(ValueError):
            condition_decision(self.ref, self.con, hazards)

    def test_unknown_row_keeps_its_original_assignment_and_denominator(self):
        changed = copy.deepcopy(self.attack)
        changed[0]["value"] = None
        result = simultaneous_risk(changed)
        self.assertEqual(result["n"], 6)
        self.assertEqual(result["unknown"], 1)
        self.assertIsNone(result["point_rate"])


class OriginalTaskIdentityTests(unittest.TestCase):
    def test_original_alias_cannot_add_task_or_sampling_mass(self):
        one = original_task(alias="alias-one")
        two = {**copy.deepcopy(one), "task_id": "alias-two"}
        with self.assertRaises(ValueError):
            validate_tasks([one, two])
        with self.assertRaises(ValueError):
            planned(tasks=[one, two])

    def test_same_original_number_in_different_source_or_suite_is_not_merged(self):
        cases = [[original_task(), original_task(source="OtherPublicBenchmark")],
                 [original_task(), original_task(suite="travel")],
                 [original_task(), original_task(original_id="user_task_9", alias="another-local-task")]]
        for tasks in cases:
            with self.subTest(identities=[(r["source"], r["suite"], r["original_id"]) for r in tasks]):
                validate_tasks(tasks)
                self.assertEqual(planned(tasks=tasks)["original_task_count"], 2)

    def test_alias_rename_does_not_change_uniform_original_task_draws(self):
        tasks = [original_task(alias="z-alias"), original_task(original_id="user_task_9", alias="a-alias")]
        first = planned(n=30, tasks=tasks)
        second = planned(n=30, tasks=[{**tasks[0], "task_id": "a-renamed"}, {**tasks[1], "task_id": "z-renamed"}])
        self.assertEqual([row["original_id"] for row in first["draws"]], [row["original_id"] for row in second["draws"]])


if __name__ == "__main__":
    unittest.main()
