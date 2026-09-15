"""Denominator/identity arithmetic fixtures, never generated research samples."""

import copy
import itertools
import unittest

from agentmembrane.host_v2.rq1_collab_v1.paired_analysis import PairedAnalysisError, summarize_paired


def schedule(tasks=("user_task_24",), repetitions=1, arms=("PLAIN", "CAP"), levels=("A0", "A4"), reference=True):
    cells = []
    for task in tasks:
        for repetition in range(1, repetitions + 1):
            conditions = [(arm, level, regime) for arm in arms for level in levels for regime in ("clean", "attack")]
            if reference:
                conditions.append(("H_ONLY", "A4", "reference"))
            for arm, level, regime in conditions:
                identity = f"{task}-{repetition}-{arm}-{level}-{regime}"
                cells.append({"assignment_id": "assignment-" + identity, "episode_id": "episode-" + identity,
                              "suite": "workspace", "task_id": task, "arm": arm, "level": level,
                              "regime": regime, "goal_id": "injection_task_0", "repetition": repetition,
                              "pair_id": f"pair-{task}-{repetition}-{arm}-{level}",
                              "repetition_id": f"repeat-{repetition}", "campaign_id": "fixture-campaign",
                              "source_world_id": "agentdojo:workspace:snapshot-locked",
                              "world_id": "agentdojo:workspace:snapshot-locked", "group_id": "agentdojo:workspace",
                              "initial_state_sha256": "snapshot-locked"})
    return cells


def rows(cells, *, utility=1, goal=0):
    return [{**copy.deepcopy(cell), "status": "executed", "flow_valid": True,
             "strict_utility": utility, "native_attack_success": goal, "initial_hash": "snapshot-locked"}
            for cell in cells]


def condition(result, arm, level, regime):
    return next(item for item in result["by_condition"] if (item["arm"], item["level"], item["regime"]) == (arm, level, regime))


class PairedAnalysisTests(unittest.TestCase):
    def test_known_paired_effects_keep_utility_separate_from_goal(self):
        cells = schedule(arms=("PLAIN",), levels=("A4",), repetitions=2)
        actual = rows(cells)
        for row in actual:
            if row["regime"] == "attack":
                row["strict_utility"] = 0
                row["native_attack_success"] = 1
        result = summarize_paired(cells, actual)
        paired = result["paired_differences"][0]
        self.assertEqual(paired["assigned_pairs"], 2)
        self.assertEqual(paired["strict_utility"]["attack_minus_clean_mean"], -1)
        self.assertEqual(paired["native_attack_success"]["attack_minus_clean_mean"], 1)
        attack = condition(result, "PLAIN", "A4", "attack")
        self.assertEqual(attack["joint_task_and_native_goal"]["counts"]["task_failure__goal_achieved"], 2)
        self.assertEqual(result["overall"]["distinct_original_tasks"], 1)

    def test_transient_goal_is_preserved_separately_from_terminal_negative(self):
        cells = schedule(arms=("CAP",), levels=("A4",), reference=False)
        actual = rows(cells)
        actual[0]["observed_goal_ever_achieved"] = 0
        actual[1]["observed_goal_ever_achieved"] = 1
        # Registered target occurred in a verified prefix, then was undone.
        actual[1]["native_attack_success"] = 0
        result = summarize_paired(cells, actual)
        paired = result["paired_differences"][0]
        self.assertEqual(paired["native_attack_success"]["attack_minus_clean_mean"], 0)
        self.assertEqual(paired["observed_goal_ever_achieved"]["attack_minus_clean_mean"], 1)
        attack = condition(result, "CAP", "A4", "attack")
        self.assertEqual(attack["joint_task_and_native_goal"]["counts"]["task_success__goal_not_achieved"], 1)
        self.assertEqual(attack["joint_task_and_observed_ever_goal"]["counts"]["task_success__goal_achieved"], 1)

    def test_missing_ever_outcome_is_not_filled_from_terminal_zero_or_one(self):
        cells = schedule(arms=("CAP",), levels=("A4",), reference=False)
        actual = rows(cells)
        actual[1]["native_attack_success"] = 1
        result = summarize_paired(cells, actual)
        self.assertEqual(result["overall"]["outcomes"]["observed_goal_ever_achieved"]["unknown"], 2)
        self.assertEqual(result["paired_differences"][0]["observed_goal_ever_achieved"]["attack_minus_clean_missingness_bounds"], {"lower": -1, "upper": 1})

    def test_ever_outcome_requires_binary_and_not_run_cannot_claim_it(self):
        cells = schedule()
        for value in (True, "1", 1.0):
            actual = rows(cells)
            actual[0]["observed_goal_ever_achieved"] = value
            with self.subTest(value=value), self.assertRaises(PairedAnalysisError):
                summarize_paired(cells, actual)
        actual = rows(cells)
        actual[0].update(status="not_run", strict_utility=None, native_attack_success=None, flow_valid=None, observed_goal_ever_achieved=1)
        with self.assertRaises(PairedAnalysisError):
            summarize_paired(cells, actual)
        actual = rows(cells)
        actual[0].update(native_attack_success=1, observed_goal_ever_achieved=0)
        with self.assertRaisesRegex(PairedAnalysisError, "terminal_goal_positive"):
            summarize_paired(cells, actual)

    def test_missing_rows_preserve_denominator_and_all_pairs(self):
        cells = schedule(repetitions=2)
        actual = rows(cells)[:2]
        result = summarize_paired(cells, actual)
        self.assertEqual(result["schedule_cells"], len(cells))
        self.assertEqual(result["received_rows"], 2)
        self.assertEqual(result["synthesized_not_run_rows"], len(cells) - 2)
        self.assertEqual(len(result["cells"]), len(cells))
        self.assertEqual(len(result["pairs"]), 8)
        rates = result["overall"]["outcomes"]["strict_utility"]
        self.assertEqual(rates["assigned"], len(cells))
        self.assertEqual(rates["unknown"], len(cells) - 2)
        self.assertEqual(rates["missingness_bounds"], {"lower": 2 / len(cells), "upper": 1})

    def test_completely_unrun_schedule_has_full_uncertainty(self):
        cells = schedule(arms=("CAP",), levels=("A0",), reference=False)
        result = summarize_paired(cells, [])
        paired = result["paired_differences"][0]
        self.assertEqual(paired["native_attack_success"]["attack_minus_clean_missingness_bounds"], {"lower": -1, "upper": 1})
        self.assertEqual(result["overall"]["outcomes"]["strict_utility"]["missingness_bounds"], {"lower": 0, "upper": 1})
        self.assertEqual(result["overall"]["status_counts"]["not_run"], 2)

    def test_failed_reference_does_not_filter_its_task_or_other_cells(self):
        cells = schedule()
        actual = rows(cells)
        baseline = next(row for row in actual if row["regime"] == "reference")
        baseline["strict_utility"] = 0
        result = summarize_paired(cells, actual)
        self.assertEqual(result["schedule_cells"], 9)
        self.assertEqual(len(result["pairs"]), 4)
        reference = condition(result, "H_ONLY", "A4", "reference")
        self.assertEqual(reference["outcomes"]["strict_utility"]["zeros"], 1)
        self.assertEqual(reference["outcomes"]["native_attack_success"]["zeros"], 1)

    def test_failed_flow_preserves_actual_known_effect_and_adds_conservative_sensitivity(self):
        cells = schedule(arms=("PLAIN",), levels=("A4",), reference=False)
        actual = rows(cells)
        actual[1].update(status="failed", flow_valid=False, native_attack_success=1, strict_utility=None)
        result = summarize_paired(cells, actual)
        attack = condition(result, "PLAIN", "A4", "attack")
        self.assertEqual(attack["outcomes"]["native_attack_success"]["ones"], 1)
        self.assertEqual(attack["flow_qualified_outcomes"]["native_attack_success"]["unknown"], 1)
        paired = result["paired_differences"][0]
        self.assertEqual(paired["native_attack_success"]["attack_minus_clean_mean"], 1)
        self.assertEqual(paired["flow_qualified"]["native_attack_success"]["attack_minus_clean_missingness_bounds"], {"lower": 0, "upper": 1})

    def test_partial_missingness_bounds_match_all_binary_completions(self):
        for clean, attack in itertools.product((0, 1, None), repeat=2):
            with self.subTest(clean=clean, attack=attack):
                cells = schedule(arms=("CAP",), levels=("A3",), reference=False)
                actual = rows(cells)
                actual[0]["native_attack_success"], actual[1]["native_attack_success"] = clean, attack
                result = summarize_paired(cells, actual)
                intervals = result["paired_differences"][0]["native_attack_success"]
                completions = [a - c for c in ((0, 1) if clean is None else (clean,))
                               for a in ((0, 1) if attack is None else (attack,))]
                self.assertEqual(intervals["attack_minus_clean_missingness_bounds"], {"lower": min(completions), "upper": max(completions)})

    def test_every_joint_binary_unknown_state_is_counted_once(self):
        cells = schedule(repetitions=1)
        actual = rows(cells)
        for row, (utility, goal) in zip(actual, itertools.product((1, 0, None), repeat=2)):
            row["strict_utility"], row["native_attack_success"] = utility, goal
        result = summarize_paired(cells, actual)
        counts = result["overall"]["joint_task_and_native_goal"]["counts"]
        self.assertEqual(sum(counts.values()), 9)
        self.assertEqual(set(counts.values()), {1})

    def test_repetition_count_not_task_or_world_count(self):
        cells = schedule(tasks=("user_task_24", "user_task_26"), repetitions=3)
        result = summarize_paired(cells, rows(cells))
        self.assertEqual(result["schedule_cells"], 54)
        self.assertEqual(result["overall"]["distinct_original_tasks"], 2)
        self.assertEqual(result["overall"]["distinct_task_goal_repetitions"], 6)
        self.assertEqual(result["overall"]["known_distinct_source_worlds"], 1)
        self.assertEqual(result["overall"]["known_world_family_groups"], 1)
        self.assertEqual([task["distinct_repetitions"] for task in result["by_task"]], [3, 3])
        self.assertIsNone(result["inference"]["sampling_confidence_intervals"])
        self.assertFalse(result["inference"]["cluster_independence_established"])

    def test_missing_world_identity_never_inferred_from_suites(self):
        cells = schedule()
        for cell in cells:
            for field in ("source_world_id", "world_id", "group_id"):
                del cell[field]
        result = summarize_paired(cells, rows(cells))
        self.assertEqual(result["overall"]["known_distinct_source_worlds"], 0)
        self.assertFalse(result["overall"]["source_world_count_exact"])
        self.assertEqual(result["overall"]["cells_without_source_world_id"], len(cells))

    def test_same_world_cannot_gain_extra_cluster_by_changing_reference_label(self):
        cells = schedule()
        cells[-1]["group_id"] = "invented-second-independent-world"
        with self.assertRaisesRegex(PairedAnalysisError, "inconsistent_group"):
            summarize_paired(cells, [])

    def test_missing_actual_initial_hash_is_not_verified_pairing(self):
        cells = schedule(arms=("PLAIN",), levels=("A4",), reference=False)
        actual = rows(cells)
        del actual[1]["initial_hash"]
        result = summarize_paired(cells, actual)
        self.assertEqual(result["pairs"][0]["actual_initial_state_match"], "unknown")
        qualified = result["paired_differences"][0]["flow_qualified"]["strict_utility"]
        self.assertEqual(qualified["attack_minus_clean_missingness_bounds"], {"lower": -1, "upper": 1})

    def test_actual_initial_hash_conflict_rejected(self):
        cells = schedule()
        actual = rows(cells)
        actual[1]["initial_hash"] = "changed-state"
        with self.assertRaisesRegex(PairedAnalysisError, "actual_initial_hash"):
            summarize_paired(cells, actual)
        for cell in cells:
            del cell["initial_state_sha256"]
        actual = rows(cells)
        actual[1]["initial_hash"] = "changed-state"
        with self.assertRaisesRegex(PairedAnalysisError, "paired_actual_initial"):
            summarize_paired(cells, actual)

    def test_duplicate_assignment_episode_and_semantic_alias_rejected(self):
        cells = schedule()
        actual = rows(cells)
        with self.assertRaisesRegex(PairedAnalysisError, "duplicate_result_assignment"):
            summarize_paired(cells, actual + [copy.deepcopy(actual[0])])
        duplicate = copy.deepcopy(cells[0])
        duplicate["assignment_id"] = "other-assignment"
        with self.assertRaisesRegex(PairedAnalysisError, "duplicate_schedule_episode"):
            summarize_paired(cells + [duplicate], [])
        duplicate["episode_id"] = "other-episode"
        duplicate["task_id"] = "workspace/" + duplicate["task_id"]
        with self.assertRaisesRegex(PairedAnalysisError, "duplicate_semantic_cell"):
            summarize_paired(cells + [duplicate], [])

    def test_extra_unassigned_retry_or_identity_changes_rejected(self):
        cells = schedule()
        actual = rows(cells)
        retry = copy.deepcopy(actual[0])
        retry["assignment_id"] += "-retry"
        retry["episode_id"] += "-retry"
        with self.assertRaisesRegex(PairedAnalysisError, "unassigned"):
            summarize_paired(cells, actual + [retry])
        for field, value in (("regime", "attack"), ("task_id", "other"), ("episode_id", "other"),
                             ("goal_id", "another-goal"), ("repetition", True), ("source_world_id", "other")):
            mutated = copy.deepcopy(actual)
            mutated[0][field] = value
            with self.subTest(field=field), self.assertRaises(PairedAnalysisError):
                summarize_paired(cells, mutated)

    def test_unknown_outcome_not_boolean_or_numeric_coercion(self):
        cells = schedule()
        for field in ("strict_utility", "native_attack_success"):
            for invalid in (True, False, "1", 1.0, -1, 2, float("nan")):
                actual = rows(cells)
                actual[0][field] = invalid
                with self.subTest(field=field, invalid=invalid), self.assertRaises(PairedAnalysisError):
                    summarize_paired(cells, actual)
        actual = rows(cells)
        actual[0]["flow_valid"] = 1
        with self.assertRaises(PairedAnalysisError):
            summarize_paired(cells, actual)

    def test_not_run_cannot_claim_results_but_failed_known_result_remains(self):
        cells = schedule()
        actual = rows(cells)
        actual[0]["status"] = "not_run"
        with self.assertRaisesRegex(PairedAnalysisError, "not_run"):
            summarize_paired(cells, actual)
        actual[0].update(strict_utility=None, native_attack_success=None, flow_valid=None)
        actual[1].update(status="failed", flow_valid=False, native_attack_success=1)
        result = summarize_paired(cells, actual)
        self.assertEqual(result["overall"]["status_counts"]["failed"], 1)
        self.assertEqual(result["overall"]["outcomes"]["native_attack_success"]["ones"], 1)

    def test_schedule_requires_partner_but_not_full_factorial(self):
        cells = schedule(arms=("CAP",), levels=("A0",), reference=False)
        self.assertEqual(len(summarize_paired(cells, []) ["pairs"]), 1)
        with self.assertRaisesRegex(PairedAnalysisError, "missing_clean_or_attack"):
            summarize_paired(cells[:1], [])
        with self.assertRaises(PairedAnalysisError):
            summarize_paired([], [])

    def test_reference_identity_and_pair_world_must_match(self):
        cells = schedule()
        for field, value in (("arm", "PLAIN"), ("level", "A0")):
            changed = copy.deepcopy(cells)
            changed[-1][field] = value
            with self.subTest(field=field), self.assertRaises(PairedAnalysisError):
                summarize_paired(changed, [])
        cells[1]["source_world_id"] = "other-world"
        with self.assertRaisesRegex(PairedAnalysisError, "world_mismatch"):
            summarize_paired(cells, [])

    def test_optional_pair_and_campaign_id_collisions_fail(self):
        cells = schedule()
        changed = copy.deepcopy(cells)
        changed[2]["pair_id"] = changed[0]["pair_id"]
        with self.assertRaisesRegex(PairedAnalysisError, "pair_id_reused"):
            summarize_paired(changed, [])
        changed = copy.deepcopy(cells)
        changed[0]["campaign_id"] = "another-campaign"
        with self.assertRaises(PairedAnalysisError):
            summarize_paired(changed, [])

    def test_equal_task_weighting_not_silently_equal_run_weighting(self):
        first = schedule(tasks=("user_task_24",), repetitions=1, arms=("CAP",), levels=("A4",), reference=False)
        second = schedule(tasks=("user_task_26",), repetitions=3, arms=("CAP",), levels=("A4",), reference=False)
        cells = first + second
        actual = rows(cells)
        for row in actual:
            row["native_attack_success"] = int(row["task_id"] == "user_task_24" and row["regime"] == "attack")
        metrics = summarize_paired(cells, actual)["paired_differences"][0]["native_attack_success"]
        self.assertEqual(metrics["attack_minus_clean_mean"], 0.25)
        self.assertEqual(metrics["equal_task_weighted_missingness_bounds"], {"lower": 0.5, "upper": 0.5})

    def test_input_unchanged_and_output_does_not_leak_private_goal_record(self):
        cells = schedule()
        cells[0]["public_goal_record"] = {"private_diagnostic": "not_a_score"}
        actual = rows(cells)
        actual[0]["raw_native_attack_success"] = 1
        original_cells, original_rows = copy.deepcopy(cells), copy.deepcopy(actual)
        result = summarize_paired(cells, actual)
        self.assertEqual(cells, original_cells)
        self.assertEqual(actual, original_rows)
        self.assertNotIn("public_goal_record", result["cells"][0])
        self.assertEqual(result["overall"]["outcomes"]["native_attack_success"]["ones"], 0)
        self.assertIsNone(result["inference"]["formal_A_star"])
        self.assertFalse(result["inference"]["five_hazard_risk_certified"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
