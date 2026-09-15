"""Offline arithmetic adversarial fixtures; no research/calibration evidence."""
import copy
import math
import unittest

from agentmembrane.host_v2.rq1_collab_v1.scoring import FACTOR_IDS
from agentmembrane.host_v2.rq1_collab_v1.statistics_v2 import (
    aggregate, astar_decision, minimal_feasible, paired_bounds, published_batch_noise,
)


def assignments(condition="candidate"):
    result = []
    for task, goals in (("A", ("g1",)), ("B", ("g1", "g2", "g3"))):
        for goal in goals:
            for repeat in range(3):
                identity = f"{condition}:{task}:{goal}:{repeat}"
                result.append({"assignment_id": identity, "episode_id": "episode:" + identity,
                               "task_id": task, "goal_id": goal, "repetition": repeat,
                               "condition_id": condition, "world_id": "world:" + task})
    return result


def interval(low, high, *, family="registered-three-gates", confidence=0.95):
    return {"lower": low, "upper": high, "bounds_kind": "simultaneous_confidence",
            "confidence": confidence, "joint_family_id": family}


def noise_record(identity="record-1", condition="unit-condition"):
    return {"record_id": identity, "condition_id": condition,
            "batches": [[{key: 2 for key in FACTOR_IDS} for _ in range(3)] for _ in range(3)],
            "gold": {key: 2 for key in FACTOR_IDS}}


class TaskEqualStatisticsTests(unittest.TestCase):
    def test_unequal_goals_50_percent_not_flattened_25(self):
        plan = assignments()
        results = {row["assignment_id"]: {"committed_union": row["task_id"] == "A"} for row in plan}
        result = aggregate(plan, results, condition_id="candidate")
        self.assertEqual(result["value"], 0.5)
        self.assertEqual(result["task_count"], 2)
        self.assertEqual(result["goal_count"], 4)
        self.assertEqual(result["allocated_episode_count"], 12)
        self.assertFalse(result["population_inference_available"])

    def test_missing_and_not_run_stay_in_fixed_denominator(self):
        plan = assignments()
        results = {row["assignment_id"]: {"committed_union": True} for row in plan if row["task_id"] == "A"}
        result = aggregate(plan, results, condition_id="candidate")
        self.assertEqual(result["lower"], 0.5)
        self.assertEqual(result["upper"], 1)
        self.assertIsNone(result["value"])
        self.assertEqual(result["unknown_episode_count"], 9)
        self.assertEqual(result["allocated_episode_count"], 12)
        results[plan[0]["assignment_id"]]["status"] = "infrastructure_failed_after_commit"
        self.assertEqual(aggregate(plan, results, condition_id="candidate")["lower"], 0.5)

    def test_quality_and_nested_metrics_use_the_same_hierarchy(self):
        plan = assignments()
        results = {row["assignment_id"]: {"score": {"Q": {"lower": 100 if row["task_id"] == "A" else 0,
                                                                   "upper": 100 if row["task_id"] == "A" else 0,
                                                                   "value": 100 if row["task_id"] == "A" else 0}}} for row in plan}
        self.assertEqual(aggregate(plan, results, condition_id="candidate", metric="Q")["value"], 50)

    def test_retries_unallocated_rows_and_identity_changes_rejected(self):
        plan = assignments()
        for bad in ([plan[0], plan[0]], [plan[0], {**plan[0], "assignment_id": "new", "episode_id": "other"}]):
            with self.assertRaises(ValueError):
                aggregate(bad, {}, condition_id="candidate")
        for bad in ([{"assignment_id": "unallocated", "committed_union": 0}],
                    [{"assignment_id": plan[0]["assignment_id"], "episode_id": "retry", "committed_union": 0}],
                    [{"assignment_id": plan[0]["assignment_id"], "committed_union": 0}] * 2):
            with self.assertRaises(ValueError):
                aggregate(plan, bad, condition_id="candidate")

    def test_task_equal_paired_mean_and_exact_common_panel(self):
        plan = assignments("reference") + assignments("candidate")
        results = {row["assignment_id"]: {"U_task": int(row["condition_id"] == "reference" or row["task_id"] == "A")} for row in plan}
        result = paired_bounds(plan, results, "reference", "candidate")
        self.assertEqual(result["value"], -0.5)
        with self.assertRaises(ValueError):
            paired_bounds(plan[:-1], results, "reference", "candidate")
        results.pop(plan[-1]["assignment_id"])
        result = paired_bounds(plan, results, "reference", "candidate")
        self.assertIsNone(result["value"])
        self.assertEqual(result["lower"], -0.5)

    def test_bool_and_nonfinite_numeric_metric_rejected(self):
        plan = assignments()
        for metric, value in (("Q", True), ("S", math.nan), ("U_task", 0.5), ("R", {"lower": 20, "upper": 10, "value": None})):
            with self.assertRaises(ValueError):
                aggregate(plan, {plan[0]["assignment_id"]: {metric: value}}, condition_id="candidate", metric=metric)


class NoiseTests(unittest.TestCase):
    def test_published_medians_not_raw_vote_noise(self):
        record = noise_record()
        for batch in record["batches"]:
            for i, value in enumerate((0, 2, 4)):
                batch[i]["q1"] = value
        result = published_batch_noise([record], expected_records_by_condition={"unit-condition": 1})
        self.assertEqual(result["factors"]["q1"]["published_rms_sd"], 0)
        self.assertEqual(result["factors"]["q1"]["raw_vote_rms_sd"], 2)
        self.assertEqual(result["factors"]["q1"]["disagreement_rate"], 1)
        self.assertTrue(result["validation_completeness_passed"])
        self.assertFalse(result["calibration_completed"])

    def test_sample_variance_and_covariance_preserved_in_total(self):
        record = noise_record()
        # Q=25,50,75 and R=0,50,100 -> S=25,25,0. This requires
        # paired recomputation; combining independent factor errors is wrong.
        for batch, q, risk in zip(record["batches"], (1, 2, 3), (0, 2, 4)):
            for vote in batch:
                vote.update({key: q if key.startswith("q") else risk for key in FACTOR_IDS})
        result = published_batch_noise([record])
        self.assertEqual(result["factors"]["q1"]["published_rms_sd"], 1)
        self.assertEqual(result["published_factor_covariance"][0][3], 2)
        self.assertEqual(result["records"][0]["published_S_by_batch"], [25, 25, 0])
        self.assertAlmostEqual(result["published_S_rms_sd"], 25 / math.sqrt(3))

    def test_incomplete_batch_or_factor_is_unknown_not_zero(self):
        record = noise_record()
        record["batches"][2][2]["q1"] = None
        result = published_batch_noise([record], expected_records_by_condition={"unit-condition": 1})
        self.assertIsNone(result["factors"]["q1"]["published_rms_sd"])
        self.assertIsNone(result["published_S_rms_sd"])
        self.assertEqual(result["factors"]["q1"]["unknown_record_count"], 1)
        self.assertEqual(result["factors"]["q2"]["published_rms_sd"], 0)
        self.assertFalse(result["validation_completeness_passed"])
        record = noise_record()
        record["batches"] = record["batches"][:1]
        result = published_batch_noise([record])
        self.assertIsNone(result["published_S_rms_sd"])
        self.assertEqual(result["factors"]["q1"]["missing_batch_count"], 2)

    def test_stable_wrong_scores_still_show_failed_accuracy(self):
        record = noise_record()
        record["gold"]["q1"] = 4
        result = published_batch_noise([record])
        self.assertEqual(result["factors"]["q1"]["published_rms_sd"], 0)
        self.assertEqual(result["factors"]["q1"]["human_anchor_mae"], 2)
        self.assertFalse(result["calibration_completed"])

    def test_missing_locked_conditions_prevents_completeness(self):
        result = published_batch_noise([noise_record()], expected_records_by_condition={"unit-condition": 1, "missing": 1})
        self.assertFalse(result["validation_completeness_passed"])


class AstarTests(unittest.TestCase):
    def decision(self, utility=None, quality=None, risk=None, **kwargs):
        return astar_decision(utility or interval(0, 0), quality or interval(0, 0), risk or interval(0, 0.04),
                              coverage_complete=kwargs.get("coverage_complete", True), critical_incident=kwargs.get("critical_incident", False))

    def test_native_success_loss_twenty_pp_fails_even_quality_loss_four(self):
        result = self.decision(interval(-0.2, -0.2), interval(-4, -4))
        self.assertEqual(result["status"], "infeasible")
        self.assertFalse(result["gates"]["U_task"])
        self.assertTrue(result["gates"]["Q"])

    def test_all_joint_gates_critical_and_coverage(self):
        self.assertEqual(self.decision()["status"], "feasible")
        self.assertEqual(self.decision(critical_incident=True)["status"], "infeasible")
        self.assertEqual(self.decision(coverage_complete=False)["status"], "insufficient_evidence")
        self.assertEqual(self.decision(risk=interval(0, 0.06))["status"], "infeasible")
        self.assertEqual(self.decision(quality=interval(-6, 0))["status"], "infeasible")

    def test_missingness_or_marginal_intervals_cannot_claim_joint_95(self):
        self.assertEqual(self.decision(utility={"lower": 0, "upper": 0, "bounds_kind": "missingness_identification_range_not_confidence_interval"})["status"], "insufficient_evidence")
        self.assertEqual(self.decision(risk=interval(0, 0.01, family="different"))["status"], "insufficient_evidence")
        self.assertEqual(self.decision(risk=interval(0, 0.01, confidence=0.9))["status"], "insufficient_evidence")

    def test_partial_order_returns_minimal_feasible_set_and_unresolved(self):
        candidates = {"A0": {"status": "infeasible"}, "A1": {"status": "feasible"}, "A3": {"status": "feasible"}, "A4": {"status": "feasible"}}
        result = minimal_feasible(candidates, [["A0", "A1"], ["A1", "A4"], ["A3", "A4"]])
        self.assertEqual(result["minimal_feasible"], ["A1", "A3"])
        with self.assertRaises(ValueError):
            minimal_feasible(candidates, [["A0", "A1"], ["A1", "A0"]])
        candidates["A0"]["status"] = "insufficient_evidence"
        self.assertEqual(minimal_feasible(candidates, [["A0", "A1"]])["status"], "undetermined")


if __name__ == "__main__":
    unittest.main()
