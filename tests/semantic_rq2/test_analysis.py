from __future__ import annotations

import unittest

from agentmembrane.semantic_rq2.analysis import analyze_multiseed_records, analyze_records
from agentmembrane.semantic_rq2.schema import RECEPTOR_ORDER


def records_for(
    *,
    attack_target_from: int | None,
    invalid_attack: bool = False,
    descending: bool = False,
) -> list[dict]:
    records: list[dict] = []
    for index in range(100):
        case_id = f"case-{index}"
        common = {
            "case_id": case_id,
            "cluster_id": f"doc-{index}",
            "downstream_id": "victim-a",
            "downstream_model": "model-a",
            "gold_label": "Entailment",
            "assigned_target": "Contradiction",
            "packet_sha256": "sha",
            "packet_identity_ok": True,
            "terminal_status": "completed",
            "hard_valid": True,
        }
        records.append(common | {"arm_id": "E_evidence_only", "mode": "control", "receptor": None, "label": "Entailment"})
        records.append(common | {"arm_id": "C_explicit_recommendation_ceiling", "mode": "control", "receptor": None, "label": "Contradiction"})
        for receptor_index, receptor in enumerate(RECEPTOR_ORDER):
            records.append(
                common
                | {
                    "arm_id": f"honest:{receptor.value}",
                    "mode": "honest",
                    "receptor": receptor.value,
                    "label": "Entailment",
                }
            )
            if descending:
                reaches = receptor_index == 0
            elif attack_target_from is None:
                reaches = False
            else:
                reaches = receptor_index >= attack_target_from
            records.append(
                common
                | {
                    "arm_id": f"attack:{receptor.value}",
                    "mode": "attack",
                    "receptor": receptor.value,
                    "label": "Contradiction" if reaches else "Entailment",
                    "hard_valid": not invalid_attack,
                }
            )
    return records


class AnalysisTests(unittest.TestCase):
    def test_positive_monotonic_boundary_and_r_star(self) -> None:
        result = analyze_records(records_for(attack_target_from=2), seed=7, bootstrap_samples=200)
        row = result["per_downstream"]["victim-a"]
        self.assertEqual(row["result_label"], "positive_receptor_boundary_signal")
        self.assertTrue(row["all_measurement_gates_pass"])
        self.assertTrue(row["monotonic_non_decreasing_observed"])
        self.assertEqual(row["descriptive_R_star_first_unsafe"], "R2_structured_inference")

    def test_powered_null_is_not_positive(self) -> None:
        result = analyze_records(records_for(attack_target_from=None), seed=8, bootstrap_samples=200)
        row = result["per_downstream"]["victim-a"]
        self.assertEqual(row["result_label"], "bounded_null_below_5pp")

    def test_invalid_cases_are_not_encoded_as_zero(self) -> None:
        result = analyze_records(
            records_for(attack_target_from=2, invalid_attack=True),
            seed=9,
            bootstrap_samples=200,
        )
        row = result["per_downstream"]["victim-a"]
        self.assertEqual(row["result_label"], "not_estimable")
        valid = row["attack_minus_honest_by_receptor"]["R2_structured_inference"]["construct_valid"]
        self.assertEqual(valid["construct_valid_pair_n"], 0)
        self.assertEqual(valid["invalid_stratum_sensitivity_bounds"], [-1.0, 1.0])
        self.assertIsNone(valid["point"])

    def test_non_monotonic_signal_is_retained(self) -> None:
        result = analyze_records(records_for(attack_target_from=None, descending=True), seed=10, bootstrap_samples=200)
        row = result["per_downstream"]["victim-a"]
        self.assertEqual(row["result_label"], "non_monotonic_boundary_signal")
        self.assertFalse(row["monotonic_non_decreasing_observed"])

    def test_flat_positive_effect_is_not_mislabeled_as_boundary(self) -> None:
        result = analyze_records(records_for(attack_target_from=0), seed=11, bootstrap_samples=200)
        row = result["per_downstream"]["victim-a"]
        self.assertEqual(row["result_label"], "semantic_influence_without_receptor_gradient")
        self.assertFalse(row["significant_positive_adjacent_gradient"])

    def test_three_seed_pool_keeps_document_as_independence_unit(self) -> None:
        combined: list[dict] = []
        for seed in (20260831, 20260901, 20260902):
            combined.extend(dict(row, seed=seed) for row in records_for(attack_target_from=2))
        result = analyze_multiseed_records(combined, bootstrap_seed=12, bootstrap_samples=100)
        pooled = result["repeated_measure_pooled"]["per_downstream"]["victim-a"]
        self.assertEqual(pooled["independent_document_clusters"], 100)
        self.assertEqual(pooled["seed_n"], 3)
        self.assertEqual(pooled["planned_repeated_pair_block_n"], 300)


if __name__ == "__main__":
    unittest.main()
