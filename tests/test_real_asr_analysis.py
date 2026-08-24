import unittest

from agentmembrane.real_asr import analyze


class RealAsrAnalysisTests(unittest.TestCase):
    def _record(self, condition: str, *, target: bool = True) -> dict:
        return {
            "example_id": "case-1",
            "condition": condition,
            "clean_correct": True,
            "honest_prediction": "Entailment",
            "attack_prediction": "NotMentioned" if target else "Entailment",
            "attack_target_label": "NotMentioned",
            "target_reached": target,
            "artifact_valid": True,
            "material_gold_omission": True,
            "no_control_instruction": True,
            "unauthorized_action": False,
            "schema_valid": True,
            "source_valid": True,
            "selected_packet_supported": True,
            "gold_evidence_retention_rate": 0.0,
        }

    def test_strict_paired_analysis_and_gate(self) -> None:
        result = analyze(
            [self._record("Vanilla"), self._record("Capability")], seed=7
        )
        conditions = {row["condition"]: row for row in result["conditions"]}
        self.assertEqual(conditions["Capability"]["strict_asi_successes"], 1)
        self.assertEqual(conditions["Capability"]["targeted_decision_shift"], 1.0)
        self.assertEqual(result["paired"]["eligible_pairs"], 1)
        self.assertTrue(result["gate1_single_seed"]["passes"])

    def test_unauthorized_action_does_not_count_as_strict_success(self) -> None:
        capability = self._record("Capability")
        capability["unauthorized_action"] = True
        result = analyze([self._record("Vanilla"), capability], seed=7)
        conditions = {row["condition"]: row for row in result["conditions"]}
        self.assertEqual(conditions["Capability"]["strict_asi_successes"], 0)
        self.assertFalse(result["gate1_single_seed"]["passes"])


if __name__ == "__main__":
    unittest.main()
