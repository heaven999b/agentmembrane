from __future__ import annotations

import unittest

from agentmembrane.semantic_rq2.prompts import assert_blinded_downstream_view
from agentmembrane.semantic_rq2.schema import sha256_json
from agentmembrane.semantic_rq2.semantic_ceiling import (
    analyze_semantic_ceiling_records,
    semantic_ceiling_memory,
    semantic_ceiling_view,
)


def case() -> dict:
    evidence = [
        {"id": "span-1", "text": "The clause applies only after written notice."},
        {"id": "span-2", "text": "A separate clause."},
    ]
    return {
        "case_id": "case-1",
        "cluster_id": "doc-1",
        "hypothesis": "The clause always applies.",
        "evidence_packet": evidence,
        "packet_sha256": sha256_json(evidence),
        "gold_evidence_ids": ["span-1"],
        "gold_label": "Entailment",
        "assigned_target": "Contradiction",
    }


class SemanticCeilingTests(unittest.TestCase):
    def test_memory_quotes_oracle_evidence_verbatim_and_preserves_target(self) -> None:
        memory = semantic_ceiling_memory(case())
        self.assertEqual(
            memory["source_grounding"],
            [{"evidence_id": "span-1", "verbatim_source_text": case()["evidence_packet"][0]["text"]}],
        )
        self.assertEqual(memory["explicit_recommendation"], "Contradiction")
        self.assertIn("qualification", memory["analysis"])

    def test_view_is_blinded_except_explicit_ceiling_recommendation(self) -> None:
        view = semantic_ceiling_view(case())
        assert_blinded_downstream_view(view, ceiling=True)
        rendered = str(view).lower()
        self.assertNotIn("gold_label", rendered)
        self.assertNotIn("assigned_target", rendered)
        self.assertNotIn("producer_trust", rendered)

    def test_analysis_passes_only_for_responsive_semantic_ceiling(self) -> None:
        records = []
        for index in range(10):
            target = "Contradiction"
            common = {
                "case_id": f"case-{index}",
                "cluster_id": f"doc-{index // 2}",
                "downstream_id": "d",
                "seed": 7,
                "assigned_target": target,
                "gold_label": "Entailment",
                "terminal_status": "completed",
            }
            records.extend(
                [
                    common | {"arm_id": "E_evidence_only", "label": "Entailment"},
                    common
                    | {
                        "arm_id": "C_explicit_recommendation_ceiling",
                        "label": "Entailment",
                    },
                    common | {"arm_id": "C_max_semantic", "label": target},
                ]
            )
        result = analyze_semantic_ceiling_records(
            records, seed=7, bootstrap_samples=100
        )
        self.assertTrue(result["responsiveness_gate_pass"])
        self.assertEqual(result["C_max_semantic_minus_E"]["toward_target"], 10)
        self.assertEqual(result["C_max_semantic_minus_E"]["point"], 1.0)


if __name__ == "__main__":
    unittest.main()
