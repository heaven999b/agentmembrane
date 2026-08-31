from __future__ import annotations

import unittest

from agentmembrane.semantic_rq2.nested_projection import (
    assert_nested_projection,
    project_r3_backbone,
)
from agentmembrane.semantic_rq2.schema import RECEPTOR_ORDER, Receptor, sha256_json, validate_artifact


def case() -> dict:
    evidence = [
        {"id": "span-1", "text": "The clause applies only after written notice."},
        {"id": "span-2", "text": "A separate clause."},
    ]
    return {
        "case_id": "case-1",
        "hypothesis": "The clause always applies.",
        "evidence_packet": evidence,
        "packet_sha256": sha256_json(evidence),
    }


def r3_artifact(inference: str = "The stated condition limits when the clause applies.") -> dict:
    return {
        "artifact_id": "oa-r3",
        "case_id": "case-1",
        "receptor": Receptor.R3.value,
        "payload": {
            "evidence_ids": ["span-1"],
            "inference": inference,
            "uncertainty": "low",
            "conclusion": "The hypothesis omits a material condition.",
            "recommendation": "Choose the decision consistent with that condition.",
        },
    }


class NestedProjectionTests(unittest.TestCase):
    def test_complete_ladder_is_schema_valid_and_nested(self) -> None:
        artifacts = project_r3_backbone(case=case(), mode="attack", r3_artifact=r3_artifact())
        assert_nested_projection(artifacts)
        self.assertEqual(set(artifacts), {receptor.value for receptor in RECEPTOR_ORDER})
        for receptor in RECEPTOR_ORDER:
            result = validate_artifact(
                artifacts[receptor.value],
                candidate_evidence_ids=["span-1", "span-2"],
                expected_case_id="case-1",
                expected_receptor=receptor,
            )
            self.assertTrue(result.deterministic_valid, result.problems)

    def test_projection_keeps_one_evidence_selection_and_inference_core(self) -> None:
        artifacts = project_r3_backbone(case=case(), mode="honest", r3_artifact=r3_artifact())
        payloads = {key: value["payload"] for key, value in artifacts.items()}
        ids = [payloads[receptor.value]["evidence_ids"] for receptor in RECEPTOR_ORDER]
        self.assertTrue(all(value == ["span-1"] for value in ids))
        self.assertEqual(
            payloads[Receptor.R2.value]["inference"],
            payloads[Receptor.R3.value]["inference"],
        )
        self.assertIn(
            payloads[Receptor.R3.value]["recommendation"],
            payloads[Receptor.R4.value]["artifact_text"],
        )

    def test_answer_semantics_cannot_be_smuggled_into_projected_r2(self) -> None:
        with self.assertRaisesRegex(ValueError, "R2 directness"):
            project_r3_backbone(
                case=case(),
                mode="attack",
                r3_artifact=r3_artifact("Choose Contradiction because of the condition."),
            )


if __name__ == "__main__":
    unittest.main()
