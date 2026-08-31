from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agentmembrane.semantic_rq2.manifest import public_case, validate_manifest
from agentmembrane.semantic_rq2.prompts import (
    assert_blinded_audit_view,
    assert_blinded_downstream_view,
    audit_view,
    downstream_view,
)
from agentmembrane.semantic_rq2.schema import Receptor, validate_artifact
from tests.semantic_rq2.fixtures import write_synthetic_manifest


def artifact(case: dict, receptor: Receptor) -> dict:
    evidence_id = case["evidence_packet"][0]["id"]
    payloads = {
        Receptor.R0: {"evidence_ids": [evidence_id]},
        Receptor.R1: {
            "evidence_ids": [evidence_id],
            "annotations": [
                {"evidence_id": evidence_id, "relevance": 0.8, "confidence": "high"}
            ],
        },
        Receptor.R2: {
            "evidence_ids": [evidence_id],
            "inference": "The selected clause bears on the hypothesis.",
            "uncertainty": "medium",
        },
        Receptor.R3: {
            "evidence_ids": [evidence_id],
            "inference": "The selected clause bears on the hypothesis.",
            "uncertainty": "medium",
            "conclusion": "The condition is material.",
            "recommendation": "Use the condition in the final decision.",
        },
        Receptor.R4: {"artifact_text": "A source-grounded free-form report."},
    }
    return {
        "artifact_id": "opaque-123",
        "case_id": case["case_id"],
        "receptor": receptor.value,
        "payload": payloads[receptor],
    }


class ManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()
        manifest_path = write_synthetic_manifest(Path(cls.temp_dir.name))
        cls.manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir.cleanup()

    def test_canonical_manifest_is_exactly_200_cases_100_clusters(self) -> None:
        check = validate_manifest(self.manifest, exact_baseline_shape=True)
        self.assertTrue(check["valid"], check["problems"])
        self.assertEqual(check["case_n"], 200)
        self.assertEqual(check["cluster_n"], 100)
        self.assertEqual(check["label_counts"], {"Entailment": 100, "Contradiction": 100})

    def test_every_packet_retains_all_gold_and_is_source_ordered(self) -> None:
        for case in self.manifest["cases"]:
            packet_ids = {row["id"] for row in case["evidence_packet"]}
            self.assertTrue(set(case["gold_evidence_ids"]).issubset(packet_ids))
            indices = [row["source_span_index"] for row in case["evidence_packet"]]
            self.assertEqual(indices, sorted(indices))

    def test_public_case_has_no_gold_or_target(self) -> None:
        visible = public_case(self.manifest["cases"][0])
        self.assertFalse({"gold_label", "assigned_target", "mode", "arm"} & set(visible))


class ReceptorSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp_dir = tempfile.TemporaryDirectory()
        manifest_path = write_synthetic_manifest(Path(cls.temp_dir.name))
        cls.case = json.loads(manifest_path.read_text(encoding="utf-8"))["cases"][0]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp_dir.cleanup()

    def test_complete_r0_to_r4_schemas_validate(self) -> None:
        candidate_ids = [row["id"] for row in self.case["evidence_packet"]]
        for receptor in Receptor:
            result = validate_artifact(
                artifact(self.case, receptor),
                candidate_evidence_ids=candidate_ids,
                expected_case_id=self.case["case_id"],
                expected_receptor=receptor,
            )
            self.assertTrue(result.deterministic_valid, (receptor, result.problems))

    def test_lower_receptor_rejects_higher_semantic_field(self) -> None:
        value = artifact(self.case, Receptor.R0)
        value["payload"]["recommendation"] = "Choose Contradiction"
        result = validate_artifact(
            value,
            candidate_evidence_ids=[row["id"] for row in self.case["evidence_packet"]],
            expected_case_id=self.case["case_id"],
            expected_receptor=Receptor.R0,
        )
        self.assertFalse(result.deterministic_valid)
        self.assertTrue(any("extra_payload_fields" in problem for problem in result.problems))

    def test_envelope_case_mismatch_is_rejected(self) -> None:
        value = artifact(self.case, Receptor.R0)
        value["case_id"] = "wrong-case"
        result = validate_artifact(
            value,
            candidate_evidence_ids=[row["id"] for row in self.case["evidence_packet"]],
            expected_case_id=self.case["case_id"],
            expected_receptor=Receptor.R0,
        )
        self.assertFalse(result.deterministic_valid)
        self.assertIn("case_id_mismatch", result.problems)

    def test_envelope_artifact_id_mismatch_is_rejected(self) -> None:
        value = artifact(self.case, Receptor.R0)
        result = validate_artifact(
            value,
            candidate_evidence_ids=[row["id"] for row in self.case["evidence_packet"]],
            expected_case_id=self.case["case_id"],
            expected_artifact_id="different-opaque-id",
            expected_receptor=Receptor.R0,
        )
        self.assertFalse(result.deterministic_valid)
        self.assertIn("artifact_id_mismatch", result.problems)

    def test_r3_and_r4_answer_semantics_are_intentionally_permitted(self) -> None:
        candidate_ids = [row["id"] for row in self.case["evidence_packet"]]
        for receptor in (Receptor.R3, Receptor.R4):
            result = validate_artifact(
                artifact(self.case, receptor),
                candidate_evidence_ids=candidate_ids,
                expected_receptor=receptor,
            )
            self.assertTrue(result.explicit_answer_permitted)

    def test_audit_and_downstream_views_are_blind(self) -> None:
        value = artifact(self.case, Receptor.R2)
        audit_payload = audit_view(self.case, value)
        assert_blinded_audit_view(audit_payload)
        self.assertNotIn("assigned_target", json.dumps(audit_payload))
        self.assertNotIn(self.case["case_id"], json.dumps(audit_payload))
        decision_payload = downstream_view(self.case, value)
        assert_blinded_downstream_view(decision_payload)
        self.assertNotIn("assigned_target", json.dumps(decision_payload))
        memory = decision_payload["persistent_memory"][0]
        self.assertEqual(set(memory), {"producer_trust", "payload"})
        self.assertNotIn("receptor", json.dumps(decision_payload))
        self.assertNotIn(self.case["case_id"], json.dumps(decision_payload))


if __name__ == "__main__":
    unittest.main()
