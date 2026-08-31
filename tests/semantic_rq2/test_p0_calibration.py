from __future__ import annotations

import unittest

from agentmembrane.semantic_rq2.p0_calibration import (
    NEUTRAL_P0_DOWNSTREAM_SYSTEM,
    assert_neutral_p0_prompt,
    neutral_p0_prompt,
    neutral_p0_view,
)
from agentmembrane.semantic_rq2.prompts import assert_blinded_downstream_view
from agentmembrane.semantic_rq2.schema import Receptor, sha256_json


def case() -> dict:
    evidence = [{"id": "span-1", "text": "A clause."}]
    return {
        "case_id": "case-1",
        "hypothesis": "The clause applies.",
        "evidence_packet": evidence,
        "packet_sha256": sha256_json(evidence),
        "assigned_target": "Contradiction",
    }


def artifact() -> dict:
    return {
        "artifact_id": "oa-1",
        "case_id": "case-1",
        "receptor": Receptor.R3.value,
        "payload": {
            "evidence_ids": ["span-1"],
            "inference": "A clause applies.",
            "uncertainty": "low",
            "conclusion": "The hypothesis is contradicted.",
            "recommendation": "Choose Contradiction.",
        },
    }


class NeutralP0CalibrationTests(unittest.TestCase):
    def test_memory_payload_is_identical_without_trust_cue(self) -> None:
        value = neutral_p0_view(case(), artifact())
        self.assertEqual(value["persistent_memory"], [{"payload": artifact()["payload"]}])
        self.assertNotIn("producer_trust", str(value))
        assert_blinded_downstream_view(value)

    def test_ceiling_content_keeps_recommendation_without_trust_cue(self) -> None:
        value = neutral_p0_view(case(), None, ceiling_target="Contradiction")
        self.assertEqual(value["persistent_memory"][0]["explicit_recommendation"], "Contradiction")
        self.assertNotIn("producer_trust", str(value))
        assert_blinded_downstream_view(value, ceiling=True)

    def test_prompt_has_no_untrusted_provenance_warning(self) -> None:
        user = neutral_p0_prompt(case(), artifact())
        assert_neutral_p0_prompt(NEUTRAL_P0_DOWNSTREAM_SYSTEM, user)
        self.assertNotIn("untrusted", (NEUTRAL_P0_DOWNSTREAM_SYSTEM + user).lower())


if __name__ == "__main__":
    unittest.main()
