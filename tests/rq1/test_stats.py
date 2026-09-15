from __future__ import annotations

import unittest

from agentmembrane.rq1.schema import (
    ArtifactCondition,
    AttackFamily,
    DecisionAction,
    DecisionPolicy,
    ExposureMode,
    FutureDecision,
    Label,
)
from agentmembrane.rq1.stats import OutcomeObservation, cluster_contrast


def _decision(label: Label, *, raw: bool = False) -> FutureDecision:
    return FutureDecision(
        action=DecisionAction.DECIDE,
        label=label,
        confidence=0.8,
        memory_ids_used=("m-1",),
        evidence_span_ids_used=("s-1",),
        used_raw_source=raw,
        short_rationale="Evidence supports this label.",
    )


class ClusterStatisticsTests(unittest.TestCase):
    def test_repetitions_do_not_inflate_document_cluster_count(self) -> None:
        observations: list[OutcomeObservation] = []
        for document in ("doc-1", "doc-2"):
            for replicate in range(3):
                observations.extend(
                    (
                        OutcomeObservation(
                            independence_id=document,
                            episode_id=f"{document}:h1",
                            attack_family=AttackFamily.OMISSION_TO_NOT_MENTIONED,
                            artifact_condition=ArtifactCondition.TARGETED_EXTRACTIVE,
                            exposure_mode=ExposureMode.PERSISTED_RETRIEVED,
                            decision_policy=DecisionPolicy.FORCED_LABEL,
                            target_label=Label.CONTRADICTION,
                            decision=_decision(Label.CONTRADICTION),
                            replicate_id=replicate,
                        ),
                        OutcomeObservation(
                            independence_id=document,
                            episode_id=f"{document}:h1",
                            attack_family=AttackFamily.OMISSION_TO_NOT_MENTIONED,
                            artifact_condition=ArtifactCondition.BALANCED,
                            exposure_mode=ExposureMode.PERSISTED_RETRIEVED,
                            decision_policy=DecisionPolicy.FORCED_LABEL,
                            target_label=Label.CONTRADICTION,
                            decision=_decision(Label.ENTAILMENT),
                            replicate_id=replicate,
                        ),
                    )
                )
        result = cluster_contrast(
            observations,
            treatment=ArtifactCondition.TARGETED_EXTRACTIVE,
            comparator=ArtifactCondition.BALANCED,
            attack_family=AttackFamily.OMISSION_TO_NOT_MENTIONED,
            exposure_mode=ExposureMode.PERSISTED_RETRIEVED,
            decision_policy=DecisionPolicy.FORCED_LABEL,
            metric="targeted_stress_success",
            bootstrap_repetitions=100,
            seed=7,
        )
        self.assertEqual(result.independent_cluster_n, 2)
        self.assertEqual(result.estimate, 1.0)
        self.assertEqual(result.ci_low, 1.0)
        self.assertEqual(result.ci_high, 1.0)

    def test_raw_source_target_decision_is_not_unsafe_commitment(self) -> None:
        safe = _decision(Label.CONTRADICTION, raw=True)
        unsafe = _decision(Label.CONTRADICTION, raw=False)
        self.assertFalse(safe.unsafe_target_commitment(Label.CONTRADICTION))
        self.assertTrue(unsafe.unsafe_target_commitment(Label.CONTRADICTION))


if __name__ == "__main__":
    unittest.main()
