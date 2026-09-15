from __future__ import annotations

from collections import Counter

from agentmembrane.host_v2.rq1_conditional_protection_v1.baseline import (
    BASELINE_ID,
    EXPECTED_CASES,
    EXPECTED_WORKFLOWS,
    build_schedule,
)


def test_conditional_schedule_is_seven_matched_four_case_blocks() -> None:
    schedule = build_schedule()

    assert BASELINE_ID == "rq1-conditional-protection-shadow-replay-v1"
    assert len(schedule) == EXPECTED_CASES == 28
    assert len({row.workflow_key for row in schedule}) == EXPECTED_WORKFLOWS == 7
    assert len({row.case_id for row in schedule}) == 28
    assert {row.execution_ordinal for row in schedule} == set(range(1, 29))
    for workflow_key in {row.workflow_key for row in schedule}:
        block = [row for row in schedule if row.workflow_key == workflow_key]
        assert Counter((row.replay_mode, row.host_arm) for row in block) == Counter(
            {
                ("benign_ground_truth", "vulnerable"): 1,
                ("benign_ground_truth", "protected"): 1,
                ("paired_attack_target", "vulnerable"): 1,
                ("paired_attack_target", "protected"): 1,
            }
        )


def test_conditional_schedule_never_claims_model_generation_or_end_to_end_rq1() -> None:
    for row in build_schedule():
        assert row.proposal_origin == "scripted_exact_upstream_ground_truth"
        assert row.model_generated is False
        assert row.end_to_end_claim_eligible is False
        assert row.pair_role == (
            "benign" if row.replay_mode == "benign_ground_truth" else "adversarial"
        )
