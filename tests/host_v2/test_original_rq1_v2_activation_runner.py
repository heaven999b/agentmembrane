from __future__ import annotations

import importlib.util
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = REPO_ROOT / "tools/run_original_rq1_v2_activation.py"


def _module():
    spec = importlib.util.spec_from_file_location("original_rq1_v2_activation_runner", RUNNER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_smoke_schedule_is_paired_and_development_only() -> None:
    runner = _module()
    profile = runner.make_profile(
        model="gpt-5.4-mini",
        reasoning_effort="low",
        protocol_sha="a" * 64,
        implementation_sha="b" * 64,
    )
    tasks, rows = runner.build_rows(
        cluster_count=1,
        profile_id=profile.raw["profile_id"],
        protocol_sha="a" * 64,
    )
    assert len(tasks) == 5
    assert len(rows) == 10
    assert {row.condition_id for row, _ in rows} == set(runner.CONDITIONS)
    assert all(task.metadata["bank_id"] == "development" for task in tasks)
    for pair_id in {row.pair_id for row, _ in rows}:
        assert {
            row.condition_id for row, _ in rows if row.pair_id == pair_id
        } == set(runner.CONDITIONS)


def test_analysis_cannot_pass_or_identify_a_star_on_smoke() -> None:
    runner = _module()
    episodes = []
    for hazard_id in runner.ORIGINAL_RQ1_HAZARDS:
        for condition_id in runner.CONDITIONS:
            episodes.append(
                {
                    "condition_id": condition_id,
                    "family": hazard_id,
                    "failure_class": "none",
                    "planner_terminal_kind": "normal",
                    "attack_process": {"route_relevant_attempt_count": 1},
                    "oracle_result": {
                        "exact_unauthorized_side_effect": condition_id.endswith("M0")
                    },
                }
            )
    result = runner.analyze(episodes, cluster_count=1)
    assert result["activation_gate"]["evaluable"] is False
    assert result["activation_gate"]["components_passed"] is False
    assert result["g3_passed"] is False
    assert result["a_star_identifiable"] is False
