"""Compile the immutable H contract from the reviewed final goal assignment.

This command performs only local source loading and contract compilation.  It
does not call a model, contact CLIProxy, allocate a cell, or activate the study.
The output path must not exist, which prevents a reviewed H contract from being
silently replaced after Q/I/D adjudication starts.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentmembrane.host_v2.rq1_collab_v1.audit import _write_new, canonical
from agentmembrane.host_v2.rq1_three_tier_formal_v1.gate import (
    build_h_output_contract,
    validate_h_output_contract,
)


HERE = Path(__file__).resolve().parent
STUDY = HERE.parent
PROJECT = STUDY.parents[2]
LIVE = PROJECT / "experiments/host_boundary_v2/rq1_collab_v1/live_readiness_20260907"
DEFAULT_MODELS = (
    LIVE / "implementations/rq1_contextual_attack_bounded_v5r2_pilot_20260910/"
    "models.json"
)
DEFAULT_QUALIFIED = STUDY / "candidate_run_006/candidate-manifest.json"


def build(args: argparse.Namespace) -> dict:
    contract = build_h_output_contract(
        identity_path=args.identity,
        pool_path=args.pool,
        analysis_path=args.candidate_analysis,
        qualified_path=args.qualified,
        goal_assignments_path=args.final_goals,
        models_path=args.models,
    )
    validate_h_output_contract(contract)
    if contract["goal_assignment_formal_activation"] is not True:
        raise ValueError("reviewed_final_goal_assignment_required")
    _write_new(args.output.resolve(), canonical(contract) + b"\n")
    return {
        "H_contract": str(args.output.resolve()),
        "H_contract_sha256": contract["H_contract_sha256"],
        "task_count": contract["task_count"],
        "condition_invariance_checks": sum(
            row["H_output_contract"]["condition_count_checked"]
            for row in contract["tasks"]
        ),
        "goal_cluster_count": len({
            row["goal_cluster_id"] for row in contract["tasks"]
        }),
        "formal_study_activated": False,
        "research_sample_count": 0,
        "model_calls": 0,
        "api_calls": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity", type=Path,
                        default=HERE / "study-identity.json")
    parser.add_argument("--pool", type=Path, default=HERE / "task-pool.json")
    parser.add_argument("--candidate-analysis", type=Path,
                        default=HERE / "statistical-analysis-plan.json")
    parser.add_argument("--final-goals", type=Path,
                        default=HERE / "final-goal-assignment.json")
    parser.add_argument("--qualified", type=Path, default=DEFAULT_QUALIFIED)
    parser.add_argument("--models", type=Path, default=DEFAULT_MODELS)
    parser.add_argument("--output", type=Path,
                        default=HERE / "H-output-contract-final-assignment.json")
    args = parser.parse_args()
    print(json.dumps(build(args), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
