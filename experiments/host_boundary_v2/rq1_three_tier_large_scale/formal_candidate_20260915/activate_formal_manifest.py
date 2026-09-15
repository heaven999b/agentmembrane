"""Create the one formal manifest after every pre-run gate is activated.

The command performs no model or network calls.  It writes the manifest with
O_EXCL, so an existing registration is never overwritten or silently resumed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentmembrane.host_v2.rq1_collab_v1.audit import _write_new, canonical, strict_loads
from agentmembrane.host_v2.rq1_three_tier_formal_v1.contract import MODEL_PROFILES
from agentmembrane.host_v2.rq1_three_tier_formal_v1.gate import (
    assemble_formal_manifest,
    file_binding,
    manifest_source_bindings,
    validate_formal_manifest,
)


HERE = Path(__file__).resolve().parent
STUDY = HERE.parent
PROJECT = STUDY.parents[2]
MODELS = (PROJECT / "experiments/host_boundary_v2/rq1_collab_v1/"
          "live_readiness_20260907/implementations/"
          "rq1_contextual_attack_bounded_v5r2_pilot_20260910/models.json")
QUALIFIED = STUDY / "candidate_run_006/candidate-manifest.json"


def load(path: Path) -> dict:
    value = strict_loads(path.read_bytes())
    if type(value) is not dict:
        raise ValueError("formal_source_object_required")
    return value


def activate(args: argparse.Namespace) -> dict:
    identity = load(args.identity)
    pool = load(args.pool)
    candidate_analysis = load(args.candidate_analysis)
    governance = load(args.governance)
    final_analysis = load(args.final_analysis)
    h_contract = load(args.h_contract)
    final_qid = load(args.final_qid)
    route_binding = load(args.route_binding)
    runtime_qualification = load(args.runtime_qualification)
    sources = manifest_source_bindings(
        candidate_identity=args.identity,
        candidate_task_pool=args.pool,
        candidate_analysis=args.candidate_analysis,
        governance_decision=args.governance,
        final_analysis=args.final_analysis,
        H_output_contract=args.h_contract,
        final_QID=args.final_qid,
        route_runtime_binding=args.route_binding,
        runtime_qualification=args.runtime_qualification,
        model_profiles=args.models,
        qualified_manifest=args.qualified,
        final_goal_assignment=args.final_goals,
        goal_balance_candidate=args.goal_balance_candidate,
        canonical_proposal=PROJECT / "docs/PROPOSAL.md",
        formal_gate_runner=(PROJECT / "agentmembrane/host_v2/"
                            "rq1_three_tier_formal_v1/gate.py"),
        formal_activation_runner=Path(__file__).resolve(),
        statistical_review_decision=args.statistical_review,
        formal_evaluator_qualification=args.evaluator_qualification,
    )
    model_binding = file_binding(args.models)
    manifest = assemble_formal_manifest(
        identity=identity,
        pool=pool,
        candidate_analysis=candidate_analysis,
        governance=governance,
        final_analysis=final_analysis,
        h_contract=h_contract,
        final_qid=final_qid,
        route_binding=route_binding,
        runtime_qualification=runtime_qualification,
        model_source={
            "source_path": model_binding["path"],
            "source_sha256": model_binding["sha256"],
            "selected_profiles": MODEL_PROFILES,
        },
        source_bindings=sources,
    )
    validate_formal_manifest(manifest)
    _write_new(args.output.resolve(), canonical(manifest) + b"\n")
    return {
        "manifest": str(args.output.resolve()),
        "manifest_sha256": manifest["manifest_sha256"],
        "task_count": manifest["task_count"],
        "condition_count": manifest["condition_count"],
        "formal_ready": True,
        "formal_activation": True,
        "research_sample_count_at_registration": 0,
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
    parser.add_argument("--governance", type=Path,
                        default=HERE / "governance-decision.json")
    parser.add_argument("--final-analysis", type=Path,
                        default=HERE / "final-statistical-analysis-plan.json")
    parser.add_argument("--statistical-review", type=Path,
                        default=HERE / "statistical-review-decision.json")
    parser.add_argument("--final-goals", type=Path,
                        default=HERE / "final-goal-assignment.json")
    parser.add_argument("--goal-balance-candidate", type=Path,
                        default=HERE / "goal-balance-candidate.json")
    parser.add_argument("--h-contract", type=Path,
                        default=HERE / "H-output-contract-final-assignment.json")
    parser.add_argument("--final-qid", type=Path,
                        default=(STUDY / "qid_formal_adjudication_20260915/"
                                 "final-adjudication.json"))
    parser.add_argument("--route-binding", type=Path,
                        default=HERE / "route-runtime-binding.json")
    parser.add_argument("--runtime-qualification", type=Path,
                        default=HERE / "formal-runtime-qualification.json")
    parser.add_argument("--evaluator-qualification", type=Path,
                        default=HERE / "formal-evaluator-qualification.json")
    parser.add_argument("--models", type=Path, default=MODELS)
    parser.add_argument("--qualified", type=Path, default=QUALIFIED)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = activate(args)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
