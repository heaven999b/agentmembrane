"""Build zero-sample formal gate artifacts from explicit, bound inputs.

The command performs no model or network calls. Route, attestation, runtime,
canary, and private candidate inputs have no machine-local defaults: callers
must name every one on the command line. Outputs are create-only so a failed
or repeated invocation cannot overwrite an existing registration artifact.
The generated preflight reports each gate independently.  The public runner
now owns and seals the per-cell proxy start/readiness/run/stop/secret-cleanup
lifecycle; activation remains blocked until every scientific and evaluator
contract is also frozen and qualified.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import tempfile

from agentmembrane.host_v2.rq1_collab_v1.audit import _write_new, canonical
from agentmembrane.host_v2.rq1_three_tier_formal_v1.gate import (
    build_h_output_contract,
    build_route_runtime_binding,
    preflight_status,
    validate_h_output_contract,
    validate_route_runtime_binding,
)


HERE = Path(__file__).resolve().parent
STUDY = HERE.parent


@dataclass(frozen=True)
class GateInputs:
    identity: Path
    pool: Path
    candidate_analysis: Path
    qualified: Path
    goal_assignments: Path
    goal_balance_candidate: Path
    models: Path
    route: Path
    attestation: Path
    lifecycle_runner: Path
    cli_proxy_binary: Path
    canary: Path
    canary_verification: Path
    governance: Path
    final_analysis: Path
    final_goals: Path
    final_qid: Path
    runtime_qualification: Path
    evaluator_qualification: Path
    h_output: Path
    route_binding_output: Path
    preflight_output: Path


def _required_regular(path: Path, label: str) -> Path:
    """Resolve one required input without accepting symlink indirection."""
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"required_input_missing_or_not_regular:{label}")
    return path.resolve(strict=True)


def _new_output(path: Path, label: str) -> Path:
    """Require an existing parent and a path that has never been materialized."""
    if path.is_symlink() or path.exists():
        raise ValueError(f"output_already_exists:{label}")
    parent = path.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ValueError(f"output_parent_not_directory:{label}")
    return parent / path.name


def _validated_paths(inputs: GateInputs) -> tuple[dict[str, Path], dict[str, Path]]:
    required = {
        "identity": inputs.identity,
        "pool": inputs.pool,
        "candidate_analysis": inputs.candidate_analysis,
        "qualified": inputs.qualified,
        "goal_assignments": inputs.goal_assignments,
        "goal_balance_candidate": inputs.goal_balance_candidate,
        "models": inputs.models,
        "route": inputs.route,
        "attestation": inputs.attestation,
        "lifecycle_runner": inputs.lifecycle_runner,
        "cli_proxy_binary": inputs.cli_proxy_binary,
        "canary": inputs.canary,
        "canary_verification": inputs.canary_verification,
    }
    resolved_inputs = {
        label: _required_regular(path, label)
        for label, path in required.items()
    }
    outputs = {
        "h_output": _new_output(inputs.h_output, "h_output"),
        "route_binding_output": _new_output(
            inputs.route_binding_output, "route_binding_output"),
        "preflight_output": _new_output(inputs.preflight_output, "preflight_output"),
    }
    if len(set(outputs.values())) != len(outputs):
        raise ValueError("formal_gate_output_paths_must_be_distinct")
    return resolved_inputs, outputs


def build(inputs: GateInputs) -> dict:
    """Validate every bound input, then create three zero-sample artifacts."""
    source, outputs = _validated_paths(inputs)
    h_contract = build_h_output_contract(
        identity_path=source["identity"],
        pool_path=source["pool"],
        analysis_path=source["candidate_analysis"],
        qualified_path=source["qualified"],
        goal_assignments_path=source["goal_assignments"],
        models_path=source["models"],
    )
    validate_h_output_contract(h_contract)

    route_binding = build_route_runtime_binding(
        route_path=source["route"],
        attestation_path=source["attestation"],
        lifecycle_runner_path=source["lifecycle_runner"],
        cli_proxy_binary_path=source["cli_proxy_binary"],
        canary_path=source["canary"],
        canary_verification_path=source["canary_verification"],
    )
    validate_route_runtime_binding(route_binding)

    # preflight_status consumes files. Use private temporary bindings first so
    # no caller-selected output is created until every builder returns.
    with tempfile.TemporaryDirectory(prefix="rq1-formal-gate-") as temporary:
        temporary_root = Path(temporary)
        temporary_h = temporary_root / "H-output-contract.json"
        temporary_route = temporary_root / "route-runtime-binding.json"
        temporary_h.write_bytes(canonical(h_contract) + b"\n")
        temporary_route.write_bytes(canonical(route_binding) + b"\n")
        preflight = preflight_status(
            candidate_identity_path=source["identity"],
            candidate_pool_path=source["pool"],
            candidate_analysis_path=source["candidate_analysis"],
            goal_balance_candidate_path=source["goal_balance_candidate"],
            h_contract_path=temporary_h,
            route_binding_path=temporary_route,
            final_goal_assignment_path=inputs.final_goals,
            governance_path=inputs.governance,
            final_analysis_path=inputs.final_analysis,
            final_qid_path=inputs.final_qid,
            evaluator_qualification_path=inputs.evaluator_qualification,
            runtime_qualification_path=inputs.runtime_qualification,
        )

    for value, path in (
        (h_contract, outputs["h_output"]),
        (route_binding, outputs["route_binding_output"]),
        (preflight, outputs["preflight_output"]),
    ):
        _write_new(path, canonical(value) + b"\n")

    return {
        "outputs": {name: str(path) for name, path in outputs.items()},
        "H_task_count": h_contract["task_count"],
        "H_condition_invariance_checks": sum(
            row["H_output_contract"]["condition_count_checked"]
            for row in h_contract["tasks"]
        ),
        "current_goal_cluster_count": len(
            {row["goal_cluster_id"] for row in h_contract["tasks"]}
        ),
        "route_binding_valid": True,
        "blocking_gates": preflight["blocking_gates"],
        "formal_ready": False,
        "formal_manifest_created": False,
        "research_sample_count": 0,
        "model_calls": 0,
        "api_calls": 0,
    }


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    command.add_argument("--identity", type=Path, default=HERE / "study-identity.json")
    command.add_argument("--pool", type=Path, default=HERE / "task-pool.json")
    command.add_argument(
        "--candidate-analysis", type=Path,
        default=HERE / "statistical-analysis-plan.json",
    )
    command.add_argument(
        "--goal-balance-candidate", type=Path,
        default=HERE / "goal-balance-candidate.json",
    )
    for name in (
        "qualified", "goal-assignments", "models", "route", "attestation",
        "lifecycle-runner", "cli-proxy-binary", "canary",
        "canary-verification", "h-output", "route-binding-output",
        "preflight-output",
    ):
        command.add_argument("--" + name, type=Path, required=True)
    command.add_argument("--governance", type=Path,
                         default=HERE / "governance-decision.json")
    command.add_argument("--final-analysis", type=Path,
                         default=HERE / "final-statistical-analysis-plan.json")
    command.add_argument("--final-goals", type=Path,
                         default=HERE / "final-goal-assignment.json")
    command.add_argument(
        "--final-qid", type=Path,
        default=STUDY / "qid_formal_adjudication_20260915/final-adjudication.json",
    )
    command.add_argument("--runtime-qualification", type=Path,
                         default=(HERE /
                                  "formal-runtime-qualification-private-v2-20260916.json"))
    command.add_argument("--evaluator-qualification", type=Path,
                         default=HERE / "formal-evaluator-qualification.json")
    return command


def parse_args(argv: list[str] | None = None) -> GateInputs:
    return GateInputs(**vars(parser().parse_args(argv)))


def main(argv: list[str] | None = None) -> int:
    print(json.dumps(build(parse_args(argv)), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
