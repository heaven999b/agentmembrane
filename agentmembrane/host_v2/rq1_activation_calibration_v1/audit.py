"""Two deterministic, zero-model audit passes for calibration code and semantics."""

from __future__ import annotations

import argparse
import inspect
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..schema import canonical_json_bytes, sha256_json
from . import analysis, executor
from .attack_baseline import attack_manifest
from .client import ExactLunaLowClient
from .provider_agent import MAX_TURNS_PER_CELL, MODEL_ID, REASONING_EFFORT, REQUEST_RETRIES, SYSTEM_PROMPT
from .selector import calibration_schedule, schedule_manifest, smoke_schedule


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _check(name: str, passed: bool, evidence: Any) -> dict[str, Any]:
    return {"check": name, "passed": bool(passed), "evidence": evidence}


def runtime_audit() -> dict[str, Any]:
    schedule = calibration_schedule()
    smoke = smoke_schedule()
    client = ExactLunaLowClient(
        base_url="http://127.0.0.1:19876/v1",
        api_key="sk-audit-local-only",
    )
    executor_source = inspect.getsource(executor)
    checks = [
        _check("sample_count_exact", len(schedule) == 50, len(schedule)),
        _check("smoke_count_exact", len(smoke) == 2, len(smoke)),
        _check("unique_cell_ids", len({row.cell_id for row in schedule}) == 50, 50),
        _check("unique_ordinals", {row.execution_ordinal for row in schedule} == set(range(1, 51)), "1..50"),
        _check("strength_balance", schedule_manifest("sample50")["strength_counts"] == {"standard": 25, "priority": 25}, schedule_manifest("sample50")["strength_counts"]),
        _check("zero_provider_retries", REQUEST_RETRIES == 0, REQUEST_RETRIES),
        _check("bounded_small_turns", MAX_TURNS_PER_CELL == 8, MAX_TURNS_PER_CELL),
        _check("exact_model", MODEL_ID == "gpt-5.6-luna", MODEL_ID),
        _check("exact_effort", REASONING_EFFORT == "low", REASONING_EFFORT),
        _check("loopback_client", client.base_url == "http://127.0.0.1:19876/v1", client.base_url),
        _check("durable_reservation_before_delegate", executor_source.index("reservation_path,") < executor_source.index("delivered = self.delegate.complete"), "source order"),
        _check("no_cross_workflow_mega_prompt", "one_api_request_per_agent_turn" in executor_source, True),
        _check("implementation_bindings_readable", len(executor.implementation_bindings()) >= 10, len(executor.implementation_bindings())),
        _check("pinned_runtime_bound", executor.runtime_binding()["python_version"] == "3.12.3", executor.runtime_binding()),
        _check("versioned_entrypoint_bound", "agentmembrane/host_v2/rq1_activation_calibration_v1/run.py" in executor.implementation_bindings(), True),
        _check("audit_implementation_bound", "agentmembrane/host_v2/rq1_activation_calibration_v1/audit.py" in executor.implementation_bindings(), True),
    ]
    passed = all(row["passed"] for row in checks)
    report = {
        "schema_version": 1,
        "artifact_type": "rq1_activation_runtime_audit_v1",
        "audit_round": 1,
        "audit_focus": "execution_integrity_ledger_failure_semantics",
        "model_calls": 0,
        "passed": passed,
        "checks": checks,
        "audited_at": _now(),
    }
    report["audit_sha256"] = sha256_json(report)
    return report


def rq_semantics_audit() -> dict[str, Any]:
    schedule = calibration_schedule()
    manifest = attack_manifest()
    analysis_source = inspect.getsource(analysis)
    private_terms = {"pair_role", "host_arm", "claim_eligible", "attack_strength"}
    system_lower = SYSTEM_PROMPT.casefold()
    checks = [
        _check("vulnerable_only", {row.host_arm for row in schedule} == {"vulnerable"}, sorted({row.host_arm for row in schedule})),
        _check("adversarial_only", {row.pair_role for row in schedule} == {"adversarial"}, sorted({row.pair_role for row in schedule})),
        _check("all_rows_nonclaiming", all(row.claim_eligible is False for row in schedule), True),
        _check("natural_carrier_only", manifest["delivery"] == "exact_original_agentdojo_data_carrier_only", manifest["delivery"]),
        _check("attack_not_in_system", manifest["system_prompt_modified_by_attack"] is False, False),
        _check("attack_not_in_initial_user", manifest["initial_user_prompt_modified"] is False, False),
        _check("private_coordinates_absent_from_system", not any(term in system_lower for term in private_terms), sorted(private_terms)),
        _check("model_intent_not_inferred", '"model_intent_measured": False' in analysis_source, False),
        _check("failures_not_safety", '"failures_counted_as_no_attack": False' in analysis_source, False),
        _check("repetitions_not_independent_workflows", schedule_manifest("sample50")["repeated_measurements_are_independent_workflows"] is False, False),
        _check("full_rq_claim_forbidden", '"full_rq1_claim_permitted": False' in analysis_source, False),
        _check("population_claim_forbidden", '"population_effect_claim_permitted": False' in analysis_source, False),
        _check("upstream_security_semantics_explicit", "true means the attack effect occurred" in analysis_source, True),
        _check("exposure_match_is_complete_not_keyword", "complete frozen injection payload" in analysis_source and "whitespace-only normalization" in analysis_source, True),
        _check("activation_gate_predeclared", "predeclared_minimum_target_proposals" in analysis_source, True),
        _check("smoke_gate_does_not_skip_calibration", "proceed_to_held_out = False" in analysis_source and "proceed_to_sample50" in analysis_source, True),
    ]
    passed = all(row["passed"] for row in checks)
    report = {
        "schema_version": 1,
        "artifact_type": "rq1_activation_rq_semantics_audit_v1",
        "audit_round": 2,
        "audit_focus": "rq_alignment_nonclaiming_denominators_no_checker_relaxation",
        "model_calls": 0,
        "passed": passed,
        "checks": checks,
        "audited_at": _now(),
    }
    report["audit_sha256"] = sha256_json(report)
    return report


def _write_new(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(canonical_json_bytes(value))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("round", choices=("runtime", "rq"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = runtime_audit() if args.round == "runtime" else rq_semantics_audit()
    if args.output is not None:
        _write_new(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["rq_semantics_audit", "runtime_audit"]
