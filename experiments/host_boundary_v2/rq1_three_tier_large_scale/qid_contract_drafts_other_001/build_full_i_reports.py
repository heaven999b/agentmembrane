"""Freeze full candidate I compilation and one sealed replay for all 22 tasks."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys


PROJECT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(PROJECT))

from agentmembrane.host_v2.rq1_collab_v1.native import NativeTask, digest
from agentmembrane.host_v2.rq1_collab_v6.evaluation import read_evidence
from agentmembrane.host_v2.rq1_measurement_v1.qid_other_information_full import (
    compile_full_candidate_contract, evaluate_full_candidate_information,
)


HERE = Path(__file__).resolve().parent
SOURCE = Path(os.environ.get(
    "AGENTDOJO_SOURCE_ROOT",
    str(PROJECT / "data/host_boundary_v2/upstream/agentdojo"),
))
CAMPAIGN = Path(os.environ.get(
    "RQ1_DIAGNOSTIC_RUNS_ROOT",
    str(HERE.parent / "live_campaign_002/runs"),
))
COMPILE_OUTPUT = HERE / "full_i_candidate_compile_001/report.json"
REPLAY_OUTPUT = HERE / "full_i_sealed_replay_001/report.json"
TESTS = {
    "full_I_unit_test_methods": 6,
    "fake_live_module_test_methods": 2,
    "fake_live_full_I_integration_test_methods": 1,
    "total_executed": 8,
    "command": (
        "python -m unittest "
        "tests.rq1_three_tier.test_qid_other_information_full "
        "tests.test_rq1_collab_v6_slack0_live_fake_transport"
    ),
}


def _write_atomic(path: Path, value: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                    indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _rank(path: Path) -> tuple:
    name = path.parents[2].name
    return ("-honest-" not in name,
            next((index for index, level in enumerate(
                ("-low-", "-medium-", "-high-")) if level in name), 3),
            name)


def _source_hashes() -> dict:
    paths = {
        "qid_other_information_full.py": PROJECT /
            "agentmembrane/host_v2/rq1_measurement_v1/qid_other_information_full.py",
        "information.py": PROJECT /
            "agentmembrane/host_v2/rq1_measurement_v1/information.py",
        "qid_registration.py": PROJECT /
            "agentmembrane/host_v2/rq1_collab_v6/qid_registration.py",
        "measurement.py": PROJECT /
            "agentmembrane/host_v2/rq1_collab_v6/measurement.py",
    }
    return {name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in paths.items()}


def main() -> None:
    package = json.loads((HERE / "drafts.json").read_text(encoding="utf-8"))
    task_keys = [row["task_key"] for row in package["tasks"]]
    if len(task_keys) != 22 or len(task_keys) != len(set(task_keys)):
        raise ValueError("exact_22_unique_other_tasks_required")
    compile_rows = []
    for task_key in task_keys:
        suite, task_id = task_key.split("/", 1)
        native = NativeTask(str(SOURCE), suite, task_id)
        contract, facts = compile_full_candidate_contract(
            task_key, native.snapshot(), native.record)
        compile_rows.append({
            "task_key": task_key,
            "source_initial_state_sha256": native.record["initial_state_sha256"],
            "field_count": contract["counts"]["I_field_count"],
            "recipient_count": contract["counts"]["R"],
            "recipient_ids": contract["recipients"],
            "raw_fact_recipient_cells": contract["counts"]["raw_fact_recipient_cells"],
            "legal_cells_excluded": contract["counts"]["legal_cells_excluded"],
            "I_cells": contract["counts"]["I_cells"],
            "legal_role_fact_paths": contract["legal_role_fact_paths"],
            "legal_native_fact_recipient_cells": contract[
                "legal_native_fact_recipient_cells"],
            "ambiguous_equal_value_fact_count": contract["counts"]
                ["ambiguous_equal_value_fact_count"],
            "intrinsically_unobservable_fact_count": contract["counts"]
                ["intrinsically_unobservable_fact_count"],
            "unknown_regions": contract["unknown_regions"],
            "candidate_contract_sha256": contract["contract_sha256"],
            "private_facts_sha256": digest(facts),
            "formal_blockers": contract["formal_blockers"],
            "formal_activation": False,
        })
    compile_report = {
        "schema_version": "rq1-qid-other-full-I-compile-report/1",
        "status": "pre_outcome_full_candidate_denominator_not_formal",
        "task_count": len(compile_rows),
        "task_keys": task_keys,
        "aggregate_counts": {
            "field_instances": sum(row["field_count"] for row in compile_rows),
            "raw_fact_recipient_cells": sum(
                row["raw_fact_recipient_cells"] for row in compile_rows),
            "legal_cells_excluded": sum(
                row["legal_cells_excluded"] for row in compile_rows),
            "I_cells": sum(row["I_cells"] for row in compile_rows),
            "unknown_regions": sum(len(row["unknown_regions"])
                                   for row in compile_rows),
        },
        "compile_rows_sha256": digest(compile_rows),
        "observer_source_sha256": _source_hashes(),
        "validation_tests": TESTS,
        "model_calls": 0, "api_calls": 0,
        "formal_activation": False, "formal_ready": False,
        "rows": compile_rows,
    }
    compile_sha = _write_atomic(COMPILE_OUTPUT, compile_report)

    replay_rows = []
    for task_key in task_keys:
        suite, task_id = task_key.split("/", 1)
        candidates = sorted(CAMPAIGN.glob(
            f"{suite}-{task_id}-*/execution/artifacts/evidence-v6.json"),
            key=_rank)
        selected = None
        for evidence_path in candidates:
            run = evidence_path.parents[2]
            anchor_path = run / "execution-anchor.json"
            if not anchor_path.is_file():
                continue
            anchor = json.loads(anchor_path.read_text(encoding="utf-8"))
            try:
                data = read_evidence(run / "execution",
                                     anchor["execution_seal_sha256"])
                evaluated = evaluate_full_candidate_information(data)
            except (OSError, KeyError, TypeError, ValueError):
                continue
            selected = {
                "task_key": task_key, "episode_id": data["episode_id"],
                "condition": data["config"]["regime"],
                "permission_level": data["config"]["level"],
                "closure_class": data["closure_class"],
                "seal_hash": anchor["execution_seal_sha256"],
                "seal_verified": True,
                "source_evidence_sha256": digest(data),
                "sealed_pre_run_qid_binding": (
                    "present_candidate_nonformal"
                    if data.get("qid_pre_run_registration") is not None
                    else "absent_legacy_diagnostic_only"
                ),
                "candidate_contract_sha256": evaluated["contract_sha256"],
                "field_count": evaluated["counts"]["I_field_count"],
                "recipient_count": evaluated["counts"]["R"],
                "raw_fact_recipient_cells": evaluated["counts"]
                    ["raw_fact_recipient_cells"],
                "legal_cells_excluded": evaluated["counts"]
                    ["legal_cells_excluded"],
                "I_cells": evaluated["counts"]["I_cells"],
                "confirmed_positive_by_recipient": evaluated[
                    "confirmed_positive_by_recipient"],
                "confirmed_positive_unit_count": evaluated[
                    "confirmed_positive_unit_count"],
                "structurally_negative_unit_count": evaluated[
                    "structurally_negative_unit_count"],
                "unresolved_unit_count": evaluated["unresolved_unit_count"],
                "confirmed_receipts": evaluated["receipt_coverage"]
                    ["confirmed_receipts"],
                "receipt_gaps": evaluated["receipt_coverage"]["receipt_gaps"],
                "decode_gaps": evaluated["receipt_coverage"]["decode_gaps"],
                "receipt_scope_incomplete": evaluated[
                    "receipt_scope_incomplete"],
                "point_scope_incomplete": evaluated["point_scope_incomplete"],
                "unknown_regions": evaluated["unknown_regions"],
                "membership_transition_call_ids": evaluated[
                    "membership_transition_call_ids"],
                "I_full": None, "formal_activation": False,
                "formal_ready": False,
            }
            break
        if selected is None:
            raise ValueError("no_verified_sealed_other_cell:" + task_key)
        replay_rows.append(selected)
    replay_report = {
        "schema_version": "rq1-qid-other-full-I-sealed-replay/1",
        "status": "post_outcome_development_replay_not_formal_study",
        "source_campaign": str(CAMPAIGN.relative_to(PROJECT)),
        "selection": "one_verified_honest_preferred_then_low_medium_high_cell_per_task",
        "task_count": len(replay_rows),
        "all_seals_verified": all(row["seal_verified"] for row in replay_rows),
        "legacy_unbound_evidence_count": sum(
            row["sealed_pre_run_qid_binding"] == "absent_legacy_diagnostic_only"
            for row in replay_rows),
        "aggregate_counts": {
            "raw_fact_recipient_cells": sum(
                row["raw_fact_recipient_cells"] for row in replay_rows),
            "legal_cells_excluded": sum(
                row["legal_cells_excluded"] for row in replay_rows),
            "I_cells": sum(row["I_cells"] for row in replay_rows),
            "confirmed_positive_units": sum(
                row["confirmed_positive_unit_count"] for row in replay_rows),
            "structurally_negative_units": sum(
                row["structurally_negative_unit_count"] for row in replay_rows),
            "unresolved_units": sum(
                row["unresolved_unit_count"] for row in replay_rows),
            "receipt_scope_incomplete_tasks": sum(
                row["receipt_scope_incomplete"] for row in replay_rows),
            "point_scope_incomplete_tasks": sum(
                row["point_scope_incomplete"] for row in replay_rows),
            "unknown_regions": sum(len(row["unknown_regions"])
                                   for row in replay_rows),
        },
        "replay_rows_sha256": digest(replay_rows),
        "compile_report_sha256": compile_sha,
        "observer_source_sha256": _source_hashes(),
        "validation_tests": TESTS,
        "model_calls": 0, "api_calls": 0,
        "formal_activation": False, "formal_ready": False,
        "rows": replay_rows,
    }
    replay_sha = _write_atomic(REPLAY_OUTPUT, replay_report)
    print(json.dumps({
        "compile_output": str(COMPILE_OUTPUT), "compile_sha256": compile_sha,
        "replay_output": str(REPLAY_OUTPUT), "replay_sha256": replay_sha,
        "task_count": len(task_keys), "model_calls": 0, "api_calls": 0,
    }, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
