"""Verify a live pilot's closed evidence and export a public aggregate snapshot.

No model calls. Arguments, messages, account bindings and private paths are never
exported. Independent native side effects are diagnostic observations, not the
unqualified formal D endpoint. Missing observations remain missing.
"""
from __future__ import annotations

import argparse
from collections import Counter
import importlib.util
import json
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))

from agentmembrane.host_v2.rq1_collab_v1.audit import _write_new, canonical, strict_loads, file_hash
from agentmembrane.host_v2.rq1_collab_v6.evaluation import read_evidence, derive_outcomes
from agentmembrane.host_v2.rq1_three_tier_formal_v1.diagnostic import (
    CONDITIONS, validate_manifest,
)


def read(path):
    return strict_loads(Path(path).read_bytes())


def summarize(manifest_path, checker_reanalysis=None):
    manifest = validate_manifest(read(manifest_path))
    revised_checker = None
    if checker_reanalysis is not None:
        path = Path(checker_reanalysis)
        if path.is_symlink() or not path.is_file():
            raise ValueError("regular_reanalysis_checker_required")
        name = "agentmembrane.host_v2.rq1_collab_v1.pilot_checkers_reanalysis"
        spec = importlib.util.spec_from_file_location(name, path)
        revised_checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(revised_checker)
    rows, running = [], []
    for cell in manifest["cells"]:
        folder = Path(manifest["run_parent"]) / cell["episode_id"]
        if not folder.exists():
            continue
        if not (folder / "summary.json").is_file():
            running.append(cell["episode_id"])
            continue
        summary = read(folder / "summary.json")
        anchor = read(folder / "execution-anchor.json")
        report = read(folder / "diagnostic-report.json")
        seal_hash = anchor["seal_sha256"]
        if (anchor["manifest_sha256"] != manifest["manifest_sha256"]
                or summary["execution_seal_sha256"] != seal_hash
                or report["execution_seal_sha256"] != seal_hash):
            raise ValueError("pilot_summary_external_anchor_mismatch")
        evidence = read_evidence(folder / "evidence", seal_hash)
        if (evidence["config"] != cell
                or summary["episode_id"] != cell["episode_id"]
                or summary["level"] != cell["level"]
                or summary["regime"] != cell["regime"]):
            raise ValueError("pilot_summary_cell_binding_mismatch")
        unknown = evidence["closure_class"] == "fatal_unknown"
        strict = report.get("strict_task_result")
        expected_g = None if unknown else report["native_goal_success"]
        expected_l = None if unknown or not isinstance(strict, dict) else strict.get("value")
        if summary["G"] != expected_g or summary["L"] != expected_l:
            raise ValueError("pilot_summary_endpoint_mismatch")
        revised_l = summary["L"]
        if revised_checker is not None and not unknown:
            record = evidence["native_record"]
            scorer = (revised_checker.strict_utility_score
                      if revised_checker.strict_utility_supported(record)
                      else revised_checker.strict_profile_score)
            revised_l = scorer(record, evidence["task"]["prompt"],
                               evidence["initial_snapshot"], evidence["terminal_snapshot"],
                               evidence["final_text"])["value"]
        observed = None
        effects = []
        observer_error = None
        try:
            outcome = derive_outcomes(evidence)
            observed = outcome.get("observed_unauthorized_effect")
            if unknown and observed is not True:
                observed = None
            calls = {c["call_id"]: c for c in evidence["native_calls"]}
            for assessment in outcome.get("request_assessments", []):
                if assessment.get("outside_request") is True:
                    call = calls[assessment["call_id"]]
                    effects.append({"actor": call["actor"], "tool": call["tool"],
                                    "dispatch_status": call["status"],
                                    "backend_entered": call.get("evidence_quality", {}).get("backend_entered")})
        except (KeyError, ValueError, TypeError) as exc:
            observer_error = type(exc).__name__
        calls = evidence["native_calls"]
        rows.append({
            "episode_id": cell["episode_id"], "task_key": summary["task_key"],
            "level": cell["level"], "regime": cell["regime"],
            "G": summary["G"], "L": revised_l, "L_original": summary["L"],
            "G_actor_lineage": "unknown" if unknown else summary["G_actor_lineage"],
            "closure_class": summary["closure_class"],
            "model_request_count": summary["model_request_count"],
            "elapsed_seconds": summary["elapsed_seconds"],
            "evaluation_error_count": len(summary["evaluation_errors"]),
            "execution_failure_count": len(summary["execution_failures"]),
            "decision_status_counts": dict(Counter(
                d["status"] for d in evidence["decisions"])),
            "native_backend_entries_by_actor": dict(Counter(
                c["actor"] for c in calls
                if c.get("evidence_quality", {}).get("backend_entered") is True)),
            "native_rejections_by_actor": dict(Counter(
                c["actor"] for c in calls if c["status"] == "rejected")),
            "observed_unauthorized_native_effect_diagnostic": observed,
            "outside_request_dispatches_diagnostic": effects,
            "native_observer_error": observer_error,
            "evidence_integrity_verified": True,
            "cleanup_confirmed": summary["cleanup_confirmed"],
        })
    groups = []
    for level, regime in CONDITIONS:
        selected = [r for r in rows if r["level"] == level and r["regime"] == regime]
        metrics = {}
        for name in ("G", "L", "observed_unauthorized_native_effect_diagnostic"):
            known = [r[name] for r in selected if r[name] is not None]
            positive = sum(v in (True, 1) for v in known)
            total = manifest["task_count"]
            metrics[name] = {"positive": positive, "identified": len(known),
                             "planned": total,
                             "rate_among_identified": positive / len(known) if known else None,
                             "bounds_including_missing_and_unattempted": [
                                 positive / total, (positive + total - len(known)) / total]}
        groups.append({"level": level, "regime": regime,
                       "closed_cells": len(selected), "metrics": metrics})
    task_counts = Counter(r["task_key"] for r in rows)
    return {
        "schema_version": "rq1-three-tier-public-live-pilot-summary/1",
        "analysis_script_sha256": file_hash(Path(__file__)),
        "checker_reanalysis_sha256": (file_hash(checker_reanalysis)
                                      if checker_reanalysis is not None else None),
        "scoring_status": ("posthoc_diagnostic_correction_original_scores_preserved"
                           if revised_checker is not None else "original_frozen_scoring"),
        "pilot_manifest_sha256": manifest["manifest_sha256"],
        "code_bundle_sha256": manifest["code_bundle_sha256"],
        "planned_tasks": manifest["task_count"], "planned_cells": len(manifest["cells"]),
        "closed_cells": len(rows), "in_progress_or_unscored_cells": len(running),
        "tasks_with_all_six_cells_closed": sum(v == 6 for v in task_counts.values()),
        "model_request_count": sum(r["model_request_count"] for r in rows),
        "unknown_closure_cells": sum(r["closure_class"] == "fatal_unknown" for r in rows),
        "all_closed_evidence_verified": True,
        "groups": groups, "cells": rows,
        "formal_sample_count": 0, "formal_ready": False,
        "Q": None, "I": None, "D": None,
        "limitations": ["engineering_pilot_not_formal_RQ1",
                        "one_run_per_cell_no_seed_replication",
                        "native_effect_diagnostic_is_not_qualified_D",
                        "unstructured_information_leakage_not_fully_observed",
                        "incomplete_batches_do_not_identify_full_pilot_rates"],
    }



def public_aggregate(value):
    """Project a verified private summary to repository aggregate evidence."""
    value = json.loads(json.dumps(value))
    rows = value.pop("cells")
    for group in value["groups"]:
        selected = [r for r in rows if (r["level"], r["regime"]) == (group["level"], group["regime"])]
        known = [r["L_original"] for r in selected if r["L_original"] is not None]
        group["original_L"] = {"identified": len(known), "positive": sum(known)}
    value["scoring_correction_count"] = sum(r["L"] != r["L_original"] for r in rows)
    value["publication_scope"] = "aggregate_only_private_cell_diagnostics_retained"
    value["projection_script_sha256"] = file_hash(Path(__file__))
    value.update(program_lineage="agentmembrane-canonical",
                 construct_id="host_mediated_capability_exploitation", construct_version="1.0.0",
                 study_id="three_tier_engineering_pilot_20260916", evidence_level="engineering",
                 claim_bearing=False)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--checker-reanalysis", type=Path)
    parser.add_argument("--aggregate-only", action="store_true", help="Required for public repository export")
    args = parser.parse_args()
    value = summarize(args.manifest, args.checker_reanalysis)
    if args.aggregate_only:
        value = public_aggregate(value)
    _write_new(args.output, canonical(value) + b"\n")
    print(json.dumps({k: value[k] for k in (
        "planned_tasks", "planned_cells", "closed_cells", "unknown_closure_cells",
        "tasks_with_all_six_cells_closed", "model_request_count",
        "all_closed_evidence_verified", "formal_sample_count")}, ensure_ascii=False))


if __name__ == "__main__":
    main()
