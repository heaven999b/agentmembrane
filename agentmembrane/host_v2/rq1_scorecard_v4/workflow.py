"""Append-only post-execution scoring of every allocated cell, including failures."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..rq1_collab_v1.audit import _write_new, canonical, file_hash, strict_loads
from ..rq1_collab_v3.evaluation import read_evidence
from .core import DIMENSIONS, compare, digest
from .native_adapter import evaluate


def write(path, value):
    _write_new(Path(path), canonical(value) + b"\n")


def run(manifest_path, runs, output):
    manifest_path, runs, output = Path(manifest_path).resolve(), Path(runs).resolve(), Path(output).resolve()
    # Evaluations cannot be added to a sealed execution directory or overwrite
    # old reports. In particular, a re-score never relaunches an actor.
    if output == runs or output.is_relative_to(runs):
        raise ValueError("score_output_must_be_outside_execution_runs")
    manifest = strict_loads(manifest_path.read_bytes())
    unsigned = {k: v for k, v in manifest.items() if k != "manifest_sha256"}
    if manifest.get("schema_version") != "rq1-workflow/3" or digest(unsigned) != manifest.get("manifest_sha256"):
        raise ValueError("historical_manifest_hash_mismatch")
    # Historical execution code can differ from a later evaluator. Do not call
    # v3.load_manifest(), which intentionally binds runtime code for NEW runs.
    cells = manifest["cells"]
    if len({c["episode_id"] for c in cells}) != len(cells) or len(cells) != manifest["condition_count"]:
        raise ValueError("duplicate_or_missing_allocations")
    for cfg in cells:
        bundle = manifest["bundles"][cfg["bundle_sha256"]]
        if digest(bundle) != cfg["bundle_sha256"]:
            raise ValueError("historical_bundle_hash_mismatch")
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    write(output / "scoring-manifest.json", {
        "schema_version": "rq1-scoring-workflow/4", "input_manifest": str(manifest_path),
        "input_manifest_sha256": file_hash(manifest_path), "runs": str(runs),
        "score_code_sha256": {p.name: file_hash(p) for p in sorted(Path(__file__).parent.glob("*.py"))},
        "dependency_code_sha256": {str(p): file_hash(p) for name in ("rq1_collab_v1", "rq1_collab_v3")
                                    for p in sorted((Path(__file__).parent.parent / name).glob("*.py"))},
        "human_review_required": False, "model_calls": 0, "formal_ready": False,
        "planned_episode_ids": [c["episode_id"] for c in cells]})
    reports, failures = {}, []
    for cfg in cells:
        episode = cfg["episode_id"]
        root = runs / episode
        try:
            if root.resolve().parent != runs:
                raise ValueError("invalid_episode_path")
            anchor = strict_loads((root / "execution-anchor.json").read_bytes())
            if anchor["manifest_sha256"] != manifest["manifest_sha256"]:
                raise ValueError("anchor_manifest_mismatch")
            data = read_evidence(root / "execution", anchor["execution_seal_sha256"])
            if data["config"] != cfg or data["bundle_sha256"] != cfg["bundle_sha256"]:
                raise ValueError("scored_cell_configuration_mismatch")
            rec = manifest["bundles"][cfg["bundle_sha256"]]
            for field in ("prompt_sha256", "class_source_sha256", "source_file_sha256", "initial_state_sha256"):
                if data["native_record"][field] != rec["source_record"][field]:
                    raise ValueError("captured_source_differs_from_admission")
            report = evaluate(data)
            report["execution_seal_sha256"] = anchor["execution_seal_sha256"]
            # Keep old native scores without allowing a modified report to act as
            # a gold label. New scores are calculated from the sealed evidence.
            status = strict_loads((root / "status.json").read_bytes())
            old = root / "report.json"
            if file_hash(old) != status.get("report_sha256"):
                raise ValueError("historical_report_hash_mismatch")
            original = strict_loads(old.read_bytes())
            if original["execution_seal_sha256"] != anchor["execution_seal_sha256"]:
                raise ValueError("historical_score_seal_mismatch")
            report["original_scores"] = {k: original[k] for k in ("native_task_success", "strict_task_result", "native_goal_success")}
            write(output / "episodes" / (episode + ".json"), report)
            reports[episode] = report
        except (OSError, KeyError, TypeError, ValueError) as exc:
            failures.append({"episode_id": episode, "error": str(exc), "error_type": type(exc).__name__})
    contrasts = []
    axes = {"level": [("high", "medium"), ("medium", "low"), ("high", "low")],
            "topology": [("H_S_E", "H_E")], "regime": [("malicious", "honest")]}
    for axis, arms in axes.items():
        for a in reports.values():
            for first, second in arms:
                if a["config"][axis] != first:
                    continue
                matches = [b for b in reports.values() if b["config"][axis] == second
                           and a["contract_sha256"] == b["contract_sha256"]
                           and all(a["config"][key] == b["config"][key] for key in ("level", "topology", "regime", "repeat") if key != axis)]
                if len(matches) == 1:
                    b = matches[0]
                    contrasts.append({"axis": axis, "A": a["episode_id"], "B": b["episode_id"],
                                      "world_id": a["independent_world_id"], **compare(a, b)})
    write(output / "paired-contrasts.json", contrasts)
    summary = {"schema_version": "rq1-score-summary/4", "assigned_episodes": len(cells),
               "scored_episodes": len(reports), "failures": failures,
               "dimensions_with_point_scores": {d: sum(r["dimensions"][d]["point"] is not None for r in reports.values()) for d in DIMENSIONS},
               "full_six_dimension_point_scores": sum(r["overall"]["point"] is not None for r in reports.values()),
               "episodes_with_critical_incident": sum(bool(r["critical_incidents"]) for r in reports.values()),
               "episodes_with_unscored_state_change": sum(bool(r["unscored_state_changes"]) for r in reports.values()),
               "behavioral_episode_count": sum(r["behavioral_n"] for r in reports.values()),
               "independent_world_count": len({r["independent_world_id"] for r in reports.values()}),
               "task_count": len({digest(r["task_binding"]) for r in reports.values()}),
               "matched_contrast_count": len(contrasts), "model_calls": 0,
               "confidence_intervals": None, "confidence_interval_reason": "development_reanalysis_no_population_inference",
               "all_allocations_accounted_for": len(reports) + len(failures) == len(cells),
               "formal_ready": False, "human_review_required": False}
    write(output / "summary.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description="Six-dimensional post-execution RQ1 scoring; zero model calls.")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--runs", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = run(args.manifest, args.runs, args.output)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result["failures"] else 0
