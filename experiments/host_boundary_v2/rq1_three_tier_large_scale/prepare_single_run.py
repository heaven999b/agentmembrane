"""Freeze one H_E three-permission attack/control development allocation per task.

This entry point deliberately has no repeats or seed argument.  It consumes an
offline readiness audit and re-runs native admission through workflow.prepare.
Preparation does not call a model and does not certify formal RQ1 readiness.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT))

from agentmembrane.host_v2.rq1_collab_v1.audit import strict_loads
from agentmembrane.host_v2.rq1_collab_v6.workflow import prepare


def freeze(candidate_dir: Path, readiness_dir: Path, output: Path, *,
           mode: str = "engineering", models_file: Path | None = None,
           provider_route_file: Path | None = None,
           inventory: Path | None = None) -> dict:
    summary = strict_loads((readiness_dir / "summary.json").read_bytes())
    assignments = strict_loads((readiness_dir / "interface-ready-goal-assignments.json").read_bytes())
    readiness_rows = strict_loads((readiness_dir / "readiness-rows.json").read_bytes())
    if (summary["repeats_per_cell"] != 1 or summary["topology"] != "H_E"
            or summary["levels"] != ["low", "medium", "high"]
            or summary["regimes"] != ["honest", "malicious"]
            or summary["engineering_interface_ready_tasks"] != len(assignments)
            or not assignments):
        raise ValueError("single_run_readiness_contract_invalid")
    goals = (readiness_dir / "interface-ready-goal-assignments.json").resolve()
    candidate = (candidate_dir / "candidate-manifest.json").resolve()
    strict_ready = {(r["suite"], r["task_id"]) for r in readiness_rows
                    if r["engineering_interface_ready"] is True
                    and r["strict_checker_ready"] is True}
    tasks = [r["suite"] + ":" + r["task_id"] for r in assignments
             if (r["suite"], r["task_id"]) in strict_ready]
    if len(tasks) != len(strict_ready) or not tasks:
        raise ValueError("strict_ready_single_run_cohort_invalid")
    result = prepare(output, tasks=tasks, repeats=1, mode=mode,
        qualified=candidate, goals=goals, topologies=("H_E",),
        levels=("low", "medium", "high"), regimes=("honest", "malicious"),
        models_file=models_file, provider_route_file=provider_route_file,
        **({"inventory": inventory} if inventory is not None else {}))
    manifest = strict_loads(Path(result["manifest"]).read_bytes())
    if (result["task_count"] != len(tasks)
            or result["condition_count"] != 6 * len(tasks)
            or manifest["repeats"] != 1
            or manifest["cell_selection"] != {
                "topologies": ["H_E"], "levels": ["low", "medium", "high"],
                "regimes": ["honest", "malicious"]}
            or {cell["repeat"] for cell in manifest["cells"]} != {0}):
        raise ValueError("prepared_matrix_not_single_run_six_cell_per_task")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate_dir", type=Path)
    parser.add_argument("readiness_dir", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--mode", choices=("engineering", "live_diagnostic"), default="engineering")
    parser.add_argument("--models-file", type=Path)
    parser.add_argument("--provider-route-file", type=Path)
    parser.add_argument("--inventory", type=Path)
    args = parser.parse_args()
    print(json.dumps(freeze(args.candidate_dir, args.readiness_dir, args.output,
                            mode=args.mode, models_file=args.models_file,
                            provider_route_file=args.provider_route_file,
                            inventory=args.inventory),
                     ensure_ascii=False, sort_keys=True))
