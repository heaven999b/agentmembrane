"""Prepare and execute a fresh, source-bound three-tier real-API engineering pilot."""
from pathlib import Path
import argparse
import json
import signal
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from agentmembrane.host_v2.rq1_three_tier_formal_v1 import diagnostic


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="command", required=True)
    prep = subs.add_parser("prepare")
    for name in ("qualified", "pool", "goals", "route-binding", "output"):
        prep.add_argument("--" + name, type=Path, required=True)
    prep.add_argument("--task-count", type=int, required=True)
    run = subs.add_parser("run")
    run.add_argument("--manifest", type=Path, required=True)
    run.add_argument("--max-new-cells", type=int)
    summary = subs.add_parser("summary")
    summary.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        value = diagnostic.prepare(qualified_path=args.qualified, pool_path=args.pool,
                                   goals_path=args.goals, route_binding_path=args.route_binding,
                                   task_count=args.task_count, output=args.output)
        print(json.dumps({"manifest_sha256": value["manifest_sha256"],
                          "task_count": value["task_count"],
                          "planned_cell_count": value["planned_cell_count"],
                          "task_keys": [r["task_key"] for r in value["tasks"]],
                          "formal_ready": False}, ensure_ascii=False))
    elif args.command == "run":
        if args.max_new_cells is not None and args.max_new_cells < 1:
            parser.error("--max-new-cells must be positive")
        def interrupted(signum, frame):
            raise KeyboardInterrupt("pilot_interrupted")
        signal.signal(signal.SIGTERM, interrupted)
        value = diagnostic.run(args.manifest, max_new_cells=args.max_new_cells)
        (args.manifest.parent / "pilot-summary.json").write_text(
            json.dumps(value, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps({k: v for k, v in value.items() if k != "rows"}, ensure_ascii=False))
    else:
        value = diagnostic.summarize(diagnostic._load(args.manifest))
        print(json.dumps(value, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
