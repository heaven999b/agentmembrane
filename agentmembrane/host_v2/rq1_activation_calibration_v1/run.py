"""CLI entrypoint for preparation, execution, analysis, and monitoring."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys


# Reboot-safe entrypoint: the ordinary shell Python does not carry the frozen
# AgentDojo dependency lock.  Re-exec before importing any experiment module.
_REPO_ROOT = Path(__file__).resolve().parents[3]
_PINNED_PYTHON = (
    _REPO_ROOT
    / "experiments/host_boundary_v2/runtime_envs/"
    "agentdojo-0.1.35-py3123-lock-395e3d0a5921-rq1v4/bin/python"
)
if __name__ == "__main__" and Path(sys.executable) != _PINNED_PYTHON:
    if not _PINNED_PYTHON.is_file():
        raise RuntimeError("frozen AgentDojo Python launcher is missing")
    os.execv(
        str(_PINNED_PYTHON),
        [
            str(_PINNED_PYTHON),
            "-m",
            "agentmembrane.host_v2.rq1_activation_calibration_v1.run",
            *sys.argv[1:],
        ],
    )

from .analysis import analyze_namespace
from .executor import OUTPUT_ROOT, execute_namespace, prepare_namespace
from .monitor import serve


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("namespace")
    prepare.add_argument("--kind", choices=("smoke", "sample50"), required=True)
    execute = sub.add_parser("execute")
    execute.add_argument("namespace")
    analyze = sub.add_parser("analyze")
    analyze.add_argument("namespace")
    monitor = sub.add_parser("monitor")
    monitor.add_argument("namespace")
    monitor.add_argument("--host", default="127.0.0.1")
    monitor.add_argument("--port", type=int, default=8768)
    args = parser.parse_args()
    if args.command == "prepare":
        result: object = {"namespace_path": str(prepare_namespace(namespace=args.namespace, run_kind=args.kind))}
    elif args.command == "execute": result = execute_namespace(OUTPUT_ROOT / args.namespace)
    elif args.command == "analyze": result = analyze_namespace(OUTPUT_ROOT / args.namespace)
    else:
        serve(OUTPUT_ROOT / args.namespace, host=args.host, port=args.port); return 0
    print(json.dumps(result, indent=2, sort_keys=True)); return 0


if __name__ == "__main__": raise SystemExit(main())
