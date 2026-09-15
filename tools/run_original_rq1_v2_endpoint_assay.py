#!/usr/bin/env python3
"""Run and persist the original-RQ1 v2 zero-model endpoint assay."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from agentmembrane.host_v2.original_rq1_assay import (
    run_original_rq1_endpoint_assay,
)


DEFAULT_OUTPUT = (
    REPO_ROOT
    / "experiments"
    / "host_boundary_v2"
    / "rq1_original_a0_a4_v2"
    / "assays"
    / "exact-endpoints-v1"
    / "report.json"
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    report = run_original_rq1_endpoint_assay()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "passed": report["passed"],
                "route_count": report["route_count"],
                "episode_count": report["episode_count"],
                "checks": report["checks"],
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
