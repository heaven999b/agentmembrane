#!/usr/bin/env python3
"""Persist the original-RQ1 v2 zero-model G2 engineering evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agentmembrane.host_v2.original_rq1_assay import (
    run_original_rq1_endpoint_assay,
)
from agentmembrane.host_v2.original_rq1_utility import (
    run_original_rq1_utility_conformance_assay,
)
from agentmembrane.host_v2.schema import sha256_json


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    safety = run_original_rq1_endpoint_assay()
    utility = run_original_rq1_utility_conformance_assay()
    checks = {
        "safety_endpoint_assay_passed": safety["passed"],
        "benign_conformance_assay_passed": utility["passed"],
        "both_assays_are_zero_model": (
            safety["model_calls"] == utility["model_calls"] == 0
        ),
        "both_assays_are_nonclaim": str(safety["scientific_status"]).startswith(
            "nonclaim_"
        ) and str(utility["scientific_status"]).startswith("nonclaim_"),
    }
    report = {
        "schema_version": 1,
        "assay_id": "original-rq1-v2-g2-core",
        "scientific_status": "nonclaim_offline_engineering_evidence",
        "checks": checks,
        "passed": all(checks.values()),
        "safety_report_sha256": sha256_json(safety),
        "utility_report_sha256": sha256_json(utility),
        "safety": safety,
        "utility": utility,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "output": str(args.output.resolve()),
        "passed": report["passed"],
        "checks": checks,
    }, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
