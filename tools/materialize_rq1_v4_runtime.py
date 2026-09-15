#!/usr/bin/env python3
"""Synchronize and receipt-bind the version-isolated RQ1 v4 runtime."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from agentmembrane.host_v2.rq1_public_agentdojo_multi_v4.runtime_receipt import (
    V4_RECEIPT_FILENAME,
    v4_runtime_expectation,
    validate_v4_runtime_receipt,
)
from agentmembrane.host_v2.runtime_provisioning import (
    validate_provisioning_receipt,
)
from experiments.host_boundary_v2.runtime_envs.materialize_runtime_receipts import (
    _receipt,
    _write_canonical,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--created-at", required=True)
    parser.add_argument("--sync", action="store_true")
    args = parser.parse_args()
    expectation = v4_runtime_expectation(repo_root=REPO_ROOT)
    if args.sync:
        completed = subprocess.run(
            [expectation.sync_executable, *expectation.sync_arguments],
            cwd=expectation.sync_cwd,
            env={
                row.name: row.value
                for row in expectation.sync_environment_overrides
            },
            check=False,
            text=True,
            capture_output=True,
            timeout=600,
        )
        if completed.returncode != 0:
            raise RuntimeError(
                "v4 frozen runtime sync failed: " + completed.stderr[-2000:]
            )
    receipt = _receipt(
        expectation=expectation,
        created_at=args.created_at,
        warnings=(),
    )
    validated = validate_provisioning_receipt(
        receipt,
        expectation=expectation,
        verify_live_files=True,
    )
    preflight = validate_v4_runtime_receipt(
        receipt,
        expected_receipt_sha256=validated.receipt_sha256,
        repo_root=REPO_ROOT,
    )
    receipt_path = (
        REPO_ROOT
        / "experiments/host_boundary_v2/runtime_envs/receipts"
        / V4_RECEIPT_FILENAME
    )
    file_sha256 = _write_canonical(receipt_path, receipt.as_json())
    if file_sha256 != validated.receipt_sha256:
        raise RuntimeError("v4 receipt file SHA differs from validated receipt")
    print(
        json.dumps(
            {
                "receipt_path": str(receipt_path.relative_to(REPO_ROOT)),
                "receipt_sha256": file_sha256,
                "payload_sha256": receipt.payload_sha256,
                "environment_tree_sha256": receipt.environment.tree_sha256,
                "upstream_tree_sha256": receipt.upstream.tree_manifest_post_sha256,
                "preflight": preflight,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
