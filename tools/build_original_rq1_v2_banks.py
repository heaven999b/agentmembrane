#!/usr/bin/env python3
"""Build and persist original-RQ1 v2 development/formal bank manifests."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agentmembrane.host_v2.original_rq1_banks import (
    compile_original_rq1_banks,
)
from agentmembrane.host_v2.schema import sha256_json


def _write(path: Path, value: object) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return sha256_json(value)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args()
    compiled = compile_original_rq1_banks(REPO_ROOT)
    output_root = args.output_root
    development = {
        key: value
        for key, value in compiled.items()
        if key not in {"formal_holdout", "development"}
    }
    development["bank_id"] = "development"
    development["clusters"] = compiled["development"]
    formal = {
        "schema_version": compiled["schema_version"],
        "protocol_id": compiled["protocol_id"],
        "bank_id": "formal_holdout",
        "selection_seed": compiled["selection_seed"],
        "bfcl_commit": compiled["bfcl_commit"],
        "scientific_status": "sealed_unexecuted_holdout",
        "clusters": compiled["formal_holdout"],
    }
    audit = {
        key: value
        for key, value in compiled.items()
        if key not in {"development", "formal_holdout", "development_schedule"}
    }
    hashes = {
        "development_manifest_sha256": _write(
            output_root / "development_manifest.json", development
        ),
        "formal_holdout_manifest_sha256": _write(
            output_root / "formal_holdout_manifest.json", formal
        ),
        "bank_audit_sha256": _write(output_root / "bank_audit.json", audit),
    }
    lock = {
        "schema_version": 1,
        "protocol_id": compiled["protocol_id"],
        "selection_seed": compiled["selection_seed"],
        "status": "formal_bank_selected_sealed_unexecuted",
        **hashes,
    }
    lock["lock_payload_sha256"] = sha256_json(lock)
    _write(output_root / "BANK_LOCK.json", lock)
    print(json.dumps({
        "output_root": str(output_root.resolve()),
        "passed": compiled["passed"],
        "checks": compiled["checks"],
        "hashes": hashes,
    }, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if compiled["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
