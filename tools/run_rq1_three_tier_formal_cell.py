"""Run one activated RQ1 three-tier cell through the production controller.

The command performs no retry and never resumes an existing attempt directory.
It prints only non-secret seal identifiers and eligibility status.  Provider
route, account material, CLIProxy binary, and lifecycle runner are resolved
from the activated manifest's exact source bindings.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[1]
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

from agentmembrane.host_v2.rq1_collab_v1.audit import strict_loads
from agentmembrane.host_v2.rq1_three_tier_formal_v1.runner import (
    run_formal_cell,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--episode-id", required=True)
    parser.add_argument("--run-parent", type=Path, required=True)
    args = parser.parse_args(argv)
    manifest = strict_loads(args.manifest.read_bytes())
    if type(manifest) is not dict:
        raise ValueError("activated_formal_manifest_object_required")
    result = run_formal_cell(
        manifest=manifest,
        episode_id=args.episode_id,
        run_parent=args.run_parent,
    )
    evidence = result["formal_evidence"]
    print(json.dumps({
        "episode_id": args.episode_id,
        "run_dir": str((args.run_parent / args.episode_id).resolve()),
        "execution_seal_sha256": result["seal"]["seal_hash"],
        "formal_evidence_sha256": evidence["formal_evidence_sha256"],
        "production_proxy_lifecycle_receipt_sha256": evidence[
            "production_proxy_lifecycle_receipt_sha256"],
        "formal_sample_eligible": evidence["formal_sample_eligible"],
        "automatic_retry": False,
        "replacement_cell_permitted": False,
    }, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
