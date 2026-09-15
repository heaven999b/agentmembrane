from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .contractnli import dataset_inventory, load_contractnli
from .data_hygiene import discover_consumed_documents, exclude_consumed_episodes
from .design import CORE_CELL_SPEC


def run_preflight(repo_root: Path) -> dict[str, Any]:
    """Run the complete no-model Gate-A audit against the local repository."""

    root = Path(repo_root).resolve()
    experiment_dir = root / "experiments/rq1_authority_semantic"
    frozen_audit = json.loads(
        (experiment_dir / "DATA_AUDIT_20260904.json").read_text(encoding="utf-8")
    )
    claim_contract = json.loads(
        (experiment_dir / "CLAIM_CONTRACT.json").read_text(encoding="utf-8")
    )
    scan_roots = tuple(root / relative for relative in frozen_audit["legacy_scan_roots"])
    current_consumed = discover_consumed_documents(scan_roots)
    frozen_consumed = {
        split: tuple(values)
        for split, values in frozen_audit["legacy_consumed_documents"].items()
    }
    checks: dict[str, bool] = {
        "construct_is_original_rq1": (
            claim_contract["rq_id"] == "RQ1"
            and claim_contract["construct_id"] == "authority_semantic_separation"
        ),
        "single_formal_benchmark": claim_contract["formal_benchmark"] == "ContractNLI",
        "document_is_independent_unit": claim_contract["independent_unit"] == "document_id",
        "core_cell_count_matches_code": (
            claim_contract["core_cell_count_per_episode"] == len(CORE_CELL_SPEC)
        ),
        "legacy_inventory_unchanged": current_consumed.documents == frozen_consumed,
        "protocol_present": (experiment_dir / "PROTOCOL.md").is_file(),
    }
    split_reports: dict[str, Any] = {}
    official_dir = root / "data/official/contract-nli"
    for split in ("train", "dev", "test"):
        episodes = load_contractnli(official_dir / f"{split}.json", split=split)
        kept = exclude_consumed_episodes(episodes, current_consumed)
        all_inventory = dataset_inventory(episodes)
        kept_inventory = dataset_inventory(kept)
        frozen = frozen_audit["official_split_inventory"][split]
        checks[f"{split}_source_hash_matches"] = (
            all_inventory["source_file_sha256"] == frozen["source_file_sha256"]
        )
        checks[f"{split}_all_schemas_valid"] = bool(
            all_inventory["all_episode_schemas_valid"]
        )
        checks[f"{split}_remaining_document_count_matches"] = (
            kept_inventory["independent_document_n"]
            == frozen["after_legacy_exclusion"]["document_n"]
        )
        checks[f"{split}_remaining_episode_count_matches"] = (
            kept_inventory["episode_n"]
            == frozen["after_legacy_exclusion"]["episode_n"]
        )
        split_reports[split] = {
            "all": all_inventory,
            "after_legacy_exclusion": kept_inventory,
        }
    return {
        "schema": "rq1-gate-a-preflight-v1",
        "passed": all(checks.values()),
        "checks": checks,
        "legacy_consumed": current_consumed.to_dict(),
        "splits": split_reports,
        "model_calls": 0,
        "claim_status": "engineering_only_no_semantic_effect_claim",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run original RQ1 offline Gate-A audit")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
    )
    arguments = parser.parse_args()
    report = run_preflight(arguments.repo_root)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
