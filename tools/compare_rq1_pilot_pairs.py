"""Pair honest/malicious utility from a separately verified private snapshot.

This computes descriptive counts, not a formal causal estimate or a new score.
The source snapshot must first pass the sealed-evidence summarizer. Its pinned
hash is required so a different checkpoint cannot silently replace the input.
Only aggregate counts and bindings are written; no private cell traces.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


def compare(snapshot, source_hash):
    if snapshot.get("all_closed_evidence_verified") is not True:
        raise ValueError("verified_snapshot_required")
    if snapshot.get("formal_sample_count") != 0:
        raise ValueError("engineering_snapshot_only")
    grouped = {}
    for row in snapshot["cells"]:
        key = row["level"], row["task_key"]
        regime = row["regime"]
        if row["level"] not in {"low", "medium", "high"} or regime not in {"honest", "malicious"}:
            raise ValueError("unknown_condition")
        pair = grouped.setdefault(key, {})
        if regime in pair:
            raise ValueError("duplicate_cell_no_repeat_pooling")
        if row["L"] not in (0, 1, None):
            raise ValueError("non_binary_utility")
        pair[regime] = row["L"]
    groups = []
    for level in ("low", "medium", "high"):
        pairs = [p for (lev, _), p in grouped.items() if lev == level
                 and p.get("honest") is not None and p.get("malicious") is not None]
        counts = Counter((int(p["honest"]), int(p["malicious"])) for p in pairs)
        n = len(pairs)
        if n > snapshot["planned_tasks"]:
            raise ValueError("too_many_original_tasks")
        groups.append({"level": level, "planned_pairs": snapshot["planned_tasks"],
            "paired_identified": n, "missing_or_unidentified_pairs": snapshot["planned_tasks"] - n,
            "honest_success": counts[1, 1] + counts[1, 0],
            "malicious_success": counts[1, 1] + counts[0, 1],
            "both_success": counts[1, 1], "both_failure": counts[0, 0],
            "honest_only_success": counts[1, 0], "malicious_only_success": counts[0, 1]})
    return {"schema_version": "rq1-pilot-paired-utility-diagnostic/1",
        "source_snapshot_sha256": source_hash,
        "pilot_manifest_sha256": snapshot["pilot_manifest_sha256"],
        "code_bundle_sha256": snapshot["code_bundle_sha256"],
        "checker_reanalysis_sha256": snapshot.get("checker_reanalysis_sha256"),
        "closed_cells_at_checkpoint": snapshot["closed_cells"],
        "scope": "same_original_task_both_regimes_identified_L_only",
        "formal_sample_count": 0, "claim_bearing": False, "groups": groups,
        "limitations": ["one_run_per_condition", "missing_pairs_retained_in_counts",
                        "task_only_L_not_a_clean_execution_metric", "no_claim_of_attack_improving_ability"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    data = args.snapshot.read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if actual != args.expected_sha256:
        raise ValueError("snapshot_hash_mismatch")
    value = compare(json.loads(data), actual)
    with args.output.open("x") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps(value["groups"]))


if __name__ == "__main__":
    main()
