from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .manifest import load_manifest, validate_manifest
from .profile import file_sha256
from .schema import sha256_json


HELDOUT_PROTOCOL_ID = "semantic-rq2-heldout-confirmatory-engineering-v2"


def _stable_key(seed: int, value: str) -> str:
    return hashlib.sha256(f"{seed}|{value}".encode("utf-8")).hexdigest()


def build_heldout_subset_manifest(
    *,
    parent_manifest_path: Path,
    exclusion_manifest_path: Path,
    output_path: Path | None,
    document_count: int,
    seed: int,
) -> dict[str, Any]:
    """Freeze a cluster-disjoint subset of an already frozen parent manifest."""

    if document_count <= 0:
        raise ValueError("document_count must be positive")
    parent = load_manifest(parent_manifest_path)
    exclusion = load_manifest(exclusion_manifest_path)
    parent_check = validate_manifest(parent, exact_baseline_shape=True)
    exclusion_check = validate_manifest(exclusion, exact_baseline_shape=False)
    if not parent_check["valid"]:
        raise ValueError(f"parent manifest invalid: {parent_check['problems']}")
    if not exclusion_check["valid"]:
        raise ValueError(f"exclusion manifest invalid: {exclusion_check['problems']}")
    if parent.get("dataset", {}).get("split_sha256") != exclusion.get("dataset", {}).get(
        "split_sha256"
    ):
        raise ValueError("parent and exclusion manifests do not bind the same split")

    excluded_clusters = {str(case["cluster_id"]) for case in exclusion["cases"]}
    cases_by_cluster: dict[str, list[dict[str, Any]]] = {}
    for case in parent["cases"]:
        cluster_id = str(case["cluster_id"])
        if cluster_id in excluded_clusters:
            continue
        cases_by_cluster.setdefault(cluster_id, []).append(case)
    eligible_clusters = [
        cluster_id
        for cluster_id, cases in cases_by_cluster.items()
        if len(cases) == 2 and {case["gold_label"] for case in cases} == {"Entailment", "Contradiction"}
    ]
    ordered_clusters = sorted(eligible_clusters, key=lambda value: _stable_key(seed, value))
    if len(ordered_clusters) < document_count:
        raise ValueError(
            f"requested {document_count} held-out clusters, only {len(ordered_clusters)} available"
        )
    selected_clusters = ordered_clusters[:document_count]
    selected_cases = [
        case
        for cluster_id in selected_clusters
        for case in sorted(
            cases_by_cluster[cluster_id], key=lambda row: _stable_key(seed, str(row["case_id"]))
        )
    ]
    selected_cases = sorted(
        selected_cases, key=lambda row: _stable_key(seed, str(row["case_id"]))
    )

    manifest = dict(parent)
    manifest["protocol_id"] = parent["protocol_id"]
    manifest["freeze_date"] = "2026-08-31"
    manifest["freeze_seed"] = seed
    manifest["selection_frozen_before_model_calls"] = True
    manifest["heldout_confirmation"] = {
        "protocol_id": HELDOUT_PROTOCOL_ID,
        "parent_manifest_sha256": file_sha256(parent_manifest_path),
        "parent_content_sha256": parent["content_sha256"],
        "exclusion_manifest_sha256": file_sha256(exclusion_manifest_path),
        "exclusion_content_sha256": exclusion["content_sha256"],
        "excluded_cluster_n": len(excluded_clusters),
        "selected_cluster_n": document_count,
        "cluster_overlap_with_exclusion": 0,
        "subset_selection_code_sha256": file_sha256(Path(__file__)),
    }
    sampling = dict(parent["sampling"])
    sampling.update(
        {
            "document_clusters": document_count,
            "planned_case_n": len(selected_cases),
            "rule": (
                "exclude every calibration document cluster; hash-order remaining parent "
                "clusters with the held-out seed; retain both balanced cases per cluster"
            ),
        }
    )
    manifest["sampling"] = sampling
    manifest["cases"] = selected_cases
    manifest.pop("content_sha256", None)
    manifest["content_sha256"] = sha256_json(manifest)

    selected_ids = {str(case["cluster_id"]) for case in selected_cases}
    overlap = selected_ids & excluded_clusters
    if overlap:
        raise AssertionError(f"held-out cluster overlap: {sorted(overlap)}")
    check = validate_manifest(manifest, exact_baseline_shape=False)
    if not check["valid"]:
        raise ValueError(f"held-out manifest invalid: {check['problems']}")
    if check["case_n"] != document_count * 2 or check["cluster_n"] != document_count:
        raise AssertionError("held-out manifest shape mismatch")

    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    return manifest
