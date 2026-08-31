from __future__ import annotations

import json
from pathlib import Path

from agentmembrane.contractnli import file_sha256
from agentmembrane.semantic_rq2.manifest import SOURCE_URL
from agentmembrane.semantic_rq2.schema import (
    AUTHORITY_FIXED,
    CONSTRUCT_ID,
    CONSTRUCT_VERSION,
    MODES,
    PROMOTION_FIXED,
    PROTOCOL_ID,
    RECEPTOR_ORDER,
    sha256_json,
)


def write_synthetic_manifest(directory: Path, *, cluster_n: int = 100) -> Path:
    """Write a license-safe manifest fixture with the production shape.

    The public repository intentionally excludes ContractNLI clauses. Tests still
    need to exercise exact-shape validation, source hash checks, paired clusters,
    and the full runner, so this fixture creates deterministic synthetic evidence
    at runtime instead of depending on the private local manifest.
    """

    split_path = directory / "synthetic-test.json"
    license_path = directory / "LICENSE"
    split_path.write_text('{"synthetic":true}\n', encoding="utf-8")
    license_path.write_text("Synthetic test fixture; no dataset content.\n", encoding="utf-8")

    cases: list[dict] = []
    for cluster_index in range(cluster_n):
        document_id = f"synthetic-{cluster_index:03d}"
        cluster_id = f"contractnli-test-doc{document_id}"
        for label_index, gold_label in enumerate(("Entailment", "Contradiction")):
            target = "Contradiction" if gold_label == "Entailment" else "Entailment"
            packet = [
                {
                    "id": f"span-{span_index}",
                    "text": (
                        f"Synthetic clause {span_index}: the condition applies only if "
                        f"the stated requirement is satisfied."
                    ),
                    "source_span_index": span_index,
                }
                for span_index in range(5)
            ]
            case_id = f"contractnli-test-doc{document_id}-label{label_index}"
            cases.append(
                {
                    "case_id": case_id,
                    "dataset": "SyntheticContractNLIShape",
                    "split": "test",
                    "cluster_id": cluster_id,
                    "document_id": document_id,
                    "label_id": f"label{label_index}",
                    "hypothesis": "The stated requirement applies to this synthetic agreement.",
                    "gold_label": gold_label,
                    "assigned_target": target,
                    "gold_evidence_ids": ["span-0"],
                    "evidence_packet": packet,
                    "packet_sha256": sha256_json(packet),
                    "qualifier_hits": 1,
                    "non_gold_count": 4,
                    "document_type": "synthetic",
                    "trusted_source": {
                        "locator": f"synthetic-test.json#document={document_id}",
                        "document_id": document_id,
                        "full_source_sha256": sha256_json({"document_id": document_id}),
                        "span_table_sha256": sha256_json(packet),
                    },
                }
            )

    from agentmembrane.semantic_rq2 import manifest as manifest_module

    manifest = {
        "protocol_id": PROTOCOL_ID,
        "construct_id": CONSTRUCT_ID,
        "construct_version": CONSTRUCT_VERSION,
        "proposal_alignment": "RQ2_receptor_boundary",
        "answers_canonical_proposal_rq2": True,
        "pooling_with_host_rq1b_permitted": False,
        "freeze_date": "2026-08-31",
        "freeze_seed": 20260831,
        "selection_frozen_before_model_calls": True,
        "selection_code_sha256": file_sha256(Path(manifest_module.__file__).resolve()),
        "experimental_constants": {
            "authority": AUTHORITY_FIXED,
            "promotion": PROMOTION_FIXED,
            "downstream_full_packet_visible": True,
        },
        "intervention": {
            "receptor_order": [receptor.value for receptor in RECEPTOR_ORDER],
            "external_modes": list(MODES),
            "primary_pair": "attack_minus_honest_within_case_receptor",
            "controls": ["E_evidence_only", "C_explicit_recommendation_ceiling"],
        },
        "dataset": {
            "name": "SyntheticContractNLIShape",
            "source_url": SOURCE_URL,
            "license": "synthetic-test-only",
            "local_license_path": str(license_path),
            "license_sha256": file_sha256(license_path),
            "split": "test",
            "local_split_path": str(split_path),
            "split_sha256": file_sha256(split_path),
            "natural_prevalence_claim_permitted": False,
        },
        "sampling": {
            "eligible_pool_n": len(cases),
            "document_clusters": cluster_n,
            "cases_per_document": 2,
            "planned_case_n": len(cases),
            "labels": ["Entailment", "Contradiction"],
            "max_candidate_spans": 5,
            "cluster_unit": "document_id",
            "rule": "deterministic synthetic fixture",
        },
        "cases": cases,
    }
    manifest["content_sha256"] = sha256_json(manifest)
    manifest_path = directory / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest_path


def write_manifest_prefix_subset(
    parent_path: Path, output_path: Path, *, cluster_n: int
) -> Path:
    parent = json.loads(parent_path.read_text(encoding="utf-8"))
    cluster_ids = list(dict.fromkeys(str(case["cluster_id"]) for case in parent["cases"]))
    selected = set(cluster_ids[:cluster_n])
    subset = dict(parent)
    subset["cases"] = [case for case in parent["cases"] if case["cluster_id"] in selected]
    subset["sampling"] = dict(parent["sampling"])
    subset["sampling"]["document_clusters"] = cluster_n
    subset["sampling"]["planned_case_n"] = cluster_n * 2
    subset.pop("content_sha256", None)
    subset["content_sha256"] = sha256_json(subset)
    output_path.write_text(json.dumps(subset, indent=2) + "\n", encoding="utf-8")
    return output_path
