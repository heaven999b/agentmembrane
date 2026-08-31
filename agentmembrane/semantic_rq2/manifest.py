from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

from ..contractnli import QUALIFIER_RE, build_candidates, file_sha256, load_split
from .schema import (
    AUTHORITY_FIXED,
    CONSTRUCT_ID,
    CONSTRUCT_VERSION,
    LABELS,
    MODES,
    PROMOTION_FIXED,
    PROTOCOL_ID,
    RECEPTOR_ORDER,
    canonical_json,
    sha256_json,
)


DEFAULT_FREEZE_SEED = 20260831
DEFAULT_DOCUMENTS = 100
DEFAULT_MAX_CANDIDATES = 12
SOURCE_URL = "https://stanfordnlp.github.io/contract-nli/"


def _portable_path(path: Path) -> str:
    repository_root = Path(__file__).resolve().parents[2]
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(repository_root))
    except ValueError:
        return str(resolved)


def _resolve_locator(locator: str) -> Path:
    path = Path(locator)
    if path.is_absolute():
        return path
    return Path(__file__).resolve().parents[2] / path


def _stable_key(seed: int, value: Any) -> str:
    return hashlib.sha256(f"{seed}|{value}".encode("utf-8")).hexdigest()


def _clean_span(text: str) -> str:
    return " ".join(text.replace("\x00", " ").split())


def _eligible_rows(
    split_path: Path,
    *,
    max_candidates: int,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    payload = load_split(split_path)
    labels = payload["labels"]
    pool: list[dict[str, Any]] = []
    source_records: dict[str, dict[str, Any]] = {}
    split_name = split_path.stem
    for document in payload["documents"]:
        document_id = str(document["id"])
        text = document["text"]
        source_records[document_id] = {
            "document_id": document_id,
            "full_source_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "span_table_sha256": sha256_json(document["spans"]),
        }
        annotations = document["annotation_sets"][0]["annotations"]
        for label_id, annotation in annotations.items():
            gold_label = annotation["choice"]
            gold_indices = list(annotation.get("spans") or [])
            if gold_label not in LABELS or not gold_indices:
                continue
            hypothesis = labels[label_id]["hypothesis"]
            candidates = build_candidates(
                document,
                hypothesis,
                gold_indices,
                max_candidates=max_candidates,
            )
            candidates = sorted(candidates, key=lambda item: item["source_span_index"])
            gold_text = " ".join(item["text"] for item in candidates if item["is_gold"])
            qualifier_hits = len(QUALIFIER_RE.findall(f"{hypothesis} {gold_text}"))
            non_gold_count = sum(not item["is_gold"] for item in candidates)
            if qualifier_hits == 0 or non_gold_count < 4:
                continue
            packet = [
                {
                    "id": item["id"],
                    "text": item["text"],
                    "source_span_index": item["source_span_index"],
                }
                for item in candidates
            ]
            pool.append(
                {
                    "case_id": f"contractnli-{split_name}-doc{document_id}-{label_id}",
                    "dataset": "ContractNLI",
                    "split": split_name,
                    "cluster_id": f"contractnli-{split_name}-doc{document_id}",
                    "document_id": document_id,
                    "label_id": label_id,
                    "hypothesis": hypothesis,
                    "gold_label": gold_label,
                    "assigned_target": (
                        "Contradiction" if gold_label == "Entailment" else "Entailment"
                    ),
                    "gold_evidence_ids": [f"span-{index}" for index in gold_indices],
                    "evidence_packet": packet,
                    "packet_sha256": sha256_json(packet),
                    "qualifier_hits": qualifier_hits,
                    "non_gold_count": non_gold_count,
                    "document_type": document.get("document_type"),
                    "trusted_source": {
                        "locator": f"contract-nli/{split_name}.json#document={document_id}",
                        **source_records[document_id],
                    },
                }
            )
    return pool, source_records


def select_balanced_document_pairs(
    pool: Iterable[dict[str, Any]],
    *,
    document_count: int,
    seed: int,
) -> list[dict[str, Any]]:
    by_document: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for row in pool:
        by_document[row["document_id"]][row["gold_label"]].append(row)

    eligible_documents = [
        document_id
        for document_id, strata in by_document.items()
        if all(strata.get(label) for label in sorted(LABELS))
    ]
    ordered_documents = sorted(
        eligible_documents, key=lambda document_id: _stable_key(seed, document_id)
    )
    if len(ordered_documents) < document_count:
        raise ValueError(
            f"requested {document_count} balanced documents, only {len(ordered_documents)} eligible"
        )

    selected: list[dict[str, Any]] = []
    for document_id in ordered_documents[:document_count]:
        for label in ("Entailment", "Contradiction"):
            rows = sorted(
                by_document[document_id][label],
                key=lambda row: _stable_key(seed, row["case_id"]),
            )
            selected.append(rows[0])
    return sorted(selected, key=lambda row: _stable_key(seed, row["case_id"]))


def build_contractnli_manifest(
    *,
    split_path: Path,
    license_path: Path,
    output_path: Path | None = None,
    document_count: int = DEFAULT_DOCUMENTS,
    seed: int = DEFAULT_FREEZE_SEED,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> dict[str, Any]:
    if split_path.stem != "test":
        raise ValueError("the canonical baseline freezes ContractNLI's untouched test split")
    pool, _ = _eligible_rows(split_path, max_candidates=max_candidates)
    cases = select_balanced_document_pairs(pool, document_count=document_count, seed=seed)
    code_path = Path(__file__).resolve()
    manifest = {
        "protocol_id": PROTOCOL_ID,
        "construct_id": CONSTRUCT_ID,
        "construct_version": CONSTRUCT_VERSION,
        "proposal_alignment": "RQ2_receptor_boundary",
        "answers_canonical_proposal_rq2": True,
        "pooling_with_host_rq1b_permitted": False,
        "freeze_date": "2026-08-31",
        "freeze_seed": seed,
        "selection_frozen_before_model_calls": True,
        "selection_code_sha256": file_sha256(code_path),
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
            "name": "ContractNLI",
            "release": "2021-10-06 local official release",
            "source_url": SOURCE_URL,
            "license": "CC BY 4.0",
            "local_license_path": _portable_path(license_path),
            "license_sha256": file_sha256(license_path),
            "split": split_path.stem,
            "local_split_path": _portable_path(split_path),
            "split_sha256": file_sha256(split_path),
            "enrichment": "qualifier-bearing binary-label cases with >=4 non-gold packet spans",
            "natural_prevalence_claim_permitted": False,
        },
        "sampling": {
            "eligible_pool_n": len(pool),
            "document_clusters": document_count,
            "cases_per_document": 2,
            "planned_case_n": len(cases),
            "labels": ["Entailment", "Contradiction"],
            "max_candidate_spans": max_candidates,
            "cluster_unit": "document_id",
            "rule": (
                "hash-order eligible documents; require both binary labels; "
                "take one hash-first case per label per document"
            ),
        },
        "cases": cases,
    }
    manifest["content_sha256"] = sha256_json(manifest)
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    return manifest


def public_case(case: dict[str, Any]) -> dict[str, Any]:
    """Return the only case fields generator/downstream roles may receive."""

    return {
        "case_id": case["case_id"],
        "hypothesis": case["hypothesis"],
        "evidence_packet": case["evidence_packet"],
        "packet_sha256": case["packet_sha256"],
    }


def validate_manifest(
    manifest: dict[str, Any],
    *,
    expected_split_path: Path | None = None,
    exact_baseline_shape: bool = True,
) -> dict[str, Any]:
    problems: list[str] = []
    if manifest.get("protocol_id") != PROTOCOL_ID:
        problems.append("protocol_id_mismatch")
    if manifest.get("construct_id") != CONSTRUCT_ID:
        problems.append("construct_id_mismatch")
    if manifest.get("proposal_alignment") != "RQ2_receptor_boundary":
        problems.append("proposal_alignment_mismatch")
    if manifest.get("pooling_with_host_rq1b_permitted") is not False:
        problems.append("host_rq1b_pooling_must_be_false")
    if manifest.get("selection_code_sha256") != file_sha256(Path(__file__).resolve()):
        problems.append("selection_code_sha256_mismatch")
    constants = manifest.get("experimental_constants", {})
    if constants.get("authority") != AUTHORITY_FIXED:
        problems.append("authority_not_fixed_at_A2")
    if constants.get("promotion") != PROMOTION_FIXED:
        problems.append("promotion_not_fixed_at_P0")
    intervention = manifest.get("intervention", {})
    if intervention.get("receptor_order") != [r.value for r in RECEPTOR_ORDER]:
        problems.append("incomplete_or_reordered_receptor_ladder")

    if expected_split_path is not None:
        expected_sha = file_sha256(expected_split_path)
        if manifest.get("dataset", {}).get("split_sha256") != expected_sha:
            problems.append("split_sha256_mismatch")
    dataset = manifest.get("dataset", {})
    for locator_field, hash_field in (
        ("local_split_path", "split_sha256"),
        ("local_license_path", "license_sha256"),
    ):
        locator = dataset.get(locator_field)
        expected_hash = dataset.get(hash_field)
        if not isinstance(locator, str) or not isinstance(expected_hash, str):
            problems.append(f"dataset_{locator_field}_or_{hash_field}_missing")
            continue
        source_path = _resolve_locator(locator)
        if not source_path.is_file():
            problems.append(f"dataset_{locator_field}_not_found")
        elif file_sha256(source_path) != expected_hash:
            problems.append(f"dataset_{hash_field}_mismatch")

    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        problems.append("cases_missing")
        cases = []
    case_ids = [row.get("case_id") for row in cases if isinstance(row, dict)]
    if len(case_ids) != len(set(case_ids)):
        problems.append("duplicate_case_id")

    cluster_counts: Counter[str] = Counter()
    label_counts: Counter[str] = Counter()
    for row in cases:
        if not isinstance(row, dict):
            problems.append("case_not_object")
            continue
        case_id = row.get("case_id", "unknown")
        label = row.get("gold_label")
        target = row.get("assigned_target")
        if label not in LABELS:
            problems.append(f"{case_id}:gold_label_invalid")
        if {label, target} != set(LABELS):
            problems.append(f"{case_id}:target_not_opposite_gold")
        packet = row.get("evidence_packet")
        if not isinstance(packet, list) or not packet:
            problems.append(f"{case_id}:packet_missing")
            continue
        packet_ids: list[str] = [
            item["id"]
            for item in packet
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        ]
        indices: list[int] = [
            item["source_span_index"]
            for item in packet
            if isinstance(item, dict) and isinstance(item.get("source_span_index"), int)
        ]
        if len(packet_ids) != len(packet) or len(packet_ids) != len(set(packet_ids)):
            problems.append(f"{case_id}:packet_ids_invalid")
        if len(indices) != len(packet) or indices != sorted(indices):
            problems.append(f"{case_id}:packet_order_not_source_order")
        if row.get("packet_sha256") != sha256_json(packet):
            problems.append(f"{case_id}:packet_sha256_mismatch")
        if not set(row.get("gold_evidence_ids", [])).issubset(set(packet_ids)):
            problems.append(f"{case_id}:gold_not_fully_retained")
        forbidden_public = set(public_case(row)) & {"gold_label", "assigned_target", "mode", "arm"}
        if forbidden_public:
            problems.append(f"{case_id}:private_field_in_public_case")
        cluster_counts[str(row.get("cluster_id"))] += 1
        label_counts[str(label)] += 1

    if any(count != 2 for count in cluster_counts.values()):
        problems.append("cluster_pairing_not_two_cases")
    if label_counts.get("Entailment") != label_counts.get("Contradiction"):
        problems.append("labels_not_balanced")
    if exact_baseline_shape:
        if len(cases) != 200 or len(cluster_counts) != 100:
            problems.append("baseline_shape_must_be_200_cases_100_clusters")

    stored_content_sha = manifest.get("content_sha256")
    unhashed = dict(manifest)
    unhashed.pop("content_sha256", None)
    if stored_content_sha != sha256_json(unhashed):
        problems.append("content_sha256_mismatch")
    return {
        "valid": not problems,
        "problems": problems,
        "case_n": len(cases),
        "cluster_n": len(cluster_counts),
        "label_counts": dict(label_counts),
        "packet_identity_ready": all(
            row.get("packet_sha256") == sha256_json(row.get("evidence_packet"))
            for row in cases
            if isinstance(row, dict) and isinstance(row.get("evidence_packet"), list)
        ),
    }


def load_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))
