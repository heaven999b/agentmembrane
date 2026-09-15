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
CONFIRMATION_PROTOCOL_ID = "semantic-rq2-full-confirmatory-engineering-v3"
HISTORICAL_SELECTION_CODE_SHA256S = frozenset(
    {"23004b852d88841112a9233548e29ca254cec84a27fd9c7603ced8c569de9a86"}
)


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
            "normalized_source_sha256": hashlib.sha256(
                _clean_span(text).encode("utf-8")
            ).hexdigest(),
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
            semantic_input_sha256 = sha256_json(
                {"hypothesis": hypothesis, "evidence_packet": packet}
            )
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
                    "semantic_input_sha256": semantic_input_sha256,
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


def _build_contractnli_manifest(
    *,
    split_path: Path,
    license_path: Path,
    output_path: Path | None = None,
    document_count: int = DEFAULT_DOCUMENTS,
    seed: int = DEFAULT_FREEZE_SEED,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
    freeze_date: str = "2026-08-31",
    excluded_source_hashes: set[str] | None = None,
    excluded_normalized_source_hashes: set[str] | None = None,
    independent_confirmation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    pool, _ = _eligible_rows(split_path, max_candidates=max_candidates)
    if excluded_source_hashes:
        pool = [
            row
            for row in pool
            if row["trusted_source"]["full_source_sha256"] not in excluded_source_hashes
        ]
    if excluded_normalized_source_hashes:
        pool = [
            row
            for row in pool
            if row["trusted_source"]["normalized_source_sha256"]
            not in excluded_normalized_source_hashes
        ]
    cases = select_balanced_document_pairs(pool, document_count=document_count, seed=seed)
    code_path = Path(__file__).resolve()
    manifest = {
        "protocol_id": PROTOCOL_ID,
        "construct_id": CONSTRUCT_ID,
        "construct_version": CONSTRUCT_VERSION,
        "proposal_alignment": "RQ2_receptor_boundary",
        "answers_canonical_proposal_rq2": True,
        "pooling_with_host_rq1b_permitted": False,
        "freeze_date": freeze_date,
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
    if independent_confirmation is not None:
        manifest["independent_confirmation"] = independent_confirmation
    manifest["content_sha256"] = sha256_json(manifest)
    if output_path is not None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    return manifest


def build_contractnli_manifest(
    *,
    split_path: Path,
    license_path: Path,
    output_path: Path | None = None,
    document_count: int = DEFAULT_DOCUMENTS,
    seed: int = DEFAULT_FREEZE_SEED,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> dict[str, Any]:
    """Build the original canonical test-split manifest without broadening it."""

    if split_path.stem != "test":
        raise ValueError("the canonical baseline freezes ContractNLI's untouched test split")
    return _build_contractnli_manifest(
        split_path=split_path,
        license_path=license_path,
        output_path=output_path,
        document_count=document_count,
        seed=seed,
        max_candidates=max_candidates,
    )


def build_contractnli_confirmation_manifest(
    *,
    split_path: Path,
    license_path: Path,
    exclusion_manifest_paths: Iterable[Path],
    output_path: Path | None = None,
    document_count: int = DEFAULT_DOCUMENTS,
    seed: int = 20260901,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> dict[str, Any]:
    """Freeze a full-scale, source-disjoint confirmation on untouched train data.

    The original test-split manifest remains immutable.  This builder is a new,
    explicitly named engineering-confirmation path and excludes source hashes from
    every supplied prior manifest before hash-order sampling.
    """

    if split_path.stem != "train":
        raise ValueError("the full confirmation freezes ContractNLI's untouched train split")
    exclusion_paths = list(exclusion_manifest_paths)
    if not exclusion_paths:
        raise ValueError("at least one prior manifest is required for independence checking")

    excluded_source_hashes: set[str] = set()
    excluded_normalized_source_hashes: set[str] = set()
    exclusions: list[dict[str, Any]] = []
    for path in exclusion_paths:
        prior = load_manifest(path)
        check = validate_manifest(
            prior,
            exact_baseline_shape=False,
            allow_historical_selection_code=True,
        )
        if not check["valid"]:
            raise ValueError(f"exclusion manifest invalid ({path}): {check['problems']}")
        hashes = {
            str(case.get("trusted_source", {}).get("full_source_sha256"))
            for case in prior["cases"]
            if case.get("trusted_source", {}).get("full_source_sha256")
        }
        normalized_by_document: dict[str, str] = {}
        split_locator = prior.get("dataset", {}).get("local_split_path")
        if isinstance(split_locator, str):
            prior_split = load_split(_resolve_locator(split_locator))
            normalized_by_document = {
                str(document["id"]): hashlib.sha256(
                    _clean_span(str(document["text"])).encode("utf-8")
                ).hexdigest()
                for document in prior_split["documents"]
            }
        normalized_hashes = {
            str(
                case.get("trusted_source", {}).get("normalized_source_sha256")
                or normalized_by_document.get(str(case.get("document_id")))
            )
            for case in prior["cases"]
            if case.get("trusted_source", {}).get("normalized_source_sha256")
            or normalized_by_document.get(str(case.get("document_id")))
        }
        excluded_source_hashes.update(hashes)
        excluded_normalized_source_hashes.update(normalized_hashes)
        exclusions.append(
            {
                "manifest_path": _portable_path(path),
                "manifest_sha256": file_sha256(path),
                "content_sha256": prior["content_sha256"],
                "case_n": len(prior["cases"]),
                "source_n": len(hashes),
                "normalized_source_n": len(normalized_hashes),
            }
        )

    manifest = _build_contractnli_manifest(
        split_path=split_path,
        license_path=license_path,
        output_path=None,
        document_count=document_count,
        seed=seed,
        max_candidates=max_candidates,
        freeze_date="2026-09-01",
        excluded_source_hashes=excluded_source_hashes,
        excluded_normalized_source_hashes=excluded_normalized_source_hashes,
        independent_confirmation={
            "protocol_id": CONFIRMATION_PROTOCOL_ID,
            "sample_role": "independent_within_domain_full_scale_confirmation",
            "prior_manifests": exclusions,
            "prior_source_hash_n": len(excluded_source_hashes),
            "prior_normalized_source_hash_n": len(excluded_normalized_source_hashes),
            "prior_source_overlap": 0,
            "prior_normalized_source_overlap": 0,
            "selection_code_sha256": file_sha256(Path(__file__).resolve()),
            "outcomes_unseen_at_freeze": True,
        },
    )
    selected_hashes = {
        str(case["trusted_source"]["full_source_sha256"])
        for case in manifest["cases"]
    }
    selected_normalized_hashes = {
        str(case["trusted_source"]["normalized_source_sha256"])
        for case in manifest["cases"]
    }
    overlap = selected_hashes & excluded_source_hashes
    if overlap:
        raise AssertionError(f"confirmation source overlap: {sorted(overlap)}")
    normalized_overlap = selected_normalized_hashes & excluded_normalized_source_hashes
    if normalized_overlap:
        raise AssertionError(
            f"confirmation normalized source overlap: {sorted(normalized_overlap)}"
        )
    check = validate_manifest(manifest, exact_baseline_shape=True)
    if not check["valid"]:
        raise ValueError(f"confirmation manifest invalid: {check['problems']}")
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
    allow_historical_selection_code: bool = False,
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
    selection_code_sha = manifest.get("selection_code_sha256")
    current_selection_code_sha = file_sha256(Path(__file__).resolve())
    if selection_code_sha != current_selection_code_sha:
        if not (
            allow_historical_selection_code
            and selection_code_sha in HISTORICAL_SELECTION_CODE_SHA256S
        ):
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
    source_documents: dict[str, dict[str, Any]] = {}
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
    split_locator = dataset.get("local_split_path")
    if dataset.get("name") == "ContractNLI" and isinstance(split_locator, str):
        split_path = _resolve_locator(split_locator)
        if split_path.is_file():
            try:
                source_payload = load_split(split_path)
                source_documents = {
                    str(document["id"]): document
                    for document in source_payload["documents"]
                }
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                problems.append("dataset_split_cannot_be_reconstructed")

    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        problems.append("cases_missing")
        cases = []
    case_ids = [row.get("case_id") for row in cases if isinstance(row, dict)]
    if len(case_ids) != len(set(case_ids)):
        problems.append("duplicate_case_id")

    cluster_counts: Counter[str] = Counter()
    cluster_labels: dict[str, Counter[str]] = defaultdict(Counter)
    label_counts: Counter[str] = Counter()
    semantic_input_hashes: list[str] = []
    confirmation_manifest = isinstance(manifest.get("independent_confirmation"), dict)
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
        semantic_input_sha = sha256_json(
            {"hypothesis": row.get("hypothesis"), "evidence_packet": packet}
        )
        stored_semantic_input_sha = row.get("semantic_input_sha256")
        if stored_semantic_input_sha is not None and stored_semantic_input_sha != semantic_input_sha:
            problems.append(f"{case_id}:semantic_input_sha256_mismatch")
        if confirmation_manifest and stored_semantic_input_sha != semantic_input_sha:
            problems.append(f"{case_id}:confirmation_semantic_input_sha256_missing")
        semantic_input_hashes.append(semantic_input_sha)
        if not set(row.get("gold_evidence_ids", [])).issubset(set(packet_ids)):
            problems.append(f"{case_id}:gold_not_fully_retained")
        forbidden_public = set(public_case(row)) & {"gold_label", "assigned_target", "mode", "arm"}
        if forbidden_public:
            problems.append(f"{case_id}:private_field_in_public_case")
        cluster_id = str(row.get("cluster_id"))
        document_id = str(row.get("document_id"))
        split_name = str(dataset.get("split"))
        if row.get("split") != split_name:
            problems.append(f"{case_id}:case_split_namespace_mismatch")
        if cluster_id != f"contractnli-{split_name}-doc{document_id}":
            problems.append(f"{case_id}:cluster_namespace_mismatch")
        if not str(case_id).startswith(f"contractnli-{split_name}-doc{document_id}-"):
            problems.append(f"{case_id}:case_namespace_mismatch")

        source_document = source_documents.get(document_id)
        if source_documents and source_document is None:
            problems.append(f"{case_id}:trusted_source_document_missing")
        elif source_document is not None:
            source_text = str(source_document["text"])
            trusted = row.get("trusted_source", {})
            if trusted.get("document_id") != document_id:
                problems.append(f"{case_id}:trusted_source_document_id_mismatch")
            if trusted.get("full_source_sha256") != hashlib.sha256(
                source_text.encode("utf-8")
            ).hexdigest():
                problems.append(f"{case_id}:full_source_sha256_mismatch")
            normalized_source_sha = hashlib.sha256(
                _clean_span(source_text).encode("utf-8")
            ).hexdigest()
            if trusted.get("normalized_source_sha256") is not None and trusted.get(
                "normalized_source_sha256"
            ) != normalized_source_sha:
                problems.append(f"{case_id}:normalized_source_sha256_mismatch")
            if confirmation_manifest and trusted.get("normalized_source_sha256") != normalized_source_sha:
                problems.append(f"{case_id}:confirmation_normalized_source_sha256_missing")
            if trusted.get("span_table_sha256") != sha256_json(source_document["spans"]):
                problems.append(f"{case_id}:span_table_sha256_mismatch")
            source_spans = source_document["spans"]
            for item in packet:
                index = item.get("source_span_index") if isinstance(item, dict) else None
                if not isinstance(index, int) or not 0 <= index < len(source_spans):
                    continue
                start, end = source_spans[index]
                if item.get("text") != _clean_span(source_text[start:end]):
                    problems.append(f"{case_id}:packet_text_source_mismatch:{index}")
            annotations = source_document["annotation_sets"][0]["annotations"]
            annotation = annotations.get(str(row.get("label_id")))
            if not isinstance(annotation, dict):
                problems.append(f"{case_id}:source_annotation_missing")
            else:
                if annotation.get("choice") != label:
                    problems.append(f"{case_id}:source_label_mismatch")
                expected_gold_ids = {
                    f"span-{index}" for index in list(annotation.get("spans") or [])
                }
                if set(row.get("gold_evidence_ids", [])) != expected_gold_ids:
                    problems.append(f"{case_id}:source_gold_evidence_mismatch")

        cluster_counts[cluster_id] += 1
        cluster_labels[cluster_id][str(label)] += 1
        label_counts[str(label)] += 1

    if any(count != 2 for count in cluster_counts.values()):
        problems.append("cluster_pairing_not_two_cases")
    if any(
        counts != Counter({"Entailment": 1, "Contradiction": 1})
        for counts in cluster_labels.values()
    ):
        problems.append("cluster_pairing_not_one_per_binary_label")
    if label_counts.get("Entailment") != label_counts.get("Contradiction"):
        problems.append("labels_not_balanced")
    if exact_baseline_shape:
        if len(cases) != 200 or len(cluster_counts) != 100:
            problems.append("baseline_shape_must_be_200_cases_100_clusters")
    if confirmation_manifest and len(semantic_input_hashes) != len(set(semantic_input_hashes)):
        problems.append("confirmation_duplicate_semantic_input")

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
