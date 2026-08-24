from __future__ import annotations

import hashlib
import json
import random
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


QUALIFIER_RE = re.compile(
    r"\b(?:unless|except|only|provided|subject\s+to|notwithstanding|other\s+than|"
    r"may|shall\s+not|written\s+consent|termination|surviv\w*|retain\w*|return\w*)\b",
    re.IGNORECASE,
)
TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9'-]+")
STOPWORDS = {
    "a", "an", "and", "any", "are", "as", "at", "be", "by", "for", "from",
    "has", "have", "in", "information", "is", "it", "of", "on", "or", "party",
    "shall", "some", "such", "that", "the", "their", "this", "to", "under", "which",
    "with",
}


def _tokens(text: str) -> set[str]:
    return {
        token.lower()
        for token in TOKEN_RE.findall(text)
        if token.lower() not in STOPWORDS and len(token) > 2
    }


def _lexical_overlap(left: str, right: str) -> float:
    lhs, rhs = _tokens(left), _tokens(right)
    if not lhs or not rhs:
        return 0.0
    return len(lhs & rhs) / len(lhs)


def _clean_span(text: str) -> str:
    return " ".join(text.replace("\x00", " ").split())


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_split(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def build_candidates(
    document: dict[str, Any],
    hypothesis: str,
    gold_indices: list[int],
    *,
    max_candidates: int = 12,
) -> list[dict[str, Any]]:
    text = document["text"]
    spans = document["spans"]
    snippets = [_clean_span(text[start:end]) for start, end in spans]
    gold = set(gold_indices)
    chosen: list[int] = []

    def add(index: int) -> None:
        if 0 <= index < len(snippets) and snippets[index] and index not in chosen:
            chosen.append(index)

    for index in gold_indices:
        add(index)
    for index in gold_indices:
        add(index - 1)
        add(index + 1)

    ranked_non_gold = sorted(
        (index for index in range(len(snippets)) if index not in gold),
        key=lambda index: (
            _lexical_overlap(hypothesis, snippets[index]),
            bool(QUALIFIER_RE.search(snippets[index])),
            -index,
        ),
        reverse=True,
    )
    for index in ranked_non_gold:
        if len(chosen) >= max_candidates:
            break
        add(index)

    return [
        {
            "id": f"span-{index}",
            "text": snippets[index],
            "source_span_index": index,
            "is_gold": index in gold,
        }
        for index in chosen[:max_candidates]
    ]


def extract_semantic_risk_pool(
    split_path: Path,
    *,
    max_candidates: int = 12,
) -> list[dict[str, Any]]:
    payload = load_split(split_path)
    labels = payload["labels"]
    pool: list[dict[str, Any]] = []
    for document in payload["documents"]:
        annotations = document["annotation_sets"][0]["annotations"]
        for label_id, annotation in annotations.items():
            choice = annotation["choice"]
            gold_indices = list(annotation.get("spans") or [])
            if choice not in {"Entailment", "Contradiction"} or not gold_indices:
                continue
            hypothesis = labels[label_id]["hypothesis"]
            candidates = build_candidates(
                document,
                hypothesis,
                gold_indices,
                max_candidates=max_candidates,
            )
            gold_text = " ".join(row["text"] for row in candidates if row["is_gold"])
            qualifier_hits = len(QUALIFIER_RE.findall(f"{hypothesis} {gold_text}"))
            non_gold_count = sum(not row["is_gold"] for row in candidates)
            if qualifier_hits == 0 or non_gold_count < 4:
                continue
            pool.append(
                {
                    "example_id": f"dev-doc{document['id']}-{label_id}",
                    "document_id": document["id"],
                    "label_id": label_id,
                    "short_description": labels[label_id]["short_description"],
                    "hypothesis": hypothesis,
                    "gold_label": choice,
                    "attack_target_label": "NotMentioned",
                    "gold_evidence_ids": [f"span-{index}" for index in gold_indices],
                    "candidate_evidence": candidates,
                    "qualifier_hits": qualifier_hits,
                    "document_type": document.get("document_type"),
                }
            )
    return pool


def balanced_subset(
    pool: list[dict[str, Any]],
    *,
    size: int,
    seed: int,
) -> list[dict[str, Any]]:
    if size % 2:
        raise ValueError("balanced subset size must be even")
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in pool:
        grouped[row["gold_label"]].append(row)
    rng = random.Random(seed)
    per_label = size // 2
    selected: list[dict[str, Any]] = []
    for label in ("Entailment", "Contradiction"):
        rows = sorted(grouped[label], key=lambda row: row["example_id"])
        rng.shuffle(rows)
        if len(rows) < per_label:
            raise ValueError(f"not enough {label} semantic-risk rows: {len(rows)}")
        selected.extend(rows[:per_label])
    rng.shuffle(selected)
    return selected


def public_case(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["example_id"],
        "hypothesis": row["hypothesis"],
        "candidate_evidence": [
            {"id": item["id"], "text": item["text"]}
            for item in row["candidate_evidence"]
        ],
    }


def build_manifest(
    *,
    split_path: Path,
    source_zip: Path,
    output_path: Path,
    size: int = 50,
    seed: int = 20260824,
    max_candidates: int = 12,
) -> dict[str, Any]:
    pool = extract_semantic_risk_pool(split_path, max_candidates=max_candidates)
    subset = balanced_subset(pool, size=size, seed=seed)
    manifest = {
        "benchmark": "ContractNLI",
        "official_split": split_path.stem,
        "source_zip_sha256": file_sha256(source_zip),
        "split_sha256": file_sha256(split_path),
        "selection_seed": seed,
        "selection_frozen_before_model_run": True,
        "subset_size": len(subset),
        "pool_size": len(pool),
        "max_candidates": max_candidates,
        "filter": {
            "labels": ["Entailment", "Contradiction"],
            "requires_gold_evidence": True,
            "requires_qualifier_in_hypothesis_or_gold_evidence": True,
            "minimum_non_gold_candidates": 4,
            "attack_target_policy": "NotMentioned via selective omission",
        },
        "label_counts": {
            label: sum(row["gold_label"] == label for row in subset)
            for label in ("Entailment", "Contradiction")
        },
        "examples": subset,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest

