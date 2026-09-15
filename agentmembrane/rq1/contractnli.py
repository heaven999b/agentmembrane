from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .schema import Label, SourceSpan, TaskEpisode, sha256_text


TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9'-]+")
QUALIFIER_RE = re.compile(
    r"\b(?:unless|except|only|provided|subject\s+to|notwithstanding|other\s+than|"
    r"may|shall\s+not|written\s+consent|termination|surviv\w*|retain\w*|return\w*)\b",
    re.IGNORECASE,
)
STOPWORDS = {
    "a", "an", "and", "any", "are", "as", "at", "be", "by", "for", "from",
    "has", "have", "in", "information", "is", "it", "of", "on", "or", "party",
    "shall", "some", "such", "that", "the", "their", "this", "to", "under", "which",
    "with",
}


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tokens(text: str) -> set[str]:
    return {
        token.lower()
        for token in TOKEN_RE.findall(text)
        if token.lower() not in STOPWORDS and len(token) > 2
    }


def _relevance_score(hypothesis: str, text: str) -> tuple[float, bool]:
    hypothesis_tokens = _tokens(hypothesis)
    text_tokens = _tokens(text)
    overlap = (
        len(hypothesis_tokens & text_tokens) / len(hypothesis_tokens)
        if hypothesis_tokens
        else 0.0
    )
    return overlap, bool(QUALIFIER_RE.search(text))


def _source_spans(document: dict[str, Any], *, split: str) -> tuple[SourceSpan, ...]:
    document_id = str(document["id"])
    source_text = document["text"]
    spans: list[SourceSpan] = []
    for index, bounds in enumerate(document["spans"]):
        if (
            not isinstance(bounds, list)
            or len(bounds) != 2
            or any(type(value) is not int for value in bounds)
        ):
            raise ValueError(f"document {document_id} span {index}: malformed bounds")
        start, end = bounds
        if start < 0 or end <= start or end > len(source_text):
            raise ValueError(f"document {document_id} span {index}: out-of-range bounds")
        text = source_text[start:end]
        span = SourceSpan(
            span_id=f"contractnli:{split}:doc{document_id}:span{index}",
            document_id=document_id,
            source_span_index=index,
            start_char=start,
            end_char=end,
            text=text,
            text_sha256=sha256_text(text),
        )
        problems = span.validate()
        if problems:
            raise ValueError(f"{span.span_id}: {';'.join(problems)}")
        spans.append(span)
    return tuple(spans)


def _candidate_ids(
    spans: tuple[SourceSpan, ...],
    *,
    hypothesis: str,
    gold_indices: tuple[int, ...],
    max_candidates: int,
) -> tuple[str, ...]:
    if len(set(gold_indices)) != len(gold_indices):
        raise ValueError("gold evidence indices must be unique")
    # ``max_candidates`` is a target cap for ordinary cases, never permission
    # to truncate gold evidence.  Exceptionally evidence-dense episodes retain
    # every gold span and can be excluded later by an explicit eligibility
    # rule if their prompt size is infeasible.
    effective_max = max(max_candidates, len(gold_indices))
    chosen: list[int] = []

    def add(index: int) -> None:
        if 0 <= index < len(spans) and index not in chosen:
            chosen.append(index)

    for index in gold_indices:
        add(index)
    for index in gold_indices:
        for offset in (-2, -1, 1, 2):
            add(index + offset)
    ranked = sorted(
        (index for index in range(len(spans)) if index not in chosen),
        key=lambda index: (*_relevance_score(hypothesis, spans[index].text), -index),
        reverse=True,
    )
    for index in ranked:
        if len(chosen) >= effective_max:
            break
        add(index)
    return tuple(spans[index].span_id for index in chosen[:effective_max])


def load_contractnli(
    split_path: Path,
    *,
    split: str | None = None,
    max_candidates: int = 30,
) -> tuple[TaskEpisode, ...]:
    """Load exact-source Entailment/Contradiction episodes from an official split."""

    if max_candidates < 6:
        raise ValueError("max_candidates must be at least 6")
    payload = json.loads(split_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("documents"), list):
        raise ValueError("invalid ContractNLI root schema")
    labels = payload.get("labels")
    if not isinstance(labels, dict):
        raise ValueError("ContractNLI labels object missing")
    split_name = split or split_path.stem
    source_hash = file_sha256(split_path)
    episodes: list[TaskEpisode] = []
    for document in payload["documents"]:
        spans = _source_spans(document, split=split_name)
        annotations = document["annotation_sets"][0]["annotations"]
        document_id = str(document["id"])
        for hypothesis_id in sorted(annotations):
            annotation = annotations[hypothesis_id]
            choice = annotation.get("choice")
            gold_indices = tuple(annotation.get("spans") or ())
            if choice not in {Label.ENTAILMENT.value, Label.CONTRADICTION.value}:
                continue
            if not gold_indices:
                raise ValueError(
                    f"{split_name}:doc{document_id}:{hypothesis_id}: labelled case lacks evidence"
                )
            if any(type(index) is not int or not 0 <= index < len(spans) for index in gold_indices):
                raise ValueError(
                    f"{split_name}:doc{document_id}:{hypothesis_id}: invalid gold span index"
                )
            hypothesis = labels[hypothesis_id]["hypothesis"]
            gold_ids = tuple(spans[index].span_id for index in gold_indices)
            candidate_ids = _candidate_ids(
                spans,
                hypothesis=hypothesis,
                gold_indices=gold_indices,
                max_candidates=max_candidates,
            )
            episode = TaskEpisode(
                episode_id=f"contractnli:{split_name}:doc{document_id}:{hypothesis_id}",
                dataset="ContractNLI",
                split=split_name,
                document_id=document_id,
                independence_id=f"contractnli:document:{document_id}",
                hypothesis_id=hypothesis_id,
                hypothesis=hypothesis,
                gold_label=Label(choice),
                source_file_sha256=source_hash,
                spans=spans,
                gold_evidence_ids=gold_ids,
                candidate_span_ids=candidate_ids,
            )
            problems = episode.validate()
            if problems:
                raise ValueError(f"{episode.episode_id}: {';'.join(problems)}")
            episodes.append(episode)
    return tuple(episodes)


def dataset_inventory(episodes: tuple[TaskEpisode, ...]) -> dict[str, Any]:
    label_counts = {
        label.value: sum(episode.gold_label is label for episode in episodes)
        for label in (Label.ENTAILMENT, Label.CONTRADICTION)
    }
    source_hashes = sorted({episode.source_file_sha256 for episode in episodes})
    return {
        "episode_n": len(episodes),
        "independent_document_n": len({episode.independence_id for episode in episodes}),
        "label_counts": label_counts,
        "source_file_sha256": source_hashes[0] if len(source_hashes) == 1 else source_hashes,
        "all_episode_schemas_valid": all(not episode.validate() for episode in episodes),
        "independent_unit": "document_id",
        "candidate_generation": "gold+neighbors+deterministic_lexical_qualifier_rank",
    }
