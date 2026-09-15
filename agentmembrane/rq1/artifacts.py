from __future__ import annotations

import hashlib
import itertools
import json
import random
from dataclasses import replace
from typing import Iterable

from .schema import (
    ArtifactCondition,
    AttackFamily,
    EvidenceMemo,
    EvidenceRef,
    SemanticRiskAnnotation,
    SemanticType,
    TaskEpisode,
    canonical_json,
    validate_condition_blind_id,
)


OUTPUT_CONTRACT_VERSION = "rq1-extractive-evidence-v1"
ARTIFACT_TYPE = "extractive_evidence_memo"
PRODUCER_PRINCIPAL = "external_analyst"


class RandomMatchError(ValueError):
    """Raised when no honest matched-random control can be constructed."""


def _opaque_id(prefix: str, *parts: object, length: int) -> str:
    material = "\0".join(str(part) for part in parts).encode("utf-8")
    return f"{prefix}-{hashlib.sha256(material).hexdigest()[:length]}"


def condition_blind_id(
    episode_id: str,
    condition: ArtifactCondition,
    *,
    attack_family: AttackFamily,
    blind_salt: str,
    draw_id: int = 0,
) -> str:
    if not blind_salt:
        raise ValueError("blind_salt must be non-empty")
    if type(draw_id) is not int or draw_id < 0:
        raise ValueError("draw_id must be a non-negative integer")
    return _opaque_id(
        "c",
        blind_salt,
        episode_id,
        attack_family.value,
        condition.value,
        draw_id,
        length=16,
    )


def _memo(
    episode: TaskEpisode,
    *,
    selected_span_ids: Iterable[str],
    condition: ArtifactCondition,
    attack_family: AttackFamily,
    blind_salt: str,
    draw_id: int = 0,
) -> EvidenceMemo:
    selected = tuple(selected_span_ids)
    span_map = episode.span_map()
    if not selected or len(selected) != len(set(selected)):
        raise ValueError("selected span IDs must be a non-empty unique sequence")
    missing = set(selected) - set(episode.candidate_span_ids)
    if missing:
        raise ValueError(f"selected spans outside frozen candidate pool: {sorted(missing)}")
    refs = tuple(
        EvidenceRef(span_id=span_id, text_sha256=span_map[span_id].text_sha256)
        for span_id in selected
    )
    blind_id = condition_blind_id(
        episode.episode_id,
        condition,
        attack_family=attack_family,
        blind_salt=blind_salt,
        draw_id=draw_id,
    )
    artifact_id = _opaque_id(
        "a",
        blind_salt,
        episode.episode_id,
        attack_family.value,
        condition.value,
        draw_id,
        *(ref.span_id for ref in refs),
        length=24,
    )
    memo = EvidenceMemo(
        artifact_id=artifact_id,
        episode_id=episode.episode_id,
        producer_principal=PRODUCER_PRINCIPAL,
        artifact_type=ARTIFACT_TYPE,
        semantic_type=SemanticType.EVIDENCE,
        coverage="partial",
        completeness_guarantee=False,
        evidence_refs=refs,
        free_text_claims=(),
        future_instructions=(),
        output_contract_version=OUTPUT_CONTRACT_VERSION,
        condition_blind_id=blind_id,
    )
    problems = validate_memo(memo, episode, expected_selected_ids=selected)
    if problems:
        raise ValueError("invalid constructed memo: " + ";".join(problems))
    return memo


def _validate_annotation(
    episode: TaskEpisode, annotation: SemanticRiskAnnotation
) -> None:
    problems = annotation.validate(episode)
    if problems:
        raise ValueError("invalid semantic-risk annotation: " + ";".join(problems))


def build_balanced_memo(
    episode: TaskEpisode,
    annotation: SemanticRiskAnnotation,
    *,
    blind_salt: str,
) -> EvidenceMemo:
    _validate_annotation(episode, annotation)
    return _memo(
        episode,
        selected_span_ids=annotation.balanced_span_ids,
        condition=ArtifactCondition.BALANCED,
        attack_family=annotation.attack_family,
        blind_salt=blind_salt,
    )


def build_targeted_memo(
    episode: TaskEpisode,
    annotation: SemanticRiskAnnotation,
    *,
    blind_salt: str,
) -> EvidenceMemo:
    _validate_annotation(episode, annotation)
    return _memo(
        episode,
        selected_span_ids=annotation.targeted_span_ids,
        condition=ArtifactCondition.TARGETED_EXTRACTIVE,
        attack_family=annotation.attack_family,
        blind_salt=blind_salt,
    )


def _candidate_random_subsets(
    candidate_ids: tuple[str, ...],
    *,
    subset_size: int,
    seed: int,
    maximum_trials: int,
) -> tuple[tuple[str, ...], ...]:
    combination_n = 1
    for numerator, denominator in zip(
        range(len(candidate_ids) - subset_size + 1, len(candidate_ids) + 1),
        range(1, subset_size + 1),
    ):
        combination_n = combination_n * numerator // denominator

    if combination_n <= maximum_trials:
        values = list(itertools.combinations(candidate_ids, subset_size))
        random.Random(seed).shuffle(values)
        return tuple(values)

    generator = random.Random(seed)
    seen: set[tuple[str, ...]] = set()
    ordered = {span_id: index for index, span_id in enumerate(candidate_ids)}
    while len(seen) < maximum_trials:
        sample = tuple(
            sorted(generator.sample(candidate_ids, subset_size), key=ordered.__getitem__)
        )
        seen.add(sample)
    return tuple(seen)


def build_random_memo(
    episode: TaskEpisode,
    annotation: SemanticRiskAnnotation,
    *,
    blind_salt: str,
    random_seed: int,
    draw_id: int = 0,
    maximum_relative_length_delta: float = 0.20,
    maximum_trials: int = 20_000,
) -> EvidenceMemo:
    """Build a deterministic matched-random control.

    A random memo has the targeted memo's span count and approximately its
    exact-source character count.  It cannot equal either curated selection.
    Different draws are nested perturbations of the same episode, never new
    independent observations.
    """

    _validate_annotation(episode, annotation)
    if type(random_seed) is not int:
        raise ValueError("random_seed must be an integer")
    if type(draw_id) is not int or draw_id < 0:
        raise ValueError("draw_id must be a non-negative integer")
    if not 0.0 <= maximum_relative_length_delta <= 1.0:
        raise ValueError("maximum_relative_length_delta must be in [0, 1]")
    if maximum_trials < 1:
        raise ValueError("maximum_trials must be positive")

    subset_size = len(annotation.targeted_span_ids)
    candidates = episode.candidate_span_ids
    if subset_size > len(candidates):
        raise RandomMatchError("targeted selection is larger than the candidate pool")
    excluded = {
        frozenset(annotation.targeted_span_ids),
        frozenset(annotation.balanced_span_ids),
    }
    span_map = episode.span_map()
    target_chars = sum(len(span_map[span_id].text) for span_id in annotation.targeted_span_ids)
    denominator = max(1, target_chars)
    proposals = _candidate_random_subsets(
        candidates,
        subset_size=subset_size,
        seed=random_seed + draw_id * 1_000_003,
        maximum_trials=maximum_trials,
    )
    admissible = [selection for selection in proposals if frozenset(selection) not in excluded]
    if not admissible:
        raise RandomMatchError("no non-curated random subset exists")
    scored = sorted(
        admissible,
        key=lambda selection: (
            abs(sum(len(span_map[item].text) for item in selection) - target_chars),
            hashlib.sha256(
                f"{random_seed}\0{draw_id}\0{'|'.join(selection)}".encode("utf-8")
            ).hexdigest(),
        ),
    )
    selected = scored[0]
    selected_chars = sum(len(span_map[span_id].text) for span_id in selected)
    relative_delta = abs(selected_chars - target_chars) / denominator
    if relative_delta > maximum_relative_length_delta:
        raise RandomMatchError(
            "closest random control misses length tolerance: "
            f"delta={relative_delta:.6f}, tolerance={maximum_relative_length_delta:.6f}"
        )
    return _memo(
        episode,
        selected_span_ids=selected,
        condition=ArtifactCondition.RANDOM_OMISSION,
        attack_family=annotation.attack_family,
        blind_salt=blind_salt,
        draw_id=draw_id,
    )


def validate_memo(
    memo: EvidenceMemo,
    episode: TaskEpisode,
    *,
    expected_selected_ids: Iterable[str] | None = None,
) -> tuple[str, ...]:
    """Deterministically enforce the fact-preserving artifact boundary."""

    problems: list[str] = []
    if memo.episode_id != episode.episode_id:
        problems.append("memo_episode_mismatch")
    if not memo.artifact_id.startswith("a-") or len(memo.artifact_id) != 26:
        problems.append("artifact_id_not_opaque")
    if memo.producer_principal != PRODUCER_PRINCIPAL:
        problems.append("unexpected_producer_principal")
    if memo.artifact_type != ARTIFACT_TYPE:
        problems.append("artifact_type_invalid")
    if memo.semantic_type != SemanticType.EVIDENCE:
        problems.append("semantic_type_invalid")
    if memo.coverage != "partial" or memo.completeness_guarantee is not False:
        problems.append("coverage_contract_invalid")
    if memo.free_text_claims:
        problems.append("free_text_claims_forbidden")
    if memo.future_instructions:
        problems.append("future_instructions_forbidden")
    if memo.output_contract_version != OUTPUT_CONTRACT_VERSION:
        problems.append("output_contract_version_invalid")
    if not validate_condition_blind_id(memo.condition_blind_id):
        problems.append("condition_blind_id_invalid")

    ids = tuple(ref.span_id for ref in memo.evidence_refs)
    if not ids or len(ids) != len(set(ids)):
        problems.append("evidence_refs_invalid")
    span_map = episode.span_map()
    if not set(ids).issubset(episode.candidate_span_ids):
        problems.append("evidence_outside_candidate_pool")
    for ref in memo.evidence_refs:
        source = span_map.get(ref.span_id)
        if source is None:
            problems.append(f"unknown_span:{ref.span_id}")
        elif source.text_sha256 != ref.text_sha256:
            problems.append(f"source_hash_mismatch:{ref.span_id}")
    if expected_selected_ids is not None and ids != tuple(expected_selected_ids):
        problems.append("selected_span_sequence_mismatch")
    return tuple(problems)


def render_memo(memo: EvidenceMemo, episode: TaskEpisode) -> str:
    """Render only exact source slices; never synthesize artifact prose."""

    problems = validate_memo(memo, episode)
    if problems:
        raise ValueError("cannot render invalid memo: " + ";".join(problems))
    span_map = episode.span_map()
    payload = memo.to_dict()
    payload["evidence"] = [
        {
            "span_id": ref.span_id,
            "text": span_map[ref.span_id].text,
            "text_sha256": ref.text_sha256,
        }
        for ref in memo.evidence_refs
    ]
    del payload["evidence_refs"]
    return canonical_json(payload)


def memo_with_refs(memo: EvidenceMemo, refs: tuple[EvidenceRef, ...]) -> EvidenceMemo:
    """Test helper for constructing tampered copies without mutating originals."""

    return replace(memo, evidence_refs=refs)


def parse_rendered_memo(value: str) -> dict[str, object]:
    """Strict JSON parsing helper used by offline conformance tests."""

    payload = json.loads(value)
    if not isinstance(payload, dict):
        raise ValueError("rendered memo root must be an object")
    return payload
