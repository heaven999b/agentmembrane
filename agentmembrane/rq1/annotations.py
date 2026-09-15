from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .schema import AttackFamily, Label, SemanticRiskAnnotation, TaskEpisode


ANNOTATION_MANIFEST_SCHEMA = "rq1-semantic-risk-annotations-v1"


def load_annotation_manifest(
    path: Path,
    *,
    episodes: Iterable[TaskEpisode],
) -> tuple[SemanticRiskAnnotation, ...]:
    """Load a frozen, adjudicated annotation manifest for victim execution."""

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("annotation manifest root must be an object")
    if payload.get("schema") != ANNOTATION_MANIFEST_SCHEMA:
        raise ValueError("annotation manifest schema mismatch")
    if payload.get("victim_outputs_seen") is not False:
        raise ValueError("manifest must certify victim_outputs_seen=false")
    if payload.get("frozen_before_victim") is not True:
        raise ValueError("manifest must be frozen before victim execution")
    annotation_version = payload.get("annotation_version")
    if not isinstance(annotation_version, str) or not annotation_version:
        raise ValueError("annotation_version must be a non-empty string")
    entries = payload.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("annotation manifest entries must be a non-empty list")

    episode_lookup = {episode.episode_id: episode for episode in episodes}
    annotations: list[SemanticRiskAnnotation] = []
    seen_cases: set[tuple[str, AttackFamily]] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"annotation entry {index} must be an object")
        try:
            annotation = SemanticRiskAnnotation(
                episode_id=entry["episode_id"],
                attack_family=AttackFamily(entry["attack_family"]),
                predefined_target_label=Label(entry["predefined_target_label"]),
                balanced_span_ids=tuple(entry["balanced_span_ids"]),
                targeted_span_ids=tuple(entry["targeted_span_ids"]),
                annotator_ids=tuple(entry["annotator_ids"]),
                adjudicated=entry["adjudicated"],
                annotation_version=annotation_version,
                frozen_before_victim=True,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"annotation entry {index} is malformed") from exc
        if type(annotation.adjudicated) is not bool:
            raise ValueError(f"annotation entry {index}: adjudicated must be boolean")
        episode = episode_lookup.get(annotation.episode_id)
        if episode is None:
            raise ValueError(f"annotation entry {index}: unknown episode")
        case_key = (annotation.episode_id, annotation.attack_family)
        if case_key in seen_cases:
            raise ValueError(f"annotation entry {index}: duplicate attack case")
        seen_cases.add(case_key)
        problems = annotation.validate(episode)
        if problems:
            raise ValueError(
                f"annotation entry {index} failed validation: {';'.join(problems)}"
            )
        annotations.append(annotation)
    return tuple(annotations)
