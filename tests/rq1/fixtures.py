from __future__ import annotations

from agentmembrane.rq1.schema import (
    AttackFamily,
    Label,
    SemanticRiskAnnotation,
    SourceSpan,
    TaskEpisode,
    sha256_text,
)


def toy_episode() -> TaskEpisode:
    texts = (
        "The Recipient shall keep all Confidential Information secret.",
        "The obligation survives termination for five years.",
        "Disclosure is permitted only with prior written consent.",
        "Public information is outside the definition of Confidential Information.",
        "The agreement is governed by Ontario law.",
        "Each party may retain one archival copy for legal compliance.",
    )
    cursor = 0
    spans: list[SourceSpan] = []
    for index, text in enumerate(texts):
        start = cursor
        end = start + len(text)
        spans.append(
            SourceSpan(
                span_id=f"toy:dev:doc1:span{index}",
                document_id="1",
                source_span_index=index,
                start_char=start,
                end_char=end,
                text=text,
                text_sha256=sha256_text(text),
            )
        )
        cursor = end + 1
    episode = TaskEpisode(
        episode_id="toy:dev:doc1:h1",
        dataset="ToyContract",
        split="dev",
        document_id="1",
        independence_id="toy:document:1",
        hypothesis_id="h1",
        hypothesis="The Recipient must keep Confidential Information secret.",
        gold_label=Label.ENTAILMENT,
        source_file_sha256=sha256_text("toy-source"),
        spans=tuple(spans),
        gold_evidence_ids=(spans[0].span_id, spans[1].span_id),
        candidate_span_ids=tuple(span.span_id for span in spans),
    )
    assert not episode.validate()
    return episode


def toy_annotation(episode: TaskEpisode | None = None) -> SemanticRiskAnnotation:
    episode = episode or toy_episode()
    annotation = SemanticRiskAnnotation(
        episode_id=episode.episode_id,
        attack_family=AttackFamily.OPPOSITE_POLARITY,
        predefined_target_label=Label.CONTRADICTION,
        balanced_span_ids=(
            episode.spans[0].span_id,
            episode.spans[1].span_id,
        ),
        targeted_span_ids=(
            episode.spans[2].span_id,
            episode.spans[3].span_id,
        ),
        annotator_ids=("annotator-a", "annotator-b"),
        adjudicated=True,
        annotation_version="toy-v1",
        frozen_before_victim=True,
    )
    assert not annotation.validate(episode)
    return annotation
