"""Canonical original RQ1: Authority--Semantic Separation.

The package intentionally does not import the later ``semantic_rq2`` or
``host_v2/rq1_*`` experiment families.  Official source data and the generic
capability kernel are the only reusable dependencies.
"""

from .artifacts import (
    RandomMatchError,
    build_balanced_memo,
    build_random_memo,
    build_targeted_memo,
    render_memo,
    validate_memo,
)
from .annotations import ANNOTATION_MANIFEST_SCHEMA, load_annotation_manifest
from .contractnli import dataset_inventory, load_contractnli
from .data_hygiene import (
    ConsumedDocumentInventory,
    discover_consumed_documents,
    exclude_consumed_episodes,
)
from .design import AttackCase, RunCell, build_core_schedule, validate_core_schedule
from .runtime import OriginBoundMemoryRuntime
from .stats import ClusterContrast, OutcomeObservation, cluster_contrast
from .schema import (
    ArtifactCondition,
    AttackFamily,
    DecisionAction,
    DecisionPolicy,
    EvidenceMemo,
    ExposureMode,
    FutureDecision,
    Label,
    MemoryRecord,
    SemanticRiskAnnotation,
    SourceSpan,
    TaskEpisode,
)

__all__ = [
    "ArtifactCondition",
    "ANNOTATION_MANIFEST_SCHEMA",
    "AttackFamily",
    "AttackCase",
    "ClusterContrast",
    "ConsumedDocumentInventory",
    "DecisionAction",
    "DecisionPolicy",
    "EvidenceMemo",
    "ExposureMode",
    "FutureDecision",
    "Label",
    "MemoryRecord",
    "OriginBoundMemoryRuntime",
    "OutcomeObservation",
    "RandomMatchError",
    "RunCell",
    "SemanticRiskAnnotation",
    "SourceSpan",
    "TaskEpisode",
    "build_balanced_memo",
    "build_core_schedule",
    "build_random_memo",
    "build_targeted_memo",
    "cluster_contrast",
    "dataset_inventory",
    "discover_consumed_documents",
    "exclude_consumed_episodes",
    "load_contractnli",
    "load_annotation_manifest",
    "render_memo",
    "validate_core_schedule",
    "validate_memo",
]
