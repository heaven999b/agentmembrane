from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Operation(StrEnum):
    READ_PUBLIC = "read_public"
    SUBMIT_PROPOSAL = "submit_proposal"
    PERSISTENT_COMMIT = "persistent_commit"
    GRANT_CAPABILITY = "grant_capability"
    CALL_SENSITIVE_TOOL = "call_sensitive_tool"


class Receptor(StrEnum):
    R0 = "R0_evidence_selection"
    R2 = "R2_structured_inference"
    R3 = "R3_recommendation"
    R4 = "R4_free_form"


class PromotionPolicy(StrEnum):
    P0 = "P0_direct_commit"
    P3 = "P3_transitive_taint"
    P5 = "P5_independent_declassification"


class Taint(StrEnum):
    EXTERNAL = "external"
    VERIFIED = "verified"
    TRUSTED = "trusted"


@dataclass(frozen=True)
class Artifact:
    artifact_id: str
    producer: str
    receptor: Receptor
    payload: dict[str, Any]
    evidence_ids: tuple[str, ...]
    semantic_type: str
    taint: Taint = Taint.EXTERNAL
    dependencies: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["receptor"] = self.receptor.value
        value["taint"] = self.taint.value
        value["evidence_ids"] = list(self.evidence_ids)
        value["dependencies"] = list(self.dependencies)
        return value

