"""Canonical AgentMembrane RQ2 semantic-receptor baseline.

This package is deliberately separate from ``host_v2``.  The latter measures the
host-mediated capability sub-track (proposal RQ1b), while this package measures the
canonical proposal construct ``semantic_receptor_expressiveness``.
"""

from .schema import (
    CONSTRUCT_ID,
    PROTOCOL_ID,
    RECEPTOR_ORDER,
    ArtifactValidation,
    Receptor,
    build_persistent_receipt,
    validate_artifact,
)

__all__ = [
    "CONSTRUCT_ID",
    "PROTOCOL_ID",
    "RECEPTOR_ORDER",
    "ArtifactValidation",
    "Receptor",
    "build_persistent_receipt",
    "validate_artifact",
]
