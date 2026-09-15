"""Host Boundary V2: frozen, fail-closed RQ1--RQ4 experiment harness."""

from .schema import (
    FailureClass,
    IntegrityError,
    PlannerRole,
    RunKind,
    RunState,
    SchemaError,
    TaskOrigin,
)

__all__ = [
    "FailureClass", "IntegrityError", "PlannerRole", "RunKind", "RunState",
    "SchemaError", "TaskOrigin",
]
