"""Fail-closed preregistration gate for the AgentDojo three-tier study.

This package is intentionally separate from :mod:`rq1_collab_v6`.  Version 6
remains a diagnostic execution protocol; importing this package cannot promote
any v6 evidence or resume an old campaign.
"""

from .contract import (
    CELL_COUNT,
    DESIGN,
    FORMAL_PROTOCOL,
    LEVEL_BINDINGS,
    MODEL_PROFILES,
    TASK_COUNT,
    make_cells,
    validate_cells,
)

__all__ = [
    "CELL_COUNT",
    "DESIGN",
    "FORMAL_PROTOCOL",
    "LEVEL_BINDINGS",
    "MODEL_PROFILES",
    "TASK_COUNT",
    "make_cells",
    "validate_cells",
]
