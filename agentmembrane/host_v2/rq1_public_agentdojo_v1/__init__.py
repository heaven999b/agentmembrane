"""Canonical RQ1 AgentDojo host-integration engineering slice v1."""

from typing import Any

from .checker_hook import OfflineExactStateCheckerHook
from .host import RQ1AgentDojoHostSession


def run_zero_token_four_cell_gate() -> dict[str, Any]:
    """Load and run the gate lazily so ``python -m ...gate`` stays clean."""

    from .gate import run_zero_token_four_cell_gate as run_gate

    return run_gate()

__all__ = [
    "OfflineExactStateCheckerHook",
    "RQ1AgentDojoHostSession",
    "run_zero_token_four_cell_gate",
]
