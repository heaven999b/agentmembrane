"""Post-hoc analyzer amendment for the completed RQ1 v5-001 namespace.

The production profile bound ``analysis.py`` with two stale v4 design
constants (12 workflows and 12 assignments per four-cell coordinate). The v5
selector and executor correctly contain 7 workflows and 7 assignments per
coordinate, for 28 total episodes. Mutating the bound analyzer after execution
would make the consumed profile unverifiable, so this module applies only that
design-size correction at call time and labels every result as post-hoc.
"""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence, TypeVar

from ..schema import canonical_json_bytes
from . import analysis as _frozen


POSTHOC_ANALYSIS_ARTIFACT_TYPE = (
    "agentmembrane_rq1_public_agentdojo_analysis_posthoc_v5_001"
)
_V5_ASSIGNED_PER_COORDINATE = 7
_V5_INDEPENDENT_WORKFLOWS = 7
_T = TypeVar("_T")


def _with_v5_design_constants(function: Callable[..., _T], *args: Any, **kwargs: Any) -> _T:
    """Invoke the frozen metric code with the two corrected v5 design sizes."""

    old_per_coordinate = _frozen.ASSIGNED_PER_COORDINATE
    old_workflows = _frozen.INDEPENDENT_WORKFLOWS
    if (old_per_coordinate, old_workflows) != (12, 12):
        raise _frozen.PublicAgentDojoAnalysisError(
            "frozen analyzer no longer has the audited v4 constant residue"
        )
    try:
        _frozen.ASSIGNED_PER_COORDINATE = _V5_ASSIGNED_PER_COORDINATE
        _frozen.INDEPENDENT_WORKFLOWS = _V5_INDEPENDENT_WORKFLOWS
        return function(*args, **kwargs)
    finally:
        _frozen.ASSIGNED_PER_COORDINATE = old_per_coordinate
        _frozen.INDEPENDENT_WORKFLOWS = old_workflows


def _label_posthoc(result: Mapping[str, Any]) -> dict[str, Any]:
    labeled = copy.deepcopy(dict(result))
    source_artifact_type = labeled.get("artifact_type")
    labeled["artifact_type"] = POSTHOC_ANALYSIS_ARTIFACT_TYPE
    labeled["posthoc_amendment"] = {
        "pre_registered": False,
        "claim_eligible": False,
        "source_analysis_artifact_type": source_artifact_type,
        "reason": "frozen v5 analyzer retained v4 12-by-12 design constants",
        "changes": {
            "assigned_per_coordinate": {"from": 12, "to": 7},
            "independent_workflows": {"from": 12, "to": 7},
        },
        "metric_logic_changed": False,
        "executor_records_changed": False,
        "executor_report_changed": False,
    }
    canonical_json_bytes(labeled)
    return labeled


def analyze_executor_records(
    cell_records: Sequence[Mapping[str, Any]],
    *,
    executor_report: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    result = _with_v5_design_constants(
        _frozen.analyze_executor_records,
        cell_records,
        executor_report=executor_report,
    )
    return _label_posthoc(result)


def analyze_executor_namespace(namespace_path: Path) -> dict[str, Any]:
    result = _with_v5_design_constants(
        _frozen.analyze_executor_namespace,
        namespace_path,
    )
    return _label_posthoc(result)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("namespace_path", type=Path)
    args = parser.parse_args()
    result = analyze_executor_namespace(args.namespace_path)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "POSTHOC_ANALYSIS_ARTIFACT_TYPE",
    "analyze_executor_namespace",
    "analyze_executor_records",
]
