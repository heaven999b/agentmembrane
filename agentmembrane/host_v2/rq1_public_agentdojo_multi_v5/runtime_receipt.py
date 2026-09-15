"""RQ1 v5 binding to the already frozen AgentDojo v4 runtime bytes.

Only the ordinary-agent model changes in v5. Reusing the validated v4
AgentDojo checkout and environment keeps benchmark/runtime bytes identical
across the strong- and weak-model baselines instead of adding a confounder.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from ..runtime_provisioning import ProvisioningReceipt
from ..rq1_public_agentdojo_multi_v4.runtime_receipt import (
    V4_CHECKOUT_RELATIVE,
    V4_RECEIPT_FILENAME,
    V4_RUNTIME_ENVIRONMENT_NAME,
    v4_runtime_expectation,
    validate_v4_runtime_receipt,
)


V5_RUNTIME_ENVIRONMENT_NAME = V4_RUNTIME_ENVIRONMENT_NAME
V5_RECEIPT_FILENAME = V4_RECEIPT_FILENAME
V5_CHECKOUT_RELATIVE = V4_CHECKOUT_RELATIVE


def v5_runtime_expectation(*, repo_root: str | Path):
    return v4_runtime_expectation(repo_root=repo_root)


def validate_v5_runtime_receipt(
    value: Mapping[str, Any] | ProvisioningReceipt,
    *,
    expected_receipt_sha256: str,
    repo_root: str | Path,
) -> dict[str, Any]:
    result = validate_v4_runtime_receipt(
        value,
        expected_receipt_sha256=expected_receipt_sha256,
        repo_root=repo_root,
    )
    return {
        **result,
        "artifact_type": "agentmembrane_rq1_v5_import_only_runtime_preflight",
        "reused_immutable_runtime_from": "rq1_public_agentdojo_multi_v4",
    }


__all__ = [
    "V5_CHECKOUT_RELATIVE",
    "V5_RECEIPT_FILENAME",
    "V5_RUNTIME_ENVIRONMENT_NAME",
    "v5_runtime_expectation",
    "validate_v5_runtime_receipt",
]
