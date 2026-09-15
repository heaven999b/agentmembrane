"""Deterministic NO-GO evidence for the native-runtime provisioning Gate.

The artifact binds validated provisioning receipts and synthetic projected
checker outputs while keeping task execution, parity, runtime-probe network,
provider/model/API calls, and every scientific run authorization at zero/false.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Sequence

from .projected_checker import ProjectedCheckerResult
from .runtime_provisioning import (
    RunAuthorizations,
    ValidatedProvisioningReceipt,
    receipt_payload_sha256,
)
from .schema import IntegrityError, SchemaError, canonical_json_bytes, sha256_bytes


PUBLIC_RUNTIME_EVIDENCE_SCHEMA_VERSION = 1
PUBLIC_RUNTIME_EVIDENCE_ARTIFACT_TYPE = (
    "agentmembrane_native_runtime_projected_checker_offline_gate"
)


@dataclass(frozen=True)
class RuntimeReceiptReference:
    runtime_id: str
    benchmark: str
    upstream_version_or_commit: str
    receipt_sha256: str
    receipt_payload_sha256: str
    environment_tree_sha256: str
    upstream_tree_sha256: str
    uv_wheel_sha256: str
    uv_executable_sha256: str

    def as_json(self) -> dict[str, str]:
        return {
            "runtime_id": self.runtime_id,
            "benchmark": self.benchmark,
            "upstream_version_or_commit": self.upstream_version_or_commit,
            "receipt_sha256": self.receipt_sha256,
            "receipt_payload_sha256": self.receipt_payload_sha256,
            "environment_tree_sha256": self.environment_tree_sha256,
            "upstream_tree_sha256": self.upstream_tree_sha256,
            "uv_wheel_sha256": self.uv_wheel_sha256,
            "uv_executable_sha256": self.uv_executable_sha256,
        }


@dataclass(frozen=True)
class ProjectedCheckerReference:
    benchmark: str
    task_id: str
    trace_id: str
    input_sha256: str
    checker_implementation_sha256: str
    output_sha256: str
    checker_complete: bool
    decision: str

    def as_json(self) -> dict[str, Any]:
        return {
            "benchmark": self.benchmark,
            "task_id": self.task_id,
            "trace_id": self.trace_id,
            "input_sha256": self.input_sha256,
            "checker_implementation_sha256": self.checker_implementation_sha256,
            "output_sha256": self.output_sha256,
            "checker_complete": self.checker_complete,
            "decision": self.decision,
        }


@dataclass(frozen=True)
class OfflineExecutionEvidence:
    task_executions: int
    parity_executions: int
    native_checker_executions: int
    runtime_probe_network_attempts: int
    provider_calls: int
    model_calls: int
    api_calls: int
    approved_provisioning_downloads: int
    synthetic_projected_checker_evaluations: int

    def as_json(self) -> dict[str, int]:
        return {
            "task_executions": self.task_executions,
            "parity_executions": self.parity_executions,
            "native_checker_executions": self.native_checker_executions,
            "runtime_probe_network_attempts": self.runtime_probe_network_attempts,
            "provider_calls": self.provider_calls,
            "model_calls": self.model_calls,
            "api_calls": self.api_calls,
            "approved_provisioning_downloads": self.approved_provisioning_downloads,
            "synthetic_projected_checker_evaluations": (
                self.synthetic_projected_checker_evaluations
            ),
        }


@dataclass(frozen=True)
class ScientificClaims:
    native_checker_parity_established: bool
    public_readiness_established: bool
    calibration_completed: bool
    formal_results_claimed: bool

    def as_json(self) -> dict[str, bool]:
        return {
            "native_checker_parity_established": self.native_checker_parity_established,
            "public_readiness_established": self.public_readiness_established,
            "calibration_completed": self.calibration_completed,
            "formal_results_claimed": self.formal_results_claimed,
        }


@dataclass(frozen=True)
class PublicRuntimeEvidence:
    schema_version: int
    artifact_type: str
    gate_id: str
    generated_at: str
    required_runtime_ids: tuple[str, ...]
    runtime_receipts: tuple[RuntimeReceiptReference, ...]
    projected_checker_results: tuple[ProjectedCheckerReference, ...]
    offline_execution: OfflineExecutionEvidence
    run_authorizations: RunAuthorizations
    scientific_claims: ScientificClaims
    blocker_codes: tuple[str, ...]
    decision: str
    artifact_sha256: str

    def payload_json(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "artifact_type": self.artifact_type,
            "gate_id": self.gate_id,
            "generated_at": self.generated_at,
            "required_runtime_ids": list(self.required_runtime_ids),
            "runtime_receipts": [item.as_json() for item in self.runtime_receipts],
            "projected_checker_results": [
                item.as_json() for item in self.projected_checker_results
            ],
            "offline_execution": self.offline_execution.as_json(),
            "run_authorizations": self.run_authorizations.as_json(),
            "scientific_claims": self.scientific_claims.as_json(),
            "blocker_codes": list(self.blocker_codes),
            "decision": self.decision,
        }

    def as_json(self) -> dict[str, Any]:
        return {**self.payload_json(), "artifact_sha256": self.artifact_sha256}


def _false_authorizations() -> RunAuthorizations:
    return RunAuthorizations(
        task_execution=False,
        checker_parity=False,
        calibration=False,
        formal_run=False,
        public_run=False,
        provider_calls=False,
        model_calls=False,
        api_calls=False,
    )


def _false_claims() -> ScientificClaims:
    return ScientificClaims(
        native_checker_parity_established=False,
        public_readiness_established=False,
        calibration_completed=False,
        formal_results_claimed=False,
    )


def build_public_runtime_evidence(
    *,
    gate_id: str,
    generated_at: str,
    receipts: Sequence[ValidatedProvisioningReceipt] = (),
    projected_results: Sequence[ProjectedCheckerResult] = (),
    required_runtime_ids: Sequence[str] = (
        "agentdojo-0.1.35-py3123-lock-395e3d0a5921",
        "tau2-py3123-lock-62d3a8c4807b",
    ),
) -> PublicRuntimeEvidence:
    """Bind validated inputs into an explicit, non-authorizing NO-GO artifact."""

    if not isinstance(gate_id, str) or not gate_id.strip():
        raise SchemaError("gate_id must be a nonempty string")
    _validate_timestamp(generated_at)
    required = tuple(sorted(_unique_strings(required_runtime_ids, "required_runtime_ids")))
    receipt_refs: list[RuntimeReceiptReference] = []
    provisioning_downloads = 0
    for index, validated in enumerate(receipts):
        if not isinstance(validated, ValidatedProvisioningReceipt):
            raise SchemaError(
                f"receipts[{index}] must be a ValidatedProvisioningReceipt"
            )
        receipt = validated.receipt
        if receipt.payload_sha256 != receipt_payload_sha256(receipt):
            raise IntegrityError("validated receipt payload SHA-256 no longer matches")
        if validated.receipt_sha256 != sha256_bytes(
            canonical_json_bytes(receipt.as_json())
        ):
            raise IntegrityError("validated receipt SHA-256 no longer matches receipt")
        forbidden_count_fields = (
            "task_executions", "parity_executions", "native_checker_executions",
            "provider_calls", "model_calls", "api_calls",
            "runtime_probe_network_attempts",
        )
        if any(
            getattr(receipt.execution_counts, field) != 0
            for field in forbidden_count_fields
        ):
            raise IntegrityError("runtime receipt is not offline Gate evidence")
        if any(receipt.authorizations.as_json().values()):
            raise IntegrityError("runtime receipt contains a run authorization")
        if (
            receipt.upstream.tree_manifest_pre_sha256
            != receipt.upstream.tree_manifest_post_sha256
        ):
            raise IntegrityError("runtime receipt records upstream mutation")
        receipt_refs.append(
            RuntimeReceiptReference(
                runtime_id=receipt.runtime_id,
                benchmark=receipt.benchmark,
                upstream_version_or_commit=receipt.upstream_version_or_commit,
                receipt_sha256=validated.receipt_sha256,
                receipt_payload_sha256=receipt.payload_sha256,
                environment_tree_sha256=receipt.environment.tree_sha256,
                upstream_tree_sha256=receipt.upstream.tree_manifest_post_sha256,
                uv_wheel_sha256=receipt.bootstrap.wheel_sha256,
                uv_executable_sha256=receipt.bootstrap.uv_executable_sha256,
            )
        )
        provisioning_downloads += receipt.execution_counts.provisioning_downloads
    receipt_refs.sort(key=lambda item: item.runtime_id)
    runtime_ids = tuple(item.runtime_id for item in receipt_refs)
    if len(runtime_ids) != len(set(runtime_ids)):
        raise IntegrityError("public runtime evidence contains duplicate runtime IDs")

    projected_refs: list[ProjectedCheckerReference] = []
    for index, result in enumerate(projected_results):
        if not isinstance(result, ProjectedCheckerResult):
            raise SchemaError(
                f"projected_results[{index}] must be a ProjectedCheckerResult"
            )
        if result.decision != "NO_GO":
            raise IntegrityError("projected checker result must remain NO_GO")
        if result.output_sha256 != sha256_bytes(
            canonical_json_bytes(result._payload_json())
        ):
            raise IntegrityError("projected checker output SHA-256 mismatch")
        projected_refs.append(
            ProjectedCheckerReference(
                benchmark=result.benchmark,
                task_id=result.task_id,
                trace_id=result.trace_id,
                input_sha256=result.input_sha256,
                checker_implementation_sha256=result.checker_implementation_sha256,
                output_sha256=result.output_sha256,
                checker_complete=result.checker_complete,
                decision=result.decision,
            )
        )
    projected_refs.sort(key=lambda item: (item.benchmark, item.task_id, item.trace_id))

    blockers = {
        "NATIVE_CHECKER_PARITY_NOT_EXECUTED",
        "PUBLIC_READINESS_NOT_ESTABLISHED",
        "RUN_AUTHORIZATION_WITHHELD",
    }
    missing = sorted(set(required) - set(runtime_ids))
    if missing:
        blockers.add("REQUIRED_RUNTIME_RECEIPT_MISSING")
    if any(not item.checker_complete for item in projected_refs):
        blockers.add("PROJECTED_CHECKER_EVIDENCE_INSUFFICIENT")
    offline = OfflineExecutionEvidence(
        task_executions=0,
        parity_executions=0,
        native_checker_executions=0,
        runtime_probe_network_attempts=0,
        provider_calls=0,
        model_calls=0,
        api_calls=0,
        approved_provisioning_downloads=provisioning_downloads,
        synthetic_projected_checker_evaluations=len(projected_refs),
    )
    artifact = PublicRuntimeEvidence(
        schema_version=PUBLIC_RUNTIME_EVIDENCE_SCHEMA_VERSION,
        artifact_type=PUBLIC_RUNTIME_EVIDENCE_ARTIFACT_TYPE,
        gate_id=gate_id,
        generated_at=generated_at,
        required_runtime_ids=required,
        runtime_receipts=tuple(receipt_refs),
        projected_checker_results=tuple(projected_refs),
        offline_execution=offline,
        run_authorizations=_false_authorizations(),
        scientific_claims=_false_claims(),
        blocker_codes=tuple(sorted(blockers)),
        decision="NO_GO",
        artifact_sha256="",
    )
    return PublicRuntimeEvidence(
        **{
            **artifact.__dict__,
            "artifact_sha256": sha256_bytes(
                canonical_json_bytes(artifact.payload_json())
            ),
        }
    )


def _validate_timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value.endswith("Z") or "T" not in value:
        raise SchemaError("generated_at must be an RFC 3339 UTC timestamp")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise SchemaError(f"generated_at is invalid: {exc}") from exc
    return value


def _unique_strings(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise SchemaError(f"{label} must be a list or tuple")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise SchemaError(f"{label} items must be nonempty strings")
        result.append(item)
    if len(result) != len(set(result)):
        raise IntegrityError(f"{label} must not contain duplicates")
    return tuple(result)


def _sha(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise SchemaError(f"{label} must be a lowercase SHA-256")
    return value


def _exact(value: Any, fields: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SchemaError(f"{label} must be an object")
    missing = sorted(fields - set(value))
    unknown = sorted(set(value) - fields)
    if missing or unknown:
        raise SchemaError(f"{label} fields invalid: missing={missing}, unknown={unknown}")
    return value


def validate_public_runtime_evidence(
    value: Mapping[str, Any] | PublicRuntimeEvidence,
) -> PublicRuntimeEvidence:
    """Strictly parse and verify a serialized offline Gate artifact."""

    raw = value.as_json() if isinstance(value, PublicRuntimeEvidence) else value
    item = _exact(
        raw,
        {
            "schema_version", "artifact_type", "gate_id", "generated_at",
            "required_runtime_ids", "runtime_receipts", "projected_checker_results",
            "offline_execution", "run_authorizations", "scientific_claims",
            "blocker_codes", "decision", "artifact_sha256",
        },
        "public runtime evidence",
    )
    if item["schema_version"] != PUBLIC_RUNTIME_EVIDENCE_SCHEMA_VERSION:
        raise SchemaError("public runtime evidence schema_version must equal 1")
    if item["artifact_type"] != PUBLIC_RUNTIME_EVIDENCE_ARTIFACT_TYPE:
        raise SchemaError("invalid public runtime evidence artifact_type")
    gate_id = item["gate_id"]
    if not isinstance(gate_id, str) or not gate_id.strip():
        raise SchemaError("public runtime evidence gate_id must be nonempty")
    generated_at = _validate_timestamp(item["generated_at"])
    required = _unique_strings(item["required_runtime_ids"], "required_runtime_ids")
    if required != tuple(sorted(required)):
        raise IntegrityError("required_runtime_ids must be sorted")

    raw_receipts = item["runtime_receipts"]
    if not isinstance(raw_receipts, list):
        raise SchemaError("runtime_receipts must be a list")
    receipt_refs: list[RuntimeReceiptReference] = []
    receipt_fields = {
        "runtime_id", "benchmark", "upstream_version_or_commit", "receipt_sha256",
        "receipt_payload_sha256", "environment_tree_sha256", "upstream_tree_sha256",
        "uv_wheel_sha256", "uv_executable_sha256",
    }
    for index, raw_receipt in enumerate(raw_receipts):
        entry = _exact(raw_receipt, receipt_fields, f"runtime_receipts[{index}]")
        for field in ("runtime_id", "benchmark", "upstream_version_or_commit"):
            if not isinstance(entry[field], str) or not entry[field].strip():
                raise SchemaError(f"runtime_receipts[{index}].{field} invalid")
        for field in receipt_fields - {
            "runtime_id", "benchmark", "upstream_version_or_commit"
        }:
            _sha(entry[field], f"runtime_receipts[{index}].{field}")
        receipt_refs.append(RuntimeReceiptReference(**entry))
    if receipt_refs != sorted(receipt_refs, key=lambda row: row.runtime_id):
        raise IntegrityError("runtime_receipts must be sorted by runtime_id")
    if len({row.runtime_id for row in receipt_refs}) != len(receipt_refs):
        raise IntegrityError("runtime_receipts contains duplicate runtime IDs")

    raw_projected = item["projected_checker_results"]
    if not isinstance(raw_projected, list):
        raise SchemaError("projected_checker_results must be a list")
    projected_refs: list[ProjectedCheckerReference] = []
    projected_fields = {
        "benchmark", "task_id", "trace_id", "input_sha256",
        "checker_implementation_sha256", "output_sha256", "checker_complete", "decision",
    }
    for index, raw_result in enumerate(raw_projected):
        entry = _exact(raw_result, projected_fields, f"projected_results[{index}]")
        for field in ("benchmark", "task_id", "trace_id"):
            if not isinstance(entry[field], str) or not entry[field].strip():
                raise SchemaError(f"projected_results[{index}].{field} invalid")
        for field in ("input_sha256", "checker_implementation_sha256", "output_sha256"):
            _sha(entry[field], f"projected_results[{index}].{field}")
        if not isinstance(entry["checker_complete"], bool):
            raise SchemaError("projected checker_complete must be boolean")
        if entry["decision"] != "NO_GO":
            raise IntegrityError("projected checker reference must remain NO_GO")
        projected_refs.append(ProjectedCheckerReference(**entry))
    if projected_refs != sorted(
        projected_refs, key=lambda row: (row.benchmark, row.task_id, row.trace_id)
    ):
        raise IntegrityError("projected_checker_results must be canonically sorted")

    execution_fields = {
        "task_executions", "parity_executions", "native_checker_executions",
        "runtime_probe_network_attempts", "provider_calls", "model_calls", "api_calls",
        "approved_provisioning_downloads", "synthetic_projected_checker_evaluations",
    }
    execution = _exact(item["offline_execution"], execution_fields, "offline_execution")
    for field in execution_fields:
        if (
            not isinstance(execution[field], int)
            or isinstance(execution[field], bool)
            or execution[field] < 0
        ):
            raise SchemaError(f"offline_execution.{field} invalid")
    for field in execution_fields - {
        "approved_provisioning_downloads",
        "synthetic_projected_checker_evaluations",
    }:
        if execution[field] != 0:
            raise IntegrityError(f"offline_execution.{field} must equal zero")
    if execution["synthetic_projected_checker_evaluations"] != len(projected_refs):
        raise IntegrityError("synthetic projected-checker count mismatch")
    offline = OfflineExecutionEvidence(**execution)

    authorization_fields = set(_false_authorizations().as_json())
    authorizations = _exact(
        item["run_authorizations"], authorization_fields, "run_authorizations"
    )
    if any(value is not False for value in authorizations.values()):
        raise IntegrityError("every run authorization must equal false")
    authorization = RunAuthorizations(**authorizations)
    claim_fields = set(_false_claims().as_json())
    claims = _exact(item["scientific_claims"], claim_fields, "scientific_claims")
    if any(value is not False for value in claims.values()):
        raise IntegrityError("every scientific claim flag must equal false")
    scientific_claims = ScientificClaims(**claims)
    blockers = _unique_strings(item["blocker_codes"], "blocker_codes")
    if blockers != tuple(sorted(blockers)):
        raise IntegrityError("blocker_codes must be sorted")
    required_blockers = {
        "NATIVE_CHECKER_PARITY_NOT_EXECUTED",
        "PUBLIC_READINESS_NOT_ESTABLISHED",
        "RUN_AUTHORIZATION_WITHHELD",
    }
    if not required_blockers.issubset(blockers):
        raise IntegrityError("public runtime evidence lacks mandatory NO-GO blockers")
    if item["decision"] != "NO_GO":
        raise IntegrityError("public runtime evidence decision must equal NO_GO")
    artifact = PublicRuntimeEvidence(
        schema_version=PUBLIC_RUNTIME_EVIDENCE_SCHEMA_VERSION,
        artifact_type=PUBLIC_RUNTIME_EVIDENCE_ARTIFACT_TYPE,
        gate_id=gate_id,
        generated_at=generated_at,
        required_runtime_ids=required,
        runtime_receipts=tuple(receipt_refs),
        projected_checker_results=tuple(projected_refs),
        offline_execution=offline,
        run_authorizations=authorization,
        scientific_claims=scientific_claims,
        blocker_codes=blockers,
        decision="NO_GO",
        artifact_sha256=_sha(item["artifact_sha256"], "artifact_sha256"),
    )
    if artifact.artifact_sha256 != sha256_bytes(
        canonical_json_bytes(artifact.payload_json())
    ):
        raise IntegrityError("public runtime evidence artifact_sha256 mismatch")
    return artifact


__all__ = [
    "OfflineExecutionEvidence",
    "PUBLIC_RUNTIME_EVIDENCE_ARTIFACT_TYPE",
    "PUBLIC_RUNTIME_EVIDENCE_SCHEMA_VERSION",
    "ProjectedCheckerReference",
    "PublicRuntimeEvidence",
    "RuntimeReceiptReference",
    "ScientificClaims",
    "build_public_runtime_evidence",
    "validate_public_runtime_evidence",
]
