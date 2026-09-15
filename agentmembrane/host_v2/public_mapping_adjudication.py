"""Pure, fail-closed schemas for public mapping review and parity planning.

The functions in this module validate or combine already-produced JSON-like
objects.  They perform no file writes, benchmark execution, checker calls,
network access, or automatic label inference.  In particular, adjudication is
an intersection of two independent decisions, never a majority vote.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any

from .public_readiness import HOST_ACTION_MECHANISMS, REQUIRED_PARITY_CATEGORIES
from .schema import IntegrityError, SchemaError, canonical_json_bytes


MAPPING_ADJUDICATION_SCHEMA_VERSION = 1
EXPECTED_PUBLIC_PACK_COUNT = 2
EXPECTED_PUBLIC_MAPPING_ROW_COUNT = 108
MINIMUM_PARITY_SOURCE_COUNT = 20

MAPPING_STATUSES = frozenset({"mapped", "excluded", "ambiguous", "unreviewed"})
ALLOWED_DECISION_BASES = frozenset(
    {
        "task_specific_fixture",
        "task_specific_oracle",
        "trusted_event_trace",
        "native_checker_contract",
        "explicit_authority_analysis",
        "explicit_no_mechanism_analysis",
    }
)
FORBIDDEN_DECISION_BASIS_TOKENS = frozenset(
    {"family", "rq", "adversarial", "benign", "label"}
)

_REVIEW_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "review_id",
        "reviewer",
        "definitions_sha256",
        "packs",
    }
)
_REVIEWER_FIELDS = frozenset(
    {
        "reviewer_id",
        "mapping_author_id",
        "independent_from_mapping_author",
        "independent_from_other_reviewer",
        "reviewed_at",
        "method",
    }
)
_REVIEW_PACK_FIELDS = frozenset(
    {
        "pack_id",
        "manifest_sha256",
        "tasks_sha256",
        "taskpack_content_sha256",
        "rows",
    }
)
_REVIEW_ROW_FIELDS = frozenset(
    {
        "task_id",
        "source_workflow_id",
        "status",
        "mechanisms",
        "decision_basis",
        "rationale",
        "evidence",
    }
)
_EVIDENCE_FIELDS = frozenset({"path", "file_sha256", "note", "locator"})

_PLAN_FIELDS = frozenset(
    {
        "schema_version",
        "artifact_type",
        "plan_id",
        "benchmark",
        "pack_binding",
        "runtime_binding",
        "adapter_binding",
        "projected_checker_binding",
        "execution_authorized",
        "actual_execution_counts",
        "namespace_contract",
        "source_cases",
    }
)
_PACK_BINDING_FIELDS = frozenset(
    {"pack_id", "manifest_sha256", "tasks_sha256", "taskpack_content_sha256"}
)
_RUNTIME_BINDING_FIELDS = frozenset(
    {"runtime_id", "runtime_implementation_sha256"}
)
_ADAPTER_BINDING_FIELDS = frozenset(
    {"adapter_id", "adapter_implementation_sha256"}
)
_PROJECTED_BINDING_FIELDS = frozenset(
    {"projected_checker_id", "projected_checker_implementation_sha256"}
)
_COUNT_FIELDS = frozenset(
    {
        "task_execution_count",
        "reset_count",
        "dispatch_count",
        "native_checker_invocation_count",
        "projected_checker_invocation_count",
        "parity_comparison_count",
        "external_call_count",
    }
)
_NAMESPACE_FIELDS = frozenset(
    {
        "strategy",
        "require_nonexistent_before_case",
        "reuse_permitted",
        "cleanup_required",
        "cleanup_verification",
        "cleanup_on_failure",
    }
)
_SOURCE_CASE_FIELDS = frozenset({"source_task_id", "task_id", "cases"})
_CASE_FIELDS = frozenset(
    {"case_id", "category", "native_evidence", "projected_evidence", "expected_signals"}
)
_EXPECTED_SIGNAL_FIELDS = frozenset({"native", "projected", "expected_match"})
_VERDICT_FIELDS = frozenset({"utility", "security"})


def _exact_object(value: Any, fields: frozenset[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SchemaError(f"{label} must be an object")
    missing = sorted(fields - set(value))
    unknown = sorted(set(value) - fields)
    if missing or unknown:
        raise SchemaError(f"{label} fields invalid: missing={missing}, unknown={unknown}")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SchemaError(f"{label} must be a nonempty string")
    return value


def _sha(value: Any, label: str) -> str:
    text = _string(value, label)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise SchemaError(f"{label} must be a lowercase SHA-256")
    return text


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise SchemaError(f"{label} must be boolean")
    return value


def _list(value: Any, label: str, *, nonempty: bool = False) -> list[Any]:
    if not isinstance(value, list) or (nonempty and not value):
        qualifier = "nonempty " if nonempty else ""
        raise SchemaError(f"{label} must be a {qualifier}list")
    return value


def _strings(value: Any, label: str, *, nonempty: bool = False) -> list[str]:
    rows = _list(value, label, nonempty=nonempty)
    result = [_string(item, f"{label}[{index}]") for index, item in enumerate(rows)]
    if len(result) != len(set(result)):
        raise IntegrityError(f"{label} must not contain duplicates")
    return result


def _timestamp(value: Any, label: str) -> str:
    text = _string(value, label)
    if not text.endswith("Z"):
        raise SchemaError(f"{label} must be RFC 3339 UTC ending in Z")
    try:
        datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise SchemaError(f"{label} must be RFC 3339 UTC ending in Z") from exc
    return text


def _repo_relative_path(value: Any, label: str) -> str:
    text = _string(value, label)
    if "\\" in text:
        raise IntegrityError(f"{label} must use repository-relative POSIX syntax")
    path = PurePosixPath(text)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise IntegrityError(f"{label} must be a bounded repository-relative path")
    return path.as_posix()


def _validate_evidence(value: Any, label: str) -> dict[str, Any]:
    item = _exact_object(value, _EVIDENCE_FIELDS, label)
    path = _repo_relative_path(item["path"], f"{label}.path")
    file_sha256 = _sha(item["file_sha256"], f"{label}.file_sha256")
    note = _string(item["note"], f"{label}.note")
    locator = item["locator"]
    if not isinstance(locator, Mapping):
        raise SchemaError(f"{label}.locator must be an object")
    kind = locator.get("kind")
    if kind == "line_range":
        located = _exact_object(locator, frozenset({"kind", "start", "end"}), f"{label}.locator")
        start, end = located["start"], located["end"]
        if (
            isinstance(start, bool)
            or isinstance(end, bool)
            or not isinstance(start, int)
            or not isinstance(end, int)
            or start < 1
            or end < start
        ):
            raise IntegrityError(f"{label}.locator line range must satisfy 1 <= start <= end")
        normalized_locator: dict[str, Any] = {"kind": kind, "start": start, "end": end}
    elif kind == "json_pointer":
        located = _exact_object(locator, frozenset({"kind", "pointer"}), f"{label}.locator")
        pointer = _string(located["pointer"], f"{label}.locator.pointer")
        if not pointer.startswith("/") or "#" in pointer:
            raise IntegrityError(f"{label}.locator.pointer must be an absolute JSON Pointer")
        normalized_locator = {"kind": kind, "pointer": pointer}
    else:
        raise SchemaError(f"{label}.locator.kind must be line_range or json_pointer")
    return {
        "path": path,
        "file_sha256": file_sha256,
        "note": note,
        "locator": normalized_locator,
    }


def _normalize_expected_pack_bindings(
    expected_pack_bindings: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, str]]:
    if not isinstance(expected_pack_bindings, Mapping):
        raise SchemaError("expected_pack_bindings must be an object")
    if len(expected_pack_bindings) != EXPECTED_PUBLIC_PACK_COUNT:
        raise IntegrityError("mapping reviews must bind exactly two public packs")
    normalized: dict[str, dict[str, str]] = {}
    for raw_pack_id, raw_binding in expected_pack_bindings.items():
        pack_id = _string(raw_pack_id, "expected pack ID")
        binding = _exact_object(
            raw_binding,
            frozenset({"manifest_sha256", "tasks_sha256", "taskpack_content_sha256"}),
            f"expected_pack_bindings[{pack_id}]",
        )
        normalized[pack_id] = {
            "manifest_sha256": _sha(binding["manifest_sha256"], "expected manifest SHA"),
            "tasks_sha256": _sha(binding["tasks_sha256"], "expected tasks SHA"),
            "taskpack_content_sha256": _sha(
                binding["taskpack_content_sha256"], "expected taskpack content SHA"
            ),
        }
    return normalized


def _normalize_expected_task_sources(
    expected_task_sources: Mapping[str, Mapping[str, str]],
    pack_ids: set[str],
) -> dict[str, dict[str, str]]:
    if not isinstance(expected_task_sources, Mapping) or set(expected_task_sources) != pack_ids:
        raise IntegrityError("expected task-source tables must exactly match the two public packs")
    normalized: dict[str, dict[str, str]] = {}
    for pack_id, raw_tasks in expected_task_sources.items():
        if not isinstance(raw_tasks, Mapping) or not raw_tasks:
            raise SchemaError(f"expected_task_sources[{pack_id}] must be a nonempty object")
        tasks: dict[str, str] = {}
        for task_id, source_id in raw_tasks.items():
            tasks[_string(task_id, "expected task ID")] = _string(
                source_id, f"expected source ID for {task_id}"
            )
        normalized[pack_id] = tasks
    if sum(len(rows) for rows in normalized.values()) != EXPECTED_PUBLIC_MAPPING_ROW_COUNT:
        raise IntegrityError("expected public task inventory must contain exactly 108 rows")
    return normalized


def validate_independent_mapping_review(
    artifact: Mapping[str, Any],
    *,
    expected_pack_bindings: Mapping[str, Mapping[str, Any]],
    expected_task_sources: Mapping[str, Mapping[str, str]],
    definitions_sha256: str,
) -> dict[str, Any]:
    """Validate one independent, byte-bound, complete 108-row review."""

    value = _exact_object(artifact, _REVIEW_FIELDS, "mapping review")
    if value["schema_version"] != MAPPING_ADJUDICATION_SCHEMA_VERSION:
        raise SchemaError("mapping review schema_version must equal 1")
    if value["artifact_type"] != "agentmembrane_public_independent_mapping_review":
        raise SchemaError("invalid independent mapping review artifact_type")
    review_id = _string(value["review_id"], "mapping review.review_id")
    expected_definitions = _sha(definitions_sha256, "expected definitions_sha256")
    if _sha(value["definitions_sha256"], "mapping review.definitions_sha256") != expected_definitions:
        raise IntegrityError("mapping review definitions SHA-256 mismatch")

    reviewer = _exact_object(value["reviewer"], _REVIEWER_FIELDS, "mapping review.reviewer")
    reviewer_id = _string(reviewer["reviewer_id"], "mapping review.reviewer.reviewer_id")
    author_id = _string(reviewer["mapping_author_id"], "mapping review.reviewer.mapping_author_id")
    if reviewer_id == author_id:
        raise IntegrityError("mapping reviewer cannot be the mapping author")
    if not _boolean(reviewer["independent_from_mapping_author"], "independent_from_mapping_author"):
        raise IntegrityError("mapping review must be independent from the mapping author")
    if not _boolean(reviewer["independent_from_other_reviewer"], "independent_from_other_reviewer"):
        raise IntegrityError("mapping review must be independent from the other reviewer")
    _timestamp(reviewer["reviewed_at"], "mapping review.reviewer.reviewed_at")
    _string(reviewer["method"], "mapping review.reviewer.method")

    bindings = _normalize_expected_pack_bindings(expected_pack_bindings)
    sources = _normalize_expected_task_sources(expected_task_sources, set(bindings))
    raw_packs = _list(value["packs"], "mapping review.packs", nonempty=True)
    if len(raw_packs) != EXPECTED_PUBLIC_PACK_COUNT:
        raise IntegrityError("mapping review must contain exactly two public packs")
    seen_packs: set[str] = set()
    normalized_packs: dict[str, dict[str, Any]] = {}
    total_rows = 0
    status_counts = {status: 0 for status in sorted(MAPPING_STATUSES)}
    for pack_index, raw_pack in enumerate(raw_packs):
        pack = _exact_object(raw_pack, _REVIEW_PACK_FIELDS, f"mapping review.packs[{pack_index}]")
        pack_id = _string(pack["pack_id"], f"mapping review.packs[{pack_index}].pack_id")
        if pack_id in seen_packs or pack_id not in bindings:
            raise IntegrityError(f"unknown or duplicate mapping review pack_id: {pack_id}")
        seen_packs.add(pack_id)
        for field in ("manifest_sha256", "tasks_sha256", "taskpack_content_sha256"):
            actual = _sha(pack[field], f"mapping review pack {pack_id}.{field}")
            if actual != bindings[pack_id][field]:
                raise IntegrityError(f"mapping review {pack_id} {field} mismatch")

        raw_rows = _list(pack["rows"], f"mapping review pack {pack_id}.rows")
        task_sources = sources[pack_id]
        if len(raw_rows) != len(task_sources):
            raise IntegrityError(f"mapping review {pack_id} does not cover every task exactly once")
        seen_tasks: set[str] = set()
        rows: dict[str, dict[str, Any]] = {}
        for row_index, raw_row in enumerate(raw_rows):
            label = f"mapping review pack {pack_id}.rows[{row_index}]"
            row = _exact_object(raw_row, _REVIEW_ROW_FIELDS, label)
            task_id = _string(row["task_id"], f"{label}.task_id")
            if task_id in seen_tasks or task_id not in task_sources:
                raise IntegrityError(f"unknown or duplicate mapping review task_id: {task_id}")
            seen_tasks.add(task_id)
            source_id = _string(row["source_workflow_id"], f"{label}.source_workflow_id")
            if source_id != task_sources[task_id]:
                raise IntegrityError(f"mapping review source identity mismatch: {task_id}")
            status = row["status"]
            if status not in MAPPING_STATUSES:
                raise SchemaError(f"invalid mapping review status for {task_id}: {status!r}")
            mechanisms = _strings(row["mechanisms"], f"{label}.mechanisms")
            unknown_mechanisms = sorted(set(mechanisms) - HOST_ACTION_MECHANISMS)
            if unknown_mechanisms:
                raise IntegrityError(f"unknown Host-action mechanisms for {task_id}: {unknown_mechanisms}")
            if status == "mapped" and not mechanisms:
                raise IntegrityError(f"mapped review row has no mechanism: {task_id}")
            if status != "mapped" and mechanisms:
                raise IntegrityError(f"{status} review row must have no mechanisms: {task_id}")
            bases = _strings(row["decision_basis"], f"{label}.decision_basis", nonempty=True)
            unknown_bases = sorted(set(bases) - ALLOWED_DECISION_BASES)
            if unknown_bases:
                raise IntegrityError(f"forbidden or unknown decision basis for {task_id}: {unknown_bases}")
            for basis in bases:
                tokens = set(basis.casefold().replace("-", "_").split("_"))
                if tokens & FORBIDDEN_DECISION_BASIS_TOKENS:
                    raise IntegrityError(f"label-derived decision basis forbidden for {task_id}: {basis}")
            rationale = _string(row["rationale"], f"{label}.rationale")
            raw_evidence = _list(
                row["evidence"], f"{label}.evidence", nonempty=status != "unreviewed"
            )
            evidence = [
                _validate_evidence(item, f"{label}.evidence[{index}]")
                for index, item in enumerate(raw_evidence)
            ]
            rows[task_id] = {
                "task_id": task_id,
                "source_workflow_id": source_id,
                "status": status,
                "mechanisms": sorted(mechanisms),
                "decision_basis": sorted(bases),
                "rationale": rationale,
                "evidence": evidence,
            }
            status_counts[status] += 1
        if seen_tasks != set(task_sources):
            raise IntegrityError(f"mapping review {pack_id} task coverage mismatch")
        total_rows += len(rows)
        normalized_packs[pack_id] = {
            "pack_id": pack_id,
            **bindings[pack_id],
            "rows": rows,
        }
    if seen_packs != set(bindings) or total_rows != EXPECTED_PUBLIC_MAPPING_ROW_COUNT:
        raise IntegrityError("mapping review must cover both packs in exactly 108 rows")
    canonical_json_bytes(artifact)
    return {
        "review_id": review_id,
        "reviewer_id": reviewer_id,
        "mapping_author_id": author_id,
        "definitions_sha256": expected_definitions,
        "row_count": total_rows,
        "pack_count": len(normalized_packs),
        "status_counts": status_counts,
        "packs": normalized_packs,
    }


def adjudicate_mapping_reviews(
    review_m1: Mapping[str, Any],
    review_m2: Mapping[str, Any],
    *,
    expected_pack_bindings: Mapping[str, Mapping[str, Any]],
    expected_task_sources: Mapping[str, Mapping[str, str]],
    definitions_sha256: str,
    adjudication_id: str = "host-v2.1-public-mapping-dual-review-adjudication",
) -> dict[str, Any]:
    """Return the exact M1/M2 intersection as a permanently NO_GO artifact."""

    m1 = validate_independent_mapping_review(
        review_m1,
        expected_pack_bindings=expected_pack_bindings,
        expected_task_sources=expected_task_sources,
        definitions_sha256=definitions_sha256,
    )
    m2 = validate_independent_mapping_review(
        review_m2,
        expected_pack_bindings=expected_pack_bindings,
        expected_task_sources=expected_task_sources,
        definitions_sha256=definitions_sha256,
    )
    if m1["review_id"] == m2["review_id"] or m1["reviewer_id"] == m2["reviewer_id"]:
        raise IntegrityError("dual adjudication requires two distinct reviews and reviewers")
    output_packs: list[dict[str, Any]] = []
    total_consensus = 0
    total_disagreements = 0
    total_unreviewed = 0
    consensus_status_counts = {status: 0 for status in sorted(MAPPING_STATUSES)}
    for pack_id in sorted(m1["packs"]):
        left_pack = m1["packs"][pack_id]
        right_pack = m2["packs"][pack_id]
        rows: list[dict[str, Any]] = []
        for task_id in sorted(left_pack["rows"]):
            left = left_pack["rows"][task_id]
            right = right_pack["rows"].get(task_id)
            if right is None:
                raise IntegrityError(f"M2 lacks validated task {pack_id}/{task_id}")
            left_decision = {
                "review_id": m1["review_id"],
                "status": left["status"],
                "mechanisms": list(left["mechanisms"]),
                "evidence_valid": True,
            }
            right_decision = {
                "review_id": m2["review_id"],
                "status": right["status"],
                "mechanisms": list(right["mechanisms"]),
                "evidence_valid": True,
            }
            identity_agrees = (
                left["task_id"] == right["task_id"]
                and left["source_workflow_id"] == right["source_workflow_id"]
            )
            decision_agrees = (
                left["status"] == right["status"]
                and left["mechanisms"] == right["mechanisms"]
            )
            if identity_agrees and decision_agrees:
                status = left["status"]
                mechanisms = list(left["mechanisms"])
                if status == "unreviewed":
                    total_unreviewed += 1
                    rationale = "Both reviewers recorded this task as unreviewed."
                else:
                    total_consensus += 1
                    consensus_status_counts[status] += 1
                    rationale = "Two independent reviews reached the same task-specific decision."
            else:
                status = "unreviewed"
                mechanisms = []
                total_disagreements += 1
                total_unreviewed += 1
                rationale = (
                    "Independent reviews disagreed; the task remains unreviewed and "
                    "no mechanism label was inferred or selected."
                )
            rows.append(
                {
                    "task_id": task_id,
                    "source_workflow_id": left["source_workflow_id"],
                    "status": status,
                    "mechanisms": mechanisms,
                    "rationale": rationale,
                    "evidence_refs": [],
                    "review_decisions": [left_decision, right_decision],
                }
            )
        output_packs.append(
            {
                "schema_version": 1,
                "artifact_type": "agentmembrane_public_mechanism_mapping_adjudication",
                "mapping_id": f"{pack_id}-dual-review-intersection-v1",
                "pack_id": pack_id,
                "manifest_sha256": left_pack["manifest_sha256"],
                "tasks_sha256": left_pack["tasks_sha256"],
                "taskpack_content_sha256": left_pack["taskpack_content_sha256"],
                "construct_id": "host_mediated_capability_exploitation",
                "proposal_alignment": "RQ1b_host_mediated",
                "answers_canonical_proposal_rq2": False,
                "pooling_with_semantic_rq2_permitted": False,
                "definitions_sha256": m1["definitions_sha256"],
                "review": {
                    "decision": "partial_consensus",
                    "review_ids": [m1["review_id"], m2["review_id"]],
                    "approved_formal_mapping": False,
                },
                "rows": rows,
                "mapping_status": "partial_consensus",
                "decision": "NO_GO",
                "claim_eligible": False,
                "formal_run_permitted": False,
                "approved_formal_mapping": False,
            }
        )
    result = {
        "schema_version": 1,
        "artifact_type": "agentmembrane_public_mapping_adjudication",
        "adjudication_id": _string(adjudication_id, "adjudication_id"),
        "review_ids": [m1["review_id"], m2["review_id"]],
        "mapping_status": "partial_consensus",
        "decision": "NO_GO",
        "claim_eligible": False,
        "formal_run_permitted": False,
        "approved_formal_mapping": False,
        "summary": {
            "row_count": EXPECTED_PUBLIC_MAPPING_ROW_COUNT,
            "consensus_count": total_consensus,
            "consensus_status_counts": consensus_status_counts,
            "accepted_mapped_count": consensus_status_counts["mapped"],
            "disagreement_count": total_disagreements,
            "unreviewed_count": total_unreviewed,
        },
        "packs": output_packs,
    }
    canonical_json_bytes(result)
    return result


def _validate_binding(
    value: Any,
    fields: frozenset[str],
    id_field: str,
    sha_fields: Sequence[str],
    label: str,
) -> dict[str, str]:
    binding = _exact_object(value, fields, label)
    result = {id_field: _string(binding[id_field], f"{label}.{id_field}")}
    for field in sha_fields:
        result[field] = _sha(binding[field], f"{label}.{field}")
    return result


def _validate_expected_signals(value: Any, label: str) -> dict[str, Any]:
    signals = _exact_object(value, _EXPECTED_SIGNAL_FIELDS, label)
    normalized: dict[str, Any] = {}
    for side in ("native", "projected"):
        verdict = _exact_object(signals[side], _VERDICT_FIELDS, f"{label}.{side}")
        side_value: dict[str, bool | None] = {}
        for field in ("utility", "security"):
            item = verdict[field]
            if item is not None and not isinstance(item, bool):
                raise SchemaError(f"{label}.{side}.{field} must be boolean or null")
            side_value[field] = item
        if all(item is None for item in side_value.values()):
            raise IntegrityError(f"{label}.{side} must expect at least one checker signal")
        normalized[side] = side_value
    expected_match = _boolean(signals["expected_match"], f"{label}.expected_match")
    derived = normalized["native"] == normalized["projected"]
    if not expected_match or expected_match != derived:
        raise IntegrityError(f"{label}.expected_match must be true and derived from equal signals")
    normalized["expected_match"] = True
    return normalized


def validate_parity_fixture_plan(
    artifact: Mapping[str, Any],
    *,
    expected_bindings: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Validate an unexecuted, six-category-per-source parity fixture plan."""

    value = _exact_object(artifact, _PLAN_FIELDS, "parity fixture plan")
    if value["schema_version"] != 1:
        raise SchemaError("parity fixture plan schema_version must equal 1")
    if value["artifact_type"] != "agentmembrane_public_checker_parity_fixture_plan":
        raise SchemaError("invalid parity fixture plan artifact_type")
    plan_id = _string(value["plan_id"], "parity fixture plan.plan_id")
    benchmark = _string(value["benchmark"], "parity fixture plan.benchmark")
    bindings = {
        "pack_binding": _validate_binding(
            value["pack_binding"], _PACK_BINDING_FIELDS, "pack_id",
            ("manifest_sha256", "tasks_sha256", "taskpack_content_sha256"), "pack_binding"
        ),
        "runtime_binding": _validate_binding(
            value["runtime_binding"], _RUNTIME_BINDING_FIELDS, "runtime_id",
            ("runtime_implementation_sha256",), "runtime_binding"
        ),
        "adapter_binding": _validate_binding(
            value["adapter_binding"], _ADAPTER_BINDING_FIELDS, "adapter_id",
            ("adapter_implementation_sha256",), "adapter_binding"
        ),
        "projected_checker_binding": _validate_binding(
            value["projected_checker_binding"], _PROJECTED_BINDING_FIELDS, "projected_checker_id",
            ("projected_checker_implementation_sha256",), "projected_checker_binding"
        ),
    }
    if expected_bindings is not None:
        if not isinstance(expected_bindings, Mapping) or set(expected_bindings) != set(bindings):
            raise IntegrityError("expected parity bindings must contain exactly four bindings")
        for name, binding in bindings.items():
            if dict(expected_bindings[name]) != binding:
                raise IntegrityError(f"parity fixture plan {name} mismatch")
    if _boolean(value["execution_authorized"], "execution_authorized"):
        raise IntegrityError("parity fixture plan must keep execution_authorized=false")
    counts = _exact_object(value["actual_execution_counts"], _COUNT_FIELDS, "actual_execution_counts")
    for name, count in counts.items():
        if isinstance(count, bool) or not isinstance(count, int) or count != 0:
            raise IntegrityError(f"actual_execution_counts.{name} must equal integer zero")
    namespace = _exact_object(value["namespace_contract"], _NAMESPACE_FIELDS, "namespace_contract")
    if namespace["strategy"] != "fresh_per_case":
        raise IntegrityError("namespace_contract.strategy must equal fresh_per_case")
    required_true = (
        "require_nonexistent_before_case", "cleanup_required", "cleanup_on_failure"
    )
    for field in required_true:
        if not _boolean(namespace[field], f"namespace_contract.{field}"):
            raise IntegrityError(f"namespace_contract.{field} must be true")
    if _boolean(namespace["reuse_permitted"], "namespace_contract.reuse_permitted"):
        raise IntegrityError("namespace reuse must remain forbidden")
    _string(namespace["cleanup_verification"], "namespace_contract.cleanup_verification")

    source_cases = _list(value["source_cases"], "source_cases", nonempty=True)
    if len(source_cases) < MINIMUM_PARITY_SOURCE_COUNT:
        raise IntegrityError("parity fixture plan requires at least 20 distinct sources")
    seen_sources: set[str] = set()
    seen_tasks: set[str] = set()
    seen_case_ids: set[str] = set()
    case_count = 0
    for source_index, raw_source in enumerate(source_cases):
        label = f"source_cases[{source_index}]"
        source = _exact_object(raw_source, _SOURCE_CASE_FIELDS, label)
        source_id = _string(source["source_task_id"], f"{label}.source_task_id")
        task_id = _string(source["task_id"], f"{label}.task_id")
        if source_id in seen_sources:
            raise IntegrityError(f"duplicate parity source_task_id: {source_id}")
        if task_id in seen_tasks:
            raise IntegrityError(f"duplicate parity task_id: {task_id}")
        seen_sources.add(source_id)
        seen_tasks.add(task_id)
        cases = _list(source["cases"], f"{label}.cases", nonempty=True)
        categories: set[str] = set()
        if len(cases) != len(REQUIRED_PARITY_CATEGORIES):
            raise IntegrityError(f"{label} must contain exactly six category cases")
        for case_index, raw_case in enumerate(cases):
            case_label = f"{label}.cases[{case_index}]"
            case = _exact_object(raw_case, _CASE_FIELDS, case_label)
            case_id = _string(case["case_id"], f"{case_label}.case_id")
            if case_id in seen_case_ids:
                raise IntegrityError(f"duplicate parity case_id: {case_id}")
            seen_case_ids.add(case_id)
            category = case["category"]
            if category not in REQUIRED_PARITY_CATEGORIES or category in categories:
                raise IntegrityError(f"unsupported or duplicate parity category: {category!r}")
            categories.add(category)
            for evidence_field in ("native_evidence", "projected_evidence"):
                evidence = _list(case[evidence_field], f"{case_label}.{evidence_field}", nonempty=True)
                for evidence_index, item in enumerate(evidence):
                    _validate_evidence(item, f"{case_label}.{evidence_field}[{evidence_index}]")
            native_fingerprints = {
                canonical_json_bytes(item)
                for item in case["native_evidence"]
            }
            projected_fingerprints = {
                canonical_json_bytes(item)
                for item in case["projected_evidence"]
            }
            if native_fingerprints == projected_fingerprints:
                raise IntegrityError(
                    f"{case_label} projected evidence must be independently constructed"
                )
            _validate_expected_signals(case["expected_signals"], f"{case_label}.expected_signals")
            case_count += 1
        if categories != set(REQUIRED_PARITY_CATEGORIES):
            raise IntegrityError(f"{label} must cover all six parity categories exactly once")
    canonical_json_bytes(artifact)
    return {
        "plan_id": plan_id,
        "benchmark": benchmark,
        "pack_id": bindings["pack_binding"]["pack_id"],
        "source_count": len(seen_sources),
        "case_count": case_count,
        "categories": sorted(REQUIRED_PARITY_CATEGORIES),
        "execution_authorized": False,
        "actual_execution_count": 0,
        "decision": "NO_GO",
    }
