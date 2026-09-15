"""Deterministic, fail-closed public-pack evidence diagnostics.

This module deliberately produces an *external* diagnostic overlay.  It never
changes a source task pack and it never upgrades a draft mapping, an empty
formal split, or a reference-only oracle into claim-ready evidence.  The
overlay is useful because it records every currently derivable provenance
fact while preserving an explicit ``NO_GO`` decision.
"""

from __future__ import annotations

from itertools import combinations
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from .schema import IntegrityError, SchemaError, canonical_json_bytes, sha256_bytes
from .taskpacks import TaskPack, TaskSpec, load_taskpack, taskpack_content_sha256


EVIDENCE_SCHEMA_VERSION = 1
OVERLAY_ID = "host-v2.1-public-readiness-offline-diagnostic"
OVERLAY_RELATIVE_ROOT = Path("experiments/host_boundary_v2/public_readiness_v2.1")
SPLIT_ORDER = ("train", "G0", "G1", "G2", "pilot", "formal")
MINIMUM_FORMAL_CLUSTERS = 60
PREFERRED_FORMAL_CLUSTERS = 100
TRUSTED_MECHANISM_IDS = (
    "capability_delegation",
    "confused_deputy",
    "cross_tool_composition",
    "internal_transformation_action_laundering",
    "multi_step_capability_chaining",
    "proposal_to_action_conversion",
)
REFERENCE_ONLY_ORACLE_TYPES = frozenset(
    {
        "exact_upstream_utility_and_security_checker_references",
        "tau2_native_criteria_plus_membrane_policy_trace",
    }
)
PACK_RELATIVE_ROOTS = (
    Path("data/host_boundary_v2/packs/agentdojo-v0.1.35-v1"),
    Path("data/host_boundary_v2/packs/tau2-v1.0.1"),
)
FULL_INVENTORY_RELATIVE_ROOT = Path("data/host_boundary_v2/full_inventory")


def _json_bytes(value: Any) -> bytes:
    return canonical_json_bytes(value) + b"\n"


def _file_sha256(path: Path) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise IntegrityError(f"cannot hash {path}: {exc}") from exc


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        canonical_json_bytes(value)
    except (OSError, UnicodeError, json.JSONDecodeError, SchemaError) as exc:
        raise IntegrityError(f"cannot load frozen JSON object {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise IntegrityError(f"frozen JSON must be an object: {path}")
    return value


def _require_sha(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise IntegrityError(f"{label} must be a lowercase SHA-256")
    return value


def _source_task_id(task: TaskSpec) -> str:
    for key in ("source_task_id", "upstream_task_id", "workflow_id"):
        value = task.metadata.get(key)
        if isinstance(value, str) and value.strip():
            return value
    raise IntegrityError(f"task {task.task_id} lacks a frozen source-task identity")


def _initial_state_sha256(task: TaskSpec) -> str:
    return _require_sha(
        task.metadata.get("initial_state_sha256"),
        f"task {task.task_id} metadata.initial_state_sha256",
    )


def _protocol_split(task: TaskSpec) -> str:
    value = task.metadata.get("protocol_split")
    if not isinstance(value, str) or value not in SPLIT_ORDER:
        raise IntegrityError(
            f"task {task.task_id} has unsupported frozen protocol_split={value!r}"
        )
    return value


def _pack_binding(pack: TaskPack, logical_sha256: str) -> dict[str, Any]:
    upstream = pack.manifest.get("upstream")
    if not isinstance(upstream, Mapping):
        raise IntegrityError(f"pack {pack.pack_id} lacks upstream provenance")
    benchmark = upstream.get("name")
    version = upstream.get("version_or_commit")
    if not isinstance(benchmark, str) or not benchmark:
        raise IntegrityError(f"pack {pack.pack_id} lacks upstream.name")
    if not isinstance(version, str) or not version:
        raise IntegrityError(f"pack {pack.pack_id} lacks upstream.version_or_commit")
    return {
        "benchmark": benchmark,
        "manifest_sha256": _file_sha256(pack.root / "manifest.json"),
        "pack_id": pack.pack_id,
        "taskpack_content_sha256": logical_sha256,
        "tasks_sha256": _file_sha256(pack.root / "tasks.jsonl"),
        "upstream_version_or_commit": version,
    }


def trusted_mechanism_definitions(*, builder_sha256: str) -> dict[str, Any]:
    """Return the exact six-ID construct dictionary; it is not a task mapping."""

    descriptions = {
        "capability_delegation": "A host delegates an authority-bearing capability across an actor or component boundary.",
        "confused_deputy": "A less-authorized requester induces a more-authorized host component to act with the component's authority.",
        "cross_tool_composition": "Authority emerges from composing two or more tool actions that must be evaluated as one flow.",
        "internal_transformation_action_laundering": "A host transformation obscures the origin or authorization status of a later external action.",
        "multi_step_capability_chaining": "Multiple host-mediated steps chain capabilities so the final action exceeds the initiating authority.",
        "proposal_to_action_conversion": "Host logic converts non-authoritative proposal content into an authority-bearing action.",
    }
    return {
        "artifact_type": "agentmembrane_host_action_mechanism_definitions",
        "builder_implementation_sha256": builder_sha256,
        "construct_id": "host_mediated_capability_exploitation",
        "definitions": [
            {"description": descriptions[mechanism_id], "mechanism_id": mechanism_id}
            for mechanism_id in TRUSTED_MECHANISM_IDS
        ],
        "pooling_with_semantic_rq2_permitted": False,
        "proposal_alignment": "RQ1b_host_mediated",
        "schema_version": EVIDENCE_SCHEMA_VERSION,
    }


def build_mechanism_mapping_draft(
    pack: TaskPack,
    *,
    taskpack_sha256: str,
    definitions_sha256: str,
) -> dict[str, Any]:
    """Build a complete but intentionally unreviewed mapping draft.

    Current pack labels do not constitute construct evidence.  Therefore every
    row is ``ambiguous`` until task-specific evidence is independently reviewed.
    This is intentionally compatible with the readiness mapping field layout,
    but its review block must fail the claim-ready validator.
    """

    binding = _pack_binding(pack, taskpack_sha256)
    rows = []
    for task in sorted(pack.tasks, key=lambda item: item.task_id):
        fixture_sha = _require_sha(
            task.metadata.get("fixture_sha256"),
            f"task {task.task_id} metadata.fixture_sha256",
        )
        oracle_sha = _require_sha(
            task.metadata.get("oracle_sha256"),
            f"task {task.task_id} metadata.oracle_sha256",
        )
        rows.append(
            {
                "evidence_refs": [
                    f"tasks.jsonl#task_id={task.task_id}",
                    f"{task.fixture_ref}#sha256={fixture_sha}",
                    f"{task.oracle_ref}#sha256={oracle_sha}",
                ],
                "mechanisms": [],
                "rationale": (
                    "Task-specific Host-action construct evidence has not been "
                    "independently adjudicated; descriptive legacy labels are not used "
                    "as a mapping rule."
                ),
                "source_workflow_id": _source_task_id(task),
                "status": "ambiguous",
                "task_id": task.task_id,
            }
        )
    artifact = {
        "answers_canonical_proposal_rq2": False,
        "artifact_type": "agentmembrane_public_mechanism_mapping",
        "benchmark": binding["benchmark"],
        "construct_id": "host_mediated_capability_exploitation",
        "definitions_sha256": definitions_sha256,
        "mapping_id": f"{pack.pack_id}-host-action-draft-v1",
        "pack_id": pack.pack_id,
        "pooling_with_semantic_rq2_permitted": False,
        "proposal_alignment": "RQ1b_host_mediated",
        "review": {
            "decision": "not_reviewed",
            "independent_from_mapping_author": False,
            "method": "not_performed_offline_gate_diagnostic_only",
            "reviewed_at": "not_performed",
            "reviewer_id": "unassigned",
        },
        "rows": rows,
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "taskpack_content_sha256": taskpack_sha256,
        "upstream_version_or_commit": binding["upstream_version_or_commit"],
    }
    validate_mechanism_mapping_draft(artifact, pack=pack, taskpack_sha256=taskpack_sha256)
    return artifact


def validate_mechanism_mapping_draft(
    artifact: Mapping[str, Any], *, pack: TaskPack, taskpack_sha256: str
) -> None:
    """Validate completeness/status semantics while requiring the draft to stay NO-GO."""

    if artifact.get("artifact_type") != "agentmembrane_public_mechanism_mapping":
        raise IntegrityError("mapping draft artifact_type mismatch")
    if artifact.get("pack_id") != pack.pack_id:
        raise IntegrityError("mapping draft pack_id mismatch")
    if artifact.get("taskpack_content_sha256") != taskpack_sha256:
        raise IntegrityError("mapping draft taskpack_content_sha256 mismatch")
    review = artifact.get("review")
    if not isinstance(review, Mapping):
        raise IntegrityError("mapping draft review must be an object")
    if review.get("independent_from_mapping_author") is not False:
        raise IntegrityError("diagnostic mapping draft cannot claim independent review")
    if review.get("decision") != "not_reviewed":
        raise IntegrityError("diagnostic mapping draft must remain not_reviewed")
    raw_rows = artifact.get("rows")
    if not isinstance(raw_rows, list):
        raise IntegrityError("mapping draft rows must be a list")
    tasks = {task.task_id: task for task in pack.tasks}
    seen: set[str] = set()
    for index, row in enumerate(raw_rows):
        if not isinstance(row, Mapping):
            raise IntegrityError(f"mapping draft row {index} must be an object")
        task_id = row.get("task_id")
        if not isinstance(task_id, str) or task_id not in tasks or task_id in seen:
            raise IntegrityError(f"invalid or duplicate mapping draft task_id: {task_id!r}")
        seen.add(task_id)
        if row.get("source_workflow_id") != _source_task_id(tasks[task_id]):
            raise IntegrityError(f"mapping draft source identity mismatch: {task_id}")
        status = row.get("status")
        if status not in {"mapped", "excluded", "ambiguous"}:
            raise IntegrityError(f"mapping draft status invalid: {task_id}")
        mechanisms = row.get("mechanisms")
        if not isinstance(mechanisms, list) or any(
            mechanism not in TRUSTED_MECHANISM_IDS for mechanism in mechanisms
        ):
            raise IntegrityError(f"mapping draft mechanisms invalid: {task_id}")
        if len(mechanisms) != len(set(mechanisms)):
            raise IntegrityError(f"mapping draft mechanisms duplicated: {task_id}")
        if status == "mapped" and not mechanisms:
            raise IntegrityError(f"mapped row requires a mechanism: {task_id}")
        if status in {"excluded", "ambiguous"} and mechanisms:
            raise IntegrityError(f"{status} row must retain zero mechanisms: {task_id}")
        rationale = row.get("rationale")
        refs = row.get("evidence_refs")
        if not isinstance(rationale, str) or not rationale.strip():
            raise IntegrityError(f"mapping draft rationale missing: {task_id}")
        if not isinstance(refs, list) or not refs or any(
            not isinstance(item, str) or not item for item in refs
        ):
            raise IntegrityError(f"mapping draft evidence_refs missing: {task_id}")
    if seen != set(tasks):
        raise IntegrityError("mapping draft does not cover every task exactly once")
    if any(row.get("status") == "mapped" for row in raw_rows):
        raise IntegrityError("unreviewed offline diagnostic cannot emit mapped rows")


def _split_manifest_assignments(pack: TaskPack) -> tuple[dict[str, str], str]:
    path = pack.root / "fixtures" / "split_manifest.json"
    raw = _load_object(path)
    splits = raw.get("splits")
    if not isinstance(splits, Mapping):
        raise IntegrityError(f"split manifest lacks splits: {path}")
    assignments: dict[str, str] = {}
    for split_name, body in splits.items():
        if split_name not in SPLIT_ORDER or not isinstance(body, Mapping):
            raise IntegrityError(f"unsupported split manifest entry: {split_name!r}")
        task_ids = body.get("task_ids")
        if not isinstance(task_ids, list):
            raise IntegrityError(f"split manifest {split_name} task_ids must be a list")
        for task_id in task_ids:
            if not isinstance(task_id, str) or task_id in assignments:
                raise IntegrityError(f"invalid/duplicate task in split manifest: {task_id!r}")
            assignments[task_id] = split_name
    return assignments, _file_sha256(path)


def _split_summary(tasks: Sequence[TaskSpec]) -> dict[str, Any]:
    task_ids = sorted(task.task_id for task in tasks)
    cluster_ids = sorted({task.cluster_id for task in tasks})
    source_ids = sorted({_source_task_id(task) for task in tasks})
    state_ids = sorted({_initial_state_sha256(task) for task in tasks})
    return {
        "cluster_count": len(cluster_ids),
        "cluster_ids": cluster_ids,
        "initial_state_graph_count": len(state_ids),
        "initial_state_sha256s": state_ids,
        "source_task_count": len(source_ids),
        "source_task_ids": source_ids,
        "task_count": len(task_ids),
        "task_ids": task_ids,
    }


def build_split_diagnostic(
    pack: TaskPack,
    *,
    taskpack_sha256: str,
    power_facts: Mapping[str, Any],
) -> dict[str, Any]:
    """Recompute two-level disjointness without changing protocol assignments."""

    binding = _pack_binding(pack, taskpack_sha256)
    declared_assignments, split_manifest_sha = _split_manifest_assignments(pack)
    current_ids = {task.task_id for task in pack.tasks}
    if set(declared_assignments) != current_ids:
        raise IntegrityError(f"pack {pack.pack_id} split manifest task coverage mismatch")

    split_tasks: dict[str, list[TaskSpec]] = {name: [] for name in SPLIT_ORDER}
    rows: list[dict[str, Any]] = []
    cluster_splits: dict[str, set[str]] = {}
    pair_clusters: dict[str, set[str]] = {}
    source_clusters: dict[str, set[str]] = {}
    for task in sorted(pack.tasks, key=lambda item: item.task_id):
        protocol_split = _protocol_split(task)
        if declared_assignments.get(task.task_id) != protocol_split:
            raise IntegrityError(
                f"task {task.task_id} protocol_split differs from frozen split manifest"
            )
        split_tasks[protocol_split].append(task)
        cluster_splits.setdefault(task.cluster_id, set()).add(protocol_split)
        pair_clusters.setdefault(task.pair_id, set()).add(task.cluster_id)
        source_clusters.setdefault(_source_task_id(task), set()).add(task.cluster_id)
        source_split = task.metadata.get("source_split")
        rows.append(
            {
                "cluster_id": task.cluster_id,
                "initial_state_sha256": _initial_state_sha256(task),
                "pair_id": task.pair_id,
                "pair_role": task.pair_role,
                "protocol_split": protocol_split,
                "source_task_id": _source_task_id(task),
                "task_id": task.task_id,
                "upstream_source_split": source_split,
            }
        )
    if any(len(splits) != 1 for splits in cluster_splits.values()):
        raise IntegrityError(f"pack {pack.pack_id} has a workflow cluster across protocol splits")
    if any(len(clusters) != 1 for clusters in pair_clusters.values()):
        raise IntegrityError(f"pack {pack.pack_id} separates a benign/adversarial twin pair")
    if any(len(clusters) != 1 for clusters in source_clusters.values()):
        raise IntegrityError(f"pack {pack.pack_id} separates source-task variants")

    summaries = {name: _split_summary(split_tasks[name]) for name in SPLIT_ORDER}
    intersections: list[dict[str, Any]] = []
    for left, right in combinations(SPLIT_ORDER, 2):
        source_overlap = sorted(
            set(summaries[left]["source_task_ids"])
            & set(summaries[right]["source_task_ids"])
        )
        state_overlap = sorted(
            set(summaries[left]["initial_state_sha256s"])
            & set(summaries[right]["initial_state_sha256s"])
        )
        intersections.append(
            {
                "initial_state_graph_disjoint": not state_overlap,
                "initial_state_sha256_overlap": state_overlap,
                "left": left,
                "right": right,
                "source_task_disjoint": not source_overlap,
                "source_task_id_overlap": source_overlap,
            }
        )
    all_source_disjoint = all(item["source_task_disjoint"] for item in intersections)
    all_state_disjoint = all(item["initial_state_graph_disjoint"] for item in intersections)
    blockers = [
        "FORMAL_SPLIT_EMPTY",
        "G2_COST_UNRESOLVED",
        "FORMAL_POWER_BELOW_60_CURRENT_PACK",
        "FORMAL_SELECTION_REQUIRES_NEW_VERSIONED_DERIVED_PACK",
    ]
    if not all_source_disjoint:
        blockers.append("SOURCE_TASK_SPLIT_OVERLAP")
    if not all_state_disjoint:
        blockers.append("INITIAL_STATE_GRAPH_SPLIT_OVERLAP")
    formal_cluster_count = summaries["formal"]["cluster_count"]
    return {
        "all_initial_state_graph_intersections_empty": all_state_disjoint,
        "all_source_task_intersections_empty": all_source_disjoint,
        "artifact_type": "agentmembrane_public_split_diagnostic",
        "blocker_codes": sorted(set(blockers)),
        "decision": "NO_GO",
        "formal_population": {
            "current_formal_cluster_count": formal_cluster_count,
            "meets_minimum_60": formal_cluster_count >= MINIMUM_FORMAL_CLUSTERS,
            "meets_preferred_100": formal_cluster_count >= PREFERRED_FORMAL_CLUSTERS,
            "minimum_cluster_floor": MINIMUM_FORMAL_CLUSTERS,
            "preferred_cluster_floor": PREFERRED_FORMAL_CLUSTERS,
            "rq2_after_fixed_heldout_upper_bound": power_facts[
                "rq2_after_fixed_heldout_upper_bound"
            ],
        },
        "g2_additional_workflow_cost": "dynamic_unresolved",
        "intersections": intersections,
        "pack_binding": binding,
        "protocol_assignment_rule": (
            "preserve metadata.protocol_split exactly; upstream source_split is retained "
            "only as provenance and is never reinterpreted as protocol membership"
        ),
        "rows": rows,
        "schema_version": EVIDENCE_SCHEMA_VERSION,
        "split_manifest_sha256": split_manifest_sha,
        "split_order": list(SPLIT_ORDER),
        "splits": summaries,
        "twins_and_source_variants_single_cluster": True,
    }


def build_oracle_diagnostic(pack: TaskPack, *, taskpack_sha256: str) -> dict[str, Any]:
    """Bind every referenced oracle byte and report reference-only executability."""

    binding = _pack_binding(pack, taskpack_sha256)
    tasks_by_ref: dict[str, list[TaskSpec]] = {}
    for task in pack.tasks:
        tasks_by_ref.setdefault(task.oracle_ref, []).append(task)
    rows = []
    for oracle_ref, tasks in sorted(tasks_by_ref.items()):
        rel = Path(oracle_ref)
        if rel.is_absolute() or ".." in rel.parts:
            raise IntegrityError(f"oracle_ref escapes pack: {oracle_ref}")
        path = (pack.root / rel).resolve()
        try:
            path.relative_to(pack.root.resolve())
        except ValueError as exc:
            raise IntegrityError(f"oracle_ref escapes pack: {oracle_ref}") from exc
        actual_sha = _file_sha256(path)
        declared = {
            _require_sha(
                task.metadata.get("oracle_sha256"),
                f"task {task.task_id} metadata.oracle_sha256",
            )
            for task in tasks
        }
        if declared != {actual_sha}:
            raise IntegrityError(f"oracle hash binding mismatch: {oracle_ref}")
        oracle = _load_object(path)
        schema_version = oracle.get("schema_version")
        oracle_type = oracle.get("oracle_type")
        reference_only = schema_version == 1 or oracle_type in REFERENCE_ONLY_ORACLE_TYPES
        rows.append(
            {
                "blocker_code": (
                    "ORACLE_REFERENCE_ONLY_SCHEMA_V1" if reference_only else None
                ),
                "executable": False,
                "oracle_ref": oracle_ref,
                "oracle_sha256": actual_sha,
                "oracle_type": oracle_type,
                "schema_version": schema_version,
                "task_ids": sorted(task.task_id for task in tasks),
            }
        )
    blocker_codes = sorted(
        {row["blocker_code"] for row in rows if row["blocker_code"] is not None}
    )
    if any(row["executable"] for row in rows):
        raise IntegrityError("offline oracle diagnostic cannot assert executability")
    return {
        "artifact_type": "agentmembrane_public_oracle_diagnostic",
        "blocker_codes": blocker_codes,
        "decision": "NO_GO",
        "executable_oracle_count": 0,
        "oracle_count": len(rows),
        "pack_binding": binding,
        "rows": rows,
        "schema_version": EVIDENCE_SCHEMA_VERSION,
    }


def build_power_diagnostic(
    full_inventory_root: Path,
    *,
    pack_cluster_counts: Mapping[str, int],
    builder_sha256: str,
) -> dict[str, Any]:
    """Bind frozen full-inventory power facts without selecting a formal split."""

    root = Path(full_inventory_root).resolve()
    manifest_path = root / "manifest.json"
    proposed_path = root / "proposed_splits.json"
    shortfall_path = root / "eligibility_shortfall.json"
    manifest = _load_object(manifest_path)
    proposed = _load_object(proposed_path)
    shortfall = _load_object(shortfall_path)
    output_locks = {
        entry.get("path"): entry.get("sha256")
        for entry in manifest.get("outputs", [])
        if isinstance(entry, Mapping)
    }
    for path in (proposed_path, shortfall_path):
        declared = output_locks.get(path.name)
        if declared != _file_sha256(path):
            raise IntegrityError(f"full-inventory manifest hash mismatch: {path.name}")
    rq2 = shortfall.get("per_rq_pooled_upper_bounds", {}).get("RQ2")
    if not isinstance(rq2, Mapping):
        raise IntegrityError("eligibility shortfall lacks the RQ2 pooled upper bound")
    after = rq2.get("after_fixed_G0_G1_pilot_upper_bounds")
    if not isinstance(after, list) or len(after) != 1 or not isinstance(after[0], int):
        raise IntegrityError("RQ2 after-fixed-heldout upper bound is malformed")
    if proposed.get("G2_is_dynamically_generated") is not True:
        raise IntegrityError("full inventory no longer marks G2 as dynamic")
    if proposed.get("G2_placeholder_is_empty") is not True:
        raise IntegrityError("full inventory G2 placeholder is not empty")
    if proposed.get("formal_split_empty") is not True:
        raise IntegrityError("full inventory formal split is unexpectedly nonempty")
    if proposed.get("formal_run_permitted") is not False:
        raise IntegrityError("full inventory unexpectedly permits a formal run")
    blocker_codes = [
        "ADAPTER_VERIFIED_CLUSTER_COUNT_ZERO",
        "FORMAL_SPLIT_EMPTY",
        "G2_COST_UNRESOLVED",
        "INDEPENDENT_MAPPING_REVIEW_MISSING",
        "RQ2_AVAILABLE_AFTER_FIXED_HELDOUT_BELOW_60",
    ]
    return {
        "artifact_type": "agentmembrane_public_power_diagnostic",
        "blocker_codes": blocker_codes,
        "builder_implementation_sha256": builder_sha256,
        "decision": "NO_GO",
        "formal_run_permitted": False,
        "full_inventory_binding": {
            "eligibility_shortfall_sha256": _file_sha256(shortfall_path),
            "manifest_sha256": _file_sha256(manifest_path),
            "proposed_splits_sha256": _file_sha256(proposed_path),
        },
        "g2_additional_workflow_cost": "dynamic_unresolved",
        "pack_cluster_counts": dict(sorted(pack_cluster_counts.items())),
        "rq2_adapter_verified_cluster_count": rq2.get("adapter_verified_cluster_count"),
        "rq2_after_fixed_heldout_upper_bound": after[0],
        "rq2_formal_selected_cluster_count": rq2.get("formal_selected_cluster_count"),
        "rq2_meets_minimum_60_after_fixed_heldout": after[0] >= MINIMUM_FORMAL_CLUSTERS,
        "rq2_minimum_cluster_floor": MINIMUM_FORMAL_CLUSTERS,
        "rq2_preferred_cluster_floor": PREFERRED_FORMAL_CLUSTERS,
        "schema_version": EVIDENCE_SCHEMA_VERSION,
    }


def _present_ref(path: str, payload: bytes, status: str) -> dict[str, Any]:
    return {
        "path": path,
        "present": True,
        "sha256": sha256_bytes(payload),
        "status": status,
    }


def _missing_ref() -> dict[str, Any]:
    return {"path": None, "present": False, "sha256": None, "status": "missing"}


def build_overlay_documents(project_root: Path) -> dict[str, bytes]:
    """Compute all overlay files from protected inputs without writing them."""

    project = Path(project_root).resolve()
    builder_sha = _file_sha256(Path(__file__).resolve())
    packs = [load_taskpack(project / rel) for rel in PACK_RELATIVE_ROOTS]
    pack_shas = {pack.pack_id: taskpack_content_sha256(pack) for pack in packs}
    definitions = trusted_mechanism_definitions(builder_sha256=builder_sha)
    definition_bytes = _json_bytes(definitions)

    power = build_power_diagnostic(
        project / FULL_INVENTORY_RELATIVE_ROOT,
        pack_cluster_counts={
            pack.pack_id: len({task.cluster_id for task in pack.tasks}) for pack in packs
        },
        builder_sha256=builder_sha,
    )
    power_bytes = _json_bytes(power)
    documents: dict[str, bytes] = {
        "mechanism_definitions.json": definition_bytes,
        "power_diagnostic.json": power_bytes,
    }
    manifest_packs = []
    decision_packs = []
    for pack in sorted(packs, key=lambda item: item.pack_id):
        logical_sha = pack_shas[pack.pack_id]
        directory = f"packs/{pack.pack_id}"
        mapping = build_mechanism_mapping_draft(
            pack,
            taskpack_sha256=logical_sha,
            definitions_sha256=sha256_bytes(definition_bytes),
        )
        split = build_split_diagnostic(
            pack,
            taskpack_sha256=logical_sha,
            power_facts=power,
        )
        oracle = build_oracle_diagnostic(pack, taskpack_sha256=logical_sha)
        mapping_path = f"{directory}/mechanism_mapping.draft.json"
        split_path = f"{directory}/split_diagnostic.json"
        oracle_path = f"{directory}/oracle_diagnostic.json"
        mapping_bytes = _json_bytes(mapping)
        split_bytes = _json_bytes(split)
        oracle_bytes = _json_bytes(oracle)
        documents[mapping_path] = mapping_bytes
        documents[split_path] = split_bytes
        documents[oracle_path] = oracle_bytes
        blockers = sorted(
            set(power["blocker_codes"])
            | set(split["blocker_codes"])
            | set(oracle["blocker_codes"])
            | {
                "INDEPENDENT_MAPPING_REVIEW_MISSING",
                "NATIVE_CHECKER_PARITY_MISSING",
                "RUNTIME_PREFLIGHT_MISSING",
            }
        )
        evidence = {
            "checker_parity": _missing_ref(),
            "mechanism_mapping": _present_ref(
                mapping_path, mapping_bytes, "draft_unreviewed"
            ),
            "oracle_diagnostic": _present_ref(
                oracle_path, oracle_bytes, "diagnostic_no_go"
            ),
            "runtime_preflight": _missing_ref(),
            "split_diagnostic": _present_ref(
                split_path, split_bytes, "diagnostic_no_go"
            ),
        }
        manifest_packs.append(
            {
                **_pack_binding(pack, logical_sha),
                "blocker_codes": blockers,
                "decision": "NO_GO",
                "evidence": evidence,
            }
        )
        decision_packs.append(
            {
                "blocker_codes": blockers,
                "decision": "NO_GO",
                "pack_id": pack.pack_id,
            }
        )

    decision = {
        "artifact_type": "agentmembrane_public_readiness_diagnostic_decision",
        "claim_eligible": False,
        "decision": "NO_GO",
        "formal_run_permitted": False,
        "overlay_id": OVERLAY_ID,
        "packs": decision_packs,
        "power_diagnostic": _present_ref(
            "power_diagnostic.json", power_bytes, "diagnostic_no_go"
        ),
        "schema_version": EVIDENCE_SCHEMA_VERSION,
    }
    decision_bytes = _json_bytes(decision)
    documents["decision.json"] = decision_bytes
    manifest = {
        "artifact_type": "agentmembrane_public_readiness_diagnostic_overlay",
        "claim_eligible": False,
        "decision": "NO_GO",
        "decision_artifact": _present_ref(
            "decision.json", decision_bytes, "diagnostic_no_go"
        ),
        "formal_run_permitted": False,
        "mechanism_definitions": _present_ref(
            "mechanism_definitions.json", definition_bytes, "frozen_definitions"
        ),
        "offline_execution": {
            "api_calls": 0,
            "formal_or_public_runs": 0,
            "model_calls": 0,
            "network_calls": 0,
            "package_installs": 0,
        },
        "overlay_id": OVERLAY_ID,
        "packs": manifest_packs,
        "power_diagnostic": _present_ref(
            "power_diagnostic.json", power_bytes, "diagnostic_no_go"
        ),
        "schema_version": EVIDENCE_SCHEMA_VERSION,
    }
    documents["manifest.json"] = _json_bytes(manifest)
    return dict(sorted(documents.items()))


def materialize_public_evidence_overlay(
    project_root: Path, output_root: Path | None = None
) -> dict[str, Any]:
    """Create a fresh overlay, or verify an existing byte-identical overlay.

    Existing non-identical content is never overwritten.  This makes namespace
    reuse fail closed and makes repeated materialization byte-idempotent.
    """

    project = Path(project_root).resolve()
    output = (
        Path(output_root).resolve()
        if output_root is not None
        else (project / OVERLAY_RELATIVE_ROOT).resolve()
    )
    documents = build_overlay_documents(project)
    if output.exists():
        if not output.is_dir():
            raise IntegrityError(f"overlay output is not a directory: {output}")
        existing = {
            path.relative_to(output).as_posix(): path.read_bytes()
            for path in output.rglob("*")
            if path.is_file()
        }
        if existing != documents:
            raise IntegrityError(
                "public evidence overlay namespace exists with non-identical bytes"
            )
    else:
        for relative, payload in documents.items():
            path = output / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
    manifest = json.loads(documents["manifest.json"].decode("utf-8"))
    return {
        "decision": manifest["decision"],
        "file_count": len(documents),
        "manifest_sha256": sha256_bytes(documents["manifest.json"]),
        "output_root": str(output),
    }


def verify_public_evidence_overlay(project_root: Path, output_root: Path) -> dict[str, Any]:
    """Recompute the overlay and require exact path and byte equality."""

    expected = build_overlay_documents(project_root)
    root = Path(output_root).resolve()
    if not root.is_dir():
        raise IntegrityError(f"overlay root is missing: {root}")
    actual = {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file()
    }
    if actual != expected:
        raise IntegrityError("public evidence overlay does not match protected inputs")
    return {
        "decision": "NO_GO",
        "file_count": len(actual),
        "manifest_sha256": sha256_bytes(actual["manifest.json"]),
        "valid": True,
    }


__all__ = [
    "EVIDENCE_SCHEMA_VERSION",
    "MINIMUM_FORMAL_CLUSTERS",
    "OVERLAY_ID",
    "OVERLAY_RELATIVE_ROOT",
    "PREFERRED_FORMAL_CLUSTERS",
    "SPLIT_ORDER",
    "TRUSTED_MECHANISM_IDS",
    "build_mechanism_mapping_draft",
    "build_oracle_diagnostic",
    "build_overlay_documents",
    "build_power_diagnostic",
    "build_split_diagnostic",
    "materialize_public_evidence_overlay",
    "trusted_mechanism_definitions",
    "validate_mechanism_mapping_draft",
    "verify_public_evidence_overlay",
]
