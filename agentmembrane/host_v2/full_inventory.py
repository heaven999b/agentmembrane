"""Deterministic full-source inventory for the public Host Boundary V2 inputs.

This module is deliberately an inventory builder, not a benchmark runner.  It
reads the frozen tau2-bench and AgentDojo snapshots without importing them,
calling a model, or contacting a service.  In particular, it keeps generated
scenario variants and AgentDojo's user-task/injection-task Cartesian product in
their source workflow cluster instead of treating them as independent draws.

The emitted split proposal is non-claim-bearing.  Eligibility is assessed for
the pooled, cross-domain workflow population specified by STATISTICAL_PLAN.md;
there is no invented per-domain 60-workflow requirement.  Source-workflow
counts are still only upper bounds, and ``formal`` remains empty until adapter
parity, mechanism mapping, G2, and the variance-pilot decision are complete.
"""

from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any


SCHEMA_VERSION = 2
DATA_CLASS = "established_public_realistic_simulation"
PRODUCTION_DATA = False
SPLIT_SEED = "host-boundary-v2-full-inventory-split-v2"
SPLIT_ORDER = ("G0", "G1", "G2", "pilot", "reserve", "formal")
GATE_CLUSTER_TARGET = 6
PILOT_CLUSTER_TARGET = 20
FORMAL_CLUSTER_FLOORS = (60, 100)
FIXED_HELDOUT_CLUSTER_COST = 2 * GATE_CLUSTER_TARGET + PILOT_CLUSTER_TARGET

TAU2_RQ1_CONTRASTS = (
    "A0_to_A1",
    "A1_to_A2",
    "A2_to_A3",
    "A3_to_A4",
    "A4_to_A5",
)
AGENTDOJO_RQ2_MECHANISMS = (
    "confused_deputy",
    "capability_delegation",
    "proposal_to_action_conversion",
    "multi_step_capability_chaining",
    "cross_tool_composition",
    "internal_transformation_action_laundering",
)
DOMAINS = (
    "retail",
    "airline",
    "telecom",
    "banking_knowledge",
    "workspace",
    "banking",
    "slack",
    "travel",
)

_TAU2_MUTATIONS = {
    "retail": frozenset(
        {
            "cancel_pending_order",
            "exchange_delivered_order_items",
            "modify_pending_order_address",
            "modify_pending_order_items",
            "modify_pending_order_payment",
            "modify_user_address",
            "return_delivered_order_items",
        }
    ),
    "airline": frozenset(
        {
            "book_reservation",
            "cancel_reservation",
            "update_reservation_baggages",
            "update_reservation_flights",
            "update_reservation_passengers",
        }
    ),
    "telecom": frozenset(
        {"enable_roaming", "refuel_data", "resume_line", "send_payment_request"}
    ),
}
_AGENTDOJO_DOMAINS = ("workspace", "banking", "slack", "travel")
_TELECOM_ID = re.compile(r"^\[([^]]+)\](.*)\[PERSONA:([^]]*)\]$")
_CLASS_NUMBER = re.compile(r"^(?:User|Injection)Task(\d+)$")
_YAML_TOP_KEY = re.compile(r"^([A-Za-z0-9_]+):\s*$")

# Human-reviewed possible-identity aliases in the frozen banking_knowledge
# snapshot.  These edges make the primary accounting more conservative than
# explicit user_id grouping.  They are evidence links, not a claim that the
# synthetic records denote the same real person.  Additional unverified text
# similarities are deliberately not inferred by a fuzzy matcher.
_BANKING_CONSERVATIVE_ALIAS_GROUPS = (
    ("task_004", "task_005"),  # Kenji Tanaka: strong email/phone/ID alias
    ("task_014", "task_015"),  # Fatima Al-Hassan: strong age/city/phone/ID alias
    ("task_032", "task_044"),  # Sofia Papadopoulos: same-name conflict
    ("task_033", "task_051"),  # Zhang Mei: same-name conflict
    ("task_035", "task_019"),  # Priya Sharma: same-name conflict
    ("task_012", "task_024"),  # Marcus Chen: same-name conflict
    ("task_007", "task_060"),  # Jordan Mitchell: same-name conflict
)
_BANKING_VERIFIED_ALIAS_GROUPS = _BANKING_CONSERVATIVE_ALIAS_GROUPS[:2]


class FullInventoryError(RuntimeError):
    """The frozen snapshot cannot be inventoried without weakening provenance."""


@dataclass(frozen=True)
class InventoryBuild:
    root: Path
    files: tuple[str, ...]
    tree_sha256: str
    tau2_task_count: int
    agentdojo_user_task_count: int
    agentdojo_attack_pairing_count: int


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _sha_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha_json(value: Any) -> str:
    return _sha_bytes(_canonical_bytes(value))


def _sha_file(path: Path) -> str:
    try:
        return _sha_bytes(path.read_bytes())
    except OSError as exc:
        raise FullInventoryError(f"cannot hash {path}: {exc}") from exc


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise FullInventoryError(f"cannot load frozen JSON {path}: {exc}") from exc


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical_bytes(value) + b"\n")


def _write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"".join(_canonical_bytes(dict(row)) + b"\n" for row in rows))


def _require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FullInventoryError(f"{label} must be an object")
    return value


def _source_registry(repo_root: Path) -> dict[str, dict[str, Any]]:
    raw = _require_dict(
        _load_json(repo_root / "data/host_boundary_v2/upstream_manifest.json"),
        "upstream manifest",
    )
    if raw.get("schema_version") != 1 or not isinstance(raw.get("sources"), list):
        raise FullInventoryError("upstream manifest must be schema_version=1 with sources")
    result: dict[str, dict[str, Any]] = {}
    for source in raw["sources"]:
        item = _require_dict(source, "upstream source")
        source_id = item.get("source_id")
        if not isinstance(source_id, str) or not source_id or source_id in result:
            raise FullInventoryError(f"invalid or duplicate upstream source_id: {source_id!r}")
        result[source_id] = item
    return result


def _source_root(repo_root: Path, source: Mapping[str, Any]) -> Path:
    raw = source.get("local_root")
    if not isinstance(raw, str) or not raw:
        raise FullInventoryError("source.local_root must be a nonempty string")
    path = Path(raw)
    if not path.is_absolute():
        path = repo_root / path
    if not path.is_dir():
        raise FullInventoryError(f"frozen source root is missing: {path}")
    return path.resolve()


def _locked_file(root: Path, relative: str, expected: str | None = None) -> dict[str, str]:
    rel = Path(relative)
    if rel.is_absolute() or ".." in rel.parts:
        raise FullInventoryError(f"source path escapes root: {relative}")
    path = (root / rel).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise FullInventoryError(f"source path escapes root: {relative}") from exc
    if not path.is_file():
        raise FullInventoryError(f"source file is missing: {relative}")
    actual = _sha_file(path)
    if expected is not None and actual != expected:
        raise FullInventoryError(
            f"source SHA-256 mismatch for {relative}: expected={expected}, actual={actual}"
        )
    return {"path": relative, "sha256": actual}


def _stable_key(*parts: str) -> str:
    return _sha_bytes("\x00".join(parts).encode("utf-8"))


def _assign_nonformal_splits(cluster_domains: Mapping[str, str]) -> dict[str, str]:
    """Partition real clusters without ever manufacturing formal observations."""

    buckets: dict[str, list[str]] = defaultdict(list)
    for cluster_id, domain in cluster_domains.items():
        buckets[domain].append(cluster_id)
    for domain, clusters in buckets.items():
        clusters.sort(key=lambda value: (_stable_key(SPLIT_SEED, domain, value), value))
    domain_order = sorted(
        buckets, key=lambda value: (_stable_key(SPLIT_SEED, "domain", value), value)
    )
    ordered: list[str] = []
    depth = 0
    while any(depth < len(buckets[domain]) for domain in domain_order):
        for domain in domain_order:
            if depth < len(buckets[domain]):
                ordered.append(buckets[domain][depth])
        depth += 1
    result: dict[str, str] = {}
    cursor = 0
    for split in ("G0", "G1"):
        for cluster_id in ordered[cursor : cursor + GATE_CLUSTER_TARGET]:
            result[cluster_id] = split
        cursor += GATE_CLUSTER_TARGET
    for cluster_id in ordered[cursor : cursor + PILOT_CLUSTER_TARGET]:
        result[cluster_id] = "pilot"
    cursor += PILOT_CLUSTER_TARGET
    # G2 is a dynamically generated estimand-cell union.  Its workflow cost is
    # not known at source-inventory time, so assigning arbitrary clusters here
    # would falsely make it look frozen.  Unspent workflows remain reserve.
    for cluster_id in ordered[cursor:]:
        result[cluster_id] = "reserve"
    if set(result) != set(cluster_domains) or "formal" in result.values():
        raise FullInventoryError("nonformal split assignment lost or formalized a cluster")
    return result


def _directory_lock(root: Path, relative: str) -> dict[str, Any]:
    """Hash a frozen corpus without treating its files as scientific units."""

    rel = Path(relative)
    path = (root / rel).resolve()
    try:
        path.relative_to(root.resolve())
    except ValueError as exc:
        raise FullInventoryError(f"source path escapes root: {relative}") from exc
    if not path.is_dir():
        raise FullInventoryError(f"source directory is missing: {relative}")
    entries = {
        child.relative_to(path).as_posix(): _sha_file(child)
        for child in path.rglob("*")
        if child.is_file()
    }
    if not entries:
        raise FullInventoryError(f"source directory is empty: {relative}")
    return {
        "path": relative,
        "sha256": _tree_hash(entries),
        "file_count": len(entries),
        "kind": "fixed_infrastructure_corpus",
    }


def _banking_principals(task: Mapping[str, Any]) -> set[str]:
    """Recover explicit synthetic account principals without text heuristics."""

    principals: set[str] = set()
    initial = task.get("initial_state") or {}
    try:
        users = initial["initialization_data"]["agent_data"]["users"]["data"]
    except (KeyError, TypeError):
        users = {}
    if isinstance(users, dict):
        principals.update(str(value) for value in users)

    def visit(value: Any, *, key: str | None = None) -> None:
        if isinstance(value, dict):
            for nested_key, nested_value in value.items():
                visit(nested_value, key=str(nested_key))
        elif isinstance(value, list):
            for nested_value in value:
                visit(nested_value, key=key)
        elif isinstance(value, str):
            if key == "user_id" and value:
                principals.add(value)
            elif key == "arguments" and value.startswith("{"):
                try:
                    decoded = json.loads(value)
                except json.JSONDecodeError:
                    return
                visit(decoded)

    criteria = _require_dict(task.get("evaluation_criteria"), "banking criteria")
    visit(criteria.get("actions") or [])
    return principals


def _connected_task_components(
    tasks: Sequence[Mapping[str, Any]], *, key_sets: Mapping[str, set[str]]
) -> dict[str, tuple[str, ...]]:
    """Return task components connected by shared declared keys."""

    task_ids = [str(task["id"]) for task in tasks]
    parent = {task_id: task_id for task_id in task_ids}

    def find(value: str) -> str:
        while parent[value] != value:
            parent[value] = parent[parent[value]]
            value = parent[value]
        return value

    def union(left: str, right: str) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    by_key: dict[str, list[str]] = defaultdict(list)
    for task_id in task_ids:
        for value in key_sets.get(task_id, set()):
            by_key[value].append(task_id)
    for connected in by_key.values():
        for task_id in connected[1:]:
            union(connected[0], task_id)
    components: dict[str, list[str]] = defaultdict(list)
    for task_id in task_ids:
        components[find(task_id)].append(task_id)
    canonical = {
        task_id: tuple(sorted(components[find(task_id)])) for task_id in task_ids
    }
    return canonical


def _tau2_account_id(
    task: Mapping[str, Any], db: Mapping[str, Any], *, resource_key: str
) -> str:
    users = _require_dict(db.get("users"), "tau2 db.users")
    resources = _require_dict(db.get(resource_key), f"tau2 db.{resource_key}")
    instructions = _require_dict(
        _require_dict(task.get("user_scenario"), "tau2 user_scenario").get("instructions"),
        "tau2 user_scenario.instructions",
    )
    known = str(instructions.get("known_info") or "").casefold()

    matches = [str(user_id) for user_id in users if str(user_id).casefold() in known]
    if len(matches) == 1:
        return matches[0]
    for user_id, raw_user in users.items():
        user = _require_dict(raw_user, "tau2 user")
        email = str(user.get("email") or "")
        if email and email.casefold() in known:
            return str(user_id)
    for user_id, raw_user in users.items():
        user = _require_dict(raw_user, "tau2 user")
        name = _require_dict(user.get("name"), "tau2 user.name")
        address = _require_dict(user.get("address"), "tau2 user.address")
        full_name = f"{name.get('first_name', '')} {name.get('last_name', '')}".casefold()
        postal = str(address.get("zip") or "").casefold()
        if full_name.strip() and postal and full_name in known and postal in known:
            return str(user_id)

    # Refusal/read-only tasks can omit lookup actions.  Source-wide stable IDs
    # and owned resource IDs still resolve their account without guessing.
    text = json.dumps(task, ensure_ascii=False).casefold()
    found: set[str] = set()
    for user_id in users:
        if str(user_id).casefold() in text:
            found.add(str(user_id))
    for resource_id, raw_resource in resources.items():
        if str(resource_id).casefold() in text:
            resource = _require_dict(raw_resource, "tau2 owned resource")
            found.add(str(resource["user_id"]))
    if len(found) != 1:
        raise FullInventoryError(
            f"tau2 task {task.get('id')!r} has ambiguous account identity: {sorted(found)}"
        )
    return next(iter(found))


def _tau2_oracle(task: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    criteria = _require_dict(task.get("evaluation_criteria"), "tau2 evaluation_criteria")
    reward_basis = criteria.get("reward_basis")
    if not isinstance(reward_basis, list) or not reward_basis or not all(
        isinstance(value, str) and value for value in reward_basis
    ):
        raise FullInventoryError(f"tau2 task {task.get('id')!r} has no native reward basis")
    actions = criteria.get("actions") or []
    if not isinstance(actions, list):
        raise FullInventoryError(f"tau2 task {task.get('id')!r} actions must be a list")
    action_names = []
    for action in actions:
        item = _require_dict(action, "tau2 oracle action")
        name = item.get("name")
        if not isinstance(name, str) or not name:
            raise FullInventoryError("tau2 oracle action lacks a name")
        action_names.append(name)
    oracle = {
        "source_field": "evaluation_criteria",
        "sha256": _sha_json(criteria),
        "reward_basis": list(reward_basis),
        "expected_action_names_in_order": action_names,
        "action_count": len(actions),
        "env_assertion_count": len(criteria.get("env_assertions") or []),
        "nl_assertion_count": len(criteria.get("nl_assertions") or []),
        "communicate_info_count": len(criteria.get("communicate_info") or []),
        "outcome_semantics": (
            "Use the frozen tau2 evaluator on the exact evaluation_criteria object; "
            "empty expected-action lists retain native no-write/refusal semantics."
        ),
    }
    return oracle, action_names


def _inventory_tau2(
    repo_root: Path, source: Mapping[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    root = _source_root(repo_root, source)
    declared = {
        str(item["path"]): item
        for item in source.get("task_files", [])
        if isinstance(item, dict) and isinstance(item.get("path"), str)
    }
    rows: list[dict[str, Any]] = []
    locks: list[dict[str, Any]] = []
    for domain in ("retail", "airline", "telecom", "banking_knowledge"):
        relative = f"data/tau2/domains/{domain}/tasks.json"
        if relative not in declared and domain != "banking_knowledge":
            raise FullInventoryError(f"tau2 upstream registry omits {relative}")
        entry = declared.get(relative)
        expected_sha = str(entry["sha256"]) if entry is not None else None
        locks.append(_locked_file(root, relative, expected_sha))
        tasks = _load_json(root / relative)
        expected_count = entry.get("task_count") if entry is not None else 97
        if not isinstance(tasks, list) or len(tasks) != expected_count:
            raise FullInventoryError(f"tau2 task count mismatch for {domain}")
        db: dict[str, Any] | None = None
        if domain in {"retail", "airline"}:
            db_relative = f"data/tau2/domains/{domain}/db.json"
            locks.append(_locked_file(root, db_relative))
            db = _require_dict(_load_json(root / db_relative), f"tau2 {domain} db")
        banking_components: dict[str, tuple[str, ...]] = {}
        banking_explicit_components: dict[str, tuple[str, ...]] = {}
        banking_verified_components: dict[str, tuple[str, ...]] = {}
        banking_document_components: dict[str, tuple[str, ...]] = {}
        banking_principals: dict[str, set[str]] = {}
        if domain == "banking_knowledge":
            db_relative = f"data/tau2/domains/{domain}/db.json"
            docs_relative = f"data/tau2/domains/{domain}/documents"
            locks.append(_locked_file(root, db_relative))
            locks.append(_directory_lock(root, docs_relative))
            banking_principals = {
                str(_require_dict(task, "banking task")["id"]): _banking_principals(
                    _require_dict(task, "banking task")
                )
                for task in tasks
            }
            banking_explicit_components = _connected_task_components(
                tasks, key_sets=banking_principals
            )
            conservative_keys = {
                task_id: set(values) for task_id, values in banking_principals.items()
            }
            verified_keys = {
                task_id: set(values) for task_id, values in banking_principals.items()
            }
            known_task_ids = set(conservative_keys)
            for alias_index, alias_group in enumerate(
                _BANKING_CONSERVATIVE_ALIAS_GROUPS, start=1
            ):
                if not set(alias_group) <= known_task_ids:
                    raise FullInventoryError(
                        f"banking alias group references missing task: {alias_group}"
                    )
                alias_key = f"audited-possible-alias-{alias_index:02d}"
                for task_id in alias_group:
                    conservative_keys[task_id].add(alias_key)
                    if alias_group in _BANKING_VERIFIED_ALIAS_GROUPS:
                        verified_keys[task_id].add(alias_key)
            banking_components = _connected_task_components(
                tasks, key_sets=conservative_keys
            )
            banking_verified_components = _connected_task_components(
                tasks, key_sets=verified_keys
            )
            document_keys = {
                str(task["id"]): {
                    str(value) for value in task.get("required_documents") or []
                }
                for task in tasks
            }
            banking_document_components = _connected_task_components(
                tasks, key_sets=document_keys
            )
        seen: set[str] = set()
        for source_index, raw_task in enumerate(tasks):
            task = _require_dict(raw_task, f"tau2 {domain} task[{source_index}]")
            source_task_id = task.get("id")
            if not isinstance(source_task_id, str) or not source_task_id or source_task_id in seen:
                raise FullInventoryError(
                    f"tau2 {domain} has invalid/duplicate task ID {source_task_id!r}"
                )
            seen.add(source_task_id)
            oracle, action_names = _tau2_oracle(task)
            document_sensitivity: dict[str, Any] | None = None
            if domain == "telecom":
                match = _TELECOM_ID.fullmatch(source_task_id)
                if match is None:
                    raise FullInventoryError(f"unrecognized telecom generated ID: {source_task_id}")
                issue_family, raw_conditions, persona = match.groups()
                assistant_actions = tuple(
                    str(action["name"])
                    for action in task["evaluation_criteria"].get("actions") or []
                    if isinstance(action, dict) and action.get("requestor") == "assistant"
                )
                signature = assistant_actions or ("no_assistant_mutation",)
                cluster_id = f"tau2:telecom:workflow:{issue_family}:{'+'.join(signature)}"
                cluster_basis = {
                    "kind": "generated_workflow_semantics",
                    "issue_family": issue_family,
                    "assistant_action_signature": list(assistant_actions),
                    "persona_and_fault_combinations_are_variants": True,
                }
                variant = {
                    "condition_tokens": raw_conditions.split("|") if raw_conditions else [],
                    "persona": persona,
                    "counts_as_independent_cluster": False,
                }
                mutation_actions = [name for name in assistant_actions if name in _TAU2_MUTATIONS[domain]]
            elif domain in {"retail", "airline"}:
                assert db is not None
                resource_key = "orders" if domain == "retail" else "reservations"
                account_id = _tau2_account_id(task, db, resource_key=resource_key)
                cluster_id = f"tau2:{domain}:account:{account_id}"
                cluster_basis = {
                    "kind": "shared_simulated_account",
                    "account_id": account_id,
                    "tasks_sharing_account_are_independent": False,
                    "cross_account_semantic_independence_verified": False,
                }
                variant = None
                mutation_actions = [name for name in action_names if name in _TAU2_MUTATIONS[domain]]
            else:
                component = banking_components[source_task_id]
                explicit_component = banking_explicit_components[source_task_id]
                verified_component = banking_verified_components[source_task_id]
                principal_ids = sorted(
                    {
                        principal
                        for task_id in component
                        for principal in banking_principals[task_id]
                    }
                )
                component_digest = _sha_json(list(component))[:16]
                if principal_ids or len(component) > 1:
                    cluster_id = (
                        f"tau2:banking_knowledge:account-component:{component_digest}"
                    )
                    cluster_kind = (
                        "shared_synthetic_account_component"
                        if principal_ids
                        else "conservative_possible_identity_component"
                    )
                else:
                    cluster_id = f"tau2:banking_knowledge:workflow:{source_task_id}"
                    cluster_kind = "accountless_authored_workflow"
                cluster_basis = {
                    "kind": cluster_kind,
                    "component_task_ids": list(component),
                    "explicit_principal_ids": principal_ids,
                    "tasks_sharing_or_connecting_accounts_are_independent": False,
                    "cross_component_semantic_independence_verified": False,
                    "explicit_principal_sensitivity_cluster_id": (
                        "tau2:banking_knowledge:explicit-principal-component:"
                        f"{_sha_json(list(explicit_component))[:16]}"
                    ),
                    "explicit_principal_sensitivity_component_task_ids": list(
                        explicit_component
                    ),
                    "verified_identity_sensitivity_cluster_id": (
                        "tau2:banking_knowledge:verified-identity-component:"
                        f"{_sha_json(list(verified_component))[:16]}"
                    ),
                    "verified_identity_sensitivity_component_task_ids": list(
                        verified_component
                    ),
                    "conservative_alias_groups_applied": [
                        {
                            "task_ids": list(group),
                            "evidence_tier": (
                                "strong_verified_alias"
                                if group in _BANKING_VERIFIED_ALIAS_GROUPS
                                else "same_name_collision_conflict"
                            ),
                        }
                        for group in _BANKING_CONSERVATIVE_ALIAS_GROUPS
                        if set(group) & set(component)
                    ],
                }
                doc_component = banking_document_components[source_task_id]
                document_sensitivity = {
                    "required_document_corpus_is_fixed_infrastructure": True,
                    "documents_count_as_host_clusters": False,
                    "document_connected_component_id": (
                        "tau2:banking_knowledge:document-component:"
                        f"{_sha_json(list(doc_component))[:16]}"
                    ),
                    "document_connected_component_task_count": len(doc_component),
                    "purpose": (
                        "Sensitivity grouping only; shared policy documents are not "
                        "independently sampled Host workflows."
                    ),
                }
                variant = None
                mutation_actions = list(action_names)
            raw_instructions = _require_dict(
                task["user_scenario"], "tau2 user_scenario"
            )["instructions"]
            if isinstance(raw_instructions, dict):
                reason_for_call = raw_instructions.get("reason_for_call")
            elif isinstance(raw_instructions, str):
                reason_for_call = raw_instructions
            else:
                raise FullInventoryError("tau2 instructions must be an object or string")
            rows.append(
                {
                    "benchmark": "tau2-bench",
                    "benchmark_version": str(source["version"]),
                    "domain": domain,
                    "source_task_id": source_task_id,
                    "source_index": source_index,
                    "source_path": relative,
                    "source_task_sha256": _sha_json(task),
                    "workflow_id": f"tau2:{domain}:{source_task_id}",
                    "cluster_id": cluster_id,
                    "cluster_basis": cluster_basis,
                    "variant": variant,
                    "reason_for_call": reason_for_call,
                    "oracle": oracle,
                    "mutation_actions_in_order": mutation_actions,
                    "boundary_adaptable": bool(mutation_actions),
                    "native_adversarial_task": False,
                    "derived_attack_requires_frozen_adapter": bool(mutation_actions),
                    "source_usable": True,
                    "adapter_parity_verified": False,
                    "document_dependency_sensitivity": document_sensitivity,
                    "data_class": DATA_CLASS,
                    "production_data": PRODUCTION_DATA,
                }
            )
    return rows, sorted(locks, key=lambda item: item["path"])


def _decorator_matches(node: ast.expr, name: str) -> bool:
    return isinstance(node, ast.Attribute) and node.attr == name


def _assignment_source(
    source_text: str, class_node: ast.ClassDef, attribute: str
) -> tuple[str, int]:
    for node in class_node.body:
        value: ast.expr | None = None
        targets: Sequence[ast.expr] = ()
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = (node.target,), node.value
        if value is not None and any(
            isinstance(target, ast.Name) and target.id == attribute for target in targets
        ):
            segment = ast.get_source_segment(source_text, value)
            if segment is None:
                raise FullInventoryError(f"cannot recover {class_node.name}.{attribute} source")
            return segment, node.lineno
    raise FullInventoryError(f"registered class {class_node.name} lacks {attribute}")


def _method_line(class_node: ast.ClassDef, method: str) -> int:
    matches = [
        node.lineno
        for node in class_node.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == method
    ]
    if len(matches) != 1:
        raise FullInventoryError(f"registered class {class_node.name} lacks exact {method}")
    return matches[0]


def _parse_agentdojo_classes(
    root: Path,
    *,
    domain: str,
    kind: str,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    if kind not in {"user", "injection"}:
        raise ValueError("kind must be user or injection")
    relative = f"src/agentdojo/default_suites/v1/{domain}/{kind}_tasks.py"
    path = root / relative
    try:
        source_text = path.read_text(encoding="utf-8")
        tree = ast.parse(source_text, filename=relative)
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise FullInventoryError(f"cannot statically parse {relative}: {exc}") from exc
    decorator = f"register_{kind}_task"
    attribute = "PROMPT" if kind == "user" else "GOAL"
    oracle_method = "utility" if kind == "user" else "security"
    records: list[dict[str, Any]] = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or not any(
            _decorator_matches(item, decorator) for item in node.decorator_list
        ):
            continue
        match = _CLASS_NUMBER.fullmatch(node.name)
        if match is None:
            raise FullInventoryError(f"registered AgentDojo class has unknown ID rule: {node.name}")
        number = int(match.group(1))
        source_id = f"{kind}_task_{number}"
        text_source, text_line = _assignment_source(source_text, node, attribute)
        ground_truth_line = _method_line(node, "ground_truth")
        oracle_line = _method_line(node, oracle_method)
        class_segment = ast.get_source_segment(source_text, node)
        if class_segment is None:
            raise FullInventoryError(f"cannot recover source for {node.name}")
        records.append(
            {
                "benchmark": "AgentDojo",
                "suite_version": "v1",
                "domain": domain,
                "kind": kind,
                "source_id": source_id,
                "class": node.name,
                "class_line": node.lineno,
                "source_path": relative,
                "source_file_sha256": _sha_file(path),
                "source_class_sha256": _sha_bytes(class_segment.encode("utf-8")),
                f"{attribute.lower()}_source": text_source,
                f"{attribute.lower()}_line": text_line,
                "ground_truth_ref": f"{relative}:{ground_truth_line}",
                "oracle_ref": f"{relative}:{oracle_line}",
                "oracle_method": oracle_method,
                "oracle_semantics": (
                    "True means benign utility success."
                    if kind == "user"
                    else "True means the injection goal executed (attack success); safety is its complement."
                ),
                "source_usable": True,
                "adapter_parity_verified": False,
                "data_class": DATA_CLASS,
                "production_data": PRODUCTION_DATA,
            }
        )
    records.sort(key=lambda row: int(str(row["source_id"]).rsplit("_", 1)[1]))
    if len({row["source_id"] for row in records}) != len(records) or not records:
        raise FullInventoryError(f"AgentDojo {domain} {kind} task IDs are empty/duplicated")
    return records, {"path": relative, "sha256": _sha_file(path)}


def _injection_vector_ids(path: Path) -> list[str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise FullInventoryError(f"cannot read AgentDojo injection vectors {path}: {exc}") from exc
    result = [match.group(1) for line in lines if (match := _YAML_TOP_KEY.fullmatch(line))]
    if not result or len(result) != len(set(result)):
        raise FullInventoryError(f"invalid/duplicate AgentDojo injection vector catalog: {path}")
    return result


def _inventory_agentdojo(
    repo_root: Path, source: Mapping[str, Any]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, str]]]:
    root = _source_root(repo_root, source)
    declared_user_hashes = {
        str(item["path"]): str(item["sha256"])
        for item in source.get("task_files", [])
        if isinstance(item, dict) and "path" in item and "sha256" in item
    }
    users: list[dict[str, Any]] = []
    injections: list[dict[str, Any]] = []
    locks: list[dict[str, str]] = []
    vectors: dict[str, list[str]] = {}
    for domain in _AGENTDOJO_DOMAINS:
        domain_users, user_lock = _parse_agentdojo_classes(
            root, domain=domain, kind="user"
        )
        expected = declared_user_hashes.get(user_lock["path"])
        if expected is None or user_lock["sha256"] != expected:
            raise FullInventoryError(f"AgentDojo user source lock differs for {domain}")
        domain_injections, injection_lock = _parse_agentdojo_classes(
            root, domain=domain, kind="injection"
        )
        vector_relative = f"src/agentdojo/data/suites/{domain}/injection_vectors.yaml"
        vector_lock = _locked_file(root, vector_relative)
        vectors[domain] = _injection_vector_ids(root / vector_relative)
        for row in domain_users:
            row["cluster_id"] = f"agentdojo:v1:{domain}:{row['source_id']}"
            row["cluster_basis"] = {
                "kind": "official_user_task_class",
                "user_task_id": row["source_id"],
                "attack_goal_and_vector_variants_are_independent": False,
            }
        users.extend(domain_users)
        injections.extend(domain_injections)
        locks.extend((user_lock, injection_lock, vector_lock))

    by_domain_users: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_domain_injections: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in users:
        by_domain_users[str(row["domain"])].append(row)
    for row in injections:
        by_domain_injections[str(row["domain"])].append(row)
    pairings: list[dict[str, Any]] = []
    for domain in _AGENTDOJO_DOMAINS:
        for user in by_domain_users[domain]:
            for injection in by_domain_injections[domain]:
                pairing_id = (
                    f"agentdojo:v1:{domain}:{user['source_id']}:{injection['source_id']}"
                )
                pairings.append(
                    {
                        "pairing_id": pairing_id,
                        "benchmark": "AgentDojo",
                        "suite_version": "v1",
                        "domain": domain,
                        "source_user_task_id": user["source_id"],
                        "source_injection_task_id": injection["source_id"],
                        "cluster_id": user["cluster_id"],
                        "counts_as_independent_cluster": False,
                        "native_cartesian_pairing": True,
                        "injection_vector_catalog": vectors[domain],
                        "injection_vector_resolution": {
                            "mode": "native_ground_truth_reachability",
                            "source_ref": "src/agentdojo/attacks/base_attacks.py:49",
                            "note": (
                                "Reachable vector selection is user-workflow dependent and attack-runtime "
                                "specific; vector choices are variants of this user workflow, not new n."
                            ),
                        },
                        "utility_oracle_ref": user["oracle_ref"],
                        "attack_success_oracle_ref": injection["oracle_ref"],
                        "outcome_semantics": {
                            "utility": "user utility() == True",
                            "attack_success": "injection security() == True",
                            "safety": "not attack_success",
                        },
                        "source_usable": True,
                        "adapter_parity_verified": False,
                        "data_class": DATA_CLASS,
                        "production_data": PRODUCTION_DATA,
                    }
                )
    return users, injections, pairings, sorted(locks, key=lambda item: item["path"])


def _current_candidate_coverage(
    repo_root: Path,
    tau2_rows: Sequence[Mapping[str, Any]],
    agentdojo_users: Sequence[Mapping[str, Any]],
    agentdojo_pairings: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    tau_path = repo_root / "data/host_boundary_v2/taskpacks/tau2_candidate_manifest.json"
    dojo_path = repo_root / "data/host_boundary_v2/taskpacks/agentdojo_candidate_manifest.json"
    tau = _require_dict(_load_json(tau_path), "tau2 candidate manifest")
    dojo = _require_dict(_load_json(dojo_path), "AgentDojo candidate manifest")
    tau_candidates = tau.get("candidates")
    dojo_candidates = dojo.get("candidates")
    if not isinstance(tau_candidates, list) or not isinstance(dojo_candidates, list):
        raise FullInventoryError("current candidate manifests lack candidate lists")
    tau_index = {
        (str(row["domain"]), str(row["source_task_id"])): row for row in tau2_rows
    }
    dojo_user_ids = {
        (str(row["domain"]), str(row["source_id"])) for row in agentdojo_users
    }
    pairing_ids = {str(row["pairing_id"]) for row in agentdojo_pairings}
    tau_selected_clusters: set[str] = set()
    for item in tau_candidates:
        candidate = _require_dict(item, "tau2 candidate")
        key = (str(candidate["domain"]), str(candidate["upstream_task_id"]))
        if key not in tau_index:
            raise FullInventoryError(f"current tau2 candidate is absent from full source: {key}")
        tau_selected_clusters.add(str(tau_index[key]["cluster_id"]))
    dojo_selected_clusters: set[str] = set()
    dojo_selected_pairings: set[str] = set()
    for item in dojo_candidates:
        candidate = _require_dict(item, "AgentDojo candidate")
        domain = str(candidate["domain"])
        user_id = str(_require_dict(candidate["original_user_task"], "candidate user")["id"])
        injection_id = str(
            _require_dict(candidate["original_injection_task"], "candidate injection")["id"]
        )
        if (domain, user_id) not in dojo_user_ids:
            raise FullInventoryError(
                f"current AgentDojo candidate user is absent from full source: {(domain, user_id)}"
            )
        pair_id = f"agentdojo:v1:{domain}:{user_id}:{injection_id}"
        if pair_id not in pairing_ids:
            raise FullInventoryError(f"current AgentDojo pairing is absent: {pair_id}")
        dojo_selected_clusters.add(f"agentdojo:v1:{domain}:{user_id}")
        dojo_selected_pairings.add(pair_id)
    return {
        "candidate_manifests_are_inventories_not_executable_packs": True,
        "tau2": {
            "candidate_manifest_path": tau_path.relative_to(repo_root).as_posix(),
            "candidate_manifest_sha256": _sha_file(tau_path),
            "selected_source_task_count": len(tau_candidates),
            "selected_full_cluster_count": len(tau_selected_clusters),
        },
        "agentdojo": {
            "candidate_manifest_path": dojo_path.relative_to(repo_root).as_posix(),
            "candidate_manifest_sha256": _sha_file(dojo_path),
            "selected_pairing_count": len(dojo_selected_pairings),
            "selected_full_cluster_count": len(dojo_selected_clusters),
        },
    }


def _population_row(
    *,
    benchmark: str,
    rq_id: str,
    contrast_id: str,
    domain_cluster_counts: Mapping[str, int],
    observation_count: int,
    cluster_count: int,
    fixed_heldout_cluster_cost: int,
    note: str,
) -> dict[str, Any]:
    available = max(0, cluster_count - fixed_heldout_cluster_cost)
    domains = sorted(domain_cluster_counts)
    total_domain_clusters = sum(domain_cluster_counts.values())
    primary_weights = (
        {domain: 1.0 / len(domains) for domain in domains} if domains else {}
    )
    empirical_weights = (
        {
            domain: domain_cluster_counts[domain] / total_domain_clusters
            for domain in domains
        }
        if total_domain_clusters
        else {}
    )
    return {
        "benchmark": benchmark,
        "rq_id": rq_id,
        "contrast_id": contrast_id,
        "estimand": "pooled_cross_domain_workflow_population",
        "domains": domains,
        "domain_cluster_counts": {
            domain: int(domain_cluster_counts[domain]) for domain in domains
        },
        "primary_equal_domain_weights": primary_weights,
        "sensitivity_workflow_proportional_weights": empirical_weights,
        "per_domain_minimum_cluster_requirement": None,
        "usable_observation_count": observation_count,
        "independent_cluster_count": cluster_count,
        "independent_cluster_count_is_upper_bound": True,
        "verified_truly_independent_cluster_count": 0,
        "fixed_heldout_cluster_cost": fixed_heldout_cluster_cost,
        "available_after_G0_G1_and_variance_pilot_upper_bound": available,
        "G2_additional_workflow_cost": "dynamic_unresolved",
        "minimum_clusters_if_q_at_or_below_0_30": FORMAL_CLUSTER_FLOORS[0],
        "minimum_clusters_if_q_above_0_30_or_unknown": FORMAL_CLUSTER_FLOORS[1],
        "shortfall_to_60": max(0, FORMAL_CLUSTER_FLOORS[0] - cluster_count),
        "shortfall_to_100": max(0, FORMAL_CLUSTER_FLOORS[1] - cluster_count),
        "meets_60": cluster_count >= FORMAL_CLUSTER_FLOORS[0],
        "meets_100": cluster_count >= FORMAL_CLUSTER_FLOORS[1],
        "meets_60_after_fixed_heldout": available >= FORMAL_CLUSTER_FLOORS[0],
        "meets_100_after_fixed_heldout": available >= FORMAL_CLUSTER_FLOORS[1],
        "formal_selected_cluster_count": 0,
        "formal_decision": "STOP",
        "adapter_verified_cluster_count": 0,
        "note": note,
    }


def _eligibility_report(
    tau2_rows: Sequence[Mapping[str, Any]],
    agentdojo_users: Sequence[Mapping[str, Any]],
    agentdojo_pairings: Sequence[Mapping[str, Any]],
    candidate_coverage: Mapping[str, Any],
) -> dict[str, Any]:
    boundary_tau = [row for row in tau2_rows if row["boundary_adaptable"]]
    tau_domain_counts = {
        domain: len(
            {
                str(row["cluster_id"])
                for row in boundary_tau
                if row["domain"] == domain
            }
        )
        for domain in ("retail", "airline", "telecom", "banking_knowledge")
    }
    dojo_domain_counts = {
        domain: len(
            {
                str(row["cluster_id"])
                for row in agentdojo_users
                if row["domain"] == domain
            }
        )
        for domain in _AGENTDOJO_DOMAINS
    }
    tau_cluster_count = len({str(row["cluster_id"]) for row in boundary_tau})
    dojo_cluster_count = len({str(row["cluster_id"]) for row in agentdojo_users})
    populations: list[dict[str, Any]] = []
    for contrast in TAU2_RQ1_CONTRASTS:
        populations.append(
            _population_row(
                benchmark="tau2-bench",
                rq_id="RQ1",
                contrast_id=contrast,
                domain_cluster_counts=tau_domain_counts,
                observation_count=len(boundary_tau),
                cluster_count=tau_cluster_count,
                fixed_heldout_cluster_cost=FIXED_HELDOUT_CLUSTER_COST,
                note=(
                    "Pooled across four domains with a stratified workflow bootstrap. "
                    "The benign oracle is source-native; the adversarial twin is an "
                    "AgentMembrane-derived adapter and is not a native tau2 attack."
                ),
            )
        )
    for contrast in (*AGENTDOJO_RQ2_MECHANISMS, "A4_four_module_lattice"):
        if contrast == "A4_four_module_lattice":
            continue
        populations.append(
            _population_row(
                benchmark="AgentDojo",
                rq_id="RQ2",
                contrast_id=contrast,
                domain_cluster_counts=dojo_domain_counts,
                observation_count=len(agentdojo_pairings),
                cluster_count=dojo_cluster_count,
                fixed_heldout_cluster_cost=FIXED_HELDOUT_CLUSTER_COST,
                note=(
                    "Pooled across four domains with a stratified workflow bootstrap. "
                    "All native pairs retain utility and attack-success oracles, but pair/vector "
                    "variants share the user-task cluster; canonical AgentMembrane mechanism "
                    "mapping and adapter parity remain unverified."
                ),
            )
        )
    for contrast in ("persistence_lifecycle", "propagation_topology"):
        populations.append(
            _population_row(
                benchmark="no_compatible_public_pack_in_current_inventory",
                rq_id="RQ3",
                contrast_id=contrast,
                domain_cluster_counts={},
                observation_count=0,
                cluster_count=0,
                fixed_heldout_cluster_cost=0,
                note="RQ3 still requires independently authored lifecycle/topology workflows.",
            )
        )
    combined_domain_counts = dict(tau_domain_counts)
    combined_domain_counts.update(dojo_domain_counts)
    populations.append(
        _population_row(
            benchmark="tau2-bench+AgentDojo",
            rq_id="RQ4",
            contrast_id="A4_four_module_lattice_holdout",
            domain_cluster_counts=combined_domain_counts,
            observation_count=len(boundary_tau) + len(agentdojo_pairings),
            cluster_count=tau_cluster_count + dojo_cluster_count,
            fixed_heldout_cluster_cost=2 * FIXED_HELDOUT_CLUSTER_COST,
            note=(
                "Upper bound over the combined RQ1/RQ2 workflow frame. RQ4 selection and "
                "confirmatory holdout mapping are not yet frozen; benchmark strata are retained."
            ),
        )
    )
    tau_domains = {
        domain: {
            "usable_tasks": sum(row["domain"] == domain for row in tau2_rows),
            "all_workflow_clusters": len(
                {str(row["cluster_id"]) for row in tau2_rows if row["domain"] == domain}
            ),
            "boundary_adaptable_tasks": sum(row["domain"] == domain for row in boundary_tau),
            "boundary_independent_clusters": len(
                {str(row["cluster_id"]) for row in boundary_tau if row["domain"] == domain}
            ),
        }
        for domain in ("retail", "airline", "telecom", "banking_knowledge")
    }
    dojo_domains = {
        domain: {
            "user_tasks": sum(row["domain"] == domain for row in agentdojo_users),
            "native_attack_pairings": sum(row["domain"] == domain for row in agentdojo_pairings),
            "independent_user_workflow_clusters": len(
                {
                    str(row["cluster_id"])
                    for row in agentdojo_users
                    if row["domain"] == domain
                }
            ),
        }
        for domain in _AGENTDOJO_DOMAINS
    }
    banking_rows = [row for row in boundary_tau if row["domain"] == "banking_knowledge"]
    document_components = {
        str(row["document_dependency_sensitivity"]["document_connected_component_id"])
        for row in banking_rows
    }
    banking_verified_components = {
        str(row["cluster_basis"]["verified_identity_sensitivity_cluster_id"])
        for row in banking_rows
    }
    banking_evaluator_components = {
        str(row["cluster_basis"]["explicit_principal_sensitivity_cluster_id"])
        for row in banking_rows
    }
    per_rq_upper_bounds: dict[str, Any] = {}
    for rq_id in ("RQ1", "RQ2", "RQ3", "RQ4"):
        rq_rows = [row for row in populations if row["rq_id"] == rq_id]
        per_rq_upper_bounds[rq_id] = {
            "contrast_ids": [str(row["contrast_id"]) for row in rq_rows],
            "source_workflow_cluster_upper_bounds": sorted(
                {int(row["independent_cluster_count"]) for row in rq_rows}
            ),
            "after_fixed_G0_G1_pilot_upper_bounds": sorted(
                {
                    int(row["available_after_G0_G1_and_variance_pilot_upper_bound"])
                    for row in rq_rows
                }
            ),
            "q_at_or_below_0_30_threshold": FORMAL_CLUSTER_FLOORS[0],
            "q_above_0_30_or_unknown_threshold": FORMAL_CLUSTER_FLOORS[1],
            "adapter_verified_cluster_count": 0,
            "formal_selected_cluster_count": 0,
            "formal_decision": "STOP",
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "decision": "STOP",
        "status": "pooled_inventory_sufficient_for_some_rqs_but_formal_blocked",
        "formal_run_permitted": False,
        "formal_split_must_be_empty": True,
        "claim_eligible": False,
        "unit_of_independence": "source_workflow_cluster",
        "estimand_contract": {
            "population": "pooled_cross_domain_workflow_population",
            "per_domain_minimum_cluster_requirement": None,
            "primary_bootstrap": (
                "resample complete workflow clusters within domain strata; retain every "
                "condition, twin, model call, and replicate in the sampled block"
            ),
            "primary_weights": "equal domain weight, equal workflow weight within domain",
            "sensitivity_weights": "workflow-proportional empirical benchmark weights",
            "mechanism_strata_pooled": False,
            "model_strata_pooled_to_inflate_n": False,
        },
        "inventory_cluster_counts_are_upper_bounds": True,
        "verified_truly_independent_cluster_count": 0,
        "data_class": DATA_CLASS,
        "production_data": PRODUCTION_DATA,
        "external_services_used": False,
        "network_calls": 0,
        "model_calls": 0,
        "independence_rules": [
            "An AgentDojo injection-task or injection-vector variant does not create a new user-workflow cluster.",
            "A tau2 telecom persona, fault combination, lexical form, or generated source ID does not create a new workflow cluster.",
            "tau2 retail/airline tasks sharing a simulated account remain one cluster.",
            "tau2 banking_knowledge tasks sharing or connecting an explicit synthetic account remain one cluster.",
            "The banking_knowledge document corpus is fixed infrastructure, not a sampled Host cluster.",
            "Source IDs and observations are retained even when they share one statistical cluster.",
        ],
        "summary": {
            "tau2": tau_domains,
            "tau2_usable_task_count": len(tau2_rows),
            "tau2_boundary_adaptable_task_count": len(boundary_tau),
            "tau2_boundary_independent_cluster_count": len(
                {str(row["cluster_id"]) for row in boundary_tau}
            ),
            "tau2_boundary_cluster_count_is_upper_bound": True,
            "tau2_banking_knowledge_primary_conservative_upper_bound": len(
                {str(row["cluster_id"]) for row in banking_rows}
            ),
            "tau2_banking_knowledge_verified_identity_merge_sensitivity_upper_bound": len(
                banking_verified_components
            ),
            "tau2_banking_knowledge_evaluator_field_component_upper_bound": len(
                banking_evaluator_components
            ),
            "tau2_banking_knowledge_document_connected_sensitivity_cluster_count": len(
                document_components
            ),
            "agentdojo": dojo_domains,
            "agentdojo_user_task_count": len(agentdojo_users),
            "agentdojo_native_attack_pairing_count": len(agentdojo_pairings),
            "agentdojo_independent_cluster_count": len(
                {str(row["cluster_id"]) for row in agentdojo_users}
            ),
            "agentdojo_cluster_count_is_upper_bound": True,
        },
        "current_candidate_builder_coverage": dict(candidate_coverage),
        "per_rq_pooled_upper_bounds": per_rq_upper_bounds,
        "populations": populations,
        "heldout_cost": {
            "G0_independent_workflows": GATE_CLUSTER_TARGET,
            "G0_episode_count": 2 * GATE_CLUSTER_TARGET,
            "G1_additional_independent_workflows": GATE_CLUSTER_TARGET,
            "G1_additional_episode_count": 2 * GATE_CLUSTER_TARGET,
            "variance_pilot_independent_workflows": PILOT_CLUSTER_TARGET,
            "fixed_independent_workflows_removed_before_formal": FIXED_HELDOUT_CLUSTER_COST,
            "G2": "dynamic estimand-cell union; additional unique-workflow cost unresolved",
        },
        "domain_heterogeneity_caveats": [
            "Pooled inference does not imply every domain independently has n=60 or n=100.",
            "Domain-specific effects and interactions are descriptive unless separately powered.",
            "The tau2 workflow distribution is highly unbalanced across domains; equal-domain weights are primary and workflow-proportional weights are sensitivity only.",
            (
                "banking_knowledge has "
                f"{len(document_components)} document-connected task components versus "
                f"{len({str(row['cluster_id']) for row in banking_rows})} conservative "
                "same-name-collision components, "
                f"{len(banking_verified_components)} verified-identity-merge components, and "
                f"{len(banking_evaluator_components)} evaluator-field components. All are source "
                "upper bounds, not verified independent n. The primary analysis treats the shared "
                "corpus as fixed infrastructure; the document-connected collapse is disclosed as "
                "a conservative dependency sensitivity."
            ),
        ],
        "formal_stop_reasons": [
            "Adapter parity is verified for zero clusters and formal selection remains zero.",
            "AgentDojo-to-canonical-RQ2 mechanism mapping is not yet verified.",
            "The dynamic G2 union and its additional held-out workflow cost are unresolved.",
            "RQ3 has no compatible lifecycle/topology workflow pack in this inventory.",
            "RQ2 has 86 pooled source-workflow clusters but only 54 remain after fixed G0/G1/pilot reservation, before any G2 cost.",
        ],
        "prohibited_claims": [
            "formal population claim",
            "production-data claim",
            "independent replication from injection, lexical, persona, fault, or identifier variants",
            "native tau2 attack claim for an AgentMembrane-derived adversarial twin",
        ],
    }


def _split_report(
    tau2_rows: Sequence[Mapping[str, Any]],
    agentdojo_users: Sequence[Mapping[str, Any]],
    agentdojo_pairings: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    populations: dict[str, dict[str, Any]] = {}
    tau = [row for row in tau2_rows if row["boundary_adaptable"]]
    for population_id, rows, observations, observation_key in (
        (
            "tau2_boundary_adaptable",
            tau,
            tau,
            "source_task_id",
        ),
        (
            "agentdojo_native_attack_pairings",
            agentdojo_users,
            agentdojo_pairings,
            "pairing_id",
        ),
    ):
        cluster_domains = {str(row["cluster_id"]): str(row["domain"]) for row in rows}
        assignment = _assign_nonformal_splits(cluster_domains)
        snapshots: dict[str, Any] = {}
        for split in SPLIT_ORDER:
            cluster_ids = sorted(
                cluster_id for cluster_id, value in assignment.items() if value == split
            )
            cluster_set = set(cluster_ids)
            selected_observations = sorted(
                str(row[observation_key])
                for row in observations
                if str(row["cluster_id"]) in cluster_set
            )
            snapshots[split] = {
                "claim_bearing": False,
                "cluster_ids": cluster_ids,
                "cluster_count": len(cluster_ids),
                "observation_ids": selected_observations,
                "observation_count": len(selected_observations),
                "domain_ids": sorted({cluster_domains[value] for value in cluster_ids}),
            }
        sets = {key: set(value["cluster_ids"]) for key, value in snapshots.items()}
        if set().union(*sets.values()) != set(cluster_domains):
            raise FullInventoryError(f"split proposal does not cover {population_id}")
        if any(sets[left] & sets[right] for i, left in enumerate(SPLIT_ORDER) for right in SPLIT_ORDER[i + 1 :]):
            raise FullInventoryError(f"split proposal overlaps for {population_id}")
        populations[population_id] = {
            "unit_of_independence": "source_workflow_cluster",
            "formal_decision": "STOP",
            "fixed_heldout_cluster_cost": FIXED_HELDOUT_CLUSTER_COST,
            "G2_workflow_cost": "dynamic_unresolved",
            "all_pairwise_cluster_intersections_empty": True,
            "splits": snapshots,
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "assignment_seed": SPLIT_SEED,
        "split_order": list(SPLIT_ORDER),
        "split_overlap_allowed": False,
        "formal_run_permitted": False,
        "formal_split_empty": True,
        "pilot_claim_bearing": False,
        "G2_is_dynamically_generated": True,
        "G2_placeholder_is_empty": True,
        "note": (
            "G0/G1 and the 20-workflow pilot are fixed non-claim reservations. G2 is "
            "intentionally empty until generated from the frozen estimand registry; all other "
            "workflows remain reserve. Formal remains empty until adapter parity and every gate pass."
        ),
        "populations": populations,
    }


def _tree_hash(entries: Mapping[str, str]) -> str:
    return _sha_json([{"path": path, "sha256": entries[path]} for path in sorted(entries)])


def build_full_inventory(
    *,
    repo_root: Path | None = None,
    output_root: Path | None = None,
) -> InventoryBuild:
    """Build the complete offline inventory into a new, empty directory."""

    repo_root = Path(repo_root or _repo_root()).resolve()
    output_root = Path(
        output_root or repo_root / "data/host_boundary_v2/full_inventory"
    ).resolve()
    if output_root.exists():
        raise FullInventoryError(f"output root already exists: {output_root}")
    registry = _source_registry(repo_root)
    try:
        tau_source = registry["tau2-bench-v1.0.1"]
        dojo_source = registry["agentdojo-v0.1.35"]
    except KeyError as exc:
        raise FullInventoryError(f"required frozen source is missing: {exc}") from exc
    parent = output_root.parent
    parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".full-inventory-", dir=parent))
    try:
        tau2_rows, tau_locks = _inventory_tau2(repo_root, tau_source)
        dojo_users, dojo_injections, dojo_pairings, dojo_locks = _inventory_agentdojo(
            repo_root, dojo_source
        )
        coverage = _current_candidate_coverage(
            repo_root, tau2_rows, dojo_users, dojo_pairings
        )
        eligibility = _eligibility_report(
            tau2_rows, dojo_users, dojo_pairings, coverage
        )
        splits = _split_report(tau2_rows, dojo_users, dojo_pairings)
        _write_jsonl(staging / "tau2_tasks.jsonl", tau2_rows)
        _write_jsonl(staging / "agentdojo_user_tasks.jsonl", dojo_users)
        _write_jsonl(staging / "agentdojo_injection_tasks.jsonl", dojo_injections)
        _write_jsonl(staging / "agentdojo_attack_pairings.jsonl", dojo_pairings)
        _write_json(staging / "eligibility_shortfall.json", eligibility)
        _write_json(staging / "proposed_splits.json", splits)
        output_files = {
            path.relative_to(staging).as_posix(): _sha_file(path)
            for path in staging.iterdir()
            if path.is_file()
        }
        manifest = {
            "schema_version": SCHEMA_VERSION,
            "inventory_id": "host-boundary-v2-full-public-inventory-v2",
            "data_class": DATA_CLASS,
            "production_data": PRODUCTION_DATA,
            "execution": {
                "offline_static_inventory": True,
                "imports_upstream_runtime": False,
                "network_calls": 0,
                "model_calls": 0,
            },
            "generator": {
                "path": "agentmembrane/host_v2/full_inventory.py",
                "sha256": _sha_file(Path(__file__).resolve()),
            },
            "sources": [
                {
                    "source_id": tau_source["source_id"],
                    "version": tau_source["version"],
                    "commit": tau_source["commit"],
                    "license": tau_source["license"],
                    "input_files": tau_locks,
                },
                {
                    "source_id": dojo_source["source_id"],
                    "version": dojo_source["version"],
                    "commit": dojo_source["commit"],
                    "license": dojo_source["license"],
                    "input_files": dojo_locks,
                },
            ],
            "counts": eligibility["summary"],
            "formal_decision": "STOP",
            "formal_run_permitted": False,
            "outputs": [
                {"path": path, "sha256": output_files[path]}
                for path in sorted(output_files)
            ],
            "output_tree_sha256": _tree_hash(output_files),
        }
        _write_json(staging / "manifest.json", manifest)
        staging.rename(output_root)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    files = tuple(sorted(path.name for path in output_root.iterdir() if path.is_file()))
    hashes = {name: _sha_file(output_root / name) for name in files}
    return InventoryBuild(
        root=output_root,
        files=files,
        tree_sha256=_tree_hash(hashes),
        tau2_task_count=len(tau2_rows),
        agentdojo_user_task_count=len(dojo_users),
        agentdojo_attack_pairing_count=len(dojo_pairings),
    )


def check_full_inventory(
    *, repo_root: Path | None = None, output_root: Path | None = None
) -> dict[str, Any]:
    """Rebuild in a temporary directory and compare every committed byte."""

    repo_root = Path(repo_root or _repo_root()).resolve()
    output_root = Path(
        output_root or repo_root / "data/host_boundary_v2/full_inventory"
    ).resolve()
    if not output_root.is_dir():
        raise FullInventoryError(f"committed inventory is missing: {output_root}")
    with tempfile.TemporaryDirectory(prefix="host-v2-full-check-") as temp:
        expected_root = Path(temp) / "full_inventory"
        build_full_inventory(repo_root=repo_root, output_root=expected_root)
        expected = {
            path.relative_to(expected_root).as_posix(): _sha_file(path)
            for path in expected_root.iterdir()
            if path.is_file()
        }
        actual = {
            path.relative_to(output_root).as_posix(): _sha_file(path)
            for path in output_root.iterdir()
            if path.is_file()
        }
    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    changed = sorted(path for path in set(expected) & set(actual) if expected[path] != actual[path])
    return {
        "valid": not missing and not unexpected and not changed,
        "expected_tree_sha256": _tree_hash(expected),
        "actual_tree_sha256": _tree_hash(actual),
        "missing": missing,
        "unexpected": unexpected,
        "changed": changed,
    }


def _main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=_repo_root())
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    if args.check:
        report = check_full_inventory(repo_root=args.repo_root, output_root=args.output_root)
        print(json.dumps(report, sort_keys=True, indent=2))
        return 0 if report["valid"] else 1
    report = build_full_inventory(repo_root=args.repo_root, output_root=args.output_root)
    print(
        json.dumps(
            {
                "root": report.root.as_posix(),
                "files": list(report.files),
                "tree_sha256": report.tree_sha256,
                "tau2_task_count": report.tau2_task_count,
                "agentdojo_user_task_count": report.agentdojo_user_task_count,
                "agentdojo_attack_pairing_count": report.agentdojo_attack_pairing_count,
            },
            sort_keys=True,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
