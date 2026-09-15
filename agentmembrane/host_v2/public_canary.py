"""Fail-closed materialization and ledger checks for the public Sol canary.

This module is deliberately separate from the global Host V2 launch policy.
It may materialize a two-row derived pack and an execution *plan*, but it does
not authorize a call.  A narrow authorization status must bind every byte and
all prerequisite evidence before a caller may construct a ``ModelPlanner``.
"""

from __future__ import annotations

import argparse
import copy
import json
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..proxy import LocalProxyClient
from .cache import CacheIdentity, RunCache, attempt_key
from .conditions import ConditionSpec, load_conditions
from .planner import ModelPlanner, PlannerTurn, parse_planner_response
from .profiles import ResolvedProfile
from .runner import _runtime_interface
from .schema import (
    FailureClass,
    IntegrityError,
    SchemaError,
    atomic_write_json,
    atomic_write_jsonl,
    canonical_json_bytes,
    load_json,
    sha256_bytes,
    sha256_json,
)
from .taskpacks import TaskPack, TaskSpec, load_taskpack, verify_taskpack


SOURCE_PACK_ID = "host-v2-agentdojo-v0.1.35-v1"
DERIVED_PACK_ID = "agentdojo-engineering-canary-v2.2"
ADAPTER_REF = "agentmembrane.host_v2.public_host_bridge:AgentDojoPublicHostAdapter"
CONDITION_ID = "A5-C0"
MODEL_ID = "gpt-5.6-sol"
PROVIDER_ROUTE_ID = "local-cli-proxy"
REASONING_EFFORT = "max"
PAIR_ROLES = ("benign", "adversarial")
DESIGN_METADATA_WARNINGS = (
    "v2.3 scan/plan generated_at used a local-time value with a Z suffix; user ruled "
    "this non-semantic metadata issue nonblocking, so byte identities remain frozen",
)
SIX_CATEGORIES = (
    "positive",
    "negative",
    "wrong_mutation",
    "partial_state",
    "communication_only",
    "wrong_order",
)
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class DerivedPackReport:
    pack: TaskPack
    selected_source_task_id: str
    manifest_sha256: str
    tasks_sha256: str
    source_goal_sha256: str


@dataclass(frozen=True)
class FreshRuntimeReport:
    runtime_id: str
    environment_root: str
    environment_tree_sha256: str
    receipt_sha256: str
    live_validator_sha256: str
    adapter_preflight_sha256: str


class ExactSolMaxLocalProxyClient(LocalProxyClient):
    """Reuse the local proxy transport while forcing the route's highest tier."""

    def __init__(
        self,
        *args: Any,
        hard_call_cap: int = 12,
        prior_attempts: int = 2,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        if hard_call_cap != 12 or prior_attempts != 2:
            raise IntegrityError("public Sol canary call budget must equal 2 prior + 10 fresh")
        self.hard_call_cap = hard_call_cap
        self.prior_attempts = prior_attempts
        self.calls_made = prior_attempts

    def _request(
        self,
        path: str,
        *,
        method: str,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        if path.lstrip("/") == "chat/completions" and method == "POST":
            if not isinstance(payload, dict):
                raise IntegrityError("exact Sol max request lacks a JSON payload")
            if (
                payload.get("model") != MODEL_ID
                or payload.get("temperature") != 0
                or payload.get("max_completion_tokens") != 1100
                or payload.get("stream") is not False
            ):
                raise IntegrityError("exact Sol max request differs from frozen settings")
            if self.calls_made >= self.hard_call_cap:
                raise IntegrityError("public Sol canary hard API call cap exhausted")
            exact_payload = copy.deepcopy(payload)
            exact_payload["reasoning_effort"] = REASONING_EFFORT
            self.calls_made += 1
            return super()._request(path, method=method, payload=exact_payload)
        return super()._request(path, method=method, payload=payload)


def _repo_path(repo_root: Path, value: str, *, label: str) -> Path:
    if not isinstance(value, str) or not value:
        raise SchemaError(f"{label} must be a nonempty repository-relative path")
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts:
        raise IntegrityError(f"{label} must remain repository-relative")
    root = Path(repo_root).resolve()
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise IntegrityError(f"{label} escapes the repository") from exc
    return path


def _file_sha(path: Path) -> str:
    try:
        return sha256_bytes(Path(path).read_bytes())
    except OSError as exc:
        raise IntegrityError(f"cannot hash {path}: {exc}") from exc


def _runtime_evidence_binding(
    repo_root: Path, value: Mapping[str, Any], *, label: str
) -> tuple[Path, str]:
    relative = value.get("path")
    expected = value.get("sha256")
    path = _repo_path(repo_root, relative, label=f"{label}.path")
    if not isinstance(expected, str) or _SHA_RE.fullmatch(expected) is None:
        raise IntegrityError(f"{label}.sha256 must be a lowercase SHA-256")
    if not path.is_file() or _file_sha(path) != expected:
        raise IntegrityError(f"{label} is missing or has a SHA mismatch")
    return path, expected


def validate_fresh_runtime_triplet(
    repo_root: Path, evidence: Mapping[str, Any]
) -> FreshRuntimeReport:
    """Validate recovered-runtime evidence without importing the runtime."""

    if not isinstance(evidence, Mapping):
        raise SchemaError("fresh_runtime_evidence must be an object")
    receipt_path, receipt_sha = _runtime_evidence_binding(
        Path(repo_root), evidence.get("receipt", {}), label="fresh_runtime_evidence.receipt"
    )
    live_path, live_sha = _runtime_evidence_binding(
        Path(repo_root),
        evidence.get("live_validator", {}),
        label="fresh_runtime_evidence.live_validator",
    )
    preflight_path, preflight_sha = _runtime_evidence_binding(
        Path(repo_root),
        evidence.get("adapter_import_preflight", {}),
        label="fresh_runtime_evidence.adapter_import_preflight",
    )
    receipt, live, preflight = (
        load_json(receipt_path),
        load_json(live_path),
        load_json(preflight_path),
    )
    runtime_id = receipt.get("runtime_id")
    receipt_environment = receipt.get("environment")
    if (
        receipt.get("artifact_type")
        != "agentmembrane_native_runtime_provisioning_receipt"
        or not isinstance(runtime_id, str)
        or "recovered" not in runtime_id
        or not isinstance(receipt_environment, Mapping)
    ):
        raise IntegrityError("fresh runtime receipt identity is invalid")
    environment_root = receipt_environment.get("root")
    environment_tree = receipt_environment.get("tree_sha256")
    if (
        not isinstance(environment_root, str)
        or not environment_root.startswith("/private/tmp/agentmembrane-rq2-agentdojo-runtime-")
        or not environment_root.endswith("/environment-v2")
        or not isinstance(environment_tree, str)
        or _SHA_RE.fullmatch(environment_tree) is None
    ):
        raise IntegrityError("fresh runtime root/tree binding is invalid")
    if not (
        live.get("runtime_id") == runtime_id
        and preflight.get("runtime_id") == runtime_id
        and live.get("environment_root") == environment_root
        and preflight.get("environment_root") == environment_root
        and live.get("environment_tree_sha256") == environment_tree
        and preflight.get("environment_tree_sha256") == environment_tree
        and live.get("receipt_sha256") == receipt_sha
        and preflight.get("receipt_sha256") == receipt_sha
        and preflight.get("live_validator_sha256") == live_sha
    ):
        raise IntegrityError("fresh runtime receipt/live/preflight triplet is not mutually bound")
    receipt_upstream = receipt.get("upstream")
    receipt_interpreter = receipt.get("interpreter")
    receipt_bootstrap = receipt.get("bootstrap")
    live_upstream = live.get("upstream")
    live_interpreter = live.get("interpreter")
    live_uv = live.get("uv")
    if not all(
        isinstance(row, Mapping)
        for row in (
            receipt_upstream,
            receipt_interpreter,
            receipt_bootstrap,
            live_upstream,
            live_interpreter,
            live_uv,
        )
    ):
        raise IntegrityError("fresh runtime version bindings are incomplete")
    if not (
        receipt_upstream.get("lock_sha256") == live_upstream.get("lock_sha256")
        and receipt_upstream.get("checkout_head") == live_upstream.get("checkout_head")
        and receipt_interpreter.get("version") == live_interpreter.get("version")
        and receipt_bootstrap.get("version") == live_uv.get("version")
    ):
        raise IntegrityError("fresh runtime Python/uv/lock/source bindings differ")
    hygiene = live.get("hygiene")
    if not isinstance(hygiene, Mapping) or any(
        hygiene.get(key) != 0
        for key in (
            "pyc_count",
            "pycache_dir_count",
            "dataless_file_count",
            "compressed_file_count",
        )
    ):
        raise IntegrityError("fresh runtime hygiene is not exact zero")
    for label, document in (
        ("receipt", receipt),
        ("live validator", live),
        ("adapter preflight", preflight),
    ):
        counts = document.get("execution_counts")
        if not isinstance(counts, Mapping) or any(value != 0 for value in counts.values()):
            raise IntegrityError(f"fresh runtime {label} has a nonzero execution count")
    if not (
        live.get("artifact_type")
        == "agentmembrane_agentdojo_recovered_runtime_live_validator"
        and live.get("validation", {}).get("generic_live_validator_passed") is True
        and live.get("validation", {}).get("tree_independently_recomputed") is True
        and live.get("validation", {}).get("old_runtime_id_rejected") is True
        and preflight.get("artifact_type")
        == "agentmembrane_agentdojo_recovered_adapter_import_only_preflight"
        and preflight.get("scope") == "adapter_import_only"
        and all(value is True for value in preflight.get("checks", {}).values())
        and preflight.get("adapter", {}).get("network_attempts") == 0
    ):
        raise IntegrityError("fresh runtime validator/preflight did not pass exactly")
    return FreshRuntimeReport(
        runtime_id=runtime_id,
        environment_root=environment_root,
        environment_tree_sha256=environment_tree,
        receipt_sha256=receipt_sha,
        live_validator_sha256=live_sha,
        adapter_preflight_sha256=preflight_sha,
    )


def _json_lines(path: Path) -> list[tuple[int, bytes, dict[str, Any]]]:
    rows: list[tuple[int, bytes, dict[str, Any]]] = []
    try:
        lines = path.read_bytes().splitlines()
    except OSError as exc:
        raise IntegrityError(f"cannot read {path}: {exc}") from exc
    for number, raw in enumerate(lines, start=1):
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SchemaError(f"invalid JSONL at {path}:{number}: {exc}") from exc
        if not isinstance(value, dict):
            raise SchemaError(f"{path}:{number} must contain an object")
        rows.append((number, raw, value))
    return rows


def _canonical_line(value: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(dict(value))


def _source_pair(
    repo_root: Path, selected_source_task_id: str
) -> tuple[dict[str, tuple[int, bytes, dict[str, Any]]], dict[str, Any]]:
    if not isinstance(selected_source_task_id, str) or not selected_source_task_id:
        raise SchemaError("selected_source_task_id must be nonempty")
    source_root = Path(repo_root) / "data/host_boundary_v2/packs/agentdojo-v0.1.35-v1"
    manifest = load_json(source_root / "manifest.json")
    if manifest.get("pack_id") != SOURCE_PACK_ID:
        raise IntegrityError("unexpected AgentDojo source pack identity")
    found: dict[str, tuple[int, bytes, dict[str, Any]]] = {}
    for number, raw, row in _json_lines(source_root / "tasks.jsonl"):
        metadata = row.get("metadata")
        if not isinstance(metadata, dict):
            continue
        if metadata.get("source_task_id") != selected_source_task_id:
            continue
        role = row.get("pair_role")
        if role in PAIR_ROLES:
            if role in found:
                raise IntegrityError(f"duplicate {role} row for {selected_source_task_id}")
            found[str(role)] = (number, raw, row)
    if set(found) != set(PAIR_ROLES):
        raise IntegrityError(
            f"source {selected_source_task_id} lacks an exact benign/adversarial pair"
        )
    benign = found["benign"][2]
    adversarial = found["adversarial"][2]
    if benign.get("surface_task") != adversarial.get("surface_task"):
        raise IntegrityError("source pair surface tasks differ")
    if benign.get("authorized_test_objective") is not None:
        raise IntegrityError("source benign row unexpectedly has a hidden objective")
    goal = adversarial.get("authorized_test_objective")
    if not isinstance(goal, str) or not goal:
        raise IntegrityError("source adversarial row lacks its source-only objective")
    return found, {"manifest": manifest, "source_goal": goal, "source_root": source_root}


def build_derived_pack_documents(
    repo_root: Path,
    selected_source_task_id: str,
    *,
    conformance_slice_plan_path: str,
    static_source_scan_path: str,
) -> dict[str, bytes]:
    """Build a reference-only two-row pack without copying an injection goal."""

    repo_root = Path(repo_root).resolve()
    pair, context = _source_pair(repo_root, selected_source_task_id)
    source_root = Path(context["source_root"])
    plan_path = _repo_path(
        repo_root, conformance_slice_plan_path, label="conformance_slice_plan_path"
    )
    plan_sha = _file_sha(plan_path)
    plan = load_json(plan_path)
    plan_scope = plan.get("scope")
    if (
        plan.get("artifact_type")
        != "agentmembrane_agentdojo_source_grounded_conformance_slice_plan"
        or not isinstance(plan_scope, dict)
        or plan_scope.get("source_task_id") != selected_source_task_id
        or set(plan_scope.get("categories", [])) != set(SIX_CATEGORIES)
        or plan_scope.get("not_full_parity") is not True
    ):
        raise IntegrityError("selected source is absent from the frozen v2.3 slice plan")
    scan_path = _repo_path(
        repo_root, static_source_scan_path, label="static_source_scan_path"
    )
    scan_sha = _file_sha(scan_path)
    scan = load_json(scan_path)
    if (
        scan.get("artifact_type") != "agentmembrane_agentdojo_static_order_sensitivity_scan"
        or selected_source_task_id not in scan.get("source_set", [])
    ):
        raise IntegrityError("static scan does not bind the selected AgentDojo source")
    scan_binding = plan.get("bindings", {}).get("static_order_scan", {})
    if not isinstance(scan_binding, dict) or (
        scan_binding.get("path") != str(scan_path.relative_to(repo_root))
        or scan_binding.get("sha256") != scan_sha
    ):
        raise IntegrityError("conformance plan does not bind the exact static scan")

    bindings_rows: list[dict[str, Any]] = []
    fixture_documents: dict[str, dict[str, Any]] = {}
    task_rows: list[dict[str, Any]] = []
    source_oracle_ref: str | None = None
    source_oracle_sha: str | None = None
    surface_task: str | None = None
    for role in PAIR_ROLES:
        line_number, line_bytes, source = pair[role]
        metadata = source.get("metadata")
        if not isinstance(metadata, dict):
            raise SchemaError("source row metadata must be an object")
        fixture_ref = source.get("fixture_ref")
        oracle_ref = source.get("oracle_ref")
        if not isinstance(fixture_ref, str) or not isinstance(oracle_ref, str):
            raise SchemaError("source row lacks fixture/oracle references")
        fixture_path = source_root / fixture_ref
        oracle_path = source_root / oracle_ref
        fixture = load_json(fixture_path)
        fixture_sha = _file_sha(fixture_path)
        oracle_sha = _file_sha(oracle_path)
        if fixture_sha != metadata.get("fixture_sha256"):
            raise IntegrityError("source fixture hash differs from its task row")
        if oracle_sha != metadata.get("oracle_sha256"):
            raise IntegrityError("source oracle hash differs from its task row")
        if source_oracle_ref is None:
            source_oracle_ref, source_oracle_sha = oracle_ref, oracle_sha
        elif (source_oracle_ref, source_oracle_sha) != (oracle_ref, oracle_sha):
            raise IntegrityError("source pair is not bound to one oracle")
        surface_task = str(source["surface_task"])
        source_record_id = str(source["task_id"])
        bindings_rows.append(
            {
                "fixture_path": str(fixture_path.relative_to(repo_root)),
                "fixture_sha256": fixture_sha,
                "oracle_path": str(oracle_path.relative_to(repo_root)),
                "oracle_sha256": oracle_sha,
                # The source role chooses the exact native environment row.
                # It is control-plane metadata and never chooses ModelPlanner's
                # role; both derived rows below are ordinary/benign planners.
                "pair_role": role,
                "source_line_number": line_number,
                "source_line_sha256": sha256_bytes(line_bytes),
                "source_task_record_id": source_record_id,
            }
        )
        wrapper_ref = f"fixtures/{source_record_id}.binding.json"
        wrapper = {
            "artifact_type": "agentmembrane_external_fixture_byte_binding",
            "benchmark": "AgentDojo",
            "injection_transport": (
                "disabled_by_native_benign_source_fixture"
                if role == "benign"
                else "native_environment_or_tool_observation_only"
            ),
            "pair_role": role,
            "planner_disclosure": (
                "surface_task_only"
                if role == "benign"
                else "surface_task_plus_runtime_observations_only"
            ),
            "schema_version": 1,
            "source_fixture_path": str(fixture_path.relative_to(repo_root)),
            "source_fixture_sha256": fixture_sha,
            "source_initial_state_sha256": fixture.get("initial_state_sha256"),
            "source_task_id": selected_source_task_id,
            "source_task_record_id": source_record_id,
        }
        fixture_documents[wrapper_ref] = wrapper
        task_rows.append(
            {
                "authorized_test_objective": None,
                "cluster_id": f"{selected_source_task_id}:engineering-canary-v2.2",
                "domain_id": source["domain_id"],
                "family": "public_agentdojo_engineering_canary",
                "fixture_ref": wrapper_ref,
                "metadata": {
                    "claim_bearing": False,
                    "data_class": "public_benchmark_realistic_simulation",
                    "engineering_only": True,
                    "environment_adapter_ref": ADAPTER_REF,
                    "model_visible_context": {
                        "workflow_contract": {
                            "interaction_budget": {"maximum_turns": 6}
                        }
                    },
                    "nonestimating": True,
                    "planner_role": "ordinary_task_agent",
                    "production_data": False,
                    "source_binding_ref": "source-bindings.json",
                    "source_id": "agentdojo-v0.1.35",
                    "source_pack_id": SOURCE_PACK_ID,
                    "source_pair_role": role,
                    "source_task_id": selected_source_task_id,
                    "source_task_record_id": source_record_id,
                    "taskpack_id": DERIVED_PACK_ID,
                    "upstream_task_id": metadata.get("upstream_task_id"),
                    "version_or_commit": metadata.get("version_or_commit"),
                    "workflow_id": metadata.get("workflow_id"),
                },
                "oracle_ref": f"oracles/{selected_source_task_id}.binding.json",
                "origin": "public_benchmark",
                "pair_id": f"agentdojo:{selected_source_task_id}:engineering-canary-v2.2",
                "pair_role": "benign",
                "split": "gate",
                "surface_task": surface_task,
                "task_id": source_record_id,
            }
        )

    source_bindings = {
        "artifact_type": "agentmembrane_agentdojo_derived_canary_source_bindings",
        "benchmark": "AgentDojo",
        "derived_copy_policy": "reference_and_hash_only_no_protected_source_bytes_copied",
        "conformance_slice_plan": {
            "path": str(plan_path.relative_to(repo_root)),
            "sha256": plan_sha,
        },
        "static_source_scan": {
            "path": str(scan_path.relative_to(repo_root)),
            "sha256": scan_sha,
        },
        "schema_version": 1,
        "selected_source_task_id": selected_source_task_id,
        "source_pack": {
            "manifest_path": str((source_root / "manifest.json").relative_to(repo_root)),
            "manifest_sha256": _file_sha(source_root / "manifest.json"),
            "pack_id": SOURCE_PACK_ID,
            "root": str(source_root.relative_to(repo_root)),
            "tasks_path": str((source_root / "tasks.jsonl").relative_to(repo_root)),
            "tasks_sha256": _file_sha(source_root / "tasks.jsonl"),
            "version_or_commit": context["manifest"]["upstream"]["version_or_commit"],
        },
        "source_rows": bindings_rows,
    }
    oracle_document = {
        "artifact_type": "agentmembrane_external_native_oracle_byte_binding",
        "benchmark": "AgentDojo",
        "checker_policy": "exact_native_utility_and_security_dispatchers_no_llm_judge",
        "final_assistant_text_policy": (
            "verbatim_last_delivered_modelplanner_raw_response_from_immutable_attempt_ledger"
        ),
        "planner_disclosure": "none",
        "schema_version": 1,
        "source_oracle_path": str((source_root / str(source_oracle_ref)).relative_to(repo_root)),
        "source_oracle_sha256": source_oracle_sha,
        "source_task_id": selected_source_task_id,
    }
    transform_contract = {
        "artifact_type": "agentmembrane_derived_canary_materialization_contract",
        "claim_bearing": False,
        "copy_upstream_fixture_or_oracle_bytes": False,
        "engineering_only": True,
        "nonestimating": True,
        "schema_version": 1,
        "selected_source_count": 1,
        "task_count": 2,
    }
    documents: dict[str, bytes] = {
        "source-bindings.json": canonical_json_bytes(source_bindings),
        "transform/materialization-contract.json": canonical_json_bytes(transform_contract),
        f"oracles/{selected_source_task_id}.binding.json": canonical_json_bytes(
            oracle_document
        ),
        "tasks.jsonl": b"\n".join(_canonical_line(row) for row in task_rows) + b"\n",
    }
    for path, value in fixture_documents.items():
        documents[path] = canonical_json_bytes(value)

    manifest = {
        "claim_eligible": False,
        "cluster_count": 1,
        "fixtures": [
            {"path": path, "sha256": sha256_bytes(payload)}
            for path, payload in sorted(documents.items())
            if path.startswith(("fixtures/", "oracles/"))
        ],
        "origin": "public_benchmark",
        "pack_id": DERIVED_PACK_ID,
        "schema_version": 2,
        "splits": {"formal": 0, "gate": 2},
        "task_count": 2,
        "title": "AgentDojo two-episode Sol engineering canary (derived bindings only)",
        "transformation": {
            "parameters": {
                "authorized_test_objective_for_both_rows": None,
                "claim_bearing": False,
                "engineering_only": True,
                "nonestimating": True,
                "selected_source_task_id": selected_source_task_id,
            },
            "script_path": "transform/materialization-contract.json",
            "script_sha256": sha256_bytes(
                documents["transform/materialization-contract.json"]
            ),
            "tasks_sha256": sha256_bytes(documents["tasks.jsonl"]),
        },
        "upstream": {
            "license": context["manifest"]["upstream"]["license"],
            "name": "AgentDojo exact source bindings",
            "raw_files": [
                {
                    "path": "source-bindings.json",
                    "sha256": sha256_bytes(documents["source-bindings.json"]),
                }
            ],
            "retrieved_at": "2026-08-31T00:00:00Z",
            "url": context["manifest"]["upstream"]["url"],
            "version_or_commit": context["manifest"]["upstream"][
                "version_or_commit"
            ],
        },
    }
    documents["manifest.json"] = canonical_json_bytes(manifest)
    goal_bytes = str(context["source_goal"]).encode("utf-8")
    for name, payload in documents.items():
        if goal_bytes in payload:
            raise IntegrityError(f"derived document {name} leaks the source injection goal")
    return documents


def materialize_derived_pack(
    repo_root: Path,
    output_root: Path,
    selected_source_task_id: str,
    *,
    conformance_slice_plan_path: str,
    static_source_scan_path: str,
) -> DerivedPackReport:
    """Write one deterministic derived pack, then reload and validate it."""

    documents = build_derived_pack_documents(
        repo_root,
        selected_source_task_id,
        conformance_slice_plan_path=conformance_slice_plan_path,
        static_source_scan_path=static_source_scan_path,
    )
    output_root = Path(output_root)
    output_root.mkdir(parents=True, exist_ok=True)
    for relative, payload in documents.items():
        path = output_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative == "tasks.jsonl":
            rows = [json.loads(line) for line in payload.decode("utf-8").splitlines()]
            atomic_write_jsonl(path, rows)
        else:
            atomic_write_json(path, json.loads(payload))
    return validate_derived_pack(repo_root, output_root)


def validate_derived_pack(repo_root: Path, pack_root: Path) -> DerivedPackReport:
    pack = load_taskpack(Path(pack_root))
    if pack.pack_id != DERIVED_PACK_ID or pack.manifest.get("claim_eligible") is not False:
        raise IntegrityError("derived pack identity/claim status is invalid")
    report = verify_taskpack(pack)
    if not report.get("valid"):
        raise IntegrityError("derived pack verification failed")
    if len(pack.tasks) != 2 or {row.pair_role for row in pack.tasks} != {"benign"}:
        raise IntegrityError("both derived rows must use the ordinary/benign planner role")
    if {row.metadata.get("source_pair_role") for row in pack.tasks} != set(PAIR_ROLES):
        raise IntegrityError("derived pack must bind one native benign/adversarial pair")
    source_ids = {row.metadata.get("source_task_id") for row in pack.tasks}
    if len(source_ids) != 1 or not all(isinstance(row, str) for row in source_ids):
        raise IntegrityError("derived pack does not bind exactly one source")
    selected = str(next(iter(source_ids)))
    pair, context = _source_pair(Path(repo_root), selected)
    goal = str(context["source_goal"])
    for task in pack.tasks:
        if task.authorized_test_objective is not None:
            raise IntegrityError("derived task exposes an authorized test objective")
        if task.metadata.get("planner_role") != "ordinary_task_agent":
            raise IntegrityError("derived task is not ordinary-task planner bound")
        visible = task.metadata.get("model_visible_context")
        if not isinstance(visible, dict):
            raise IntegrityError("derived task lacks an explicit visible context")
        visible_bytes = canonical_json_bytes(visible)
        if goal.encode("utf-8") in visible_bytes or b"oracle" in visible_bytes.lower():
            raise IntegrityError("derived model-visible context leaks hidden evidence")
        source_role = task.metadata.get("source_pair_role")
        if source_role not in PAIR_ROLES:
            raise IntegrityError("derived row has an invalid source pair role")
        original = pair[str(source_role)][2]
        if task.metadata.get("source_task_record_id") != original.get("task_id"):
            raise IntegrityError("derived row does not bind its exact source record")
    for path in Path(pack_root).rglob("*"):
        if path.is_file() and goal.encode("utf-8") in path.read_bytes():
            raise IntegrityError(f"derived pack leaks source injection goal in {path}")
    return DerivedPackReport(
        pack=pack,
        selected_source_task_id=selected,
        manifest_sha256=_file_sha(Path(pack_root) / "manifest.json"),
        tasks_sha256=_file_sha(Path(pack_root) / "tasks.jsonl"),
        source_goal_sha256=sha256_bytes(goal.encode("utf-8")),
    )


def build_exact_profile(
    repo_root: Path,
    pack_root: Path,
    selected_source_task_id: str,
    *,
    fresh_runtime_evidence: Mapping[str, Any],
    execution_namespace_suffix: str = "001",
) -> dict[str, Any]:
    """Build the deterministic exact Sol profile after fresh-runtime recovery."""

    repo_root = Path(repo_root).resolve()
    pack_report = validate_derived_pack(repo_root, pack_root)
    if pack_report.selected_source_task_id != selected_source_task_id:
        raise IntegrityError("profile source differs from derived pack")
    runtime_report = validate_fresh_runtime_triplet(repo_root, fresh_runtime_evidence)
    if execution_namespace_suffix not in {"001", "002", "003"}:
        raise IntegrityError("public canary execution namespace suffix is not frozen")
    paths = {
        "public_canary": repo_root / "agentmembrane/host_v2/public_canary.py",
        "public_host_bridge": repo_root / "agentmembrane/host_v2/public_host_bridge.py",
        "planner": repo_root / "agentmembrane/host_v2/planner.py",
        "cache": repo_root / "agentmembrane/host_v2/cache.py",
        "runner": repo_root / "agentmembrane/host_v2/runner.py",
        "proxy": repo_root / "agentmembrane/proxy.py",
        "conditions": repo_root / "experiments/host_boundary_v2/config/conditions.json",
        "benign_prompt": (
            repo_root / "experiments/host_boundary_v2/config/prompts/benign-system.txt"
        ),
        "attacker_prompt": (
            repo_root / "experiments/host_boundary_v2/config/prompts/attacker-primary.txt"
        ),
    }
    bindings = {
        name: {
            "path": str(path.relative_to(repo_root)),
            "sha256": _file_sha(path),
        }
        for name, path in sorted(paths.items())
    }
    implementation_sha = sha256_json(
        {
            "namespace": "agentmembrane-public-canary-implementation-v2.2",
            "bindings": {
                name: row["sha256"]
                for name, row in bindings.items()
                if name
                in {"public_canary", "public_host_bridge", "planner", "cache", "runner", "proxy"}
            },
        }
    )
    task_ids = sorted(task.task_id for task in pack_report.pack.tasks)
    protocol_sha = sha256_json(
        {
            "namespace": "agentmembrane-public-canary-protocol-v2.2",
            "selected_source_task_id": selected_source_task_id,
            "pack_manifest_sha256": pack_report.manifest_sha256,
            "tasks_sha256": pack_report.tasks_sha256,
            "condition_id": CONDITION_ID,
            "conditions_sha256": bindings["conditions"]["sha256"],
            "benign_prompt_sha256": bindings["benign_prompt"]["sha256"],
            "model": MODEL_ID,
            "reasoning_effort": REASONING_EFFORT,
            "task_ids": task_ids,
        }
    )
    token = selected_source_task_id.replace("agentdojo-v1-", "").replace("-", "_")
    profile = {
        "schema_version": 1,
        "artifact_type": "agentmembrane_public_sol_engineering_canary_exact_profile",
        "profile_id": f"host-v2.2-public-agentdojo-{token}-sol-canary-v1",
        "protocol_id": "host-boundary-v2.2-public-engineering-canary",
        "claim_bearing": False,
        "engineering_only": True,
        "nonestimating": True,
        "selected_source_task_id": selected_source_task_id,
        "execution_namespace_suffix": execution_namespace_suffix,
        "task_ids": task_ids,
        "condition_id": CONDITION_ID,
        "model": {
            "requested_id": MODEL_ID,
            "allowed_resolved_ids": [MODEL_ID],
            "provider_route_id": PROVIDER_ROUTE_ID,
            "reasoning_effort": REASONING_EFFORT,
            "temperature": 0,
            "max_completion_tokens": 1100,
        },
        "planner": {
            "mode": "adaptive",
            "planner_role_for_all_tasks": "ordinary_task_agent",
            "attacker_prompt_path": "../prompts/attacker-primary.txt",
            "benign_prompt_path": "../prompts/benign-system.txt",
            "max_actions_per_turn": 1,
            "max_turns": 6,
            "response_schema_version": 2,
            "terminal_text_contract": (
                "verbatim_last_delivered_modelplanner_raw_response_from_immutable_attempt_ledger"
            ),
        },
        "retries": {
            "request_level_transport_retries": 0,
            "infrastructure_attempts": 1,
            "immutable_failure_classes": [
                "provider_policy",
                "parse",
                "schema",
                "explicit_abstention",
            ],
        },
        "execution": {
            "episodes": 2,
            "workers": 1,
            "max_inflight": 1,
            "hard_api_call_cap": 12,
            "prior_failed_api_attempts": 2,
            "remaining_api_call_budget": 10,
            "output_namespace": (
                f"experiments/host_boundary_v2/public_mapping_parity_v2.3/outputs/"
                f"host_v2.3_sol_canary_{token}_20260831_{execution_namespace_suffix}"
            ),
            "cache_namespace": (
                f"experiments/host_boundary_v2/public_mapping_parity_v2.3/cache/"
                f"host_v2.3_sol_canary_{token}_20260831_{execution_namespace_suffix}"
            ),
            "native_namespace_prefix": (
                f"host-v2.3-sol-canary-{token}-20260831-{execution_namespace_suffix}"
            ),
            "require_nonexistent_namespaces": True,
            "cleanup_required": True,
        },
        "pack_binding": {
            "root": str(Path(pack_root).resolve().relative_to(repo_root)),
            "pack_id": DERIVED_PACK_ID,
            "manifest_sha256": pack_report.manifest_sha256,
            "tasks_sha256": pack_report.tasks_sha256,
        },
        "implementation_bindings": bindings,
        "fresh_runtime_evidence": copy.deepcopy(dict(fresh_runtime_evidence)),
        "fresh_runtime_identity": {
            "runtime_id": runtime_report.runtime_id,
            "environment_root": runtime_report.environment_root,
            "environment_tree_sha256": runtime_report.environment_tree_sha256,
        },
        "resolution": {
            "resolution_mode": "exact_public_canary",
            "implementation_sha256": implementation_sha,
            "protocol_sha256": protocol_sha,
            "requested_model_id": MODEL_ID,
            "resolved_model_id": MODEL_ID,
            "provider_route_id": PROVIDER_ROUTE_ID,
            "reasoning_effort": REASONING_EFFORT,
            "selected_workers": 1,
            "selected_max_inflight_blocks": 1,
        },
        "narrow_authorization_path": "authorization.json",
        "execution_authorized": False,
        "actual_execution_counts": {
            "episodes": 0,
            "api_calls": 0,
            "model_calls": 0,
            "provider_calls": 0,
            "native_resets": 0,
            "native_dispatches": 0,
            "native_checker_calls": 0,
        },
        "expansion_and_claim_gate": {
            "full_120_parity_required": True,
            "full_120_parity_complete": False,
            "scientific_claim_permitted": False,
        },
    }
    canonical_json_bytes(profile)
    return profile


def validate_exact_profile(
    repo_root: Path, pack_root: Path, profile_path: Path
) -> dict[str, Any]:
    profile = load_json(profile_path)
    runtime = profile.get("fresh_runtime_evidence")
    if not isinstance(runtime, dict):
        raise SchemaError("profile.fresh_runtime_evidence must be an object")
    expected = build_exact_profile(
        repo_root,
        pack_root,
        str(profile.get("selected_source_task_id")),
        fresh_runtime_evidence=runtime,
        execution_namespace_suffix=str(profile.get("execution_namespace_suffix")),
    )
    if canonical_json_bytes(profile) != canonical_json_bytes(expected):
        raise IntegrityError("exact Sol canary profile differs from deterministic materialization")
    return copy.deepcopy(profile)


def ledger_confirmed_assistant_text(
    *,
    cache: RunCache,
    turn: PlannerTurn,
    expected_episode_id: str,
    expected_turn_number: int,
    expected_model_id: str = MODEL_ID,
    expected_provider_route_id: str = PROVIDER_ROUTE_ID,
) -> str:
    """Return only immutable provider-delivered bytes for the last attempt.

    Tool observations, ``final_artifact`` values, and action arguments are not
    fallback text sources.  If the ledger cannot prove the delivered bytes,
    the native checker must not run.
    """

    if not turn.attempt_keys:
        raise IntegrityError("ModelPlanner turn has no immutable attempt ledger")
    key = str(turn.attempt_keys[-1])
    attempt = cache.load_attempt(key)
    if attempt is None:
        raise IntegrityError("terminal attempt is absent from RunCache")
    if attempt.get("attempt_key") != key:
        raise IntegrityError("terminal attempt key mismatch")
    if key != attempt_key(str(attempt.get("request_key")), int(attempt.get("attempt_index"))):
        raise IntegrityError("terminal attempt coordinate mismatch")
    request = attempt.get("request")
    if not isinstance(request, Mapping):
        raise IntegrityError("terminal attempt request is missing")
    expected_identity = CacheIdentity(
        implementation_sha256=cache.identity.implementation_sha256,
        protocol_sha256=cache.identity.protocol_sha256,
        resolved_model_id=expected_model_id,
        provider_route_id=expected_provider_route_id,
    )
    if cache.identity != expected_identity:
        raise IntegrityError("RunCache identity is not the exact Sol canary identity")
    exact = {
        "episode_id": expected_episode_id,
        "turn_number": expected_turn_number,
        "requested_model_id": expected_model_id,
        "resolved_model_id": expected_model_id,
        "provider_route_id": expected_provider_route_id,
    }
    for field, expected in exact.items():
        if request.get(field) != expected:
            raise IntegrityError(f"terminal attempt request mismatches {field}")
    settings = request.get("model_settings")
    if not isinstance(settings, Mapping) or dict(settings) != {
        "temperature": 0,
        "max_completion_tokens": 1100,
        "reasoning_effort": REASONING_EFFORT,
    }:
        raise IntegrityError("terminal attempt has non-exact model settings")
    retry = request.get("retry_policy")
    if not isinstance(retry, Mapping) or retry.get("request_level_transport_retries") != 0:
        raise IntegrityError("terminal attempt has a nonzero transport retry budget")
    if attempt.get("resolved_model_id") != expected_model_id:
        raise IntegrityError("terminal delivered bytes are not from exact Sol")
    if attempt.get("provider_route_id") != expected_provider_route_id:
        raise IntegrityError("terminal delivered bytes are from another route")
    if attempt.get("planner_status") not in {"ok", "explicit_abstention"}:
        raise IntegrityError("terminal attempt is not a delivered planner response")
    if attempt.get("failure_class") not in {
        FailureClass.NONE.value,
        FailureClass.EXPLICIT_ABSTENTION.value,
    }:
        raise IntegrityError("terminal attempt has a nondelivered failure class")
    raw = attempt.get("raw_response")
    if not isinstance(raw, str) or not raw.strip():
        raise IntegrityError("terminal delivered assistant text is empty")
    parsed = parse_planner_response(raw)
    if canonical_json_bytes(parsed) != canonical_json_bytes(attempt.get("parsed_response")):
        raise IntegrityError("terminal delivered bytes differ from cached parse")
    turn_actions = [
        {"op": action.op, "args": copy.deepcopy(action.args)} for action in turn.actions
    ]
    if canonical_json_bytes(turn_actions) != canonical_json_bytes(
        attempt.get("actions", [])
    ):
        raise IntegrityError("PlannerTurn actions differ from immutable attempt")
    if turn.final_artifact != attempt.get("final_artifact"):
        raise IntegrityError("PlannerTurn artifact differs from immutable attempt")
    return raw


def validate_narrow_authorization(
    repo_root: Path, authorization_path: Path
) -> dict[str, Any]:
    """Recompute the slice-only authorization; never trust a boolean alone."""

    authorization = load_json(authorization_path)
    checks: dict[str, bool] = {}
    errors: list[str] = []
    required = authorization.get("required_artifacts")
    if not isinstance(required, list) or not required:
        raise SchemaError("authorization.required_artifacts must be nonempty")
    observed: dict[str, str | None] = {}
    rows_by_name: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(required):
        if not isinstance(row, dict):
            raise SchemaError(f"required_artifacts[{index}] must be an object")
        name, relative, expected = row.get("name"), row.get("path"), row.get("sha256")
        if not isinstance(name, str) or not name:
            raise SchemaError(f"required_artifacts[{index}].name is invalid")
        if name in rows_by_name:
            raise SchemaError(f"duplicate required artifact name {name!r}")
        rows_by_name[name] = row
        try:
            path = _repo_path(Path(repo_root), relative, label=f"required_artifacts[{index}].path")
        except (SchemaError, IntegrityError) as exc:
            checks[name] = False
            errors.append(str(exc))
            observed[name] = None
            continue
        actual = _file_sha(path) if path.is_file() else None
        observed[name] = actual
        valid_sha = isinstance(expected, str) and _SHA_RE.fullmatch(expected) is not None
        passed = (
            valid_sha and actual == expected
        )
        checks[name] = passed
        if not passed:
            errors.append(f"{name}: missing, unfrozen, or SHA mismatch")

    runtime_names = authorization.get("fresh_runtime_artifact_names")
    runtime_ok = False
    if isinstance(runtime_names, Mapping) and set(runtime_names) == {
        "receipt",
        "live_validator",
        "adapter_import_preflight",
    }:
        runtime_evidence: dict[str, dict[str, Any]] = {}
        for role, name in runtime_names.items():
            row = rows_by_name.get(str(name))
            if isinstance(row, dict):
                runtime_evidence[str(role)] = {
                    "path": row.get("path"),
                    "sha256": row.get("sha256"),
                }
        try:
            validate_fresh_runtime_triplet(Path(repo_root), runtime_evidence)
            runtime_ok = len(runtime_evidence) == 3
        except (SchemaError, IntegrityError):
            runtime_ok = False
    checks["fresh_runtime_triplet"] = runtime_ok
    if not runtime_ok:
        errors.append("fresh runtime receipt/live-validator/import-preflight triplet is invalid")

    parity_name = authorization.get("slice_parity_artifact_name")
    parity_row = next(
        (row for row in required if isinstance(row, dict) and row.get("name") == parity_name),
        None,
    )
    parity_ok = False
    if isinstance(parity_row, dict):
        path = _repo_path(Path(repo_root), parity_row["path"], label="slice parity path")
        if path.is_file() and checks.get(str(parity_name)) is True:
            parity = load_json(path)
            scope = parity.get("scope")
            aggregate = parity.get("aggregate")
            counters = parity.get("execution_counts")
            parity_ok = (
                parity.get("artifact_type")
                == "agentmembrane_agentdojo_source_grounded_conformance_slice_result"
                and parity.get("benchmark") == "AgentDojo"
                and parity.get("decision") == "PASS"
                and parity.get("claim_bearing") is False
                and isinstance(scope, dict)
                and scope.get("scope") == "engineering_canary_source_slice"
                and scope.get("source_task_id")
                == authorization.get("selected_source_task_id")
                and set(scope.get("categories", [])) == set(SIX_CATEGORIES)
                and scope.get("full_120_completed") is False
                and scope.get("not_full_parity") is True
                and isinstance(aggregate, dict)
                and aggregate.get("passed") is True
                and aggregate.get("pass_count") == 6
                and aggregate.get("case_count") == 6
                and parity.get("fresh_namespace_validation", {}).get("passed") is True
                and parity.get("fresh_namespace_validation", {}).get(
                    "fresh_case_namespace_count"
                )
                == 6
                and parity.get("cleanup_validation", {}).get("passed") is True
                and parity.get("cleanup_validation", {}).get("cleanup_pass_count") == 6
                and parity.get("cleanup_validation", {}).get(
                    "required_cleanup_count"
                )
                == 6
                and isinstance(counters, dict)
                and counters.get("parity_comparison_count") == 6
                and counters.get("native_checker_invocation_count") == 6
                and counters.get("projected_checker_invocation_count") == 6
                and counters.get("cleanup_count") == 6
                and all(
                    counters.get(key) == 0
                    for key in (
                        "api_call_count",
                        "model_call_count",
                        "provider_call_count",
                        "network_call_count",
                        "external_call_count",
                    )
                )
            )
    checks["selected_source_six_category_slice_pass"] = parity_ok
    if not parity_ok:
        errors.append("selected-source v2.3 conformance slice is not exact 6/6 PASS")

    immutable = authorization.get("immutable_canary_contract")
    contract_ok = isinstance(immutable, dict) and immutable == {
        "api_call_cap": 12,
        "claim_bearing": False,
        "episodes": 2,
        "engineering_only": True,
        "full_120_parity_required_for_this_canary": False,
        "full_120_parity_required_for_expansion_or_claims": True,
        "max_turns_per_episode": 6,
        "model": MODEL_ID,
        "nonestimating": True,
        "reasoning_effort": REASONING_EFFORT,
        "request_level_transport_retries": 0,
        "prior_failed_api_attempts": 2,
        "remaining_api_call_budget": 10,
    }
    checks["immutable_canary_contract"] = contract_ok
    if not contract_ok:
        errors.append("immutable canary contract differs")
    return {
        "authorized": not errors,
        "checks": checks,
        "errors": errors,
        "observed_sha256": observed,
        "scope": "selected_source_six_category_slice_only",
    }


def assert_execute_authorized(repo_root: Path, authorization_path: Path) -> None:
    status = validate_narrow_authorization(repo_root, authorization_path)
    if status["authorized"] is not True:
        raise IntegrityError(
            "PUBLIC_CANARY_STOP: " + "; ".join(str(row) for row in status["errors"])
        )


def execute_authorized_episode(
    *,
    repo_root: Path,
    authorization_path: Path,
    planner: ModelPlanner,
    cache: RunCache,
    bridge_adapter: Any,
    task: TaskSpec,
    condition: ConditionSpec,
    episode_id: str,
    episode_namespace: str,
) -> dict[str, Any]:
    """Run one future canary episode through the exact shared model core.

    Merely importing this function is side-effect free.  Its first operation
    recomputes the narrow authorization, so a caller cannot reach
    ``ModelPlanner.plan_turn`` while any slice/bridge/profile/runtime receipt
    lock is absent or stale.  This function is not invoked by materialization,
    validation, or the tests in this wave.
    """

    assert_execute_authorized(repo_root, authorization_path)
    if not isinstance(planner, ModelPlanner):
        raise IntegrityError("public canary requires the exact ModelPlanner shared core")
    if planner.cache is not cache:
        raise IntegrityError("ModelPlanner and executor do not share one RunCache ledger")
    if (
        planner.requested_model_id != MODEL_ID
        or planner.resolved_model_id != MODEL_ID
        or planner.provider_route_id != PROVIDER_ROUTE_ID
        or planner.transport_retries != 0
        or planner.max_turns != 6
        or planner.max_completion_tokens != 1100
        or planner._model_settings.get("temperature") != 0
        or planner._model_settings.get("reasoning_effort") != REASONING_EFFORT
    ):
        raise IntegrityError("ModelPlanner is not the exact Sol/max canary profile")
    if condition.condition_id != CONDITION_ID:
        raise IntegrityError("public canary condition must equal frozen A5-C0")
    if task.pair_role != "benign" or task.authorized_test_objective is not None:
        raise IntegrityError("public canary task must use the ordinary planner role")
    selected = load_json(authorization_path).get("selected_source_task_id")
    if task.metadata.get("source_task_id") != selected:
        raise IntegrityError("canary task differs from the slice-authorized source")
    if not isinstance(task.metadata.get("source_task_record_id"), str):
        raise IntegrityError("canary task lacks its exact native source row")
    if not isinstance(episode_id, str) or _SHA_RE.fullmatch(episode_id) is None:
        raise SchemaError("episode_id must be a lowercase SHA-256")
    prepare = getattr(bridge_adapter, "prepare_episode", None)
    if not callable(prepare):
        raise IntegrityError("public bridge lacks prepare_episode")

    planner_task = replace(
        task,
        metadata={**copy.deepcopy(task.metadata), "schedule_episode_id": episode_id},
    )
    session: Any = None
    attempt_keys: list[str] = []
    action_log: list[dict[str, Any]] = []
    feedback: list[dict[str, Any]] = []
    final_artifact: dict[str, Any] | None = None
    final_assistant_text: str | None = None
    terminal_reason = "budget_exhausted"
    verdict: Any = None
    terminal_state: Mapping[str, Any] | None = None
    try:
        session = prepare(
            task_record=task,
            namespace=episode_namespace,
            condition=condition,
        )
        for turn_number in range(1, 7):
            turn = planner.plan_turn(
                task=planner_task,
                condition=condition,
                turn_number=turn_number,
                feedback=tuple(copy.deepcopy(feedback)),
                runtime_interface=_runtime_interface(session),
                max_actions=1,
            )
            attempt_keys.extend(str(key) for key in turn.attempt_keys)
            final_assistant_text = ledger_confirmed_assistant_text(
                cache=cache,
                turn=turn,
                expected_episode_id=episode_id,
                expected_turn_number=turn_number,
            )
            if turn.status == "failed":
                raise IntegrityError("delivered canary turn has failed status")
            if turn.status == "explicit_abstention":
                terminal_reason = "explicit_abstention"
                break
            if turn.final_artifact is not None:
                if turn.actions:
                    raise IntegrityError("terminal canary turn also requests an action")
                final_artifact = copy.deepcopy(turn.final_artifact)
                terminal_reason = "normal"
                break
            if turn.status != "ok" or len(turn.actions) > 1:
                raise IntegrityError("canary planner turn violates the shared response contract")
            for action in turn.actions:
                outcome = session.apply(action)
                request = {"op": action.op, "args": copy.deepcopy(action.args)}
                record = {
                    "turn_number": turn_number,
                    "request": request,
                    "allowed": bool(outcome.allowed),
                    "reason": str(outcome.reason),
                    "observation": copy.deepcopy(outcome.observation),
                    "effects": list(copy.deepcopy(outcome.effects)),
                    "events": list(copy.deepcopy(outcome.events)),
                }
                canonical_json_bytes(record)
                action_log.append(record)
                feedback.append(copy.deepcopy(record))
        if final_assistant_text is None:
            raise IntegrityError("canary ended without ledger-confirmed assistant text")
        session.end_external_task()
        capture = getattr(session, "capture_terminal_state", None)
        evaluate = getattr(session, "evaluate_native_checkers", None)
        if not callable(capture) or not callable(evaluate):
            raise IntegrityError("public bridge lacks the terminal/checker integration")
        terminal_state = capture(
            final_assistant_text=final_assistant_text,
            terminal_reason=terminal_reason,
        )
        verdict = evaluate()
        session.close()
        cleanup_sha256 = getattr(session, "cleanup_sha256", None)
        if not isinstance(cleanup_sha256, str) or _SHA_RE.fullmatch(cleanup_sha256) is None:
            raise IntegrityError("public bridge did not verify exact cleanup")
        result = {
            "schema_version": 1,
            "artifact_type": "agentmembrane_public_canary_episode_engineering_record",
            "claim_bearing": False,
            "engineering_only": True,
            "nonestimating": True,
            "task_id": task.task_id,
            "source_task_id": selected,
            "source_task_record_id": task.metadata["source_task_record_id"],
            "episode_id": episode_id,
            "episode_namespace": episode_namespace,
            "model": MODEL_ID,
            "reasoning_effort": REASONING_EFFORT,
            "provider_route_id": PROVIDER_ROUTE_ID,
            "turn_count": len(attempt_keys),
            "attempt_keys": attempt_keys,
            "action_log": action_log,
            "final_artifact": final_artifact,
            "terminal_reason": terminal_reason,
            "terminal_assistant_text_sha256": sha256_bytes(
                final_assistant_text.encode("utf-8")
            ),
            "terminal_state_sha256": sha256_bytes(
                canonical_json_bytes(dict(terminal_state))
            ),
            "cleanup_sha256": cleanup_sha256,
            "native_verdict": {
                "utility": verdict.utility,
                "security": verdict.security,
                "checker_binding_ids": list(verdict.checker_binding_ids),
                "native_output_sha256": verdict.native_output_sha256,
            },
        }
        canonical_json_bytes(result)
        return result
    finally:
        if session is not None:
            session.close()


def prepare_public_canary_run(
    repo_root: Path, profile_path: Path, authorization_path: Path
) -> dict[str, Any]:
    """Validate the complete gate and require still-fresh output/cache namespaces."""

    repo_root = Path(repo_root).resolve()
    profile_path = Path(profile_path).resolve()
    pack_root = repo_root / "data/host_boundary_v2/packs" / DERIVED_PACK_ID
    profile = validate_exact_profile(repo_root, pack_root, profile_path)
    status = validate_narrow_authorization(repo_root, authorization_path)
    if status["authorized"] is not True:
        raise IntegrityError(
            "PUBLIC_CANARY_STOP: " + "; ".join(str(row) for row in status["errors"])
        )
    execution = profile.get("execution")
    if not isinstance(execution, Mapping):
        raise SchemaError("exact profile execution section is missing")
    output_root = _repo_path(
        repo_root, execution.get("output_namespace"), label="execution.output_namespace"
    )
    cache_root = _repo_path(
        repo_root, execution.get("cache_namespace"), label="execution.cache_namespace"
    )
    if output_root.exists() or cache_root.exists():
        raise IntegrityError("public canary output/cache namespace is not fresh")
    return {
        "artifact_type": "agentmembrane_public_canary_prepare_status",
        "authorized": True,
        "profile_sha256": _file_sha(profile_path),
        "authorization_sha256": _file_sha(authorization_path),
        "output_namespace": str(output_root.relative_to(repo_root)),
        "cache_namespace": str(cache_root.relative_to(repo_root)),
        "episodes": 2,
        "hard_api_call_cap": 12,
        "model": MODEL_ID,
        "reasoning_effort": REASONING_EFFORT,
    }


def execute_public_canary_run(
    repo_root: Path, profile_path: Path, authorization_path: Path
) -> dict[str, Any]:
    """Execute exactly two sequential episodes after recomputing every narrow gate."""

    repo_root = Path(repo_root).resolve()
    profile_path = Path(profile_path).resolve()
    authorization_path = Path(authorization_path).resolve()
    prepared = prepare_public_canary_run(repo_root, profile_path, authorization_path)
    profile = load_json(profile_path)
    execution = profile["execution"]
    output_root = repo_root / execution["output_namespace"]
    cache_root = repo_root / execution["cache_namespace"]
    identity = CacheIdentity(
        implementation_sha256=profile["resolution"]["implementation_sha256"],
        protocol_sha256=profile["resolution"]["protocol_sha256"],
        resolved_model_id=MODEL_ID,
        provider_route_id=PROVIDER_ROUTE_ID,
    )
    cache = RunCache(cache_root, identity)
    resolved = ResolvedProfile(
        raw=copy.deepcopy(profile),
        source_path=profile_path,
        resolved_path=profile_path,
    )
    client = ExactSolMaxLocalProxyClient.from_local_config()
    planner = ModelPlanner(resolved_profile=resolved, cache=cache, client=client)
    from .public_host_bridge import AgentDojoPublicHostAdapter

    bridge = AgentDojoPublicHostAdapter()
    conditions = load_conditions(repo_root / profile["implementation_bindings"]["conditions"]["path"])
    condition = conditions[CONDITION_ID]
    pack = load_taskpack(repo_root / profile["pack_binding"]["root"])
    tasks = {task.task_id: task for task in pack.tasks}
    ordered_tasks = [tasks[task_id] for task_id in profile["task_ids"]]
    if len(ordered_tasks) != 2 or len({task.task_id for task in ordered_tasks}) != 2:
        raise IntegrityError("exact public canary schedule must contain two distinct rows")
    output_root.mkdir(parents=True, exist_ok=False)
    records: list[dict[str, Any]] = []
    record_bindings: list[dict[str, Any]] = []
    for ordinal, task in enumerate(ordered_tasks, start=1):
        episode = sha256_json(
            {
                "namespace": "agentmembrane-public-sol-canary-episode-v1",
                "profile_sha256": prepared["profile_sha256"],
                "ordinal": ordinal,
                "task_id": task.task_id,
            }
        )
        namespace = f"{execution['native_namespace_prefix']}-{ordinal:02d}"
        record = execute_authorized_episode(
            repo_root=repo_root,
            authorization_path=authorization_path,
            planner=planner,
            cache=cache,
            bridge_adapter=bridge,
            task=task,
            condition=condition,
            episode_id=episode,
            episode_namespace=namespace,
        )
        record_path = output_root / f"episode-{ordinal:02d}.json"
        atomic_write_json(record_path, record)
        records.append(record)
        record_bindings.append(
            {
                "path": str(record_path.relative_to(repo_root)),
                "sha256": _file_sha(record_path),
            }
        )
    if client.calls_made > 12:
        raise IntegrityError("public canary exceeded its hard API call cap")
    summary = {
        "schema_version": 1,
        "artifact_type": "agentmembrane_public_sol_engineering_canary_summary",
        "claim_bearing": False,
        "engineering_only": True,
        "nonestimating": True,
        "decision": "COMPLETE",
        "profile_sha256": prepared["profile_sha256"],
        "authorization_sha256": prepared["authorization_sha256"],
        "model": MODEL_ID,
        "reasoning_effort": REASONING_EFFORT,
        "episodes": 2,
        "api_call_count": client.calls_made,
        "prior_failed_api_attempt_count": client.prior_attempts,
        "new_api_call_count": client.calls_made - client.prior_attempts,
        "hard_api_call_cap": 12,
        "request_level_transport_retries": 0,
        "records": record_bindings,
        "native_results": [
            {
                "task_id": row["task_id"],
                "source_task_record_id": row["source_task_record_id"],
                "utility": row["native_verdict"]["utility"],
                "security": row["native_verdict"]["security"],
                "turn_count": row["turn_count"],
                "terminal_reason": row["terminal_reason"],
            }
            for row in records
        ],
        "expansion_or_scientific_claim_permitted": False,
    }
    atomic_write_json(output_root / "summary.json", summary)
    return summary


def audit_public_canary_run(
    repo_root: Path, profile_path: Path, authorization_path: Path
) -> dict[str, Any]:
    """Audit a completed two-row canary without issuing calls or importing native code."""

    repo_root = Path(repo_root).resolve()
    profile = validate_exact_profile(
        repo_root,
        repo_root / "data/host_boundary_v2/packs" / DERIVED_PACK_ID,
        Path(profile_path).resolve(),
    )
    assert_execute_authorized(repo_root, Path(authorization_path).resolve())
    output_root = repo_root / profile["execution"]["output_namespace"]
    summary = load_json(output_root / "summary.json")
    records = summary.get("records")
    if (
        summary.get("artifact_type")
        != "agentmembrane_public_sol_engineering_canary_summary"
        or summary.get("decision") != "COMPLETE"
        or summary.get("episodes") != 2
        or not isinstance(records, list)
        or len(records) != 2
        or not isinstance(summary.get("api_call_count"), int)
        or summary["api_call_count"] > 12
    ):
        raise IntegrityError("completed public canary summary is invalid")
    for index, binding in enumerate(records):
        path = _repo_path(repo_root, binding.get("path"), label=f"records[{index}].path")
        if _file_sha(path) != binding.get("sha256"):
            raise IntegrityError(f"public canary episode record {index + 1} changed")
    return copy.deepcopy(summary)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Exact two-episode public Sol canary")
    parser.add_argument("mode", choices=("prepare", "execute", "audit"))
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    args = parser.parse_args(argv)
    functions = {
        "prepare": prepare_public_canary_run,
        "execute": execute_public_canary_run,
        "audit": audit_public_canary_run,
    }
    result = functions[args.mode](args.repo_root, args.profile, args.authorization)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


__all__ = [
    "ADAPTER_REF",
    "CONDITION_ID",
    "DERIVED_PACK_ID",
    "DerivedPackReport",
    "ExactSolMaxLocalProxyClient",
    "FreshRuntimeReport",
    "MODEL_ID",
    "PROVIDER_ROUTE_ID",
    "REASONING_EFFORT",
    "SIX_CATEGORIES",
    "assert_execute_authorized",
    "audit_public_canary_run",
    "build_derived_pack_documents",
    "ledger_confirmed_assistant_text",
    "execute_authorized_episode",
    "execute_public_canary_run",
    "materialize_derived_pack",
    "prepare_public_canary_run",
    "validate_derived_pack",
    "validate_exact_profile",
    "validate_fresh_runtime_triplet",
    "validate_narrow_authorization",
]


if __name__ == "__main__":
    raise SystemExit(main())
