"""Manifest-bound execution and sealed evidence for the formal three-tier study.

The formal runtime deliberately reuses the reviewed v6 controller for native
state, authority enforcement and phase budgets. It adds the missing study
boundary around that controller: a fresh per-attempt allocation is written
before actor execution, and a compact formal evidence record is written before
the same collector is sealed. Neither a bare v6 trajectory nor a caller-
supplied hash can therefore be promoted into a formal observation afterwards.
"""
from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import re

from ..rq1_collab_v1.admission import TaskBundle
from ..rq1_collab_v1.audit import (
    _write_new,
    canonical,
    file_hash,
    strict_loads,
    verify,
)
from ..rq1_collab_v3.contract import clone, digest
from ..rq1_collab_v6.attack_spec import compile_attack_spec
from ..rq1_collab_v6.contract import (
    FIXED_BUDGET,
    PHASE_SCHEDULE,
    PROTOCOL as INNER_PROTOCOL,
    make_config,
)
from ..rq1_collab_v6.evaluation import validate_evidence as validate_inner_evidence
from ..rq1_collab_v6.runtime import run_episode as run_inner_episode
from .contract import (
    FORMAL_PROTOCOL,
    LEVEL_BINDINGS,
    MODEL_PROFILES,
    REGIMES,
    TOPOLOGY,
)


FORMAL_EVIDENCE_SCHEMA = "rq1-evidence-formal/1"
FORMAL_ALLOCATION_SCHEMA = "rq1-formal-cell-allocation/1"
FORMAL_EVIDENCE_PATH = "artifacts/evidence-formal-v1.json"
FORMAL_ALLOCATION_PATH = "artifacts/formal-allocation.json"
HEX64 = re.compile(r"[0-9a-f]{64}")
_ONE_SHOT_CLAIM_ATTR = "_rq1_formal_one_shot_claim"
_EVALUATOR_ONLY_ATTR = "_rq1_formal_evaluator_only"
_RUNTIME_OBJECT_SCOPE = ["adapter", "collector", "driver", "transport"]


def _valid_hash(value) -> bool:
    return type(value) is str and HEX64.fullmatch(value) is not None


def _contains_s_principal(value) -> bool:
    scalar = {"actor", "principal", "recipient", "sender", "from", "to"}
    plural = {"actors", "actor_set", "recipients", "roles"}
    if type(value) is dict:
        for key, item in value.items():
            if key in scalar and item == "S":
                return True
            if key in plural and type(item) in {list, tuple, set} and "S" in item:
                return True
            if _contains_s_principal(item):
                return True
    elif type(value) is list:
        return any(_contains_s_principal(item) for item in value)
    return False


def _one(rows, task_key: str, error: str) -> dict:
    matches = [row for row in rows
               if type(row) is dict and row.get("task_key") == task_key]
    if len(matches) != 1:
        raise ValueError(error)
    return matches[0]


def _task_key_from_record(record: object) -> str:
    if type(record) is not dict:
        raise ValueError("formal_task_bundle_record_required")
    suite, original_id = record.get("suite"), record.get("original_id")
    if (type(suite) is not str or not suite or type(original_id) is not str
            or not original_id):
        raise ValueError("formal_task_bundle_identity_required")
    return suite + "/" + original_id


def _bound_source(manifest: dict, name: str) -> dict:
    binding = manifest.get("source_bindings", {}).get(name)
    if (type(binding) is not dict or set(binding) != {"path", "sha256"}
            or not _valid_hash(binding.get("sha256"))):
        raise ValueError("formal_runtime_source_binding_required:" + name)
    path = Path(binding["path"])
    if file_hash(path) != binding["sha256"]:
        raise ValueError("formal_runtime_source_changed:" + name)
    value = strict_loads(path.read_bytes())
    if type(value) is not dict:
        raise ValueError("formal_runtime_source_object_required:" + name)
    return value


def _registered_route(manifest: dict) -> dict:
    """Reload the exact local provider route without persisting private inputs."""
    binding = _bound_source(manifest, "route_runtime_binding")
    unsigned = {key: clone(value) for key, value in binding.items()
                if key != "route_runtime_binding_sha256"}
    route_source = binding.get("route")
    route = route_source.get("route") if type(route_source) is dict else None
    if (binding.get("route_runtime_binding_sha256")
            != manifest.get("route_runtime_binding_sha256")
            or binding.get("route_runtime_binding_sha256") != digest(unsigned)
            or type(route_source) is not dict
            or type(route) is not dict
            or route.get("schema_version") != "rq1-provider-route/1"
            or type(route.get("endpoint")) is not str
            or type(route.get("credential_env")) is not str
            or not _valid_hash(route_source.get("sha256"))
            or file_hash(route_source.get("path", "")) != route_source["sha256"]
            or strict_loads(Path(route_source["path"]).read_bytes()) != route):
        raise ValueError("formal_runtime_route_binding_mismatch")
    return clone(route)


def validate_cell(cell: dict) -> dict:
    binding = LEVEL_BINDINGS.get(cell.get("level")) if type(cell) is dict else None
    if (type(cell) is not dict
            or cell.get("protocol_version") != FORMAL_PROTOCOL
            or cell.get("topology") != TOPOLOGY
            or binding is None
            or cell.get("runtime_external_level") != binding["runtime_level"]
            or cell.get("legacy_canonical_analog")
               != binding["legacy_canonical_analog"]
            or cell.get("canonical_ladder_level_claimed") is not None
            or cell.get("regime") not in REGIMES
            or cell.get("repeat") != 0
            or cell.get("models") != MODEL_PROFILES
            or cell.get("budget") != FIXED_BUDGET
            or cell.get("phase_schedule") != PHASE_SCHEDULE
            or cell.get("execution_mode") != "formal_live"
            or cell.get("automatic_retry") is not False
            or cell.get("replacement_cell_permitted") is not False
            or not _valid_hash(cell.get("formal_task_binding_sha256"))
            or not _valid_hash(cell.get("goal_cluster_id", "").rsplit("/", 1)[-1])):
        raise ValueError("formal_cell_runtime_contract_mismatch")
    if _contains_s_principal(cell):
        raise ValueError("formal_cell_contains_S")
    return clone(cell)


def inner_config(cell: dict, bundle_sha256: str) -> dict:
    """Translate a registered formal cell to the unchanged v6 controller shape."""
    cell = validate_cell(cell)
    if not _valid_hash(bundle_sha256):
        raise ValueError("formal_bundle_sha256_required")
    task_slug = cell["episode_id"].rsplit("-H_E-", 1)[0]
    config = make_config(
        bundle_sha256,
        task_slug,
        TOPOLOGY,
        cell["level"],
        cell["regime"],
        cell["repeat"],
        mode="live_diagnostic",
        models=MODEL_PROFILES,
        budget=FIXED_BUDGET,
    )
    if config["episode_id"] != cell["episode_id"]:
        raise ValueError("formal_to_inner_episode_identity_mismatch")
    return config


def _registered_context(manifest: dict, cell: dict, bundle) -> dict:
    """Bind the runtime bundle to the registered goal, H contract and Q/I/D row."""
    if type(bundle) is not TaskBundle:
        raise ValueError("reviewed_task_bundle_type_required")
    record = bundle.record()
    task = _one(manifest.get("tasks", []), cell["task_key"],
                "exact_registered_formal_task_required")
    unsigned_task = {key: clone(value) for key, value in task.items()
                     if key != "formal_task_binding_sha256"}
    if (task.get("formal_task_binding_sha256")
            != cell["formal_task_binding_sha256"]
            or task.get("goal_cluster_id") != cell["goal_cluster_id"]
            or digest(unsigned_task) != task.get("formal_task_binding_sha256")):
        raise ValueError("formal_runtime_cell_task_binding_mismatch")

    goals = _bound_source(manifest, "final_goal_assignment")
    qid = _bound_source(manifest, "final_QID")
    h_contract = _bound_source(manifest, "H_output_contract")
    goal = _one(goals.get("assignments", []), cell["task_key"],
                "exact_registered_goal_assignment_required")
    qid_task = _one(qid.get("tasks", []), cell["task_key"],
                    "exact_registered_QID_task_required")
    h_task = _one(h_contract.get("tasks", []), cell["task_key"],
                  "exact_registered_H_task_required")
    attack_spec = compile_attack_spec(
        record.get("public", {}).get("goal", {}).get("goal"))

    qid_source = qid_task.get("source_binding")
    source = record.get("source_record")
    public = record.get("public")
    if (goals.get("goal_assignment_sha256")
            != manifest.get("goal_assignment_sha256")
            or qid.get("adjudication_sha256")
            != manifest.get("QID_adjudication_sha256")
            or h_contract.get("H_contract_sha256")
            != manifest.get("H_contract_sha256")
            or digest(qid_task) != task.get("QID_adjudicated_task_sha256")
            or h_task.get("H_output_contract_sha256")
               != task.get("H_output_contract_sha256")
            or _task_key_from_record(record) != cell["task_key"]
            or type(source) is not dict
            or source != task.get("source_record")
            or type(public) is not dict
            or h_task.get("bundle_sha256") != bundle.sha256
            or h_task.get("public_user_request") != public.get("user_request")
            or h_task.get("public_goal") != public.get("goal")
            or digest(public.get("user_request"))
               != h_task.get("public_user_request_sha256")
            or public.get("goal") != goal.get("goal_source_binding")
            or digest(public.get("goal")) != h_task.get("public_goal_sha256")
            or record.get("task_policy_sha256")
               != h_task.get("task_policy_sha256")
            or goal.get("goal_cluster_id") != cell["goal_cluster_id"]
            or h_task.get("goal_cluster_id") != cell["goal_cluster_id"]
            or attack_spec.get("spec_sha256") != goal.get("attack_spec_sha256")
            or attack_spec.get("fixed", {}).get("goal_binding", {}).get("suite")
               != record.get("suite")
            or attack_spec.get("fixed", {}).get("goal_binding", {}).get("goal_id")
               != goal.get("goal_id")
            or type(qid_source) is not dict
            or qid_source.get("suite") != source.get("suite")
            or qid_source.get("task_id") != source.get("task_id")
            or qid_source.get("initial_state_sha256")
               != source.get("initial_state_sha256")
            or qid_source.get("prompt_sha256") != source.get("prompt_sha256")
            or qid_source.get("tool_schema_sha256")
               != source.get("tool_schema_sha256")
            or qid_source.get("assigned_goal_id") != goal.get("goal_id")
            or qid_source.get("assigned_goal_sha256")
               != goal.get("goal_source_binding", {}).get("goal_sha256")
            or qid_source.get("attack_spec_sha256")
               != goal.get("attack_spec_sha256")
            or qid_source.get("goal_cluster_id") != cell["goal_cluster_id"]):
        raise ValueError("formal_runtime_bundle_goal_QID_binding_mismatch")
    return {
        "task": task,
        "goal": goal,
        "qid_task": qid_task,
        "h_task": h_task,
        "record": record,
        "attack_spec": attack_spec,
    }


@contextmanager
def registered_task_resource(manifest: dict, task_key: str):
    """Load one manifest-registered bundle and trusted evaluator adapter.

    Downstream analysis must not deserialize a caller-provided bundle or trust
    an adapter supplied alongside an evaluation JSON.  This resolver starts
    from the exact, hash-bound qualified source and final goal assignment in an
    activated manifest, reloads the public AgentDojo task locally, and shuts
    the evaluator worker down when the caller leaves the context.
    """
    from ..rq1_collab_v1.admission import load_development_bundles
    from ..rq1_collab_v1.process_backend import ProcessNativeTask
    from .gate import validate_formal_manifest

    manifest = validate_formal_manifest(manifest)
    task = _one(manifest.get("tasks", []), task_key,
                "exact_registered_formal_task_required")
    cells = [cell for cell in manifest.get("cells", [])
             if cell.get("task_key") == task_key]
    if not cells:
        raise ValueError("registered_formal_task_has_no_cell")
    cell = validate_cell(cells[0])
    goal_source = _bound_source(manifest, "final_goal_assignment")
    assignment = _one(goal_source.get("assignments", []), task_key,
                      "exact_registered_goal_assignment_required")
    qualified_binding = manifest.get("source_bindings", {}).get(
        "qualified_manifest")
    if (type(qualified_binding) is not dict
            or set(qualified_binding) != {"path", "sha256"}
            or not _valid_hash(qualified_binding.get("sha256"))
            or file_hash(qualified_binding.get("path", ""))
               != qualified_binding["sha256"]):
        raise ValueError("formal_runtime_source_binding_required:qualified_manifest")
    qualified = strict_loads(Path(qualified_binding["path"]).read_bytes())
    if (type(qualified) is not dict
            or type(qualified.get("source_root")) is not str
            or type(qualified.get("native_python")) is not str):
        raise ValueError("qualified_manifest_runtime_fields_required")
    suite, original_id = task_key.split("/", 1)
    bundles = load_development_bundles(
        qualified_binding["path"], [{
            "suite": suite,
            "task_id": original_id,
            "goal_id": assignment["goal_id"],
        }], native_python=qualified["native_python"],
    )
    if len(bundles) != 1:
        raise ValueError("exact_registered_task_bundle_required")
    bundle = bundles[0]
    context = _registered_context(manifest, cell, bundle)
    if (bundle.sha256 != context["h_task"].get("bundle_sha256")
            or task.get("source_record") != context["record"].get(
                "source_record")):
        raise ValueError("registered_task_bundle_reload_mismatch")

    adapter = ProcessNativeTask(
        qualified["native_python"], qualified["source_root"], suite,
        original_id, timeout=30,
    )
    try:
        record = context["record"]
        if (any(adapter.record.get(key) != value
                for key, value in record["source_record"].items())
                or digest(adapter.prompt)
                   != record["source_record"]["prompt_sha256"]
                or digest(adapter.tool_specs)
                   != record["source_record"]["tool_schema_sha256"]):
            raise ValueError("registered_evaluator_adapter_source_mismatch")
        setattr(adapter, _EVALUATOR_ONLY_ATTR, True)
        yield {"bundle": bundle, "adapter": adapter}
    finally:
        adapter.shutdown()


def evaluate_registered_native_endpoints(*, adapter, run_root: str | Path,
                                         expected_seal_hash: str,
                                         manifest: dict, episode_id: str,
                                         bundle) -> dict:
    """Recompute native utility from one sealed run with its exact call trace.

    The function accepts no caller-supplied snapshots, answer, or function-call
    list.  Those inputs are read only after the execution seal and full formal
    bindings validate.  A backend-commit-unknown call makes the endpoint
    unknown instead of being silently dropped from the native grader trace.
    """
    from ..rq1_collab_v1.process_backend import PipeWorker, ProcessNativeTask

    if (type(adapter) is not ProcessNativeTask
            or getattr(adapter, _EVALUATOR_ONLY_ATTR, False) is not True
            or getattr(adapter, _ONE_SHOT_CLAIM_ATTR, None) is not None
            or type(bundle) is not TaskBundle):
        raise ValueError("registered_evaluator_resource_required")
    record = bundle.record()
    if (any(adapter.record.get(key) != value
            for key, value in record.get("source_record", {}).items())
            or digest(adapter.prompt)
               != record.get("source_record", {}).get("prompt_sha256")
            or digest(adapter.tool_specs)
               != record.get("source_record", {}).get("tool_schema_sha256")):
        raise ValueError("registered_evaluator_bundle_mismatch")
    admitted = validate_sealed_formal_run(
        run_root, expected_seal_hash=expected_seal_hash,
        manifest=manifest, episode_id=episode_id, bundle=bundle,
    )
    inner = admitted["inner_evidence"]
    function_calls = []
    for call in inner["native_calls"]:
        quality = call.get("evidence_quality")
        entered = quality.get("backend_entered") \
            if type(quality) is dict else None
        if entered is None:
            raise ValueError("formal_native_function_call_trace_commit_unknown")
        if entered is True:
            function_calls.append({
                "function": call["tool"],
                "args": clone(call["arguments"]),
            })
    before, after, final_text = (
        inner.get("initial_snapshot"), inner.get("terminal_snapshot"),
        inner.get("final_text"),
    )
    if (type(before) is not dict or type(after) is not dict
            or type(final_text) is not str):
        raise ValueError("sealed_native_endpoint_inputs_missing")
    with PipeWorker(mode="evaluator", **adapter.arguments) as evaluator:
        score = evaluator.request(
            "score", before=before, after=after, final_text=final_text,
            function_calls=function_calls,
        )
    if type(score) is not dict or set(score) != {
            "native", "native_detail", "strict"}:
        raise ValueError("registered_native_endpoint_result_invalid")
    return {
        "episode_id": episode_id,
        "admitted": {
            "formal_evidence": clone(admitted["formal_evidence"]),
            "inner_evidence": clone(admitted["inner_evidence"]),
        },
        "formal_evidence_sha256": admitted["formal_evidence"][
            "formal_evidence_sha256"],
        "execution_seal_sha256": admitted["seal"]["seal_hash"],
        "initial_snapshot_sha256": digest(before),
        "terminal_snapshot_sha256": digest(after),
        "function_call_count": len(function_calls),
        "function_calls_sha256": digest(function_calls),
        "native": clone(score["native"]),
        "native_detail": clone(score["native_detail"]),
        "strict": clone(score["strict"]),
    }


def _collector_identity(collector, episode_id: str) -> dict:
    if (getattr(collector, "episode_id", None) != episode_id
            or not isinstance(getattr(collector, "run_dir", None), Path)):
        raise ValueError("formal_collector_episode_binding_mismatch")
    lock_path = collector.run_dir / ".collector.lock"
    lock = strict_loads(lock_path.read_bytes())
    if (type(lock) is not dict or lock.get("episode_id") != episode_id
            or not re.fullmatch(r"[0-9a-f]{32}", str(lock.get("collector_id", "")))):
        raise ValueError("fresh_formal_collector_lock_required")
    return {"collector_id": lock["collector_id"],
            "collector_lock_sha256": file_hash(lock_path)}


def _claim_one_shot_runtime_objects(*, manifest: dict, cell: dict,
                                    adapter, driver, collector,
                                    registered_route: dict) -> dict:
    """Consume the in-process runtime objects exactly once.

    This proves only the Python object lifecycle exercised by the controller.
    It deliberately makes no claim that an external CLIProxy process was
    started or stopped; the production lifecycle runner must provide that
    separate, structured receipt before the formal gate can be activated.
    """
    from ..rq1_collab_v1.audit import EventCollector
    from ..rq1_collab_v1.process_backend import ProcessNativeTask
    from ..rq1_collab_v3.proxy_transport import BoundProxyTransport
    from ..rq1_collab_v6.provider_route import BoundRouteTransport
    from .driver import FormalRoleModelDriver

    transport = getattr(driver, "transport", None)
    children = getattr(driver, "children", None)
    if (type(adapter) is not ProcessNativeTask
            or type(driver) is not FormalRoleModelDriver
            or type(collector) is not EventCollector
            or type(transport) not in {BoundProxyTransport, BoundRouteTransport}
            or transport.endpoint != registered_route.get("endpoint")
            or transport.credential_env
               != registered_route.get("credential_env")
            or getattr(driver, "collector", None) is not collector
            or type(children) is not dict
            or any(getattr(child, "transport", None) is not transport
                   or getattr(child, "collector", None) is not collector
                   for child in children.values())):
        raise ValueError("formal_runtime_object_graph_mismatch")
    objects = {
        "driver": driver,
        "transport": transport,
        "adapter": adapter,
        "collector": collector,
    }
    for name, value in objects.items():
        if getattr(value, _EVALUATOR_ONLY_ATTR, False) is True:
            raise ValueError("formal_evaluator_object_cannot_execute:" + name)
        if getattr(value, _ONE_SHOT_CLAIM_ATTR, None) is not None:
            raise ValueError("formal_runtime_object_reuse_forbidden:" + name)
        if not hasattr(value, "__dict__"):
            raise ValueError("formal_runtime_object_not_claimable:" + name)
    collector_identity = _collector_identity(collector, cell["episode_id"])
    body = {
        "schema_version": "rq1-formal-runtime-object-claim/1",
        "protocol_version": FORMAL_PROTOCOL,
        "formal_manifest_sha256": manifest["manifest_sha256"],
        "episode_id": cell["episode_id"],
        "collector_id": collector_identity["collector_id"],
        "object_scope": clone(_RUNTIME_OBJECT_SCOPE),
        "one_shot_runtime_objects": True,
        "route_runtime_binding_sha256": manifest[
            "route_runtime_binding_sha256"],
        "route_endpoint_sha256": digest(registered_route["endpoint"]),
        "route_credential_env_sha256": digest(
            registered_route["credential_env"]),
        "proxy_process_lifecycle_proven": False,
    }
    claim = {**body, "runtime_object_claim_sha256": digest(body)}
    for value in objects.values():
        setattr(value, _ONE_SHOT_CLAIM_ATTR, clone(claim))
    return claim


def _validate_runtime_object_claim(claim: object, *, manifest: dict,
                                   cell: dict, collector_id: str) -> dict:
    registered_route = _registered_route(manifest)
    unsigned = ({key: clone(value) for key, value in claim.items()
                 if key != "runtime_object_claim_sha256"}
                if type(claim) is dict else {})
    expected = {
        "schema_version": "rq1-formal-runtime-object-claim/1",
        "protocol_version": FORMAL_PROTOCOL,
        "formal_manifest_sha256": manifest["manifest_sha256"],
        "episode_id": cell["episode_id"],
        "collector_id": collector_id,
        "object_scope": clone(_RUNTIME_OBJECT_SCOPE),
        "one_shot_runtime_objects": True,
        "route_runtime_binding_sha256": manifest[
            "route_runtime_binding_sha256"],
        "route_endpoint_sha256": digest(registered_route["endpoint"]),
        "route_credential_env_sha256": digest(
            registered_route["credential_env"]),
        "proxy_process_lifecycle_proven": False,
    }
    claim_hash = (claim.get("runtime_object_claim_sha256")
                  if type(claim) is dict else None)
    if unsigned != expected or claim_hash != digest(unsigned):
        raise ValueError("formal_runtime_object_claim_mismatch")
    return clone(claim)


def _make_allocation(*, manifest: dict, cell: dict, bundle,
                     context: dict, collector, runtime_claim: dict) -> dict:
    collector_identity = _collector_identity(collector, cell["episode_id"])
    _validate_runtime_object_claim(
        runtime_claim, manifest=manifest, cell=cell,
        collector_id=collector_identity["collector_id"],
    )
    body = {
        "schema_version": FORMAL_ALLOCATION_SCHEMA,
        "protocol_version": FORMAL_PROTOCOL,
        "formal_manifest_sha256": manifest["manifest_sha256"],
        "code_bundle_sha256": manifest["code_bundle_sha256"],
        "research_sample_count_at_manifest_registration": 0,
        "allocated_after_manifest_validation": True,
        "legacy_or_resumed_attempt": False,
        "episode_id": cell["episode_id"],
        "formal_cell_sha256": digest(cell),
        "formal_task_binding_sha256": cell["formal_task_binding_sha256"],
        "goal_assignment_sha256": manifest["goal_assignment_sha256"],
        "goal_assignment_task_sha256": digest(context["goal"]),
        "goal_cluster_id": cell["goal_cluster_id"],
        "attack_spec_sha256": context["attack_spec"]["spec_sha256"],
        "H_contract_sha256": manifest["H_contract_sha256"],
        "H_output_contract_sha256": context["task"]["H_output_contract_sha256"],
        "QID_adjudication_sha256": manifest["QID_adjudication_sha256"],
        "QID_adjudicated_task_sha256": context["task"][
            "QID_adjudicated_task_sha256"],
        "bundle_sha256": bundle.sha256,
        "bundle_record_sha256": digest(context["record"]),
        "runtime_object_claim": clone(runtime_claim),
        **collector_identity,
    }
    allocation = {**body, "allocation_sha256": digest(body)}
    _write_new(collector.run_dir / FORMAL_ALLOCATION_PATH,
               canonical(allocation) + b"\n")
    collector.emit("formal_cell_allocated", {
        "formal_manifest_sha256": manifest["manifest_sha256"],
        "episode_id": cell["episode_id"],
        "formal_cell_sha256": digest(cell),
        "allocation_sha256": allocation["allocation_sha256"],
        "bundle_sha256": bundle.sha256,
        "runtime_object_claim_sha256": runtime_claim[
            "runtime_object_claim_sha256"],
        "QID_adjudicated_task_sha256": context["task"][
            "QID_adjudicated_task_sha256"],
    }, evidence_quality="formal_controller_pre_actor_binding")
    return allocation


def validate_allocation(allocation: dict, *, manifest: dict, cell: dict,
                        bundle, context: dict, collector=None) -> dict:
    cell = validate_cell(cell)
    unsigned = ({key: clone(value) for key, value in allocation.items()
                 if key != "allocation_sha256"}
                if type(allocation) is dict else {})
    collector_id = allocation.get("collector_id") \
        if type(allocation) is dict else None
    runtime_claim = _validate_runtime_object_claim(
        allocation.get("runtime_object_claim")
        if type(allocation) is dict else None,
        manifest=manifest, cell=cell, collector_id=collector_id,
    )
    expected = {
        "schema_version": FORMAL_ALLOCATION_SCHEMA,
        "protocol_version": FORMAL_PROTOCOL,
        "formal_manifest_sha256": manifest["manifest_sha256"],
        "code_bundle_sha256": manifest["code_bundle_sha256"],
        "research_sample_count_at_manifest_registration": 0,
        "allocated_after_manifest_validation": True,
        "legacy_or_resumed_attempt": False,
        "episode_id": cell["episode_id"],
        "formal_cell_sha256": digest(cell),
        "formal_task_binding_sha256": cell["formal_task_binding_sha256"],
        "goal_assignment_sha256": manifest["goal_assignment_sha256"],
        "goal_assignment_task_sha256": digest(context["goal"]),
        "goal_cluster_id": cell["goal_cluster_id"],
        "attack_spec_sha256": context["attack_spec"]["spec_sha256"],
        "H_contract_sha256": manifest["H_contract_sha256"],
        "H_output_contract_sha256": context["task"]["H_output_contract_sha256"],
        "QID_adjudication_sha256": manifest["QID_adjudication_sha256"],
        "QID_adjudicated_task_sha256": context["task"][
            "QID_adjudicated_task_sha256"],
        "bundle_sha256": bundle.sha256,
        "bundle_record_sha256": digest(context["record"]),
        "runtime_object_claim": runtime_claim,
        "collector_id": collector_id,
        "collector_lock_sha256": allocation.get("collector_lock_sha256")
            if type(allocation) is dict else None,
    }
    if (unsigned != expected
            or allocation.get("allocation_sha256") != digest(unsigned)
            or not re.fullmatch(r"[0-9a-f]{32}", str(expected["collector_id"]))
            or not _valid_hash(expected["collector_lock_sha256"])):
        raise ValueError("formal_allocation_binding_mismatch")
    if collector is not None and _collector_identity(
            collector, cell["episode_id"]) != {
                "collector_id": expected["collector_id"],
                "collector_lock_sha256": expected["collector_lock_sha256"],
            }:
        raise ValueError("formal_allocation_collector_mismatch")
    return clone(allocation)


def _validate_formal_permissions(inner: dict) -> None:
    if (inner.get("actor_protocol") != FORMAL_PROTOCOL
            or set(inner.get("actors", {})) != {"H", "E"}
            or inner.get("delegations") != []
            or _contains_s_principal(inner)):
        raise ValueError("inner_evidence_not_formal_H_E_execution")
    for delivery in inner.get("deliveries", []):
        actor = delivery.get("actor")
        payload = delivery.get("payload")
        permissions = payload.get("permissions") if type(payload) is dict else None
        expected_recipients = (["H"] if actor == "E" else []
                               if actor == "H" else None)
        specs = payload.get("available_tools") if type(payload) is dict else None
        if (expected_recipients is None or type(permissions) is not dict
                or permissions.get("can_delegate") is not False
                or permissions.get("recipients") != expected_recipients
                or "delegatable_tools" in payload
                or type(specs) is not list
                or permissions.get("tools")
                   != sorted(spec.get("name") for spec in specs)):
            raise ValueError("formal_observation_permission_mismatch")
    for row in inner.get("decisions", []):
        action = row.get("action")
        prohibited = type(action) is dict and (
                action.get("type") == "delegate"
                or action.get("type") == "send_message"
                   and not (row.get("actor") == "E"
                            and action.get("recipient") == "H"))
        # A model can violate the advertised JSON schema.  Preserve that as
        # observed behavior only when the runtime demonstrably rejected it
        # before dispatch; it must never appear as an admitted capability use.
        if prohibited and (row.get("status") != "rejected"
                           or row.get("dispatch_domain")
                           != "formal_actor_protocol_guard"):
            raise ValueError("formal_decision_protocol_mismatch")
    if any(row.get("sender") != "E" or row.get("recipient") != "H"
           for row in inner.get("messages", [])):
        raise ValueError("formal_message_protocol_mismatch")


def wrap_evidence(inner: dict, *, manifest: dict, cell: dict,
                  allocation: dict, context: dict) -> dict:
    """Create the compact formal record that will enter the execution seal."""
    cell = validate_cell(cell)
    validate_allocation(allocation, manifest=manifest, cell=cell,
                        bundle=context["bundle"], context=context)
    validate_inner_evidence(inner)
    _validate_formal_permissions(inner)
    if (inner.get("episode_id") != cell["episode_id"]
            or inner.get("config", {}).get("protocol_version") != INNER_PROTOCOL
            or inner.get("config", {}).get("topology") != TOPOLOGY
            or inner.get("config", {}).get("models") != MODEL_PROFILES
            or inner.get("config", {}).get("level") != cell["level"]
            or inner.get("config", {}).get("regime") != cell["regime"]
            or inner.get("config", {}).get("repeat") != 0
            or inner.get("config", {}).get("execution_mode") != "live_diagnostic"
            or inner.get("config", {}).get("bundle_sha256")
               != allocation["bundle_sha256"]
            or inner.get("bundle_sha256") != allocation["bundle_sha256"]
            or inner.get("bundle_public") != context["record"]["public"]
            or inner.get("attack_spec_sha256")
               != allocation["attack_spec_sha256"]
            or inner.get("qid_pre_run_registration") is not None):
        raise ValueError("inner_evidence_formal_binding_mismatch")
    body = {
        "schema_version": FORMAL_EVIDENCE_SCHEMA,
        "protocol_version": FORMAL_PROTOCOL,
        "formal_manifest_sha256": manifest["manifest_sha256"],
        "code_bundle_sha256": manifest["code_bundle_sha256"],
        "allocation_sha256": allocation["allocation_sha256"],
        "allocated_after_manifest_registration": True,
        "legacy_source": False,
        "episode_id": cell["episode_id"],
        "formal_cell_sha256": digest(cell),
        "formal_task_binding_sha256": cell["formal_task_binding_sha256"],
        "goal_assignment_sha256": manifest["goal_assignment_sha256"],
        "goal_assignment_task_sha256": allocation[
            "goal_assignment_task_sha256"],
        "goal_cluster_id": cell["goal_cluster_id"],
        "attack_spec_sha256": allocation["attack_spec_sha256"],
        "H_contract_sha256": manifest["H_contract_sha256"],
        "H_output_contract_sha256": allocation[
            "H_output_contract_sha256"],
        "QID_adjudication_sha256": manifest["QID_adjudication_sha256"],
        "QID_adjudicated_task_sha256": allocation[
            "QID_adjudicated_task_sha256"],
        "bundle_sha256": allocation["bundle_sha256"],
        "bundle_record_sha256": allocation["bundle_record_sha256"],
        "runtime_object_claim_sha256": allocation[
            "runtime_object_claim"]["runtime_object_claim_sha256"],
        "actor_set": ["H", "E"],
        "actor_protocol": FORMAL_PROTOCOL,
        "inner_controller_protocol": INNER_PROTOCOL,
        "inner_config_sha256": digest(inner["config"]),
        "inner_evidence_path": "artifacts/evidence-v6.json",
        "inner_evidence_sha256": digest(inner),
    }
    return {**body, "formal_evidence_sha256": digest(body)}


def _validate_evidence_components(evidence: dict, *, manifest: dict,
                                  cell: dict, allocation: dict,
                                  inner_evidence: dict, bundle,
                                  events=None) -> dict:
    """Validate the envelope and underlying H/E execution from first principles."""
    cell = validate_cell(cell)
    context = _registered_context(manifest, cell, bundle)
    context["bundle"] = bundle
    validate_allocation(allocation, manifest=manifest, cell=cell,
                        bundle=bundle, context=context)
    expected = wrap_evidence(inner_evidence, manifest=manifest, cell=cell,
                             allocation=allocation, context=context)
    if type(evidence) is not dict or evidence != expected:
        raise ValueError("formal_evidence_envelope_binding_mismatch")
    if events is not None:
        validate_inner_evidence(inner_evidence, events=events)
    return clone(evidence)


def _formal_seal_extension(evidence: dict, allocation: dict) -> dict:
    return {
        "schema_version": "rq1-formal-seal-extension/1",
        "formal_protocol_version": FORMAL_PROTOCOL,
        "formal_manifest_sha256": evidence["formal_manifest_sha256"],
        "episode_id": evidence["episode_id"],
        "formal_cell_sha256": evidence["formal_cell_sha256"],
        "allocation_path": FORMAL_ALLOCATION_PATH,
        "allocation_sha256": allocation["allocation_sha256"],
        "formal_evidence_path": FORMAL_EVIDENCE_PATH,
        "formal_evidence_sha256": evidence["formal_evidence_sha256"],
        "bundle_sha256": evidence["bundle_sha256"],
        "goal_assignment_task_sha256": evidence[
            "goal_assignment_task_sha256"],
        "QID_adjudicated_task_sha256": evidence[
            "QID_adjudicated_task_sha256"],
        "runtime_object_claim_sha256": evidence[
            "runtime_object_claim_sha256"],
        "legacy_evidence_eligible": False,
    }


def _seal_failed_attempt(collector, *, manifest: dict, cell: dict,
                         allocation: dict | None, exc: Exception) -> None:
    if getattr(collector, "_sealed", False):
        return
    data = {
        "formal_manifest_sha256": manifest.get("manifest_sha256"),
        "episode_id": cell.get("episode_id"),
        "formal_cell_sha256": digest(cell),
        "allocation_sha256": (allocation or {}).get("allocation_sha256"),
        "failure_class": type(exc).__name__,
        "formal_evidence_admitted": False,
        "replacement_cell_permitted": False,
    }
    try:
        collector.emit("formal_attempt_failed", data,
                       evidence_quality="formal_controller_failure_boundary")
        collector.seal({
            "protocol_version": INNER_PROTOCOL,
            "actor_protocol": FORMAL_PROTOCOL,
            "formal_ready": False,
            "formal_extension": None,
            "formal_failure": data,
        })
    except Exception:
        try:
            collector.abort()
        except Exception:
            pass


def _lifecycle(events: list[dict], episode_id: str) -> None:
    names = ("formal_cell_allocated", "episode_started", "episode_closed",
             "formal_evidence_admitted", "collector_seal")
    selected = {}
    for name in names:
        rows = [row for row in events if row.get("kind") == name]
        if len(rows) != 1:
            raise ValueError("formal_cell_lifecycle_event_mismatch:" + name)
        selected[name] = rows[0]
    if [selected[name]["seq"] for name in names] != sorted(
            selected[name]["seq"] for name in names):
        raise ValueError("formal_cell_lifecycle_order_mismatch")
    if any(row.get("episode_id") != episode_id for row in selected.values()):
        raise ValueError("formal_cell_lifecycle_episode_mismatch")


def validate_sealed_formal_run(run_dir: str | Path, *,
                               expected_seal_hash: str, manifest: dict,
                               episode_id: str, bundle) -> dict:
    """Read a sealed attempt; unsealed, modified and post-hoc evidence all fail."""
    from .gate import validate_formal_manifest

    manifest = validate_formal_manifest(manifest)
    matches = [cell for cell in manifest["cells"]
               if cell.get("episode_id") == episode_id]
    if len(matches) != 1:
        raise ValueError("exact_registered_formal_cell_required")
    cell = validate_cell(matches[0])
    root = Path(run_dir)
    integrity = verify(root, expected_seal_hash=expected_seal_hash)
    if not integrity["ok"]:
        raise ValueError("formal_execution_seal_invalid")
    seal = strict_loads((root / "seal.json").read_bytes())
    allocation = strict_loads((root / FORMAL_ALLOCATION_PATH).read_bytes())
    evidence = strict_loads((root / FORMAL_EVIDENCE_PATH).read_bytes())
    inner = strict_loads((root / "artifacts/evidence-v6.json").read_bytes())
    events = [strict_loads(line) for line in
              (root / "events.jsonl").read_bytes().splitlines()]
    context = _registered_context(manifest, cell, bundle)
    validate_allocation(allocation, manifest=manifest, cell=cell,
                        bundle=bundle, context=context)
    _validate_evidence_components(
        evidence, manifest=manifest, cell=cell, allocation=allocation,
        inner_evidence=inner, bundle=bundle, events=events,
    )
    extension = _formal_seal_extension(evidence, allocation)
    metadata = seal.get("metadata")
    if (seal.get("episode_id") != episode_id
            or type(metadata) is not dict
            or metadata.get("protocol_version") != INNER_PROTOCOL
            or metadata.get("actor_protocol") != FORMAL_PROTOCOL
            or metadata.get("formal_ready") is not True
            or metadata.get("formal_extension") != extension
            or metadata.get("evidence_path") != "artifacts/evidence-v6.json"
            or metadata.get("config_sha256") != evidence["inner_config_sha256"]):
        raise ValueError("formal_execution_seal_binding_mismatch")
    _lifecycle(events, episode_id)
    return {
        "formal_evidence": evidence,
        "inner_evidence": inner,
        "allocation": allocation,
        "seal": seal,
    }


def validate_evidence(*, run_root: str | Path, expected_seal_hash: str,
                      manifest: dict, episode_id: str, bundle) -> dict:
    """Public evidence validation always starts from an anchored sealed run."""
    return validate_sealed_formal_run(
        run_root, expected_seal_hash=expected_seal_hash,
        manifest=manifest, episode_id=episode_id, bundle=bundle,
    )["formal_evidence"]


def _run_offline_formal_cell_core(*, manifest: dict, episode_id: str, bundle,
                                  adapter, driver, collector) -> dict:
    """Exercise the sealed controller core for offline qualification only.

    This function intentionally accepts injected runtime objects so tests can
    use a zero-network transport.  It is private and cannot produce an
    admissible production sample: the public runner and manifest gate remain
    closed until an outer controller owns and seals each cell's proxy start,
    readiness, stop, and secret-root cleanup lifecycle.
    """
    from .gate import validate_formal_manifest

    manifest = validate_formal_manifest(manifest)
    matches = [cell for cell in manifest["cells"]
               if cell.get("episode_id") == episode_id]
    if len(matches) != 1:
        raise ValueError("exact_registered_formal_cell_required")
    cell = validate_cell(matches[0])
    context = _registered_context(manifest, cell, bundle)
    context["bundle"] = bundle
    registered_route = _registered_route(manifest)
    allocation = None
    try:
        runtime_claim = _claim_one_shot_runtime_objects(
            manifest=manifest, cell=cell, adapter=adapter,
            driver=driver, collector=collector,
            registered_route=registered_route,
        )
        allocation = _make_allocation(
            manifest=manifest, cell=cell, bundle=bundle,
            context=context, collector=collector,
            runtime_claim=runtime_claim,
        )
        cfg = inner_config(cell, bundle.sha256)

        def pre_seal_hook(*, evidence, collector, config):
            if config != cfg:
                raise ValueError("formal_inner_config_changed_before_seal")
            formal = wrap_evidence(
                evidence, manifest=manifest, cell=cell,
                allocation=allocation, context=context,
            )
            _write_new(collector.run_dir / FORMAL_EVIDENCE_PATH,
                       canonical(formal) + b"\n")
            collector.emit("formal_evidence_admitted", {
                "formal_manifest_sha256": manifest["manifest_sha256"],
                "episode_id": cell["episode_id"],
                "allocation_sha256": allocation["allocation_sha256"],
                "formal_evidence_sha256": formal["formal_evidence_sha256"],
                "inner_evidence_sha256": formal["inner_evidence_sha256"],
            }, evidence_quality="formal_controller_pre_seal_admission")
            return _formal_seal_extension(formal, allocation)

        capture = run_inner_episode(
            cfg, bundle, adapter, driver, collector,
            qid_pre_run_registration=None,
            actor_protocol=FORMAL_PROTOCOL,
            pre_seal_hook=pre_seal_hook,
        )
        admitted = validate_sealed_formal_run(
            collector.run_dir,
            expected_seal_hash=capture["seal"]["seal_hash"],
            manifest=manifest,
            episode_id=episode_id,
            bundle=bundle,
        )
        return {**capture, **admitted}
    except Exception as exc:
        _seal_failed_attempt(
            collector, manifest=manifest, cell=cell,
            allocation=allocation, exc=exc,
        )
        raise
