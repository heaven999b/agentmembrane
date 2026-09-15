"""Source-bound development admission for the versioned RQ1 experiment.

Discovery, a balanced histogram, and passing reference answers are not admission.
This route accepts source-locked AgentDojo user tasks for development apparatus
checks. It deliberately cannot manufacture a confirmatory sample or private gold.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
from pathlib import Path
import re

from .audit import canonical, file_hash, strict_loads
from .policy import compile_task_policy
from .six_sample import identity_matches, verify_upstream

PROTOCOL = "rq1-multifactor/2"
_IDENTITY_KEYS = ("suite", "task_id", "benchmark_version", "prompt_sha256",
                  "class_source_sha256", "source_file_sha256",
                  "initial_state_sha256", "tool_schema_sha256")
_HASH_KEYS = tuple(k for k in _IDENTITY_KEYS if k.endswith("sha256"))
_MISSING_FAMILIES = ("rM", "rK", "rC")
_PUBLIC_INVENTORY_ROOT = Path(__file__).resolve().parents[3] / "data/host_boundary_v2/full_inventory"
_PUBLIC_INVENTORY_MANIFEST_SHA256 = "a906ae44c9084b24c052206b7bbb6ae341dbd912987f820a1a26e696c4f578f1"
_PUBLIC_AGENTDOJO_TASKS_SHA256 = "d764c88496cb1eb5dd5ab9ce1ac1b70959540154fcc623e99ff44e81e7fa097b"
_PUBLIC_AGENTDOJO_SUITES = frozenset({"banking", "slack", "travel", "workspace"})
_RUNTIME_INVENTORY = (Path(__file__).resolve().parents[3] / "experiments/host_boundary_v2/"
                      "rq1_collab_v1/live_readiness_20260907/implementations/"
                      "rq1_permission_v6_20260914/source_locked_runtime_inventory_v3_20260915/manifest.json")
_RUNTIME_INVENTORY_FILE_SHA256 = "5d6a4d05e630905702ab57f56a9616c64402de0177020afffb49cb0654ef0a6c"
_RUNTIME_IDENTITY_KEYS = _IDENTITY_KEYS + ("class_name", "class_module", "source_file", "source_line")
_REVIEWED_RUNTIME_OVERRIDES = frozenset({("workspace", "user_task_31"),
                                        ("workspace", "user_task_32")})


def _hash(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def locked_agentdojo_user_inventory():
    """Read candidate identities only, with both inventory files pinned.

    ``source_usable`` is source metadata, not adapter parity, pair eligibility,
    permission coverage, or an experimental admission decision.
    """
    manifest_path = _PUBLIC_INVENTORY_ROOT / "manifest.json"
    tasks_path = _PUBLIC_INVENTORY_ROOT / "agentdojo_user_tasks.jsonl"
    if file_hash(manifest_path) != _PUBLIC_INVENTORY_MANIFEST_SHA256:
        raise ValueError("public_inventory_manifest_changed")
    manifest = strict_loads(manifest_path.read_bytes())
    outputs = {item.get("path"): item.get("sha256") for item in manifest.get("outputs", [])}
    if (manifest.get("inventory_id") != "host-boundary-v2-full-public-inventory-v2"
            or outputs.get(tasks_path.name) != _PUBLIC_AGENTDOJO_TASKS_SHA256
            or file_hash(tasks_path) != _PUBLIC_AGENTDOJO_TASKS_SHA256):
        raise ValueError("public_agentdojo_inventory_changed")
    rows = {}
    for raw in tasks_path.read_bytes().splitlines():
        item = strict_loads(raw)
        suite, task_id = item.get("domain"), item.get("source_id")
        if (suite not in _PUBLIC_AGENTDOJO_SUITES
                or not isinstance(task_id, str)
                or re.fullmatch(r"user_task_(0|[1-9][0-9]*)", task_id) is None
                or item.get("benchmark") != "AgentDojo"
                or item.get("suite_version") != "v1"
                or item.get("source_usable") is not True
                or item.get("source_path") != f"src/agentdojo/default_suites/v1/{suite}/user_tasks.py"
                or not isinstance(item.get("source_file_sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", item["source_file_sha256"]) is None
                or (suite, task_id) in rows):
            raise ValueError("invalid_public_agentdojo_inventory_row")
        rows[(suite, task_id)] = item
    if not rows:
        raise ValueError("empty_public_agentdojo_inventory")
    return rows


def locked_agentdojo_runtime_inventory(*, source_root=None):
    """Return effective v1 user classes, including two v1_2 import overrides.

    Every entry was captured by a separate fresh ``ProcessNativeTask`` reset.
    This is source admission for *development*, not utility or pair eligibility.
    The caller still compares each fresh runtime identity before admission.
    """
    static = locked_agentdojo_user_inventory()
    if file_hash(_RUNTIME_INVENTORY) != _RUNTIME_INVENTORY_FILE_SHA256:
        raise ValueError("effective_runtime_inventory_file_changed")
    manifest = strict_loads(_RUNTIME_INVENTORY.read_bytes())
    unsigned = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    if (manifest.get("schema_version") != "rq1-agentdojo-effective-runtime-inventory/3"
            or manifest.get("benchmark_version") != "v1"
            or manifest.get("qualification") != "source_bound_development_candidate_only"
            or manifest.get("formal_ready") is not False
            or manifest.get("model_calls") != 0
            or manifest.get("manifest_sha256") != _hash(unsigned)
            or manifest.get("task_count") != len(static)
            or manifest.get("static_inventory") != {
                "manifest_sha256": _PUBLIC_INVENTORY_MANIFEST_SHA256,
                "agentdojo_user_tasks_sha256": _PUBLIC_AGENTDOJO_TASKS_SHA256,
            }):
        raise ValueError("effective_runtime_inventory_identity_mismatch")
    origin = manifest.get("qualified_source")
    if (type(origin) is not dict or set(origin) != {"path", "sha256"}
            or file_hash(origin["path"]) != origin["sha256"]):
        raise ValueError("effective_runtime_inventory_qualification_changed")
    root = Path(manifest["source_root"]).resolve()
    if source_root is not None and Path(source_root).resolve() != root:
        raise ValueError("effective_runtime_inventory_source_root_changed")
    files = manifest.get("loader_and_effective_task_files")
    if (not isinstance(files, dict)
            or not {"src/agentdojo/task_suite/load_suites.py",
                    "src/agentdojo/task_suite/task_suite.py",
                    "src/agentdojo/default_suites/v1/workspace/user_tasks.py",
                    "src/agentdojo/default_suites/v1_2/workspace/user_tasks.py",
                    "src/agentdojo/default_suites/v1_2/__init__.py"} <= set(files)):
        raise ValueError("effective_loader_source_lock_missing")
    for relative, expected in files.items():
        path = (root / relative).resolve()
        if (type(relative) is not str or Path(relative).is_absolute()
                or not path.is_relative_to(root) or file_hash(path) != expected):
            raise ValueError("effective_loader_or_task_source_changed")
    loader = (root / "src/agentdojo/task_suite/load_suites.py").read_text()
    v12_module = (root / "src/agentdojo/default_suites/v1_2/__init__.py").read_text()
    v12_tasks = (root / "src/agentdojo/default_suites/v1_2/workspace/user_tasks.py").read_text()
    if (loader.find("import agentdojo.default_suites.v1_1") < 0
            or loader.find("import agentdojo.default_suites.v1_2") <
            loader.find("import agentdojo.default_suites.v1_1")
            or "import agentdojo.default_suites.v1_2.workspace.user_tasks" not in v12_module
            or "from agentdojo.default_suites.v1.workspace.user_tasks import" not in v12_tasks
            or "@task_suite.register_user_task\nclass UserTask31" not in v12_tasks
            or "@task_suite.register_user_task\nclass UserTask32" not in v12_tasks):
        raise ValueError("effective_loader_import_order_or_override_changed")
    records, overrides = {}, set()
    for record in manifest.get("tasks", []):
        if type(record) is not dict or set(record) != set(_RUNTIME_IDENTITY_KEYS):
            raise ValueError("invalid_effective_runtime_task_identity")
        identity = record["suite"], record["task_id"]
        if identity not in static or identity in records:
            raise ValueError("effective_runtime_task_absent_or_duplicate")
        relative = record["source_file"]
        if (record["benchmark_version"] != "v1"
                or record["class_name"] != "UserTask" + record["task_id"].removeprefix("user_task_")
                or record["source_file_sha256"] != files.get(relative)
                or any(type(record[key]) is not str or re.fullmatch(r"[0-9a-f]{64}", record[key]) is None
                       for key in _HASH_KEYS)):
            raise ValueError("effective_runtime_task_source_unbound")
        if (relative != static[identity]["source_path"]
                or record["source_file_sha256"] != static[identity]["source_file_sha256"]):
            overrides.add(identity)
            if (identity not in _REVIEWED_RUNTIME_OVERRIDES
                    or relative != "src/agentdojo/default_suites/v1_2/workspace/user_tasks.py"
                    or record["class_module"] != "agentdojo.default_suites.v1_2.workspace.user_tasks"):
                raise ValueError("unreviewed_effective_runtime_override")
        records[identity] = record
    if set(records) != set(static) or overrides != _REVIEWED_RUNTIME_OVERRIDES:
        raise ValueError("effective_runtime_task_coverage_changed")
    return records


@dataclass(frozen=True)
class TaskBundle:
    """Immutable serialized controller bundle; actor input is an allowlist."""
    payload: bytes
    sha256: str

    def record(self):
        if hashlib.sha256(self.payload).hexdigest() != self.sha256:
            raise ValueError("task_bundle_hash_mismatch")
        result = strict_loads(self.payload)
        if result.get("schema_version") != "rq1-task-bundle/2":
            raise ValueError("wrong_task_bundle_version")
        return result

    def actor_input(self, actor, regime="honest"):
        if actor not in {"H", "E"} or regime not in {"honest", "malicious", "reference"}:
            raise ValueError("invalid_actor_or_regime")
        item = self.record()
        result = {"user_request": item["public"]["user_request"]}
        if actor == "E" and regime == "malicious":
            result["public_goal"] = item["public"]["goal"]["goal"]
        # No whole initial world, source paths, grader, reference calls, private
        # annotations, or broad native tool schema is put into the observation.
        # Runtime applies its actual granted-tool projection independently.
        return result


def admit_task(record, expected_record, *, source_root, upstream_hashes,
               prompt, tool_specs, public_goal, initial_goal_assessment=None, mode="development"):
    """Verify freshly loaded public identity, then admit for development only.

    ``record`` must originate in the trusted native adapter, not model JSON.
    The controller verifies the expected manifest before invoking this function.
    No outcome is an inclusion predicate, and no reference answer is read here.
    """
    if mode != "development":
        raise ValueError("confirmatory_admission_requires_new_public_data_and_independent_review")
    if not isinstance(record, dict) or not isinstance(expected_record, dict):
        raise ValueError("source_identity_required")
    identity = (record.get("suite"), record.get("task_id"))
    if (identity[0] not in _PUBLIC_AGENTDOJO_SUITES
            or not isinstance(identity[1], str)
            or re.fullmatch(r"user_task_(0|[1-9][0-9]*)", identity[1]) is None
            or record.get("benchmark_version") != "v1"
            or record.get("source") != "agentdojo"):
        raise ValueError("unimplemented_public_task_adapter")
    if not identity_matches(record, expected_record):
        raise ValueError("loaded_source_identity_mismatch")
    for key in _HASH_KEYS:
        if not isinstance(record.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", record[key]):
            raise ValueError("source_hash_missing:" + key)
    if not isinstance(prompt, str) or not prompt or _hash(prompt) != record["prompt_sha256"]:
        raise ValueError("public_request_hash_mismatch")
    if not isinstance(tool_specs, list) or _hash(tool_specs) != record["tool_schema_sha256"]:
        raise ValueError("tool_schema_hash_mismatch")
    root = Path(source_root).resolve()
    verify_upstream(str(root), upstream_hashes)
    relative = record.get("source_file")
    if not isinstance(relative, str) or Path(relative).is_absolute():
        raise ValueError("public_source_path_invalid")
    source = (root / relative).resolve()
    if not source.is_relative_to(root) or file_hash(source) != record["source_file_sha256"]:
        raise ValueError("public_source_file_mismatch")
    if upstream_hashes.get(relative) != record["source_file_sha256"]:
        raise ValueError("source_file_absent_from_reviewed_lock")
    if (not isinstance(public_goal, dict) or public_goal.get("schema_version") != "rq1-public-native-goal/1"
            or public_goal.get("source") != "agentdojo" or public_goal.get("suite") != identity[0]
            or public_goal.get("benchmark_version") != record["benchmark_version"]
            or not isinstance(public_goal.get("goal"), str) or not public_goal["goal"]
            or public_goal.get("goal_sha256") != _hash(public_goal["goal"])
            or not re.fullmatch(r"injection_task_[0-9]+", str(public_goal.get("goal_id", "")))):
        raise ValueError("public_goal_identity_mismatch")
    # Independently reload GOAL and effective checker provenance. A caller's
    # hash-shaped string is not evidence that an original public goal exists.
    from .native_goals import public_native_goal_record
    actual_goal = public_native_goal_record(str(root), identity[0], public_goal["goal_id"], record["benchmark_version"])
    if actual_goal != public_goal:
        raise ValueError("public_goal_source_mismatch")
    initial_goal = {"status": "not_checked", "initial_goal_value": None,
                    "behavioral_pair_admitted": False,
                    "authorization_conflict_review": "requires_independent_original_request_review"}
    if initial_goal_assessment is not None:
        assessment = strict_loads(canonical(initial_goal_assessment))
        if (not isinstance(assessment, dict)
                or assessment.get("initial_snapshot_sha256") != record["initial_state_sha256"]
                or assessment.get("public_goal_sha256") != _hash(actual_goal)):
            raise ValueError("initial_goal_assessment_binding_mismatch")
        detail = assessment.get("result")
        if (not isinstance(detail, dict) or detail.get("source_bound") is not True
                or detail.get("goal_record") != actual_goal):
            raise ValueError("initial_goal_checker_source_unverified")
        initial_value = detail.get("initial_goal_value")
        # Original NativeTask goal predicates serialize known bools as 0/1.
        # Keep the original result intact and normalize only this typed truth.
        if type(initial_value) is int and initial_value in (0, 1):
            initial_value = bool(initial_value)
        if initial_value is not None and type(initial_value) is not bool:
            raise ValueError("invalid_initial_goal_truth")
        initial_goal.update(status="initially_true_ineligible" if initial_value is True else
                            "initially_false_only_not_full_pair_admission" if initial_value is False else "unknown",
                            initial_goal_value=initial_value, source_assessment=assessment)
    policy = compile_task_policy(identity[0], identity[1], prompt)
    value = {"schema_version": "rq1-task-bundle/2", "protocol_version": PROTOCOL,
             "task_id": "agentdojo:" + identity[0] + ":" + identity[1],
             "original_id": identity[1], "suite": identity[0], "source": "agentdojo",
             "world_id": "agentdojo:" + identity[0] + ":" + record["initial_state_sha256"],
             "source_record": {k: record[k] for k in _IDENTITY_KEYS},
             "upstream_hashes_sha256": _hash(upstream_hashes),
             "public": {"user_request": prompt, "goal": actual_goal},
             "task_policy": policy, "task_policy_sha256": _hash(policy),
             "goal_admission": initial_goal,
             "admission": {"status": "development_only", "exposure": "previously_exposed",
                           "formal_ready": False, "confirmatory_n": 0,
                           "outcome_filter": False, "synthetic_research_sample": False},
             "risk_coverage": {"unsupported_public_carriers": list(_MISSING_FAMILIES),
                               "other_families": "requires_episode_evidence_not_predeclared_safe"}}
    raw = canonical(value)
    return TaskBundle(raw, hashlib.sha256(raw).hexdigest())


def load_development_bundles(qualified_manifest, goal_assignments, *, native_python=None):
    """Fresh public worlds and source identities; no model/credentials or gold."""
    from .process_backend import ProcessNativeTask
    manifest = strict_loads(Path(qualified_manifest).read_bytes())
    assignments = list(goal_assignments)
    identities = [(x["suite"], x["task_id"]) for x in assignments]
    if not identities or len(set(identities)) != len(identities):
        raise ValueError("duplicate_or_missing_task_assignments")
    inventory = locked_agentdojo_runtime_inventory(source_root=manifest["source_root"])
    if any(identity not in inventory for identity in identities):
        raise ValueError("task_absent_from_locked_public_inventory")
    source_root = manifest["source_root"]
    locked = manifest["qualified_upstream_hashes"]
    verify_upstream(source_root, locked)
    for identity in identities:
        candidate = inventory[identity]
        if locked.get(candidate["source_file"]) != candidate["source_file_sha256"]:
            raise ValueError("qualified_source_differs_from_public_inventory")
    python = native_python or manifest["native_python"]
    bundles = []
    for assignment in assignments:
        suite, task_id = assignment["suite"], assignment["task_id"]
        candidates = [r for r in manifest["selection"] if r["suite"] == suite and r["task_id"] == task_id]
        if len(candidates) != 1:
            raise ValueError("duplicate_or_missing_source_record")
        if (candidates[0].get("source_file") != inventory[(suite, task_id)]["source_file"]
                or candidates[0].get("source_file_sha256") != inventory[(suite, task_id)]["source_file_sha256"]):
            raise ValueError("qualified_task_differs_from_public_inventory")
        task = ProcessNativeTask(python, source_root, suite, task_id, timeout=30)
        try:
            snapshot = task.snapshot()
            if _hash(snapshot) != task.record["initial_state_sha256"]:
                raise ValueError("fresh_world_hash_mismatch")
            if any(task.record.get(key) != inventory[(suite, task_id)][key]
                   for key in _RUNTIME_IDENTITY_KEYS):
                raise ValueError("fresh_task_differs_from_effective_runtime_inventory")
            goal = task.native_goal_record(assignment["goal_id"])
            initial_goal = task.native_attack_score_detail(assignment["goal_id"], snapshot, snapshot, "", function_calls=[])
            bundles.append(admit_task(task.record, candidates[0], source_root=source_root,
                upstream_hashes=locked, prompt=task.prompt, tool_specs=task.tool_specs, public_goal=goal,
                initial_goal_assessment={"initial_snapshot_sha256": _hash(snapshot),
                    "public_goal_sha256": _hash(goal), "result": initial_goal}))
        finally:
            task.shutdown()
    verify_upstream(source_root, locked)
    return bundles


def admission_summary(bundles):
    records = [b.record() for b in bundles]
    identities = [r["task_id"] for r in records]
    if len(set(identities)) != len(identities):
        raise ValueError("duplicate_task_bundle")
    return {"schema_version": "rq1-admission-summary/2", "public_original_tasks": len(records),
            "worlds": len({r["world_id"] for r in records}),
            "suite_counts": dict(Counter(r["suite"] for r in records)),
            "task_ids": identities, "confirmatory_tasks": 0, "formal_ready": False,
            "missing_public_risk_carriers": list(_MISSING_FAMILIES),
            "outcome_based_exclusions": 0, "model_calls": 0,
            "limitation": "Source-locked public development apparatus panel; each task and attack pair still requires separate policy, checker, and parity qualification"}
