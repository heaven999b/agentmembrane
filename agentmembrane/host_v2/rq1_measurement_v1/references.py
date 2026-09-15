"""Private source-bound references. Never provide this module's output to actors."""
from __future__ import annotations

import copy
import json
from pathlib import Path

from ..rq1_collab_v1.native import digest, file_digest
from ..rq1_collab_v1.pilot_checkers import _business, independent_profile_rule
from ..rq1_collab_v1.profiles_travel import compile_travel_policy
from ..rq1_scorecard_v4.native_adapter import _rule

POLICY_DIR = Path(__file__).with_name("policy_data")
DEFAULT_SOURCE_ROOT = Path(__file__).resolve().parents[3] / "data/host_boundary_v2/upstream/agentdojo"
SOURCE_FIELDS = ("source", "suite", "task_id", "benchmark_version", "class_name", "class_module",
                 "source_file", "source_file_sha256", "class_source_sha256", "prompt_sha256",
                 "initial_state_sha256", "tool_schema_sha256")


def load_policy():
    return json.loads((POLICY_DIR / "information-travel-policy.json").read_text(encoding="utf-8"))


def source_catalog():
    """The six previously reviewed, source-specific measurement policies."""
    return json.loads((POLICY_DIR / "source-catalog.json").read_text(encoding="utf-8"))


def registration_catalog():
    """Reviewed policies plus source-only candidate bindings for preflight."""
    reviewed = source_catalog()
    candidates = json.loads((POLICY_DIR / "source-catalog-candidate-v1.json").read_text(encoding="utf-8"))
    # The six individually reviewed measurement contracts retain their exact
    # source and goal bindings. The additional rows authorize only a source
    # identity registration; they do not invent Q/I/D measurements.
    return {**candidates, **reviewed}


def canonical_bundle(data):
    """Project only pre-outcome inputs; condition/config/terminal are never read."""
    record, task = data["native_record"], data["task"]
    key = task["suite"] + "/" + task["task_id"]
    catalog = registration_catalog()
    if key not in catalog:
        raise ValueError("unregistered_original_task")
    public = data.get("bundle_public", data.get("public"))
    if public is None and type(data.get("bundle")) is dict:
        public = data["bundle"].get("public")
    if public is None:
        # Fixed archived ORIGINAL public goal, not a condition/observed attack.
        public = catalog[key]["public"]
    if public != catalog[key]["public"] or task.get("prompt") != public.get("user_request"):
        raise ValueError("original_public_request_or_goal_binding_mismatch")
    return {"suite": task["suite"], "original_id": task["task_id"],
            "source_record": copy.deepcopy(record), "public": copy.deepcopy(public)}


def build_reference(bundle_record, initial_snapshot):
    """Validate source bytes, original request and full initialized state pins."""
    if type(bundle_record) is not dict or type(initial_snapshot) is not dict:
        raise ValueError("source_bundle_and_snapshot_required")
    suite, task_id = bundle_record.get("suite"), bundle_record.get("original_id")
    key = str(suite) + "/" + str(task_id)
    catalog, policy = registration_catalog(), load_policy()
    expected = catalog.get(key)
    if expected is None:
        raise ValueError("unregistered_original_task")
    record = bundle_record.get("source_record")
    if type(record) is not dict or any(record.get(k) != value for k, value in expected["source_record"].items()):
        raise ValueError("source_identity_lock_mismatch")
    # Admission bundles intentionally retain only a compact source lock. Fill
    # deterministic metadata from the fixed suite/task, never from a response.
    derived = {"source": "agentdojo", **expected.get("source_class", {
        "class_name": "UserTask" + task_id.rsplit("_", 1)[1],
        "class_module": "agentdojo.default_suites.v1." + suite + ".user_tasks",
        "source_file": "src/agentdojo/default_suites/v1/" + suite + "/user_tasks.py"})}
    if any(k in record and record[k] != v for k, v in derived.items()):
        raise ValueError("source_identity_lock_mismatch")
    record = {**record, **derived}
    if bundle_record.get("public") != expected["public"]:
        raise ValueError("original_public_request_or_goal_binding_mismatch")
    if (digest(initial_snapshot) != record["initial_state_sha256"]
            or (key in policy["actual_counts"] and digest(initial_snapshot) != policy["source_snapshots"][suite])):
        raise ValueError("original_snapshot_lock_mismatch")
    prompt = bundle_record["public"]["user_request"]
    if digest(prompt) != record["prompt_sha256"]:
        raise ValueError("original_prompt_lock_mismatch")
    root = Path(record.get("source_root", DEFAULT_SOURCE_ROOT))
    path = root / record["source_file"]
    if not root.is_absolute() or not path.is_file() or file_digest(path) != record["source_file_sha256"]:
        raise ValueError("current_original_source_bytes_not_verified")
    goal = bundle_record["public"]["goal"]
    goal_path = root / goal["source_file"]
    if (not goal_path.is_file() or file_digest(goal_path) != goal["source_file_sha256"]
            or digest(goal["goal"]) != goal["goal_sha256"]):
        raise ValueError("original_public_goal_source_not_verified")
    minimal = {"native_record": record, "task": {"suite": suite, "task_id": task_id, "prompt": prompt},
               "initial_snapshot": initial_snapshot}
    reviewed = key in policy["actual_counts"]
    if reviewed:
        rule = _rule(minimal) if suite == "workspace" else independent_profile_rule(record, prompt)
        if rule is None:
            raise ValueError("original_request_rule_not_supported")
    else:
        rule = {"profile": key, "source": "identity_only_no_reviewed_quality_or_purpose_rule",
                "prompt_hash": record["prompt_sha256"]}
    ref = {"schema_version": "rq1-source-reference/1", "task_key": key, "suite": suite,
           "task_id": task_id, "prompt": prompt, "rule": rule,
           "source_binding": {k: record[k] for k in SOURCE_FIELDS},
           "original_goal_sha256": goal["goal_sha256"], "initial": _business(initial_snapshot),
           "measurement_adapter": "reviewed_six_v1" if reviewed else "source_identity_only_v1"}
    if reviewed and suite == "travel":
        facts = compile_travel_policy(task_id, prompt)["facts_from_actor_prompt"]
        ref["request_facts"] = facts
        if task_id == "user_task_0":
            candidates = [h for h in ref["initial"]["hotels"]["hotel_list"]
                          if h["name"] == facts["hotel_name"] and h["city"] == facts["city"]]
            if len(candidates) != 1:
                raise ValueError("source_hotel_city_name_not_unique")
            ref["hotel"] = copy.deepcopy(candidates[0])
    ref["reference_sha256"] = digest(ref)
    return ref
