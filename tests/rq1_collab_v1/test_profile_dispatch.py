"""Profile routing and effective A1 dispatch regressions; engineering fixtures."""
import copy
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1.policy import (
    BASE_SERVICES, HOST_SERVICES, PolicyError, TaskPolicy, WORKSPACE_TOOLS,
    canonical_hash, canonical_task_identity, compile_task_policy,
    compile_user_task8_policy, make_task_policy, normalize_task_id,
)
from agentmembrane.host_v2.rq1_collab_v1.runtime import (
    RuntimeConfigurationError, _native_identity, _native_scope_min_levels, run_episode,
)
from agentmembrane.host_v2.rq1_collab_v1.services import SystemServices
from tests.rq1_collab_v1.test_runtime import Collector, PROMPT, Scripted, final, tool


class DispatchFactoryTests(unittest.TestCase):
    def test_explicit_canonical_id_and_legacy_aliases(self):
        self.assertEqual(normalize_task_id("workspace", "UserTask8"), "user_task_8")
        self.assertEqual(canonical_task_identity("travel", "travel/UserTask2"), "travel/user_task_2")
        self.assertEqual(canonical_task_identity("workspace", "workspace/user_task_24"), "workspace/user_task_24")
        for suite, task in (("workspace", "travel/user_task_0"), ("travel", "UserTask20"),
                            ("workspace", "user_task_25"), (None, "user_task_8"),
                            ("workspace", "UserTask08"), ("travel", "../../user_task_0")):
            with self.subTest(suite=suite, task=task), self.assertRaises(PolicyError):
                normalize_task_id(suite, task)

    def test_legacy_api_and_new_canonical_eight_both_work(self):
        legacy = compile_user_task8_policy(PROMPT)
        canonical = compile_task_policy("workspace", "user_task_8", PROMPT)
        self.assertEqual(legacy["task"], "workspace/UserTask8")
        self.assertEqual(canonical["task"], "workspace/user_task_8")
        self.assertEqual(canonical["facts_from_actor_prompt"], legacy["facts_from_actor_prompt"])
        for manifest in (legacy, canonical):
            selected = make_task_policy("workspace", "user_task_8", PROMPT, manifest, sorted(WORKSPACE_TOOLS))
            self.assertIsInstance(selected, TaskPolicy)
            self.assertEqual(selected.manifest, manifest)

    def test_lazy_dispatch_selects_explicit_suite_module(self):
        observations = []

        def module_for(suite, class_name, compiler_name):
            module = types.ModuleType("engineering_profile_fixture_" + suite)

            def compiler(task_id, prompt):
                observations.append((suite, "compile", task_id, prompt))
                return {"schema_version": "rq1-task-policy/1", "task": suite + "/" + task_id,
                        "prompt_sha256": canonical_hash(prompt)}

            class Selected:
                def __init__(self, prompt, manifest, available_tools):
                    self.source = suite
                    self.manifest = manifest

            setattr(module, compiler_name, compiler)
            setattr(module, class_name, Selected)
            return module

        modules = {
            "agentmembrane.host_v2.rq1_collab_v1.profiles_workspace": module_for("workspace", "WorkspacePolicy", "compile_workspace_policy"),
            "agentmembrane.host_v2.rq1_collab_v1.profiles_travel": module_for("travel", "TravelPolicy", "compile_travel_policy"),
        }
        with patch.dict(sys.modules, modules):
            for suite, task in (("workspace", "user_task_24"), ("workspace", "user_task_26"),
                                ("workspace", "user_task_35"), ("travel", "user_task_0"), ("travel", "user_task_2")):
                manifest = compile_task_policy(suite, task, "engineering prompt")
                selected = make_task_policy(suite, task, "engineering prompt", manifest, [])
                self.assertEqual(selected.source, suite)
                changed = {**manifest, "task": "workspace/user_task_8"}
                with self.assertRaises(PolicyError):
                    make_task_policy(suite, task, "engineering prompt", changed, [])
        self.assertEqual({entry[0] for entry in observations}, {"workspace", "travel"})

    def record(self):
        return {"source": "agentdojo", "suite": "travel", "task_id": "user_task_0",
                "class_name": "UserTask0", "class_module": "agentdojo.default_suites.v1.travel.user_tasks",
                "class_source_sha256": "a" * 64, "source_file_sha256": "b" * 64,
                "prompt_sha256": canonical_hash("original public prompt")}

    def test_native_identity_bound_to_class_prompt_and_actual_suite(self):
        record = self.record()
        self.assertEqual(_native_identity(record, "original public prompt", {}),
                         ("travel", "user_task_0", "travel/user_task_0"))
        mutations = [({"class_name": "UserTask2"}, "original public prompt", {}),
                     ({"class_module": "agentdojo.default_suites.v1.workspace.user_tasks"}, "original public prompt", {}),
                     ({"source": "pretend"}, "original public prompt", {}),
                     ({}, "changed prompt", {}), ({}, "original public prompt", {"suite": "workspace"}),
                     ({}, "original public prompt", {"task_id": "user_task_2"}),
                     ({"original_id": "user_task_2"}, "original public prompt", {})]
        for changed, prompt, config in mutations:
            with self.subTest(changed=changed, config=config), self.assertRaises(RuntimeConfigurationError):
                _native_identity({**record, **changed}, prompt, config)

    def test_missing_suite_has_no_workspace_default(self):
        record = self.record()
        del record["suite"]
        with self.assertRaises(RuntimeConfigurationError):
            _native_identity(record, "original public prompt", {})


class A1PolicyFixture:
    """Pure interface fixture, not a replacement for the actual travel profile."""
    manifest = {"policy_hash": "engineering-a1-policy", "task": "travel/user_task_0"}
    public_tool = "get_rating_reviews_for_hotels"
    private_tool = "get_user_information"

    def native_tools(self, level):
        if level == "A0":
            return []
        if level == "A1":
            return [self.public_tool]
        return [self.public_tool, self.private_tool]

    def scopes(self, level, actor):
        scopes = set(BASE_SERVICES) | {"tool:" + name for name in self.native_tools(level)}
        if actor == "H":
            scopes |= set(HOST_SERVICES)
        return sorted(scopes)

    def labels(self, level, snapshot):
        return ["public", "protected:travel"] if level == "A4" else ["public"]

    def result_labels(self, tool, result, snapshot):
        return ["public"] if tool == self.public_tool else ["protected:travel"]

    def authorize(self, level, arm, tool, arguments, snapshot):
        return tool in self.native_tools(level), "fixture_scope"

    def project_result(self, level, arm, tool, result, snapshot):
        return copy.deepcopy(result), self.result_labels(tool, result, snapshot)


class A1NativeFixture:
    prompt = "engineering-public-read-only"
    record = {"suite": "travel", "task_id": "user_task_0", "fixture": True}
    tool_specs = [{"name": name, "description": "engineering fixture", "parameters": {}}
                  for name in (A1PolicyFixture.public_tool, A1PolicyFixture.private_tool)]

    def __init__(self, known_error=False):
        self.state = {"engineering_calls": 0}
        self.calls = []
        self.known_error = known_error

    def snapshot(self):
        return copy.deepcopy(self.state)

    def call(self, name, arguments):
        before = self.snapshot()
        self.calls.append(name)
        self.state["engineering_calls"] += 1
        return {"before": before, "after": self.snapshot(), "result": {"engineering_rating": 4.2},
                "error": "engineering-known-error" if self.known_error else None,
                "effects": [{"kind": "engineering_counter", "before": before, "after": self.snapshot()}],
                "evidence_quality": {"commit_status": "confirmed", "backend_entered": True}}


class EffectiveA1DispatchTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="rq1-six-profile-runtime-")
        self.addCleanup(self.directory.cleanup)
        self.services = SystemServices(str(Path(self.directory.name) / "services.sqlite3"), "six-runtime-engineering")
        self.addCleanup(self.services.disconnect)

    def config(self, level="A1"):
        return {"episode_id": "six-runtime-engineering", "arm": "PLAIN", "level": level,
                "seed": 20260907, "budget": {"host_decisions": 2, "external_decisions": 2, "max_delegations": 2},
                "model_profile": {"kind": "engineering"}, "protocol_hash": "engineering-only",
                "task_policy": A1PolicyFixture.manifest, "execution_mode": "engineering_offline_native_only"}

    def test_actual_earliest_public_scope_is_a1_not_a3(self):
        floors = _native_scope_min_levels(A1PolicyFixture(), [A1PolicyFixture.public_tool, A1PolicyFixture.private_tool])
        self.assertEqual(floors["tool:" + A1PolicyFixture.public_tool], "A1")
        self.assertEqual(floors["tool:" + A1PolicyFixture.private_tool], "A3")

    def test_a1_lease_reaches_registered_public_native_call(self):
        native = A1NativeFixture()
        driver = Scripted([final()], [tool(A1PolicyFixture.public_tool, hotel_names=["engineering-hotel"]), final()])
        with patch("agentmembrane.host_v2.rq1_collab_v1.runtime.make_task_policy", return_value=A1PolicyFixture()):
            result = run_episode(self.config(), native, driver, self.services, Collector())
        self.assertEqual(result["termination"], "host_final", result.get("unknown_reasons"))
        self.assertEqual(result["task"]["task_id"], "travel/user_task_0")
        self.assertEqual(native.calls, [A1PolicyFixture.public_tool])
        self.assertEqual(result["native_calls"][0]["status"], "committed")
        self.assertEqual(result["native_calls"][0]["actor"], "E")
        self.assertEqual(result["behavioral_n"], 0)

    def test_travel_error_receipt_never_uses_workspace_label(self):
        native = A1NativeFixture(known_error=True)
        collector = Collector()
        driver = Scripted([final()], [tool(A1PolicyFixture.public_tool, hotel_names=[]), final()])
        with patch("agentmembrane.host_v2.rq1_collab_v1.runtime.make_task_policy", return_value=A1PolicyFixture()):
            result = run_episode(self.config(), native, driver, self.services, collector)
        self.assertEqual(result["termination"], "host_final", result.get("unknown_reasons"))
        receipt_events = [event for event in collector.events if event["kind"] == "trusted_receipt_recorded"]
        self.assertEqual(receipt_events[0]["data"]["receipt"]["labels"], ["protected:travel"])
        self.assertEqual(receipt_events[0]["data"]["receipt"]["task_id"], "travel/user_task_0")

    def test_non_nested_profile_rejected(self):
        profile = A1PolicyFixture()
        profile.native_tools = lambda level: [profile.public_tool] if level == "A1" else []
        with self.assertRaises(RuntimeConfigurationError):
            _native_scope_min_levels(profile, [profile.public_tool])

    def test_generalization_does_not_enable_live_mode(self):
        config = self.config()
        config["execution_mode"] = "live"
        with self.assertRaises(RuntimeConfigurationError):
            run_episode(config, A1NativeFixture(), Scripted([], []), self.services, Collector())


if __name__ == "__main__":
    unittest.main()
