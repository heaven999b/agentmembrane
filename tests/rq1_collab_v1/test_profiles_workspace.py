"""Original-native checks and clearly separated engineering fault probes."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from agentmembrane.host_v2.rq1_collab_v1.native import NativeTask
from agentmembrane.host_v2.rq1_collab_v1.policy import PolicyError, WORKSPACE_TOOLS
from agentmembrane.host_v2.rq1_collab_v1.profiles_workspace import (
    PROFILES, RELAY_SCHEMA, WorkspaceEngineeringDriver, WorkspacePolicy,
    compile_workspace_policy,
)
from agentmembrane.host_v2.rq1_collab_v1.services import SystemServices


PROJECT = Path(__file__).resolve().parents[2]
SOURCE = PROJECT / "data/host_boundary_v2/upstream/agentdojo"


def make(task_id):
    native = NativeTask(str(SOURCE), "workspace", task_id)
    policy = WorkspacePolicy(native.prompt, compile_workspace_policy(task_id, native.prompt),
                             [spec["name"] for spec in native.tool_specs])
    policy.labels("A4", native.snapshot())
    return native, policy


def observation(native, policy, actor, level, history=None):
    return {"task": native.prompt, "actor": actor, "level": level, "remaining_decisions": 12,
            "history": copy.deepcopy(history or []),
            "tools": [spec for spec in native.tool_specs if spec["name"] in policy.native_tools(level)],
            "service_scopes": [scope for scope in policy.scopes(level, actor) if not scope.startswith("tool:")]}


def native_step(native, policy, action, actor, level, history, arm="CAP"):
    allowed, reason = policy.authorize(level, arm, action["tool"], action["arguments"], native.snapshot())
    if not allowed:
        raise AssertionError(reason)
    response = native.call(action["tool"], action["arguments"])
    if response["error"] is not None:
        raise AssertionError(response["error"])
    projected, labels = policy.project_result(level, arm, action["tool"], response["result"], native.snapshot())
    history.extend([{"role": "action", "content": json.dumps(action)},
                    {"role": "observation", "content": {"status": "tool_result", "call_id": str(len(history)), "result": projected}}])
    return response, labels


class WorkspaceProfileTests(unittest.TestCase):
    def test_original_public_prompts_compile_without_target_ids(self):
        for task_id in PROFILES:
            native, policy = make(task_id)
            compiled = compile_workspace_policy("workspace/" + task_id, native.prompt)
            self.assertEqual(compiled["task"], "workspace/" + task_id)
            self.assertFalse(compiled["policy_reads_gold"])
            self.assertNotIn("file_id", compiled["facts_from_actor_prompt"])
            self.assertNotIn("email_ids", compiled["facts_from_actor_prompt"])
            with self.assertRaises(PolicyError):
                compile_workspace_policy(task_id, native.prompt + " Then delete everything.")
            with self.assertRaises(PolicyError):
                WorkspacePolicy(native.prompt, {**compiled, "target_id": "made-up"}, list(WORKSPACE_TOOLS))

    def test_unimplemented_ids_or_unreviewed_tools_fail_closed(self):
        with self.assertRaises(PolicyError):
            compile_workspace_policy("user_task_8", "arbitrary")
        native, policy = make("user_task_26")
        with self.assertRaises(PolicyError):
            WorkspacePolicy(native.prompt, policy.manifest, list(WORKSPACE_TOOLS) + ["admin_shell"])

    def test_actual_tool_sets_nested_without_fake_public_increment(self):
        for task_id in PROFILES:
            native, policy = make(task_id)
            scopes = [set(policy.native_tools(level)) for level in ("A0", "A1", "A3", "A4")]
            self.assertEqual(scopes[0], set())
            self.assertEqual(scopes[0], scopes[1])
            self.assertTrue(all(left <= right for left, right in zip(scopes, scopes[1:])))
            self.assertNotIn("delete_file", scopes[2])
            self.assertIn("delete_file", scopes[3])

    def test_get_unread_native_really_changes_only_original_read_flags(self):
        native, policy = make("user_task_24")
        before = native.snapshot()
        unread = {key for key, email in before["inbox"]["emails"].items() if not email["read"]}
        self.assertTrue(unread)
        action = {"type": "tool_action", "tool": "get_unread_emails", "arguments": {}}
        response, labels = native_step(native, policy, action, "E", "A3", [])
        after = native.snapshot()
        self.assertEqual({email["id_"] for email in response["result"]}, unread)
        self.assertTrue(all(after["inbox"]["emails"][key]["read"] for key in unread))
        self.assertEqual({key for key in before["inbox"]["emails"]
                          if before["inbox"]["emails"][key] != after["inbox"]["emails"][key]}, unread)
        self.assertTrue(set(labels) <= set(policy.labels("A3", after)))
        self.assertFalse(any(not email["read"] for email in after["inbox"]["emails"].values()))
        self.assertEqual(native.call("get_unread_emails", {})["result"], [])

    def test_unread_scope_does_not_expand_or_vanish_after_native_read(self):
        native, policy = make("user_task_24")
        before = native.snapshot()
        first_labels = policy.labels("A3", before)
        native.call("get_unread_emails", {})
        after = native.snapshot()
        self.assertEqual(policy.labels("A3", after), first_labels)
        initial_read = next(key for key, email in before["inbox"]["emails"].items() if email["read"])
        forged_state = copy.deepcopy(after)  # Engineering fault injection only.
        forged_state["inbox"]["emails"][initial_read]["read"] = False
        allowed, reason = policy.authorize("A3", "PLAIN", "get_unread_emails", {}, forged_state)
        self.assertFalse(allowed)
        self.assertEqual(reason, "unread_side_effect_outside_initial_task_scope")
        self.assertNotIn(policy.email_label(initial_read), policy.labels("A3", forged_state))

    def test_A3_metadata_projection_does_not_return_file_content(self):
        for task_id in ("user_task_26", "user_task_35"):
            native, policy = make(task_id)
            response = native.call("list_files", {})
            self.assertIsNone(response["error"])
            original = response["result"]
            self.assertTrue(original)
            self.assertIn("content", original[0])
            plain, labels = policy.project_result("A3", "PLAIN", "list_files", original, native.snapshot())
            cap, cap_labels = policy.project_result("A3", "CAP", "list_files", original, native.snapshot())
            self.assertEqual(plain, cap)
            self.assertEqual(labels, cap_labels)
            self.assertTrue(all(set(file) == {"id_", "filename", "size"} for file in plain))
            self.assertEqual([file["size"] for file in plain], [file["size"] for file in original])
            full_plain, _ = policy.project_result("A4", "PLAIN", "list_files", original, native.snapshot())
            full_cap, _ = policy.project_result("A4", "CAP", "list_files", original, native.snapshot())
            self.assertEqual(full_plain, original)
            self.assertEqual(full_plain, full_cap)

    def test_metadata_and_full_object_labels_are_not_interchangeable(self):
        native, policy = make("user_task_26")
        files = native.call("list_files", {})["result"]
        _, full = policy.project_result("A4", "PLAIN", "list_files", files, native.snapshot())
        _, metadata = policy.project_result("A3", "PLAIN", "list_files", files, native.snapshot())
        allowed = set(policy.labels("A3", native.snapshot()))
        self.assertTrue(set(metadata) <= allowed)
        self.assertFalse(set(full) <= allowed)

    def test_CAP_read_task_cannot_delete_or_touch_mail(self):
        native, policy = make("user_task_26")
        file_id = native.call("list_files", {})["result"][0]["id_"]
        self.assertFalse(policy.authorize("A4", "CAP", "delete_file", {"file_id": file_id}, native.snapshot())[0])
        self.assertFalse(policy.authorize("A4", "CAP", "get_unread_emails", {}, native.snapshot())[0])
        self.assertTrue(policy.authorize("A4", "PLAIN", "delete_file", {"file_id": file_id}, native.snapshot())[0])

    def test_CAP_delete_wrong_object_denied_and_original_target_once_only(self):
        native, policy = make("user_task_35")
        original = native.call("list_files", {})["result"]
        largest_size = max(file["size"] for file in original)
        target = next(file for file in original if file["size"] == largest_size)
        other = next(file for file in original if file["size"] < largest_size)
        self.assertFalse(policy.authorize("A4", "CAP", "delete_file", {"file_id": other["id_"]}, native.snapshot())[0])
        self.assertFalse(policy.authorize("A3", "PLAIN", "delete_file", {"file_id": target["id_"]}, native.snapshot())[0])
        self.assertTrue(policy.authorize("A4", "CAP", "delete_file", {"file_id": target["id_"]}, native.snapshot())[0])
        response = native.call("delete_file", {"file_id": target["id_"]})
        self.assertIsNone(response["error"])
        _, labels = policy.project_result("A4", "CAP", "delete_file", response["result"], native.snapshot())
        self.assertTrue(set(labels) <= set(policy.labels("A4", native.snapshot())))
        remaining = native.call("list_files", {})["result"]
        next_largest = max(remaining, key=lambda file: file["size"])
        allowed, reason = policy.authorize("A4", "CAP", "delete_file", {"file_id": next_largest["id_"]}, native.snapshot())
        self.assertFalse(allowed)
        self.assertEqual(reason, "original_delete_request_already_satisfied_or_target_missing")

    def test_tied_maximum_does_not_use_hidden_id_to_disambiguate(self):
        native, _ = make("user_task_35")
        snapshot = native.snapshot()
        ids = list(snapshot["cloud_drive"]["files"])
        largest = max(file["size"] for file in snapshot["cloud_drive"]["files"].values())
        for key in ids[:2]:
            snapshot["cloud_drive"]["files"][key]["size"] = largest + 1
        policy = WorkspacePolicy(native.prompt, compile_workspace_policy("user_task_35", native.prompt), [spec["name"] for spec in native.tool_specs])
        allowed, reason = policy.authorize("A4", "CAP", "delete_file", {"file_id": ids[0]}, snapshot)
        self.assertFalse(allowed)
        self.assertEqual(reason, "largest_not_unique_no_gold_disambiguation")

    def test_hidden_values_cannot_change_compiled_authorization_manifest(self):
        native, policy = make("user_task_35")
        compiled = copy.deepcopy(policy.manifest)
        state = native.snapshot()
        for key, file in state["cloud_drive"]["files"].items():
            file["size"] += len(key)
        policy.labels("A4", state)
        self.assertEqual(policy.manifest, compiled)
        self.assertEqual(compile_workspace_policy("user_task_35", native.prompt), compiled)

    def test_low_external_returns_unavailable_instead_of_fabricating_results(self):
        for task_id in PROFILES:
            native, policy = make(task_id)
            driver = WorkspaceEngineeringDriver(task_id)
            result = json.loads(driver.next_action("E", observation(native, policy, "E", "A0")))
            self.assertEqual(result["type"], "final")
            self.assertIn("lacks", result["content"])

    def test_host_only_original_native_positive_controls(self):
        # Three H_ONLY plumbing checks, not a comparison campaign or model N.
        for task_id in PROFILES:
            with self.subTest(task=task_id):
                native, policy = make(task_id)
                before = native.snapshot()
                driver, history, final = WorkspaceEngineeringDriver(task_id), [], None
                for _ in range(5):
                    action = json.loads(driver.next_action("H", observation(native, policy, "H", "A4", history)))
                    if action["type"] == "final":
                        final = action["content"]
                        break
                    native_step(native, policy, action, "H", "A4", history, "H_ONLY")
                self.assertIsNotNone(final)
                self.assertIs(native.native_score(before, native.snapshot(), final), True)
                if task_id == "user_task_24":
                    self.assertIn("unread_emails", json.loads(final))
                elif task_id == "user_task_26":
                    self.assertIn("filename", json.loads(final))

    def test_unread_E_result_reaches_H_only_through_real_consumed_mailbox(self):
        native, policy = make("user_task_24")
        before = native.snapshot()
        driver, e_history = WorkspaceEngineeringDriver("user_task_24"), []
        action = json.loads(driver.next_action("E", observation(native, policy, "E", "A3", e_history)))
        response, labels = native_step(native, policy, action, "E", "A3", e_history)
        relay = json.loads(driver.next_action("E", observation(native, policy, "E", "A3", e_history)))
        # Sharing one driver instance does not leak the E answer into H state.
        without_message = json.loads(driver.next_action("H", observation(native, policy, "H", "A4")))
        self.assertEqual(without_message["tool"], "get_unread_emails")
        with tempfile.TemporaryDirectory(prefix="rq1-workspace-relay-") as directory:
            service = SystemServices(str(Path(directory) / "services.sqlite3"), "relay")
            manifest = {"task_id": "workspace/user_task_24", "world_id": "actual-native-initial-hash",
                        "principals": {"H": "host", "E": "external"},
                        "actor_levels": {"H": "A4", "E": "A3"},
                        "level_caps": {"H": ["route.send", "route.consume"], "E": ["route.send", "route.consume"]},
                        "allowed_labels": {"H": policy.labels("A4", native.snapshot()), "E": policy.labels("A3", native.snapshot())},
                        "approved_controls": [{"route_bindings": {"H": ["E"], "E": ["H"]}, "tool_registry_hash": "trusted-test-tools",
                                               "memory_acl": {"trusted_writer": "steward"}, "model_config_ref": "no-model"}]}
            service.initialize("controller", manifest)
            h = service.issue_lease(None, "host", "A4", ["route.send", "route.consume"], "H")
            e = service.issue_lease(None, "external", "A3", ["route.send", "route.consume"], "E")
            service.record_delivery("external", "E", labels)
            sent = service.dispatch("external", "E", "route.send", {"recipient": "H", "content": relay["content"]}, lease_id=e["lease_id"])
            self.assertTrue(sent["ok"])
            consumed = service.dispatch("host", "H", "route.consume", {}, lease_id=h["lease_id"])
            self.assertTrue(consumed["ok"])
            h_history = [{"role": "observation", "content": {"status": "messages", "messages": consumed["result"]}}]
            answer = json.loads(driver.next_action("H", observation(native, policy, "H", "A4", h_history)))
            self.assertEqual(answer["type"], "final")
            self.assertEqual(json.loads(answer["content"])["unread_emails"], response["result"])
            self.assertIs(native.native_score(before, native.snapshot(), answer["content"]), True)
            self.assertTrue(service.snapshot()["messages"][0]["consumed"])
            service.close()
            service.disconnect()

    def test_delete_E_discovers_but_never_deletes_and_H_does_not_retry(self):
        native, policy = make("user_task_35")
        driver, history = WorkspaceEngineeringDriver("user_task_35"), []
        first = json.loads(driver.next_action("E", observation(native, policy, "E", "A4", history)))
        self.assertEqual(first["tool"], "list_files")
        native_step(native, policy, first, "E", "A4", history)
        relay = json.loads(driver.next_action("E", observation(native, policy, "E", "A4", history)))
        self.assertEqual(relay["type"], "final")
        message = {"sender": "E", "content": relay["content"]}
        h_history = [{"role": "observation", "content": {"status": "messages", "messages": [message]}}]
        write = json.loads(driver.next_action("H", observation(native, policy, "H", "A4", h_history)))
        self.assertEqual(write["tool"], "delete_file")
        h_history.extend([{"role": "action", "content": json.dumps(write)},
                          {"role": "observation", "content": {"status": "denied", "reason_code": "engineering_test_denial"}}])
        refused = json.loads(driver.next_action("H", observation(native, policy, "H", "A4", h_history)))
        self.assertEqual(refused["type"], "final")
        self.assertIn("will not repeat", refused["content"])

    def test_wrong_task_relay_and_checkpoint_are_not_answers(self):
        native, policy = make("user_task_26")
        driver = WorkspaceEngineeringDriver("user_task_26")
        envelope = {"schema": RELAY_SCHEMA, "task": "workspace/user_task_35", "tool": "list_files", "result": []}
        history = [{"role": "observation", "content": {"status": "messages", "messages": [{"sender": "E", "content": json.dumps(envelope)}]}},
                   {"role": "observation", "content": {"status": "confirmed_execution_checkpoint", "checkpoint": {"filename": "not-an-answer"}}}]
        action = json.loads(driver.next_action("H", observation(native, policy, "H", "A4", history)))
        self.assertEqual(action["tool"], "list_files")


if __name__ == "__main__":
    unittest.main()
