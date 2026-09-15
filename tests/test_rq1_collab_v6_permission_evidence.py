"""Source-native, sealed v6 permission replay and tamper regressions."""

import copy
import os
from pathlib import Path
import tempfile
import unittest

from agentmembrane.host_v2.rq1_collab_v1.admission import TaskBundle
from agentmembrane.host_v2.rq1_collab_v1.audit import EventCollector, canonical
from agentmembrane.host_v2.rq1_collab_v1.native import NativeTask
from agentmembrane.host_v2.rq1_collab_v1.policy import compile_task_policy
from agentmembrane.host_v2.rq1_collab_v6.contract import digest, make_config
from agentmembrane.host_v2.rq1_collab_v6.evaluation import read_evidence, validate_evidence
from agentmembrane.host_v2.rq1_collab_v6.runtime import run_episode
from tests.rq1_collab_v1.test_runtime import final, tool
from tests.rq1_collab_v3.test_runtime_evaluation import Script


SOURCE = str(Path(os.environ.get(
    "AGENTDOJO_SOURCE_ROOT",
    Path(__file__).resolve().parents[1]
    / "data/host_boundary_v2/upstream/agentdojo",
)).expanduser().resolve())


def _delete_discovered_largest(observation):
    listed = [item["content"]["result"] for item in observation["history"]
              if item["role"] == "observation" and item["content"].get("status") == "tool_result"
              and item["content"].get("tool") == "list_files"][-1]
    largest = max(listed, key=lambda item: item["size"])
    return tool("delete_file", file_id=largest["id_"])


def _run_source_case(root, suite, number, script):
    task_id = f"user_task_{number}"
    native = NativeTask(SOURCE, suite, task_id)
    payload = {
        "schema_version": "rq1-task-bundle/2", "protocol_version": "rq1-multifactor/2",
        "suite": suite, "original_id": task_id, "source_record": native.record,
        "task_policy": compile_task_policy(suite, task_id, native.prompt),
        "goal_admission": {"initial_goal_value": False},
        "public": {"user_request": native.prompt,
                   "goal": {"goal_id": "synthetic_permission_replay_test",
                            "goal": "unregistered engineering-only probe"}},
    }
    bundle = TaskBundle(canonical(payload), digest(payload))
    cfg = make_config(bundle.sha256, f"permission-replay-{suite}-{number}",
                      "H_E", "medium", "honest")
    collector = EventCollector(root, cfg["episode_id"])
    result = run_episode(cfg, bundle, native, script, collector)
    return read_evidence(collector.run_dir, result["seal"]["seal_hash"])


class V6PermissionEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="rq1-v6-permission-evidence-")
        root = Path(cls.temp.name)
        cls.workspace = _run_source_case(root / "workspace", "workspace", 35,
            Script(E=[tool("list_files"), _delete_discovered_largest, final("done")],
                   H=[final("The requested file was deleted.")]))
        cls.travel = _run_source_case(root / "travel", "travel", 0,
            Script(E=[final("Please continue the booking.")], H=[final("Done.")]))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_source_native_full_episode_and_post_state_probe(self):
        validate_evidence(self.workspace)
        validate_evidence(self.travel)
        self.assertEqual(self.workspace["terminal_reason"], "host_final")
        self.assertTrue(any(row.get("point") == "after_native" for row in
                            self.workspace["runtime_trace"]["authority_snapshots"]))
        self.assertNotIn("get_user_information",
                         self.travel["runtime_trace"]["authority_snapshots"][0]
                         ["state"]["actors"]["E"]["effective_tools"])

    def test_legacy_false_grants_rejected_even_with_rehashed_state(self):
        for name, original, tool_name, operation in (
                ("workspace", self.workspace, "delete_file", "remove"),
                ("travel", self.travel, "get_user_information", "add")):
            with self.subTest(task=name):
                forged = copy.deepcopy(original)
                state = forged["runtime_trace"]["authority_snapshots"][0]["state"]
                grant = state["actors"]["E"]["effective_tools"]
                if operation == "remove":
                    grant.remove(tool_name)
                else:
                    grant.append(tool_name)
                    grant.sort()
                state["state_sha256"] = digest({key: value for key, value in state.items()
                                                 if key != "state_sha256"})
                with self.assertRaisesRegex(ValueError, "v6_authority_effective_grant_mismatch"):
                    validate_evidence(forged)

    def test_delivery_advertisement_and_native_dispatch_are_recomputed(self):
        forged = copy.deepcopy(self.travel)
        delivery = next(row for row in forged["deliveries"] if row["actor"] == "E")
        delivery["payload"]["permissions"]["tools"].append("get_user_information")
        with self.assertRaisesRegex(ValueError, "v6_delivery_advertised_grant_mismatch"):
            validate_evidence(forged)

        forged = copy.deepcopy(self.workspace)
        entered = next(row for row in forged["native_calls"]
                       if row["actor"] == "E" and row["tool"] == "delete_file")
        initial_files = forged["initial_snapshot"]["cloud_drive"]["files"]
        target = entered["arguments"]["file_id"]
        wrong = next(key for key in initial_files if key != target)
        entered["arguments"]["file_id"] = wrong
        decision_id = entered["call_id"].removesuffix(":native")
        decision = next(row for row in forged["decisions"] if row["event_id"] == decision_id)
        decision["resolved_action"]["arguments"]["file_id"] = wrong
        with self.assertRaisesRegex(ValueError, "v6_native_dispatch_outside_actual_grant"):
            validate_evidence(forged)

    def test_probe_coverage_and_receipts_cannot_be_erased_or_forged(self):
        forged = copy.deepcopy(self.workspace)
        forged["runtime_trace"]["authority_probes"] = []
        with self.assertRaisesRegex(ValueError, "v6_authority_probes_required"):
            validate_evidence(forged)

        forged = copy.deepcopy(self.workspace)
        forged["runtime_trace"]["authority_probes"] = [
            batch for batch in forged["runtime_trace"]["authority_probes"]
            if batch.get("native_call_id") is None]
        with self.assertRaisesRegex(ValueError, "v6_post_native_authority_probe_coverage_mismatch"):
            validate_evidence(forged)

        forged = copy.deepcopy(self.travel)
        receipt = next(row for row in forged["runtime_trace"]["authority_probes"][0]["receipts"]
                       if row["request"]["actor"] == "E"
                       and row["request"]["tool"] == "get_user_information")
        receipt["actual_allowed"] = True
        with self.assertRaisesRegex(ValueError, "v6_authority_probe_receipts_mismatch"):
            validate_evidence(forged)


if __name__ == "__main__":
    unittest.main()
