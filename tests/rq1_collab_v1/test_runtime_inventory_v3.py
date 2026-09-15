"""Effective source identity checks for the v1/v1_2 AgentDojo task collision."""
from __future__ import annotations

import json
from pathlib import Path
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1 import admission
from agentmembrane.host_v2.rq1_collab_v1.process_backend import ProcessNativeTask


PROJECT = Path(__file__).resolve().parents[2]
QUALIFIED = PROJECT / ("experiments/host_boundary_v2/rq1_collab_v1/pipeline_audit_20260907/"
                       "pilots/native_run_001/run-manifest.json")


class RuntimeInventoryTests(unittest.TestCase):
    def test_effective_inventory_keeps_86_static_tasks_and_reviews_only_two_overrides(self):
        static = admission.locked_agentdojo_user_inventory()
        effective = admission.locked_agentdojo_runtime_inventory()
        self.assertEqual(len(static), 86)
        self.assertEqual(set(effective), set(static))
        changed = {identity for identity, row in effective.items()
                   if row["source_file"] != static[identity]["source_path"]
                   or row["source_file_sha256"] != static[identity]["source_file_sha256"]}
        self.assertEqual(changed, {("workspace", "user_task_31"),
                                   ("workspace", "user_task_32")})
        for identity in changed:
            self.assertEqual(effective[identity]["source_file"],
                             "src/agentdojo/default_suites/v1_2/workspace/user_tasks.py")
            self.assertEqual(effective[identity]["class_module"],
                             "agentdojo.default_suites.v1_2.workspace.user_tasks")

    def test_unbound_inventory_or_source_root_fails_closed(self):
        with patch.object(admission, "_RUNTIME_INVENTORY_FILE_SHA256", "0" * 64):
            with self.assertRaisesRegex(ValueError, "effective_runtime_inventory_file_changed"):
                admission.locked_agentdojo_runtime_inventory()
        with self.assertRaisesRegex(ValueError, "effective_runtime_inventory_source_root_changed"):
            admission.locked_agentdojo_runtime_inventory(source_root=PROJECT)

    def test_two_overrides_match_fresh_native_processes(self):
        qualified = json.loads(QUALIFIED.read_text())
        effective = admission.locked_agentdojo_runtime_inventory(
            source_root=qualified["source_root"])
        for number in (31, 32):
            identity = "workspace", f"user_task_{number}"
            with self.subTest(identity=identity):
                task = ProcessNativeTask(qualified["native_python"], qualified["source_root"],
                                         *identity, timeout=45)
                try:
                    self.assertTrue(task.snapshot())
                    for key in admission._RUNTIME_IDENTITY_KEYS:
                        self.assertEqual(task.record[key], effective[identity][key], key)
                finally:
                    task.shutdown()


if __name__ == "__main__":
    unittest.main()
