"""Source-bound Workspace I draft denominators and actual receipt lower bounds."""
from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from agentmembrane.host_v2.rq1_collab_v1.native import digest
from agentmembrane.host_v2.rq1_collab_v1.process_backend import ProcessNativeTask
from agentmembrane.host_v2.rq1_collab_v6.workspace_qid_information import compile_workspace_draft_information
from agentmembrane.host_v2.rq1_measurement_v1.information import derive_information_effects


ROOT = Path(__file__).resolve().parents[2]
PYTHON = ROOT / "experiments/host_boundary_v2/runtime_envs/agentdojo-0.1.35-py3123-lock-395e3d0a5921-rq1v4/bin/python"
SOURCE = ROOT / "data/host_boundary_v2/upstream/agentdojo"
CATALOG = ROOT / "agentmembrane/host_v2/rq1_measurement_v1/policy_data/source-catalog-candidate-v1.json"
DRAFTS = ROOT / "experiments/host_boundary_v2/rq1_three_tier_large_scale/qid_contract_drafts_workspace_001/contracts.json"


class WorkspaceInformationDraftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        native = ProcessNativeTask(str(PYTHON), str(SOURCE), "workspace", "user_task_0")
        try:
            cls.initial = native.snapshot()
        finally:
            native.shutdown()
        cls.catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        cls.drafts = json.loads(DRAFTS.read_text(encoding="utf-8"))

    def compile(self, task_id):
        entry = self.catalog[f"workspace/{task_id}"]
        return compile_workspace_draft_information(
            entry["source_record"], entry["public"]["user_request"], self.initial)

    def test_all_eighteen_original_fact_recipient_denominators_rebuild(self):
        for draft in self.drafts:
            with self.subTest(task=draft["task_key"]):
                contract, facts = self.compile(draft["task_key"].split("/", 1)[1])
                self.assertEqual(len(facts), 793)
                self.assertEqual(contract["counts"]["I_cells"], draft["I"]["proposed_I_cells"])
                self.assertEqual(contract["status"], "diagnostic_only_not_formal_QID_registration")
                self.assertTrue(all(contract["owner_recipient"] != unit["recipient_id"]
                                    for unit in contract["units"]))

    def test_requested_fields_legal_only_for_registered_roles(self):
        contract, _ = self.compile("user_task_0")
        target = "/calendar/events/13/description"
        rules = contract["fact_rules"][target]
        self.assertIn("role:E", rules["allowed_recipients"])
        self.assertNotIn("native:alex.williams@mainsail-tech.com", rules["allowed_recipients"])
        self.assertFalse(any(unit["id"] == "I:" + target + "@role:E" for unit in contract["units"]))
        self.assertTrue(any(unit["id"] == "I:" + target + "@native:alex.williams@mainsail-tech.com"
                            for unit in contract["units"]))

    def test_confirmed_private_receipt_is_positive_but_missing_receipt_is_unknown(self):
        contract, facts = self.compile("user_task_0")
        pointer = "/calendar/events/12/description"
        private_value = facts[pointer]["value"]
        self.assertIsInstance(private_value, str)
        payload = {"unrelated_private_description": private_value}
        entry = self.catalog["workspace/user_task_0"]
        data = {"schema_version": "rq1-evidence/5", "episode_id": "test-I",
                "bundle_public": entry["public"],
                "deliveries": [{"event_id": "delivery-1", "actor": "E", "status": "model_response_observed",
                                "payload": payload,
                                "model_binding": {"actor": "E", "observation_sha256": digest(payload)}}],
                "native_calls": [], "runtime_trace": {}, "config": {}, "actors": {}}
        result = derive_information_effects(data, {"information_contract": contract,
                                                  "private_facts": facts})
        positive = [row for row in result["observations"] if row["affected"] == 1]
        self.assertTrue(any(row["unit_id"] == "I:" + pointer + "@role:E" for row in positive))
        empty = copy.deepcopy(data)
        empty["deliveries"] = []
        missing = derive_information_effects(empty, {"information_contract": contract,
                                                     "private_facts": facts})
        self.assertEqual(missing["observations"], [])

    def test_file_content_granularity_remains_explicitly_unresolved(self):
        for task_id, pointer in (("user_task_28", "/cloud_drive/files/0/content"),
                                 ("user_task_30", "/cloud_drive/files/7/content")):
            with self.subTest(task=task_id):
                contract, _ = self.compile(task_id)
                self.assertIn(pointer, contract["fact_rules"])
                self.assertIn("role:E", contract["fact_rules"][pointer]["allowed_recipients"])
                self.assertIn("content_atomization_unresolved", contract["coverage_warning"])
                self.assertEqual(contract["status"], "diagnostic_only_not_formal_QID_registration")


if __name__ == "__main__":
    unittest.main()
