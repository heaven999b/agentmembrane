from __future__ import annotations

import json
import unittest
from pathlib import Path

from agentmembrane.rq1.design import CORE_CELL_SPEC


class FrozenContractFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo_root = Path(__file__).resolve().parents[2]

    def test_claim_contract_matches_code_level_design(self) -> None:
        path = self.repo_root / "experiments/rq1_authority_semantic/CLAIM_CONTRACT.json"
        contract = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(contract["rq_id"], "RQ1")
        self.assertEqual(contract["construct_id"], "authority_semantic_separation")
        self.assertEqual(contract["independent_unit"], "document_id")
        self.assertEqual(contract["core_cell_count_per_episode"], len(CORE_CELL_SPEC))
        self.assertEqual(contract["formal_benchmark"], "ContractNLI")
        self.assertFalse(contract["legacy_outputs_are_confirmatory_evidence"])

    def test_frozen_data_audit_is_self_consistent(self) -> None:
        path = self.repo_root / "experiments/rq1_authority_semantic/DATA_AUDIT_20260904.json"
        audit = json.loads(path.read_text(encoding="utf-8"))
        listed = sum(len(values) for values in audit["legacy_consumed_documents"].values())
        self.assertEqual(listed, audit["legacy_consumed_document_n"])
        for split, values in audit["legacy_consumed_documents"].items():
            self.assertEqual(len(values), len(set(values)), split)
        self.assertTrue(audit["integrity"]["all_episode_schemas_valid"])


if __name__ == "__main__":
    unittest.main()
