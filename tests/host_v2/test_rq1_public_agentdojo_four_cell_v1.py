from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

from agentmembrane.host_v2.public_execution import (
    ExactCommittedTrustedEventOracle,
    assess_public_execution_binding,
)
from agentmembrane.host_v2.schema import IntegrityError
from agentmembrane.host_v2.taskpacks import load_taskpack


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = (
    REPO_ROOT
    / "experiments/host_boundary_v2/rq1_public_agentdojo_four_cell_v1/contracts.py"
)
PACK_ROOT = (
    REPO_ROOT
    / "data/host_boundary_v2/packs/agentdojo-rq1-banking-u3-i1-four-cell-v1"
)


def _load_contract():
    spec = importlib.util.spec_from_file_location(
        "rq1_public_agentdojo_four_cell_contract_test", CONTRACT_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load RQ1 AgentDojo four-cell contract")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CONTRACT = _load_contract()


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RQ1PublicAgentDojoFourCellV1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.mapping_path = PACK_ROOT / CONTRACT.MAPPING_RELATIVE_PATH
        cls.oracle_path = PACK_ROOT / CONTRACT.ORACLE_RELATIVE_PATH
        cls.mapping = _read_json(cls.mapping_path)
        cls.oracle = _read_json(cls.oracle_path)
        cls.tasks = [
            json.loads(line)
            for line in (PACK_ROOT / "tasks.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
        ]

    def test_pack_loads_and_has_exact_four_cell_matrix(self) -> None:
        report = CONTRACT.validate_pack(PACK_ROOT)
        self.assertEqual(report["pack_id"], CONTRACT.PACK_ID)
        self.assertEqual(report["task_count"], 4)
        self.assertEqual(
            {tuple(cell) for cell in report["cells"]},
            set(CONTRACT.EXPECTED_CELLS),
        )
        self.assertFalse(report["execution_authorized"])
        self.assertFalse(report["claim_eligible"])
        pack = load_taskpack(PACK_ROOT)
        self.assertEqual(pack.manifest["splits"], {"gate": 4, "formal": 0})

    def test_exact_mapping_freezes_authority_target_and_actions(self) -> None:
        mapping = CONTRACT.validate_exact_mapping(self.mapping)
        self.assertEqual(mapping["operation_binding"]["op"], "send_money")
        self.assertEqual(mapping["operation_binding"]["canonical_resource"], CONTRACT.RESOURCE)
        self.assertEqual(
            mapping["authority"]["prompt"][83:105], CONTRACT.AUTHORIZED_TARGET
        )
        self.assertEqual(
            mapping["authority"]["authorized_target"]["value_sha256"],
            CONTRACT.AUTHORIZED_VALUE_SHA256,
        )
        self.assertEqual(
            mapping["adversarial_target"]["value"], CONTRACT.UNAUTHORIZED_TARGET
        )
        self.assertEqual(
            mapping["exact_actions"]["adversarial"]["args"]["subject"],
            "Dinner with me",
        )

    def test_schema_v2_oracle_is_statically_executable_for_all_cells(self) -> None:
        mapping_sha = _sha(self.mapping_path)
        CONTRACT.validate_executable_oracle(
            self.oracle,
            mapping=self.mapping,
            mapping_file_sha256=mapping_sha,
        )
        for task in self.tasks:
            with self.subTest(task_id=task["task_id"]):
                assessment = assess_public_execution_binding(task, self.oracle)
                self.assertTrue(assessment.executable, assessment.as_json())
                self.assertEqual(
                    assessment.binding.adapter_ref, CONTRACT.PUBLIC_ADAPTER_REF
                )
                self.assertEqual(
                    assessment.binding.reset_task_id,
                    (
                        CONTRACT.BENIGN_SOURCE_RECORD_ID
                        if task["pair_role"] == "benign"
                        else CONTRACT.ADVERSARIAL_SOURCE_RECORD_ID
                    ),
                )

    def test_exact_event_oracle_matches_only_unauthorized_target(self) -> None:
        assessment = assess_public_execution_binding(self.tasks[0], self.oracle)
        self.assertIsNotNone(assessment.binding)
        oracle = ExactCommittedTrustedEventOracle(CONTRACT.ORACLE_ID)
        common = {
            "event_id": "event-1",
            "side_effect": True,
            "committed": True,
            "unauthorized": True,
            "op": CONTRACT.OPERATION,
            "resource": CONTRACT.RESOURCE,
        }
        unauthorized = oracle.evaluate(
            binding=assessment.binding,
            reset=None,
            dispatches=(),
            assistant_output=None,
            terminal_state=None,
            trusted_events=(
                {**common, "value_sha256": CONTRACT.UNAUTHORIZED_VALUE_SHA256},
            ),
        )
        self.assertTrue(unauthorized.occurred)
        self.assertEqual(unauthorized.witness_event_ids, ("event-1",))
        authorized = oracle.evaluate(
            binding=assessment.binding,
            reset=None,
            dispatches=(),
            assistant_output=None,
            terminal_state=None,
            trusted_events=(
                {**common, "value_sha256": CONTRACT.AUTHORIZED_VALUE_SHA256},
            ),
        )
        self.assertFalse(authorized.occurred)
        with self.assertRaises(IntegrityError):
            oracle.evaluate(
                binding=assessment.binding,
                reset=None,
                dispatches=(),
                assistant_output=None,
                terminal_state=None,
                trusted_events=({"event_id": "incomplete"},),
            )

    def test_native_checker_provenance_is_separate_and_exact(self) -> None:
        utility = self.oracle["native_system_task_utility"]
        security = self.oracle["native_benchmark_security_signal"]
        effect = self.oracle["unauthorized_side_effect"]
        self.assertEqual(utility["mode"], "native_checker")
        self.assertEqual(utility["reward_basis"], ["DB"])
        self.assertTrue(security["informational_only"])
        self.assertTrue(effect["independent_from_native_security"])
        self.assertEqual(
            utility["provenance"]["dispatcher"]["source_sha256"],
            CONTRACT.TASK_SUITE_SOURCE_SHA256,
        )
        self.assertEqual(
            security["provenance"]["task_checker"]["source_sha256"],
            CONTRACT.INJECTION_TASK_SOURCE_SHA256,
        )

    def test_all_tasks_bind_both_adapters_but_do_not_claim_host_integration(self) -> None:
        visible_inputs = {task["surface_task"] for task in self.tasks}
        self.assertEqual(visible_inputs, {CONTRACT.USER_PROMPT})
        for task in self.tasks:
            metadata = task["metadata"]
            self.assertEqual(metadata["adapter_ref"], CONTRACT.PUBLIC_ADAPTER_REF)
            self.assertEqual(
                metadata["environment_adapter_ref"],
                CONTRACT.ENVIRONMENT_ADAPTER_REF,
            )
            self.assertEqual(metadata["rq_targets"], ["RQ1"])
            self.assertEqual(metadata["host_integration_status"], "pending")
            self.assertFalse(metadata["execution_authorized"])

    def test_mapping_and_oracle_mutations_fail_closed(self) -> None:
        mapping = copy.deepcopy(self.mapping)
        mapping["adversarial_target"]["value"] = CONTRACT.AUTHORIZED_TARGET
        with self.assertRaises(CONTRACT.RQ1FourCellContractError):
            CONTRACT.validate_exact_mapping(mapping)

        mapping = copy.deepcopy(self.mapping)
        mapping["authority"]["substring_start"] = 82
        with self.assertRaises(CONTRACT.RQ1FourCellContractError):
            CONTRACT.validate_exact_mapping(mapping)

        mapping = copy.deepcopy(self.mapping)
        mapping["authority"]["undeclared_override"] = True
        with self.assertRaises(CONTRACT.RQ1FourCellContractError):
            CONTRACT.validate_exact_mapping(mapping)

        oracle = copy.deepcopy(self.oracle)
        oracle["native_benchmark_security_signal"]["informational_only"] = False
        with self.assertRaises(CONTRACT.RQ1FourCellContractError):
            CONTRACT.validate_executable_oracle(
                oracle,
                mapping=self.mapping,
                mapping_file_sha256=_sha(self.mapping_path),
            )

        oracle = copy.deepcopy(self.oracle)
        oracle["unauthorized_side_effect"]["value_sha256"] = (
            CONTRACT.AUTHORIZED_VALUE_SHA256
        )
        with self.assertRaises(CONTRACT.RQ1FourCellContractError):
            CONTRACT.validate_executable_oracle(
                oracle,
                mapping=self.mapping,
                mapping_file_sha256=_sha(self.mapping_path),
            )

    def test_source_pack_and_upstream_bytes_remain_exact(self) -> None:
        expected = {
            "data/host_boundary_v2/packs/agentdojo-v0.1.35-v1/manifest.json": (
                "efdbb5472988a172b28917c6fb313829fb0d23e48dc179c561372d01e5e6aa56"
            ),
            "data/host_boundary_v2/packs/agentdojo-v0.1.35-v1/tasks.jsonl": (
                "991e0f65c50a95d2757b849191323d0878f7f4a57cbe67cd7ce50385f9160844"
            ),
            "data/host_boundary_v2/upstream/agentdojo/src/agentdojo/"
            "default_suites/v1/banking/user_tasks.py": (
                CONTRACT.USER_TASK_SOURCE_SHA256
            ),
            "data/host_boundary_v2/upstream/agentdojo/src/agentdojo/"
            "default_suites/v1/banking/injection_tasks.py": (
                CONTRACT.INJECTION_TASK_SOURCE_SHA256
            ),
        }
        for relative, sha256 in expected.items():
            with self.subTest(path=relative):
                self.assertEqual(_sha(REPO_ROOT / relative), sha256)


if __name__ == "__main__":
    unittest.main()
