from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from agentmembrane.host_v2.rq1_public_agentdojo_v1.native_parity import (
    DEFAULT_OUTPUT,
    EXPECTED_CALLABLE_SOURCES,
    EXPECTED_RUNTIME_ENTRY_COUNT,
    EXPECTED_RUNTIME_TREE_SHA256,
    RUNTIME_RECEIPT,
    RUNTIME_ROOT,
    NativeParityError,
    run_native_checker_parity,
    validate_native_parity_record,
    write_native_parity_record,
)
from agentmembrane.host_v2.schema import canonical_json_bytes, sha256_json


@unittest.skipUnless(
    RUNTIME_ROOT.is_dir() and RUNTIME_RECEIPT.is_file(),
    "fresh cache-free AgentDojo a005 runtime is not materialized",
)
class RQ1PublicAgentDojoNativeParityV1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.record = run_native_checker_parity()

    def test_actual_native_checkers_match_all_four_offline_cells(self) -> None:
        record = self.record
        self.assertEqual(validate_native_parity_record(record), record)
        self.assertTrue(record["result"]["native_callable_executed"])
        self.assertTrue(record["result"]["native_checker_parity_established"])
        self.assertEqual(
            record["result"]["offline_native_numeric_parity_cells"], 4
        )
        expected = {
            ("benign", "vulnerable"): (True, None),
            ("benign", "protected"): (True, None),
            ("adversarial", "vulnerable"): (False, True),
            ("adversarial", "protected"): (False, False),
        }
        for cell in record["cells"]:
            coordinate = (cell["pair_role"], cell["arm"])
            native = cell["native_checker"]
            self.assertEqual(
                (native["utility"], native["security"]), expected[coordinate]
            )
            self.assertEqual(
                cell["numeric_parity"], {"utility": True, "security": True}
            )

    def test_cache_free_runtime_is_unchanged_and_network_free(self) -> None:
        integrity = self.record["runtime_integrity"]
        self.assertEqual(
            integrity["before_tree_sha256"], EXPECTED_RUNTIME_TREE_SHA256
        )
        self.assertEqual(
            integrity["after_tree_sha256"], EXPECTED_RUNTIME_TREE_SHA256
        )
        self.assertEqual(
            integrity["before_entry_count"], EXPECTED_RUNTIME_ENTRY_COUNT
        )
        self.assertEqual(
            integrity["after_entry_count"], EXPECTED_RUNTIME_ENTRY_COUNT
        )
        self.assertTrue(integrity["tree_unchanged"])
        self.assertEqual(self.record["execution_counts"]["network_attempts"], 0)
        self.assertEqual(self.record["execution_counts"]["model_calls"], 0)
        self.assertEqual(self.record["execution_counts"]["provider_calls"], 0)
        self.assertEqual(self.record["execution_counts"]["api_calls"], 0)

    def test_native_callable_sources_are_exact(self) -> None:
        actual = {
            row["callable_ref"]: row["source_sha256"]
            for row in self.record["callable_bindings"]
        }
        self.assertEqual(actual, EXPECTED_CALLABLE_SOURCES)
        self.assertEqual(self.record["execution_counts"]["native_checker_calls"], 6)
        self.assertEqual(self.record["execution_counts"]["utility_checker_calls"], 4)
        self.assertEqual(self.record["execution_counts"]["security_checker_calls"], 2)

    def test_native_security_remains_independent_and_informational(self) -> None:
        separation = self.record["semantic_separation"]
        self.assertEqual(
            separation["native_security_semantics"],
            "informational_upstream_injection_success_signal",
        )
        self.assertFalse(separation["native_security_used_for_admission"])
        self.assertFalse(
            separation["native_security_used_for_unauthorized_effect"]
        )
        self.assertFalse(separation["native_utility_used_for_admission"])
        self.assertTrue(
            separation["numeric_parity_does_not_assert_semantic_equivalence"]
        )
        for row in self.record["independent_unauthorized_effect"]:
            self.assertEqual(row["input_source"], "host_projected_trusted_events")
            self.assertFalse(row["native_security_consumed"])
            self.assertFalse(row["native_utility_consumed"])

    def test_checker_blocker_clear_does_not_authorize_real_api(self) -> None:
        result = self.record["result"]
        self.assertTrue(result["checker_blocker_cleared"])
        self.assertEqual(result["public_real_api_decision"], "NO_GO")
        self.assertFalse(self.record["execution_authorized"])
        self.assertFalse(self.record["real_public_execution_authorized"])
        self.assertFalse(self.record["claim_eligible"])

    def test_validator_rejects_parity_and_semantic_overclaims(self) -> None:
        mutations = []

        parity = copy.deepcopy(self.record)
        parity["cells"][0]["numeric_parity"]["utility"] = False
        mutations.append(parity)

        admission = copy.deepcopy(self.record)
        admission["semantic_separation"][
            "native_security_used_for_admission"
        ] = True
        mutations.append(admission)

        authorized = copy.deepcopy(self.record)
        authorized["real_public_execution_authorized"] = True
        mutations.append(authorized)

        native = copy.deepcopy(self.record)
        native_cell = native["cells"][0]["native_checker"]
        native_cell["utility"] = False
        native_payload = {
            key: row
            for key, row in native_cell.items()
            if key != "native_output_sha256"
        }
        native_cell["native_output_sha256"] = sha256_json(native_payload)
        mutations.append(native)

        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises(NativeParityError):
                    validate_native_parity_record(mutation)

    def test_writer_is_canonical_and_exclusive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "native-parity.json"
            digest = write_native_parity_record(path, self.record)
            payload = canonical_json_bytes(self.record) + b"\n"
            self.assertEqual(path.read_bytes(), payload)
            self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
            with self.assertRaises(NativeParityError):
                write_native_parity_record(path, self.record)

    def test_materialized_evidence_is_current_when_present(self) -> None:
        if not DEFAULT_OUTPUT.is_file():
            self.skipTest("native parity evidence has not been materialized yet")
        payload = DEFAULT_OUTPUT.read_bytes()
        record = json.loads(payload)
        self.assertEqual(validate_native_parity_record(record), record)
        self.assertEqual(payload, canonical_json_bytes(record) + b"\n")


if __name__ == "__main__":
    unittest.main()
