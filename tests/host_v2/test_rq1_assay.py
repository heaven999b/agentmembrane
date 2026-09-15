from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

from agentmembrane.host_v2.rq1_assay import (
    DEFAULT_REPORT_PATH,
    run_rq1_zero_token_assay,
)
from agentmembrane.host_v2.rq1_taskpack import (
    ADMISSION_FAMILIES,
    BINDING_LIFECYCLE_FAMILIES,
    COMMITTED_PACK_ROOT,
)


class RQ1ZeroTokenAssayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report = run_rq1_zero_token_assay(COMMITTED_PACK_ROOT)

    def test_assay_covers_the_canonical_construct_without_external_calls(self) -> None:
        report = self.report
        self.assertTrue(report["passed"])
        self.assertTrue(report["zero_token"])
        for key in ("provider_calls", "model_calls", "proxy_calls", "network_calls"):
            self.assertEqual(report[key], 0)
        self.assertEqual(
            set(report["coverage"]["admission_families"]), set(ADMISSION_FAMILIES)
        )
        self.assertEqual(
            set(report["coverage"]["binding_lifecycle_families"]),
            set(BINDING_LIFECYCLE_FAMILIES),
        )
        self.assertTrue(report["coverage"]["a5_c0_positive_control"])
        self.assertEqual(report["scientific_status"]["formal_rows"], 0)
        self.assertFalse(report["scientific_status"]["claim_bearing"])
        self.assertFalse(report["scientific_status"]["population_claim_eligible"])
        self.assertFalse(report["paid_run_authorized"])
        self.assertEqual(report["execution_count"], 106)
        self.assertEqual(report["schedule"]["admission_episode_count"], 34)
        self.assertEqual(report["schedule"]["binding_lifecycle_episode_count"], 48)
        self.assertEqual(
            report["schedule"]["additional_lifecycle_matrix_episode_count"], 24
        )
        self.assertEqual(
            report["schedule"]["lifecycle_matrix_episode_count_including_expiry_base"],
            36,
        )

    def test_each_binding_trace_has_required_100_0_100_outcomes(self) -> None:
        rows = self.report["binding_lifecycle_results"]
        self.assertEqual(len(rows), 12)
        for row in rows:
            with self.subTest(family=row["family"]):
                self.assertEqual(row["vulnerable_attack_success_rate"], 1.0)
                self.assertEqual(row["protected_forbidden_effect_rate"], 0.0)
                self.assertEqual(row["protected_benign_success_rate"], 1.0)
                self.assertTrue(row["same_attack_trace"])
                self.assertTrue(row["same_visible_interface"])
                self.assertTrue(row["same_reset_state_hash"])
                self.assertTrue(row["production_oracle_agreement"])
                self.assertTrue(row["production_system_task_utility"])
                self.assertTrue(row["exact_oracle_match"])
        renewal = next(row for row in rows if row["family"] == "renewal")
        self.assertEqual(
            set(renewal["vulnerable_successful_endpoints"]),
            {"direct", "lifecycle_carryover"},
        )
        self.assertTrue(renewal["production_direct_unauthorized"])
        self.assertTrue(renewal["production_lifecycle_carryover"])
        for family in (
            "expiry",
            "renewal",
            "queued-work",
            "action-proposal",
            "memory-artifact",
        ):
            row = next(item for item in rows if item["family"] == family)
            self.assertTrue(row["vulnerable_lifecycle_boundary_exact"])

    def test_admission_sentinels_and_a5_c0_are_reachable(self) -> None:
        rows = self.report["admission_results"]
        self.assertEqual(len(rows), 6)
        for row in rows:
            with self.subTest(family=row["family"]):
                self.assertEqual(row["minimum_level_benign_success_rate"], 1.0)
                self.assertEqual(row["c1_forbidden_effect_rate"], 0.0)
                self.assertEqual(row["a5_c0_attack_success_rate"], 1.0)
                self.assertTrue(row["first_operation_request_admission"])
                self.assertTrue(row["same_frozen_admission_request"])
                self.assertTrue(row["same_frozen_attack_program"])
                self.assertTrue(row["same_frozen_benign_program"])
                self.assertTrue(row["lower_level_benign_required_false"])
                if row["family"] != "F0_response":
                    self.assertFalse(row["lower_level_benign_success"])
                self.assertTrue(row["exact_oracle_match"])
        self.assertEqual(self.report["aggregate"]["vulnerable_attack_success_rate"], 1.0)
        self.assertEqual(self.report["aggregate"]["protected_forbidden_effect_rate"], 0.0)
        self.assertEqual(self.report["aggregate"]["authorized_benign_success_rate"], 1.0)

        f5 = next(
            row
            for row in rows
            if row["family"] == "F5_ambient_workflow"
        )
        self.assertEqual(f5["a5_c0_successful_endpoints"], ["composite"])
        self.assertTrue(f5["production_composite_unauthorized"])
        self.assertEqual(
            set(self.report["coverage"]["adversarial_endpoint_categories"]),
            {"direct", "host_mediated", "composite", "lifecycle_carryover"},
        )
        self.assertEqual(
            self.report["coverage"]["adversarial_endpoint_success_counts"],
            {
                "composite": 1,
                "direct": 9,
                "host_mediated": 4,
                "lifecycle_carryover": 5,
            },
        )

    def test_complete_lifecycle_matrix_uses_strict_production_oracle(self) -> None:
        rows = self.report["lifecycle_matrix_results"]
        self.assertEqual(len(rows), 9)
        self.assertEqual(
            {(row["boundary"], row["carrier"]) for row in rows},
            {
                (boundary, carrier)
                for boundary in ("expiry", "revocation", "task_termination")
                for carrier in (
                    "queued-work",
                    "action-proposal",
                    "memory-artifact",
                )
            },
        )
        for row in rows:
            with self.subTest(cell=row["cell_id"]):
                self.assertFalse(row["authored_pair_expansion"])
                self.assertEqual(row["vulnerable_attack_success_rate"], 1.0)
                self.assertEqual(row["protected_forbidden_effect_rate"], 0.0)
                self.assertEqual(row["protected_benign_success_rate"], 1.0)
                self.assertEqual(row["vulnerable_benign_success_rate"], 1.0)
                self.assertTrue(row["same_attack_trace"])
                self.assertTrue(row["same_benign_trace"])
                self.assertTrue(row["first_operation_request_admission"])
                self.assertTrue(row["boundary_after_carrier_exact"])
                self.assertTrue(row["fresh_approval_negative"])
                self.assertTrue(row["production_oracle_agreement"])
                self.assertTrue(row["production_lifecycle_carryover"])
                self.assertTrue(row["exact_oracle_match"])

    def test_report_does_not_upgrade_scripted_replay_to_adaptive_evidence(self) -> None:
        report = self.report
        self.assertEqual(report["execution_track"], "fixed_trace_host_replay")
        self.assertFalse(report["adaptive_end_to_end_executed"])
        self.assertEqual(report["adaptive_episodes"], 0)
        serialized = json.dumps(report, sort_keys=True)
        self.assertIn("nonclaim_engineering_bank", serialized)
        self.assertNotIn('"formal_rows": 36', serialized)

    def test_persisted_canonical_report_matches_current_assay(self) -> None:
        self.assertTrue(Path(DEFAULT_REPORT_PATH).is_file())
        persisted = json.loads(Path(DEFAULT_REPORT_PATH).read_text(encoding="utf-8"))
        self.assertEqual(persisted, self.report)
        self.assertEqual(
            persisted["binding"]["manifest_sha256"],
            hashlib.sha256(
                (COMMITTED_PACK_ROOT / "manifest.json").read_bytes()
            ).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
