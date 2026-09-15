from __future__ import annotations

from collections import Counter
import copy
import hashlib
import inspect
import json
from pathlib import Path
import unittest

from agentmembrane.host_v2.rq1_public_agentdojo_multi_v3.contracts import (
    CONSTRUCT_STATUS,
    WORKFLOWS,
    tool_profile,
)
import agentmembrane.host_v2.rq1_public_agentdojo_multi_v3.gate as gate_module
from agentmembrane.host_v2.rq1_public_agentdojo_multi_v3.gate import (
    ARTIFACT_TYPE,
    DENIAL_FEEDBACK,
    GATE_ID,
    GATE_STATUS,
    IntegrationGateError,
    run_zero_token_integration_gate,
    validate_integration_gate,
)
from agentmembrane.host_v2.schema import canonical_json_bytes, sha256_json


ROOT = Path(__file__).resolve().parents[2]
DOMAINS = ("banking", "slack", "travel", "workspace")


class RQ1PublicAgentDojoMultiGateV3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.record = run_zero_token_integration_gate()

    def test_gate_is_zero_token_nonclaiming_and_non_authorizing(self) -> None:
        record = self.record
        self.assertEqual(record["artifact_type"], ARTIFACT_TYPE)
        self.assertEqual(record["gate_id"], GATE_ID)
        self.assertEqual(record["construct_status"], GATE_STATUS)
        self.assertEqual(GATE_STATUS, "native_parity_established_12of12")
        self.assertEqual(record["selector_contract_status"], CONSTRUCT_STATUS)
        self.assertTrue(record["gate_passed"])
        self.assertFalse(record["claim_eligible"])
        self.assertFalse(record["execution_authorized"])
        for key in (
            "model_calls", "provider_calls", "api_calls", "network_calls",
            "llm_tokens", "native_final_checker_calls_for_admission",
        ):
            self.assertEqual(record["execution_counts"][key], 0)
        self.assertEqual(record["execution_counts"]["real_native_session_resets"], 48)

    def test_twelve_workflows_have_identical_four_cell_authority_grants(self) -> None:
        rows = self.record["workflow_authority_evidence"]
        self.assertEqual(len(rows), 12)
        self.assertEqual(
            [row["source_task_id"] for row in rows],
            [workflow.source_task_id for workflow in WORKFLOWS],
        )
        self.assertEqual(
            Counter(row["domain"] for row in rows),
            Counter({domain: 3 for domain in DOMAINS}),
        )
        all_ordinals = []
        for row in rows:
            with self.subTest(source_task_id=row["source_task_id"]):
                self.assertTrue(row["four_cell_grant_byte_identical"])
                grant = row["authority_grant"]
                grant_sha = grant["grant_sha256"]
                self.assertEqual(
                    grant_sha,
                    sha256_json({key: val for key, val in grant.items() if key != "grant_sha256"}),
                )
                self.assertEqual(len(row["cells"]), 4)
                self.assertEqual(
                    {(cell["pair_role"], cell["host_arm"]) for cell in row["cells"]},
                    {
                        ("benign", "vulnerable"), ("benign", "protected"),
                        ("adversarial", "vulnerable"),
                        ("adversarial", "protected"),
                    },
                )
                self.assertEqual(
                    {cell["authority_grant_sha256"] for cell in row["cells"]},
                    {grant_sha},
                )
                all_ordinals.extend(cell["execution_ordinal"] for cell in row["cells"])
        self.assertEqual(sorted(all_ordinals), list(range(1, 49)))

    def test_benign_and_paired_attack_projections_have_required_direction(self) -> None:
        for row in self.record["workflow_authority_evidence"]:
            with self.subTest(source_task_id=row["source_task_id"]):
                benign = row["benign_ground_truth_projections"]
                attacks = row["paired_relevant_attack_projections"]
                self.assertTrue(benign)
                self.assertTrue(attacks)
                self.assertTrue(all(item["within_authority"] for item in benign))
                self.assertTrue(all(not item["within_authority"] for item in attacks))
                self.assertTrue(all(
                    item["reason"] in {
                        "authority_grant_match", "explicit_unrestricted_metadata"
                    }
                    for item in benign
                ))
                self.assertTrue(all(
                    item["reason"] == "no_matching_user_authority_grant"
                    for item in attacks
                ))
                self.assertFalse(row["native_final_checker_used_for_admission"])
                self.assertFalse(row["claim_eligible"])

    def test_all_native_tools_are_exhaustively_classified_without_default_allow(self) -> None:
        rows = self.record["authority_coverage"]
        self.assertEqual([row["domain"] for row in rows], list(DOMAINS))
        expected_counts = {"banking": 11, "slack": 11, "travel": 28, "workspace": 24}
        for row in rows:
            with self.subTest(domain=row["domain"]):
                self.assertEqual(row["native_tool_count"], expected_counts[row["domain"]])
                self.assertEqual(row["classified_tool_count"], expected_counts[row["domain"]])
                self.assertTrue(row["exhaustive_classification"])
                self.assertFalse(row["unclassified_operation_within_authority"])
                self.assertEqual(row["unclassified_operation_reason"], "operation_unclassified")
                self.assertFalse(row["default_allow"])
                self.assertEqual(
                    row["native_tool_names_sha256"],
                    sha256_json(sorted(binding.name for binding in tool_profile(row["domain"]).tools)),
                )

    def test_every_domain_has_non_authority_allow_and_single_authority_deny(self) -> None:
        probes = self.record["domain_field_sensitivity"]
        self.assertEqual([row["domain"] for row in probes], list(DOMAINS))
        expected = {
            "banking": ("send_money", "amount", "date"),
            "slack": ("send_direct_message", "recipient", "body"),
            "travel": ("create_calendar_event", "end_time", "description"),
            "workspace": ("append_to_file", "file_id", "content"),
        }
        for row in probes:
            with self.subTest(domain=row["domain"]):
                function, authority_field, ordinary_field = expected[row["domain"]]
                self.assertEqual(row["function"], function)
                self.assertEqual(row["authority_field_changed"], authority_field)
                self.assertEqual(row["nonauthority_field_changed"], ordinary_field)
                self.assertTrue(row["nonauthority_change_allowed"])
                self.assertTrue(row["nonauthority_projection_unchanged"])
                self.assertEqual(row["single_authority_field_change_count"], 1)
                self.assertTrue(row["authority_change_denied"])
                self.assertTrue(row["authority_projection_changed"])

    def test_static_and_monkeypatch_evidence_excludes_preview_run_and_checkers(self) -> None:
        purity = self.record["admission_purity"]
        self.assertEqual(purity["static_forbidden_call_sites"], [])
        self.assertFalse(purity["candidate_preview_used_for_admission"])
        self.assertFalse(purity["candidate_run_function_used_for_admission"])
        self.assertFalse(purity["utility_checker_used_for_admission"])
        self.assertFalse(purity["injection_checker_used_for_admission"])
        self.assertEqual(purity["protected_monkeypatch_probe_count"], 12)
        self.assertEqual(purity["protected_monkeypatch_forbidden_call_count"], 0)
        for row in self.record["workflow_authority_evidence"]:
            probe = row["protected_denial_admission_probe"]
            self.assertEqual(probe["monkeypatch_forbidden_call_count"], 0)
            self.assertEqual(
                set(probe["monkeypatch_targets"]),
                {
                    "candidate_preview", "candidate_dispatch", "run_function",
                    "utility_checker", "injection_checker",
                },
            )
        source = inspect.getsource(gate_module)
        self.assertNotIn("domain_witnesses", source)
        self.assertNotIn("session.evaluate_final(", source)

    def test_protected_denial_is_predispatch_state_preserving_and_neutral(self) -> None:
        for row in self.record["workflow_authority_evidence"]:
            probe = row["protected_denial_admission_probe"]
            with self.subTest(source_task_id=row["source_task_id"]):
                self.assertFalse(probe["within_authority"])
                self.assertTrue(probe["denied_pre_dispatch"])
                self.assertFalse(probe["candidate_dispatched"])
                self.assertTrue(probe["native_state_and_trace_unchanged"])
                self.assertEqual(probe["native_dispatch_count_before"], 0)
                self.assertEqual(probe["native_dispatch_count_after"], 0)
                self.assertEqual(probe["feedback"], DENIAL_FEEDBACK)
                self.assertTrue(probe["feedback_condition_neutral"])
                rendered = probe["feedback"].casefold()
                for prohibited in (
                    "adversarial", "protected", "injection", "checker",
                    "security", "policy", "objective", "authority_grant",
                ):
                    self.assertNotIn(prohibited, rendered)

    def test_selector_receipt_has_48_cells_latin_balance_and_condition_blindness(self) -> None:
        selector = self.record["selector_audit"]
        self.assertEqual(selector["workflow_count"], 12)
        self.assertEqual(selector["cell_count"], 48)
        self.assertEqual(selector["execution_ordinals"], list(range(1, 49)))
        self.assertEqual(selector["latin_rotation_counts"], {str(i): 3 for i in range(4)})
        expected_position = {
            "adversarial/protected": 3,
            "adversarial/vulnerable": 3,
            "benign/protected": 3,
            "benign/vulnerable": 3,
        }
        self.assertTrue(all(
            row == expected_position
            for row in selector["coordinate_position_counts"].values()
        ))
        self.assertTrue(selector["condition_blind"])
        self.assertEqual(
            set(selector["condition_blind_view_sha256_by_workflow"]),
            {workflow.workflow_key for workflow in WORKFLOWS},
        )

    def test_receipt_is_canonical_deterministic_and_source_bound(self) -> None:
        second = run_zero_token_integration_gate()
        self.assertEqual(canonical_json_bytes(second), canonical_json_bytes(self.record))
        for relative, expected in self.record["implementation_bindings"].items():
            self.assertEqual(hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(), expected)
        self.assertEqual(
            self.record["gate_sha256"],
            sha256_json({key: val for key, val in self.record.items() if key != "gate_sha256"}),
        )
        canonical_json_bytes(self.record)

    def test_strict_validator_rejects_semantic_and_digest_forgery(self) -> None:
        self.assertEqual(validate_integration_gate(self.record), self.record)
        mutations = []

        extra = copy.deepcopy(self.record)
        extra["unexpected"] = False
        mutations.append(extra)

        grant = copy.deepcopy(self.record)
        grant["workflow_authority_evidence"][0]["cells"][0]["authority_grant_sha256"] = "0" * 64
        mutations.append(grant)

        projection = copy.deepcopy(self.record)
        projection["workflow_authority_evidence"][0]["paired_relevant_attack_projections"][0]["within_authority"] = True
        mutations.append(projection)

        coverage = copy.deepcopy(self.record)
        coverage["authority_coverage"][0]["default_allow"] = True
        mutations.append(coverage)

        field = copy.deepcopy(self.record)
        field["domain_field_sensitivity"][0]["authority_change_denied"] = False
        mutations.append(field)

        purity = copy.deepcopy(self.record)
        purity["admission_purity"]["candidate_run_function_used_for_admission"] = True
        mutations.append(purity)

        selector = copy.deepcopy(self.record)
        selector["selector_audit"]["latin_rotation_counts"]["0"] = 4
        mutations.append(selector)

        scope = copy.deepcopy(self.record)
        scope["scope"]["native_final_checker_is_gate_admission_input"] = True
        mutations.append(scope)

        digest = copy.deepcopy(self.record)
        digest["gate_sha256"] = "0" * 64
        mutations.append(digest)

        # Recompute all visible digests around a forged source row.  Strict
        # validation still compares it to the frozen contracts.
        forged_source = copy.deepcopy(self.record)
        source_row = forged_source["source_bindings"]["workflows"][0]
        source_row["fixture_sha256"] = "0" * 64
        source_row["binding_sha256"] = sha256_json({
            key: val for key, val in source_row.items() if key != "binding_sha256"
        })
        bindings = forged_source["source_bindings"]
        bindings["bindings_sha256"] = sha256_json({
            key: val for key, val in bindings.items() if key != "bindings_sha256"
        })
        forged_source["gate_sha256"] = sha256_json({
            key: val for key, val in forged_source.items() if key != "gate_sha256"
        })
        mutations.append(forged_source)

        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=index):
                with self.assertRaises(IntegrationGateError):
                    validate_integration_gate(mutation)

    def test_receipt_contains_no_outcome_oracle_witness(self) -> None:
        scope = self.record["scope"]
        self.assertFalse(scope["outcome_oracle_is_gate_admission_input"])
        self.assertFalse(scope["protected_candidate_preview_is_gate_admission_input"])
        self.assertFalse(scope["native_final_checker_is_gate_admission_input"])
        rendered = json.dumps(self.record, sort_keys=True).casefold()
        for prohibited in (
            "protected_post_deny_native_security",
            "vulnerable_exact_native_security",
            "benign_native_utility",
            "native_witness_row_sha256",
            "expected_outcome",
            "expected_direction_table",
        ):
            self.assertNotIn(prohibited, rendered)


if __name__ == "__main__":
    unittest.main()
