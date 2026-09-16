"""Fail-closed tests for the separate three-tier formal protocol gate."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v3.contract import digest
from agentmembrane.host_v2.rq1_collab_v6.contract import make_config as make_v6_config
from agentmembrane.host_v2.rq1_collab_v6.attack_spec import compile_attack_spec
from agentmembrane.host_v2.rq1_collab_v1.native_goals import (
    public_native_goal_record,
)
from agentmembrane.host_v2.rq1_three_tier_formal_v1.contract import (
    CELL_COUNT,
    FORMAL_PROTOCOL,
    LEVEL_BINDINGS,
    MODEL_PROFILES,
    TASK_COUNT,
    make_cells,
    validate_cells,
)
from agentmembrane.host_v2.rq1_three_tier_formal_v1 import runner as formal_runner
from agentmembrane.host_v2.rq1_three_tier_formal_v1.gate import (
    _with_digest,
    code_bundle_sha256,
    file_binding,
    preflight_status,
    validate_evidence_admission,
    validate_final_goal_assignment,
    validate_final_qid,
    validate_h_output_contract,
    validate_route_runtime_binding,
    validate_runtime_qualification,
)


PROJECT = Path(__file__).resolve().parents[2]
STUDY = PROJECT / "experiments/host_boundary_v2/rq1_three_tier_large_scale"
FORMAL = Path(os.environ.get(
    "RQ1_FORMAL_CANDIDATE_ROOT",
    STUDY / "formal_candidate_20260915",
)).expanduser().resolve()
AGENTDOJO_SOURCE = Path(os.environ.get(
    "AGENTDOJO_SOURCE_ROOT",
    PROJECT / "data/host_boundary_v2/upstream/agentdojo",
)).expanduser().resolve()


def task_bindings() -> list[dict]:
    suites = ("banking", "slack", "travel", "workspace")
    return [{
        "task_key": f"{suites[index % 4]}/user_task_{index}",
        "goal_cluster_id": (
            f"{suites[index % 4]}/injection_task_{index % 9}/" + "a" * 64
        ),
        "formal_task_binding_sha256": f"{index + 1:064x}",
    } for index in range(TASK_COUNT)]


class FormalConditionContractTests(unittest.TestCase):
    def test_exact_46_by_six_H_E_matrix(self):
        tasks = task_bindings()
        cells = make_cells(tasks, MODEL_PROFILES)
        self.assertEqual(len(cells), CELL_COUNT)
        self.assertEqual(len({cell["episode_id"] for cell in cells}), CELL_COUNT)
        self.assertEqual({cell["topology"] for cell in cells}, {"H_E"})
        self.assertEqual({cell["repeat"] for cell in cells}, {0})
        self.assertEqual({(cell["level"], cell["regime"])
                          for cell in cells}, {
            (level, regime) for level in LEVEL_BINDINGS
            for regime in ("honest", "malicious")
        })

    def test_high_runtime_A4_claims_no_ladder_level_and_records_A5_analog(self):
        self.assertEqual(LEVEL_BINDINGS["high"]["runtime_level"], "A4")
        self.assertIsNone(
            LEVEL_BINDINGS["high"]["canonical_ladder_level_claimed"])
        self.assertEqual(
            LEVEL_BINDINGS["high"]["legacy_canonical_analog"], "A5")

    def test_optional_S_or_other_model_profile_is_rejected(self):
        tasks = task_bindings()
        wrong = copy.deepcopy(MODEL_PROFILES)
        wrong["S"] = copy.deepcopy(wrong["H"])
        with self.assertRaisesRegex(ValueError, "exact_actor_model_profiles"):
            make_cells(tasks, wrong)
        wrong = copy.deepcopy(MODEL_PROFILES)
        wrong["E"]["reasoning_effort"] = "medium"
        with self.assertRaisesRegex(ValueError, "exact_registered_H_E"):
            make_cells(tasks, wrong)

    def test_partial_or_duplicate_matrix_is_rejected(self):
        tasks = task_bindings()
        cells = make_cells(tasks, MODEL_PROFILES)
        with self.assertRaisesRegex(ValueError, "exact_276"):
            validate_cells(cells[:-1], tasks, MODEL_PROFILES)
        forged = copy.deepcopy(cells)
        forged[-1] = copy.deepcopy(forged[0])
        with self.assertRaisesRegex(ValueError, "duplicate|incomplete"):
            validate_cells(forged, tasks, MODEL_PROFILES)

    def test_v6_still_refuses_formal_mode(self):
        with self.assertRaisesRegex(ValueError, "formal_execution_not_admitted"):
            make_v6_config("a" * 64, "task", "H_E", "low", "honest",
                           mode="formal_live", models=MODEL_PROFILES)


class ProductionFrozenInputTests(unittest.TestCase):
    def test_current_H_contract_is_46_task_H_E_and_condition_invariant(self):
        contract = json.loads((FORMAL / "H-output-contract-current-assignment.json")
                              .read_text(encoding="utf-8"))
        validate_h_output_contract(contract)
        self.assertEqual(contract["actor_set"], ["H", "E"])
        self.assertEqual(contract["task_count"], 46)
        self.assertFalse(contract["goal_assignment_formal_activation"])
        self.assertEqual(sum(row["H_output_contract"]["condition_count_checked"]
                             for row in contract["tasks"]), 276)
        for row in contract["tasks"]:
            prompt = row["H_output_contract"]["system_prompt"]
            self.assertNotIn("S final", prompt)
            self.assertNotIn("H and S", prompt)
            self.assertNotIn("If S", prompt)

    def test_current_route_runtime_binding_is_complete_and_no_secret(self):
        binding = json.loads((FORMAL / "route-runtime-binding.json")
                             .read_text(encoding="utf-8"))
        validate_route_runtime_binding(binding)
        self.assertFalse(binding["contains_credentials"])
        self.assertEqual(binding["formal_lifecycle_policy"]["workers"], 1)
        self.assertEqual(binding["formal_lifecycle_policy"]["request_retry"], 0)
        self.assertEqual(binding["research_sample_count"], 0)

    def test_current_preflight_passes_available_gates_and_stays_blocked(self):
        status = json.loads((FORMAL / "formal-preflight.json")
                            .read_text(encoding="utf-8"))
        self.assertTrue(status["checks"]["candidate_preregistration_valid"])
        self.assertTrue(status["checks"]["goal_balance_candidate_valid"])
        self.assertTrue(status["checks"]["H_output_contract_valid"])
        self.assertTrue(status["checks"]["switched_route_runtime_binding_valid"])
        self.assertFalse(status["all_gates_passed"])
        self.assertFalse(status["formal_manifest_created"])
        self.assertFalse(status["formal_ready"])
        self.assertEqual(status["research_sample_count"], 0)
        self.assertIn("balanced_attack_goal_assignment_not_frozen",
                      status["blocking_gates"])
        self.assertIn("H_contract_not_compiled_from_final_goal_assignment",
                      status["blocking_gates"])

    def test_live_preflight_accepts_integrated_lifecycle_but_stays_blocked(self):
        status = preflight_status(
            candidate_identity_path=FORMAL / "study-identity.json",
            candidate_pool_path=FORMAL / "task-pool.json",
            candidate_analysis_path=FORMAL / "statistical-analysis-plan.json",
            goal_balance_candidate_path=FORMAL / "goal-balance-candidate.json",
            h_contract_path=(FORMAL /
                             "H-output-contract-current-assignment.json"),
            route_binding_path=FORMAL / "route-runtime-binding.json",
            final_goal_assignment_path=FORMAL / "final-goal-assignment.json",
            governance_path=FORMAL / "governance-decision.json",
            final_analysis_path=(FORMAL /
                                 "final-statistical-analysis-plan.json"),
            final_qid_path=(STUDY / "qid_formal_adjudication_20260915/"
                            "final-adjudication.json"),
            evaluator_qualification_path=(
                FORMAL / "formal-evaluator-qualification.json"),
            runtime_qualification_path=(
                FORMAL / "formal-runtime-qualification.json"),
        )
        self.assertTrue(status["checks"][
            "formal_per_cell_proxy_lifecycle_integrated"])
        self.assertNotIn("formal_per_cell_proxy_lifecycle_not_integrated",
                         status["blocking_gates"])
        self.assertIn("formal_runtime_not_qualified",
                      status["blocking_gates"])
        self.assertFalse(status["formal_ready"])


class GoalAndQIDGateTests(unittest.TestCase):
    def setUp(self):
        self._contracts_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._contracts_tmp.cleanup)
        self.contract_root = Path(self._contracts_tmp.name)
        self._qid_call = 0
        h = json.loads((FORMAL / "H-output-contract-current-assignment.json")
                       .read_text(encoding="utf-8"))
        self.h_contract = h
        self.h_contract_path = FORMAL / "H-output-contract-current-assignment.json"
        self.h_rows = h["tasks"]
        original_goal_balance = json.loads(
            (FORMAL / "goal-balance-candidate.json").read_text(encoding="utf-8"))
        self.goal_balance = original_goal_balance
        self.goal_balance_path = self.contract_root / "goal-balance.json"
        self.goal_balance_path.write_text(
            json.dumps(self.goal_balance, sort_keys=True, separators=(",", ":"))
            + "\n", encoding="utf-8")
        assignments = []
        goal_records = {}
        for candidate in self.goal_balance["assignments"]:
            suite = candidate["suite"]
            goal_id = candidate["goal_id"]
            spec_hash = candidate["attack_spec_sha256"]
            key = (suite, goal_id)
            if key not in goal_records:
                goal_records[key] = public_native_goal_record(
                    str(AGENTDOJO_SOURCE.resolve()), suite, goal_id)
            source = copy.deepcopy(goal_records[key])
            self.assertEqual(compile_attack_spec(source["goal"])["spec_sha256"],
                             spec_hash)
            assignments.append({
                "task_key": candidate["task_key"],
                "goal_id": goal_id,
                "goal_source_binding": source,
                "attack_spec_sha256": spec_hash,
                "goal_cluster_id": candidate["goal_cluster_id"],
            })
        body = {
            "schema_version": "rq1-agentdojo-three-tier-formal-goal-assignment/1",
            "formal_activation": True,
            "outcome_blind": True,
            "assignment_uses_outcomes": False,
            "task_count": 46,
            "study_identity_sha256": self.goal_balance[
                "study_identity_sha256"],
            "task_pool_sha256": self.goal_balance["task_pool_sha256"],
            "balance_status": "frozen_and_independently_reviewed",
            "task_goal_compatibility_reviewed": True,
            "cluster_aware_analysis_required": True,
            "goal_cluster_key": "suite/goal_id/attack_spec_sha256",
            "cross_goal_generalization_permitted": False,
            "prior_campaign_goal_reuse_count": 0,
            "distinct_goal_cluster_count": 18,
            "goal_balance_candidate": file_binding(self.goal_balance_path),
            "goal_balance_sha256": self.goal_balance["goal_balance_sha256"],
            "assignments": assignments,
        }
        self.goals = _with_digest(body, "goal_assignment_sha256")

    def qid(self, h_contract=None, h_contract_path=None, *, include_s=False) -> dict:
        h_contract = self.h_contract if h_contract is None else h_contract
        h_contract_path = (self.h_contract_path if h_contract_path is None
                           else h_contract_path)
        goals = {row["task_key"]: row for row in self.goals["assignments"]}
        self._qid_call += 1
        contract_dir = self.contract_root / f"qid-{self._qid_call}"
        contract_dir.mkdir()
        observer = PROJECT / "agentmembrane/host_v2/rq1_three_tier_formal_v1/gate.py"
        observer_source = {"observer_id": "formal_fixture_observer",
                           **file_binding(observer)}
        h_source_binding = file_binding(h_contract_path)
        rows = []
        for h in h_contract["tasks"]:
            goal = goals[h["task_key"]]
            source = h["source_record"]
            goal_source = goal["goal_source_binding"]
            source_binding = {
                "suite": source["suite"],
                "task_id": source["task_id"],
                "initial_state_sha256": source["initial_state_sha256"],
                "prompt_sha256": source["prompt_sha256"],
                "task_class_source_sha256": source["class_source_sha256"],
                "assigned_goal_id": goal["goal_id"],
                "assigned_goal_sha256": goal_source["goal_sha256"],
                "assigned_goal_class_source_sha256": goal_source[
                    "class_source_sha256"],
                "attack_spec_sha256": goal["attack_spec_sha256"],
                "goal_cluster_id": goal["goal_cluster_id"],
                "tool_schema_sha256": source["tool_schema_sha256"],
            }
            common = {
                "formal_activation": True,
                "outcome_blind": True,
                "task_key": h["task_key"],
                "source_binding": source_binding,
                "formal_task_source_binding_sha256": h[
                    "formal_task_source_binding_sha256"],
                "H_output_contract_sha256": h["H_output_contract_sha256"],
                "goal_assignment_sha256": self.goals[
                    "goal_assignment_sha256"],
                "observer_sources": [observer_source],
            }
            q_units = [{
                "atom_id": "answer_atom_0",
                "description": "registered exact fixture answer atom",
                "observer_id": "formal_fixture_observer",
                "evidence_rule": {"kind": "exact_fixture_rule"},
                "unknown_on_missing": True,
            }]
            q_contract = _with_digest({
                "schema_version": "rq1-formal-Q-contract/1", **common,
                "units": q_units, "unit_count": len(q_units),
                "unit_ids_sha256": digest(["answer_atom_0"]),
                "conjunction_rule": (
                    "all_registered_atoms_required_for_task_success"),
                "unknown_atom_rule": (
                    "pre_registered_unknown_not_posthoc_drop"),
            }, "contract_sha256")
            facts = [
                {"fact_id": "fact_0", "source_path": "/fixture/0", "severity": 1},
                {"fact_id": "fact_1", "source_path": "/fixture/1", "severity": 2},
            ]
            recipients = [
                {"recipient_id": "role:E", "kind": "role", "role": "role:E"},
                {"recipient_id": "role:H", "kind": "role", "role": "role:H"},
            ]
            recipient_roles = ["role:H", "role:E"]
            if include_s:
                recipients.append({"recipient_id": "role:S", "kind": "role",
                                   "role": "role:S"})
                recipients.sort(key=lambda row: row["recipient_id"])
                recipient_roles.append("role:S")
            legal = [{"fact_id": "fact_0", "recipient_id": "role:H"}]
            empty = []
            severity = [{"fact_id": row["fact_id"], "severity": row["severity"]}
                        for row in facts]
            i_contract = _with_digest({
                "schema_version": "rq1-formal-I-contract/1", **common,
                "facts": facts, "fact_count": len(facts),
                "fact_universe_sha256": digest(facts),
                "recipients": recipients, "recipient_count": len(recipients),
                "recipient_universe_sha256": digest(recipients),
                "recipient_roles": recipient_roles,
                "legal_purpose_cells": legal,
                "legal_cells_excluded": len(legal),
                "legal_purpose_cells_sha256": digest(legal),
                "I_cells": len(facts) * len(recipients) - len(legal),
                "severity_rule": "per_fact_registered_integer_0_to_4",
                "severity_policy_sha256": digest(severity),
                "empty_fact_exclusions": empty,
                "empty_fact_exclusions_sha256": digest(empty),
                "semantic_nonarrival_rule": (
                    "semantic_nonarrival_without_proof_is_unknown_not_zero"),
                "lower_upper_reporting_rule": (
                    "sharp_lower_upper_bounds_required_point_only_if_identified"),
                "empty_fact_rule": (
                    "source_verified_zero_information_empty_fact_excluded_pre_run_otherwise_unknown"),
                "equal_value_attribution_rule": (
                    "source_lineage_required_value_equality_not_receipt"),
            }, "contract_sha256")
            d_units = [{"unit_id": "state_0", "state_path": "/fixture/state",
                        "effect_kind": "mutation", "severity": 2}]
            d_severity = [{"unit_id": "state_0", "severity": 2}]
            d_contract = _with_digest({
                "schema_version": "rq1-formal-D-contract/1", **common,
                "trajectory_units": d_units, "unit_count": len(d_units),
                "trajectory_unit_universe_sha256": digest(d_units),
                "allowed_effects": [], "allowed_effects_sha256": digest([]),
                "exclusions": [], "exclusions_sha256": digest([]),
                "severity_rule": (
                    "per_trajectory_unit_registered_integer_0_to_4"),
                "severity_policy_sha256": digest(d_severity),
                "intermediate_harm_retention_rule": (
                    "confirmed_intermediate_harm_retained_after_recovery"),
                "unknown_state_rule": "unknown_not_zero",
            }, "contract_sha256")
            references = {}
            for label, contract in (("Q", q_contract), ("I", i_contract),
                                    ("D", d_contract)):
                path = contract_dir / (h["task_key"].replace("/", "-")
                                       + f"-{label}.json")
                path.write_text(json.dumps(contract, sort_keys=True,
                                           separators=(",", ":")) + "\n",
                                encoding="utf-8")
                references[label] = {
                    "schema_version": contract["schema_version"],
                    **file_binding(path),
                    "contract_sha256": contract["contract_sha256"],
                }
            rows.append({
                "task_key": h["task_key"],
                "readiness_class": "formal_ready",
                "blockers": [],
                "source_binding": source_binding,
                "H_output_contract": {
                    "schema_version": h_contract["schema_version"],
                    **h_source_binding,
                    "required_fields_sha256": h["H_output_contract_sha256"],
                    "incomplete_rule": "report_incomplete_never_guess",
                },
                "Q_contract": references["Q"],
                "I_contract": references["I"],
                "D_contract": references["D"],
            })
        body = {
            "schema_version": "rq1-qid-formal-adjudication/1",
            "formal_activation": True,
            "outcome_blind": True,
            "independent_review_completed": True,
            "review_uses_outcomes": False,
            "legacy_evidence_eligible": False,
            "actor_set": ["H", "E"],
            "study_identity_sha256": h_contract[
                "study_identity_sha256"],
            "task_pool_sha256": h_contract["task_pool_sha256"],
            "H_contract_sha256": h_contract["H_contract_sha256"],
            "goal_balance_sha256": self.goals["goal_balance_sha256"],
            "goal_assignment_sha256": self.goals["goal_assignment_sha256"],
            "task_count": 46,
            "tasks": rows,
        }
        return _with_digest(body, "adjudication_sha256")

    def test_final_goal_assignment_requires_exact_audited_18_clusters(self):
        validate_final_goal_assignment(
            self.goals, task_keys=[row["task_key"] for row in self.h_rows])
        forged = copy.deepcopy(self.goals)
        forged["distinct_goal_cluster_count"] = 17
        forged = _with_digest({k: v for k, v in forged.items()
                               if k != "goal_assignment_sha256"},
                              "goal_assignment_sha256")
        with self.assertRaisesRegex(ValueError, "not_activated"):
            validate_final_goal_assignment(
                forged, task_keys=[row["task_key"] for row in self.h_rows])

    def test_H_E_QID_rejects_any_role_S_contract(self):
        qid = self.qid()
        validate_final_qid(qid, h_contract=self.h_contract,
                           final_goal_assignment=self.goals)
        forged = self.qid(include_s=True)
        with self.assertRaisesRegex(ValueError, "contains_role_S"):
            validate_final_qid(forged, h_contract=self.h_contract,
                               final_goal_assignment=self.goals)


class EvidenceIsolationTests(unittest.TestCase):
    def test_detached_legacy_or_rehashed_envelope_has_no_public_admission_path(self):
        legacy = {
            "schema_version": "rq1-evidence/6",
            "protocol_version": "rq1-three-actor/6",
            "formal_manifest_sha256": "a" * 64,
            "legacy_source": False,
            "allocated_after_manifest_registration": True,
            "episode_id": "new-formal-cell",
        }
        fresh = {
            "schema_version": "rq1-evidence-formal/1",
            "protocol_version": FORMAL_PROTOCOL,
            "formal_manifest_sha256": "a" * 64,
            "legacy_source": False,
            "allocated_after_manifest_registration": True,
            "episode_id": "new-formal-cell",
        }
        # The old positional (detached evidence, manifest) API is gone. Even a
        # self-consistently rehashed dict cannot bypass sealed-run admission.
        for detached in (legacy, fresh):
            with self.subTest(schema=detached["schema_version"]):
                with self.assertRaises(TypeError):
                    validate_evidence_admission(detached, {"cells": []})

    def test_public_admission_delegates_to_the_sealed_reader(self):
        manifest, bundle = {"manifest_sha256": "a" * 64}, object()
        evidence = {"formal_evidence_sha256": "b" * 64}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "seal.json").write_text(
                json.dumps({"episode_id": "new-formal-cell"}), encoding="utf-8")
            with patch(
                    "agentmembrane.host_v2.rq1_three_tier_formal_v1.runtime_impl."
                    "validate_sealed_formal_run",
                    return_value={"formal_evidence": evidence}) as reader:
                self.assertEqual(validate_evidence_admission(
                    run_root=root,
                    execution_seal_sha256="c" * 64,
                    manifest=manifest,
                    bundle=bundle,
                ), evidence)
            reader.assert_called_once_with(
                root,
                expected_seal_hash="c" * 64,
                manifest=manifest,
                episode_id="new-formal-cell",
                bundle=bundle,
            )


class FormalManifestAssemblyTests(GoalAndQIDGateTests):
    """Keep the formal assembly boundary closed to synthetic approvals."""

    @staticmethod
    def write(path: Path, value: dict) -> None:
        path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                   separators=(",", ":")) + "\n",
                        encoding="utf-8")

    def test_fake_runtime_claim_without_proxy_receipt_cannot_qualify(self):
        identity = json.loads((FORMAL / "study-identity.json").read_text())
        pool = json.loads((FORMAL / "task-pool.json").read_text())
        candidate_analysis = json.loads(
            (FORMAL / "statistical-analysis-plan.json").read_text())
        route_binding = json.loads(
            (FORMAL / "route-runtime-binding.json").read_text())
        h_contract = json.loads(
            (FORMAL / "H-output-contract-current-assignment.json").read_text())

        goal_by_task = {row["task_key"]: row
                        for row in self.goals["assignments"]}
        h_contract["goal_assignment_formal_activation"] = True
        for row in h_contract["tasks"]:
            goal = goal_by_task[row["task_key"]]
            row["goal_id"] = goal["goal_id"]
            row["public_goal_sha256"] = digest(goal["goal_source_binding"])
            row["attack_spec_sha256"] = goal["attack_spec_sha256"]
            row["goal_cluster_id"] = goal["goal_cluster_id"]
            binding = {key: copy.deepcopy(row[key]) for key in (
                "task_key", "goal_id", "source_record",
                "public_user_request_sha256", "public_goal_sha256",
                "attack_spec_sha256", "goal_cluster_id",
                "task_policy_sha256",
            )}
            row["formal_task_source_binding_sha256"] = digest(binding)

        governance_body = {
            "schema_version": "rq1-agentdojo-three-tier-governance-decision/1",
            "candidate_study_identity_sha256": identity["study_identity_sha256"],
            "activation_scope": "registered_noncanonical_RQ1_three_tier_substudy",
            "construct_id": "external_agent_business_tool_authority_gradient",
            "canonical_rq1_claim_permitted": False,
            "canonical_full_ladder_answerable": False,
            "global_A_star_identifiable": False,
            "high_runtime_level": "A4",
            "high_implementation_profile": "A4_ambient_experimental_high",
            "high_legacy_canonical_analog": "A5",
            "host_legacy_canonical_analog": "A5",
            "canonical_ladder_level_claimed": None,
            "host_mediated_endpoint_reported_separately": True,
            "legacy_evidence_eligible": False,
            "formal_activation": True,
        }
        governance = _with_digest(governance_body,
                                  "governance_decision_sha256")
        final_analysis = copy.deepcopy(candidate_analysis)
        final_analysis.pop("analysis_plan_sha256")
        final_analysis["formal_activation"] = True
        final_analysis["goal_assignment"] = {
            "status": "frozen_and_formally_adjudicated",
            "goal_assignment_sha256": self.goals["goal_assignment_sha256"],
            "goal_balance_sha256": self.goals["goal_balance_sha256"],
            "goal_cluster_count": 18,
            "prior_campaign_goal_reuse_count": 0,
            "goal_cluster_key": "suite/goal_id/attack_spec_sha256",
            "cross_goal_generalization_permitted": False,
        }
        final_analysis["verdict_rule"]["status"] = (
            "activated_before_first_formal_actor")
        final_analysis = _with_digest(final_analysis, "analysis_plan_sha256")

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            final_goal_path = root / "final-goals.json"
            self.write(final_goal_path, self.goals)
            h_contract["source_inputs"]["goal_assignments"] = file_binding(
                final_goal_path)
            h_contract.pop("H_contract_sha256")
            h_contract = _with_digest(h_contract, "H_contract_sha256")
            h_path = root / "H.json"
            self.write(h_path, h_contract)
            qid = self.qid(h_contract, h_path)
            runtime_report = {
                "schema_version": (
                    "rq1-agentdojo-three-tier-formal-runtime-test-report/1"),
                "code_bundle_sha256": code_bundle_sha256(),
                "real_model_calls": 0,
                "all_required_paths_passed": True,
                "H_E_action_schema_contains_S": False,
                "formal_evidence_envelope_passed": True,
                "fresh_proxy_per_cell_lifecycle_passed": True,
            }
            runtime_report_path = root / "runtime-report.json"
            self.write(runtime_report_path, runtime_report)
            runtime = _with_digest({
                "schema_version": "rq1-agentdojo-three-tier-formal-runtime-qualification/1",
                "formal_protocol_version": FORMAL_PROTOCOL,
                "code_bundle_sha256": code_bundle_sha256(),
                "fake_transport_only": True,
                "real_model_calls": 0,
                "formal_runner": file_binding(Path(formal_runner.__file__)),
                "fake_transport_report": file_binding(runtime_report_path),
                "actor_set": ["H", "E"],
                "action_schemas": formal_runner.FORMAL_ACTION_SCHEMAS,
                "action_schemas_sha256": digest(
                    formal_runner.FORMAL_ACTION_SCHEMAS),
                "formal_evidence_schema": formal_runner.FORMAL_EVIDENCE_SCHEMA,
                "v6_evidence_admitted_directly": False,
                "H_E_action_schema_tested": True,
                "formal_evidence_envelope_tested": True,
                "fresh_proxy_per_cell_lifecycle_tested": True,
                "all_required_paths_passed": True,
                "legacy_evidence_rejection_tested": True,
                "manifest_tamper_rejection_tested": True,
                "formal_activation": True,
            }, "runtime_qualification_sha256")

            self.assertNotIn("production_proxy_lifecycle_receipt", runtime)
            with self.assertRaisesRegex(
                    ValueError, "formal_runtime_not_qualified"):
                validate_runtime_qualification(
                    runtime,
                    code_sha256=code_bundle_sha256(),
                    route_runtime_binding=route_binding,
                )

    def test_formal_runtime_entry_is_wired_but_requires_activated_manifest(self):
        self.assertTrue(formal_runner.FORMAL_CORE_RUNTIME_IMPLEMENTED)
        self.assertTrue(formal_runner.FORMAL_RUNTIME_IMPLEMENTED)
        self.assertTrue(
            formal_runner.FORMAL_PER_CELL_PROXY_LIFECYCLE_IMPLEMENTED)
        with self.assertRaisesRegex(RuntimeError, "activated_formal_manifest"):
            formal_runner.run_formal_cell()
        with self.assertRaises(ValueError):
            formal_runner.run_formal_cell(
                manifest={}, episode_id="fixture", run_parent=Path("run"))


if __name__ == "__main__":
    unittest.main()
