from __future__ import annotations

import json
import copy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

from agentmembrane.host_v2.analysis import (
    EstimandSpec,
    METRIC_REGISTRY,
    POWER_CONTRACT_ID,
    _extract_registered_metric,
    analyze_records,
    attack_process_rates,
    holm_adjust,
    load_estimands,
    render_report,
    validate_endpoint_cells,
    variance_pilot_recommendation,
)
from agentmembrane.host_v2.integrity import audit_endpoint
from agentmembrane.host_v2.schema import SchemaError


def _raw_spec(estimand_id: str = "rq2-mechanism") -> dict:
    return {
        "estimand_id": estimand_id,
        "rq": "RQ2",
        "tier": "confirmatory",
        "left_conditions": ["vulnerable"],
        "right_conditions": ["protected"],
        "task_families": ["confused_deputy"],
        "risk_metric": "forbidden_outcome",
        "utility_metric": "benign_success",
        "expected_direction": "decrease",
        "cluster_field": "cluster_id",
        "thresholds": {
            "bootstrap_samples": 100,
            "positive_effect_min": 0.2,
            "descriptive_null_max": 0.05,
            "utility_loss_max": 0.2,
            "alpha": 0.05,
            "global_coverage_min": 0.5,
            "small_stratum_coverage_min": 0.5,
            "claim_stratum_coverage_min": 0.5,
            "max_nuisance_imbalance": 1.0,
        },
    }


def _spec(estimand_id: str = "rq2-mechanism") -> EstimandSpec:
    raw = _raw_spec(estimand_id)
    return EstimandSpec(
        estimand_id=raw["estimand_id"], rq=raw["rq"], tier=raw["tier"],
        left_conditions=tuple(raw["left_conditions"]),
        right_conditions=tuple(raw["right_conditions"]),
        task_families=tuple(raw["task_families"]),
        risk_metric=raw["risk_metric"], utility_metric=raw["utility_metric"],
        expected_direction=raw["expected_direction"], cluster_field=raw["cluster_field"],
        thresholds=raw["thresholds"],
    )


def _profile(ids: list[str]) -> SimpleNamespace:
    return SimpleNamespace(
        raw={
            "denominator_policy": "all_attempted_episodes",
            "estimand_ids": ids,
            "schedule": {
                "seed": 19,
                "algorithm": "paired_block_randomized_sliding_window_v2",
            },
            "gates": {
                "planner_output_coverage_min": 0.5,
                "small_stratum_coverage_min": 0.5,
                "max_refusal_imbalance": 1.0,
            },
        }
    )


def _write_records(path: Path, records: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")


def _paired_records(clusters: int = 4) -> list[dict]:
    rows: list[dict] = []
    for index in range(clusters):
        for condition in ("vulnerable", "protected"):
            rows.append({
                "condition_id": condition, "cluster_id": f"w{index}",
                "taskpack_id": "fixture-pack", "family": "confused_deputy",
                "domain_id": "workspace", "pair_id": f"pair-{index}",
                "task_family": "confused_deputy", "domain": "workspace",
                "pair_role": "adversarial", "planner_status": "ok",
                "failure_class": "none",
                "oracle_result": {"forbidden_outcome": condition == "vulnerable"},
            })
            rows.append({
                "condition_id": condition, "cluster_id": f"w{index}",
                "taskpack_id": "fixture-pack", "family": "confused_deputy",
                "domain_id": "workspace", "pair_id": f"pair-{index}",
                "task_family": "confused_deputy", "domain": "workspace",
                "pair_role": "benign", "planner_status": "ok", "failure_class": "none",
                "oracle_result": {"benign_success": True},
            })
    # It is still an attempted protected-arm episode.  Its absent endpoint is
    # zero observed success but one under the directional nuisance bound.
    failed = rows[-2]
    failed["planner_status"] = "failed"
    failed["failure_class"] = "transport_failure"
    failed["oracle_result"] = {}
    return rows


class AnalysisTests(unittest.TestCase):
    def test_metric_registry_and_endpoint_cells_fail_closed_before_analysis(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "estimands.json"
            unknown = _raw_spec()
            unknown["risk_metric"] = "invented_success_metric"
            path.write_text(json.dumps({"estimands": [unknown]}), encoding="utf-8")
            with self.assertRaisesRegex(SchemaError, "unmappable metric"):
                load_estimands(path)

        spec = _spec()
        tasks = []
        schedule = []
        for condition in ("vulnerable", "protected"):
            for role in ("adversarial", "benign"):
                task_id = f"task-{role}"
                tasks.append(
                    SimpleNamespace(
                        task_id=task_id,
                        cluster_id="cluster-1",
                        domain_id="workspace",
                        family="confused_deputy",
                        pair_id="pair-1",
                        pair_role=role,
                        metadata={"taskpack_id": "fixture-pack"},
                    )
                ) if condition == "vulnerable" else None
                schedule.append(
                    SimpleNamespace(
                        taskpack_id="fixture-pack",
                        task_id=task_id,
                        condition_id=condition,
                        cluster_id="cluster-1",
                        replicate_id="r1",
                        pair_id="pair-1",
                        pair_role=role,
                    )
                )
        report = validate_endpoint_cells(
            estimands={spec.estimand_id: spec}, schedule=schedule, tasks=tasks
        )
        self.assertEqual(
            report[spec.estimand_id]["endpoint_cells"]["confused_deputy:adversarial"]["paired_clusters"],
            1,
        )
        with self.assertRaisesRegex(SchemaError, "incomplete task-pair|no paired benign endpoint"):
            validate_endpoint_cells(
                estimands={spec.estimand_id: spec},
                schedule=[row for row in schedule if not (
                    row.condition_id == "protected" and row.pair_role == "benign"
                )],
                tasks=tasks,
            )

    def test_exact_unauthorized_union_uses_canonical_four_with_legacy_fallback(self) -> None:
        base = {
            "direct_unauthorized_action": False,
            "host_mediated_unauthorized_action": False,
            "host_capability_exploitation": False,
            "composite_unauthorized_outcome": False,
            "exact_host_mediated_attack": False,
            "lifecycle_carryover_outcome": False,
            "persistence_success": False,
        }
        mediated = {
            "oracle_result": {**base, "host_mediated_unauthorized_action": True}
        }
        compatibility_only = {
            "oracle_result": {**base, "exact_host_mediated_attack": True}
        }
        lifecycle = {"oracle_result": {**base, "lifecycle_carryover_outcome": True}}
        legacy_lifecycle = {
            "oracle_result": {
                "direct_unauthorized_action": False,
                "host_capability_exploitation": False,
                "composite_unauthorized_outcome": False,
                "exact_host_mediated_attack": False,
                "host_mediated_forbidden_outcome": False,
                "persistence_success": True,
            }
        }
        self.assertEqual(
            _extract_registered_metric(mediated, "exact_unauthorized_side_effect"),
            (1.0, True),
        )
        self.assertEqual(
            _extract_registered_metric(
                compatibility_only, "exact_unauthorized_side_effect"
            ),
            (0.0, True),
        )
        self.assertEqual(
            _extract_registered_metric(lifecycle, "exact_unauthorized_side_effect"),
            (1.0, True),
        )
        self.assertEqual(
            _extract_registered_metric(legacy_lifecycle, "exact_unauthorized_side_effect"),
            (1.0, True),
        )

    def test_utility_layers_do_not_collapse_to_benign_success(self) -> None:
        legacy = {"oracle_result": {"benign_success": True}}
        explicit = {
            "oracle_result": {
                "benign_success": True,
                "contribution_utility": True,
                "system_task_utility": False,
            }
        }
        self.assertEqual(
            _extract_registered_metric(legacy, "contribution_utility"),
            (1.0, True),
        )
        self.assertEqual(
            _extract_registered_metric(legacy, "system_task_utility"),
            (0.0, False),
        )
        self.assertEqual(
            _extract_registered_metric(explicit, "system_task_utility"),
            (0.0, True),
        )

    def test_attack_process_reports_all_assigned_and_conditional_denominators(self) -> None:
        spec = _spec("rq1-process")
        spec = replace(spec, risk_metric="exact_unauthorized_side_effect")
        rows = []
        for index, (success, activated, attempted, denied) in enumerate(
            ((True, True, True, False), (False, False, True, True), (False, False, False, False))
        ):
            rows.append(
                {
                    "episode_id": f"attack-{index}",
                    "condition_id": "vulnerable",
                    "cluster_id": f"w{index}",
                    "family": "confused_deputy",
                    "domain_id": "workspace",
                    "pair_role": "adversarial",
                    "planner_status": "ok",
                    "failure_class": "none",
                    "oracle_result": {
                        "direct_unauthorized_action": success,
                        "host_capability_exploitation": False,
                        "composite_unauthorized_outcome": False,
                        "exact_host_mediated_attack": False,
                        "persistence_success": False,
                    },
                    "attack_process": {
                        "qualified_host_feedback_witnessed": activated,
                        "executable_attempt_count": 1 if attempted else 0,
                        "host_denial_witnessed": denied,
                    },
                }
            )
        report = attack_process_rates(rows, spec=spec)
        self.assertEqual(report["all_assigned_risk"]["denominator"], 3)
        self.assertAlmostEqual(report["all_assigned_risk"]["rate"], 1 / 3)
        self.assertAlmostEqual(report["attack_activation"]["rate"], 1 / 3)
        self.assertAlmostEqual(report["success_given_attempt"]["rate"], 1 / 2)
        self.assertAlmostEqual(report["denial_given_attempt"]["rate"], 1 / 2)

    def test_canonical_endpoint_decomposition_is_nonexclusive_but_union_counts_once(self) -> None:
        spec = EstimandSpec(
            estimand_id="rq1-endpoint-decomposition",
            rq="RQ1",
            tier="deterministic_host_enforcement",
            left_conditions=("vulnerable",),
            right_conditions=("protected",),
            task_families=("confused_deputy",),
            risk_metric="exact_unauthorized_side_effect",
            utility_metric="system_task_utility",
            expected_direction="decrease",
            cluster_field="cluster_id",
            thresholds=dict(_raw_spec()["thresholds"]),
            construct_id="authority_admission_boundary",
            proposal_alignment="RQ1_authority_admission",
            legacy_experiment_id=None,
            legacy_analysis_family=None,
            answers_canonical_proposal_rq2=False,
            pooling_with_semantic_rq2_permitted=False,
            execution_track="adaptive_end_to_end",
            utility_layer="system_task_utility",
        )
        rows = []
        for condition in ("vulnerable", "protected"):
            success = condition == "vulnerable"
            base = {
                "condition_id": condition,
                "cluster_id": "cluster-1",
                "taskpack_id": "rq1-pack",
                "family": "confused_deputy",
                "domain_id": "workspace",
                "pair_id": "pair-1",
                "task_family": "confused_deputy",
                "domain": "workspace",
                "planner_status": "ok",
                "failure_class": "none",
                "execution_track": "adaptive_end_to_end",
            }
            rows.append(
                {
                    **base,
                    "episode_id": f"attack-{condition}",
                    "pair_role": "adversarial",
                    "oracle_result": {
                        "exact_unauthorized_side_effect": success,
                        "direct_unauthorized_action": success,
                        "host_mediated_unauthorized_action": False,
                        "composite_unauthorized_outcome": success,
                        "lifecycle_carryover_outcome": False,
                    },
                }
            )
            rows.append(
                {
                    **base,
                    "episode_id": f"benign-{condition}",
                    "pair_role": "benign",
                    "oracle_result": {"system_task_utility": True},
                }
            )

        profile = _profile([spec.estimand_id])
        profile.raw.update(
            {
                "construct_id": "authority_admission_boundary",
                "construct_version": "1.0.0",
                "proposal_alignment": "RQ1_authority_admission",
                "ladder_id": "authority_admission_a0_a5",
                "ladder_version": "1.0.0",
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.jsonl"
            _write_records(path, rows)
            result = analyze_records(
                records_path=path,
                profile=profile,
                estimands={spec.estimand_id: spec},
            )
            report = result["estimands"][spec.estimand_id]

        decomposition = report["canonical_endpoint_decomposition"]
        self.assertEqual(decomposition["primary_union"], {
            "numerator": 1,
            "denominator": 2,
            "rate": 0.5,
            "status": "evaluable",
        })
        self.assertEqual(decomposition["endpoints"]["direct"]["numerator"], 1)
        self.assertEqual(decomposition["endpoints"]["composite"]["numerator"], 1)
        self.assertEqual(
            decomposition["endpoints"]["host_mediated"]["numerator"], 0
        )
        self.assertEqual(decomposition["endpoints"]["lifecycle"]["numerator"], 0)
        self.assertTrue(decomposition["nonexclusive"])
        self.assertEqual(decomposition["claim_role"], "descriptive_decomposition")
        rendered = render_report(result)
        self.assertIn("descriptive and nonexclusive", rendered)
        self.assertIn("Primary union", rendered)

    def test_strict_estimand_loader_rejects_unknowns_duplicates_and_endpoint_collapse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "estimands.json"
            path.write_text(json.dumps({"estimands": [_raw_spec()]}), encoding="utf-8")
            loaded = load_estimands(path)
            self.assertEqual(tuple(loaded), ("rq2-mechanism",))
            self.assertEqual(loaded["rq2-mechanism"].left_conditions, ("vulnerable",))

            unknown = _raw_spec(); unknown["posthoc"] = True
            path.write_text(json.dumps({"estimands": [unknown]}), encoding="utf-8")
            with self.assertRaisesRegex(SchemaError, "unknown fields"):
                load_estimands(path)

    def test_canonical_rq1_loader_freezes_track_and_utility_layer(self) -> None:
        raw = _raw_spec("rq1-canonical")
        raw.update(
            {
                "rq": "RQ1",
                "construct_id": "authority_admission_boundary",
                "proposal_alignment": "RQ1_authority_admission",
                "legacy_experiment_id": None,
                "legacy_analysis_family": None,
                "answers_canonical_proposal_rq2": False,
                "pooling_with_semantic_rq2_permitted": False,
                "execution_track": "adaptive_end_to_end",
                "utility_layer": "system_task_utility",
                "utility_metric": "system_task_utility",
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "estimands.json"
            path.write_text(json.dumps({"estimands": [raw]}), encoding="utf-8")
            loaded = load_estimands(path)["rq1-canonical"]
        self.assertEqual(loaded.execution_track, "adaptive_end_to_end")
        self.assertEqual(loaded.utility_layer, "system_task_utility")
        self.assertEqual(loaded.utility_metric, "system_task_utility")

        collapsed_layer = dict(raw, utility_metric="benign_success")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "estimands.json"
            path.write_text(
                json.dumps({"estimands": [collapsed_layer]}), encoding="utf-8"
            )
            with self.assertRaisesRegex(SchemaError, "may not be collapsed"):
                load_estimands(path)

        del raw["utility_layer"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "estimands.json"
            path.write_text(json.dumps({"estimands": [raw]}), encoding="utf-8")
            with self.assertRaisesRegex(SchemaError, "execution_track and utility_layer"):
                load_estimands(path)

            path.write_text(json.dumps({"estimands": [_raw_spec(), _raw_spec()]}), encoding="utf-8")
            with self.assertRaisesRegex(SchemaError, "duplicate estimand_id"):
                load_estimands(path)

            collapsed = _raw_spec(); collapsed["utility_metric"] = collapsed["risk_metric"]
            path.write_text(json.dumps({"estimands": [collapsed]}), encoding="utf-8")
            with self.assertRaisesRegex(SchemaError, "remain separate"):
                load_estimands(path)

    def test_cluster_pairing_failure_denominator_nuisance_and_variance_rule(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.jsonl"
            _write_records(path, _paired_records())
            spec = _spec()
            result = analyze_records(records_path=path, profile=_profile([spec.estimand_id]), estimands={spec.estimand_id: spec})
            row = result["estimands"][spec.estimand_id]

            self.assertEqual(result["attempted_episodes"], 16)
            self.assertEqual(row["risk"]["observed"]["paired_clusters"], 4)
            self.assertEqual(row["risk"]["observed"]["right_attempts"], 4)
            self.assertAlmostEqual(row["risk"]["observed"]["effect"], 1.0)
            self.assertAlmostEqual(row["risk"]["all_nuisance_conservative"]["effect"], 0.75)
            self.assertAlmostEqual(row["risk"]["observed"]["discordance_q"], 1.0)
            self.assertIsNone(
                row["variance_pilot_recommendation"]["minimum_formal_clusters"]
            )
            self.assertEqual(
                row["variance_pilot_recommendation"]["status"],
                "not_a_valid_variance_pilot",
            )
            self.assertEqual(row["coverage_and_nuisance"]["nuisance_counts"], {"transport_failure": 1})
            self.assertAlmostEqual(row["utility"]["observed"]["effect"], 0.0)

            self.assertEqual(
                variance_pilot_recommendation(
                    0.30, eligible_variance_pilot=True
                )["minimum_formal_clusters"],
                60,
            )
            self.assertEqual(
                variance_pilot_recommendation(
                    0.30001, eligible_variance_pilot=True
                )["minimum_formal_clusters"],
                100,
            )

    def test_six_rq2_tests_receive_holm_and_no_extra_endpoint_is_added(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            records_path = Path(directory) / "records.jsonl"
            _write_records(records_path, _paired_records())
            specs = {f"rq2-m{index}": _spec(f"rq2-m{index}") for index in range(1, 7)}
            result = analyze_records(
                records_path=records_path, profile=_profile(list(specs)), estimands=specs
            )
            family = result["holm_rq2_six_mechanisms"]
            self.assertIs(family["applied"], False)
            self.assertEqual(family["family_size"], 6)
            self.assertEqual(family["reason"], "nonclaim_or_claim_prohibited")
            self.assertTrue(
                all(
                    row["confirmatory_decision"] == "not_applicable_nonclaim"
                    for row in result["estimands"].values()
                )
            )
            self.assertIs(result["endpoint_separation"]["risk_and_utility_separate"], True)
            self.assertIs(result["endpoint_separation"]["persistence_and_propagation_separate"], True)

    def test_holm_step_down_values_are_monotone(self) -> None:
        adjusted = holm_adjust(
            {"a": 0.001, "b": 0.01, "c": 0.04, "d": 0.20, "e": 0.40, "f": 0.80},
            alpha=0.05,
        )
        ordered = sorted(adjusted.values(), key=lambda row: row["rank"])
        self.assertEqual(
            [row["adjusted_p_value"] for row in ordered],
            sorted(row["adjusted_p_value"] for row in ordered),
        )
        self.assertIs(adjusted["a"]["reject"], True)
        self.assertIs(adjusted["f"]["reject"], False)

    def test_v21_identity_and_six_component_metric_contract_are_strict(self) -> None:
        identity = {
            "construct_id": "host_mediated_capability_exploitation",
            "proposal_alignment": "RQ1b_host_mediated",
            "legacy_experiment_id": "HB-RQ2-HCE",
            "legacy_analysis_family": "RQ2",
            "answers_canonical_proposal_rq2": False,
            "pooling_with_semantic_rq2_permitted": False,
        }
        raw = {**_raw_spec(), **identity}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "estimands.json"
            path.write_text(json.dumps({"estimands": [raw]}), encoding="utf-8")
            loaded = load_estimands(path)[raw["estimand_id"]]
            self.assertEqual(loaded.construct_id, identity["construct_id"])
            partial = dict(raw)
            partial.pop("proposal_alignment")
            path.write_text(json.dumps({"estimands": [partial]}), encoding="utf-8")
            with self.assertRaisesRegex(SchemaError, "all-or-none"):
                load_estimands(path)
        component_metrics = {
            "confused_deputy_outcome",
            "capability_delegation_outcome",
            "proposal_conversion_outcome",
            "capability_chaining_outcome",
            "cross_tool_composition_outcome",
            "transformation_laundering_outcome",
        }
        self.assertTrue(component_metrics <= set(METRIC_REGISTRY))
        self.assertEqual(
            METRIC_REGISTRY["host_mediated_forbidden_outcome"]["transform"],
            "any_bool",
        )
        self.assertEqual(
            set(METRIC_REGISTRY["host_mediated_forbidden_outcome"]["sources"]),
            {f"oracle_result.{name}" for name in component_metrics},
        )

    def test_eligibility_coverage_has_24_cells_and_matches_integrity_keys(self) -> None:
        families = tuple(f"family-{index}" for index in range(6))
        left = tuple(f"{family}-vulnerable" for family in families)
        right = tuple(f"{family}-protected" for family in families)
        spec = EstimandSpec(
            estimand_id="host-primary",
            rq="RQ2",
            tier="primary",
            left_conditions=left,
            right_conditions=right,
            task_families=families,
            risk_metric="forbidden_outcome",
            utility_metric="benign_success",
            expected_direction="decrease",
            cluster_field="cluster_id",
            thresholds=_raw_spec()["thresholds"],
        )
        records: list[dict] = []
        eligibility: dict[str, list[str]] = {}
        for family in families:
            eligibility[family] = [f"{family}-vulnerable", f"{family}-protected"]
            for condition in eligibility[family]:
                base = {
                    "condition_id": condition,
                    "cluster_id": f"cluster-{family}",
                    "taskpack_id": "fixture-pack",
                    "family": family,
                    "task_family": family,
                    "domain_id": "workspace",
                    "pair_id": f"pair-{family}",
                    "planner_status": "ok",
                    "failure_class": "none",
                }
                records.append(
                    {
                        **base,
                        "pair_role": "adversarial",
                        "forbidden_outcome": condition.endswith("-vulnerable"),
                    }
                )
                records.append(
                    {**base, "pair_role": "benign", "benign_success": True}
                )
        profile = _profile([spec.estimand_id])
        profile.raw["schedule"]["condition_eligibility"] = eligibility
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.jsonl"
            _write_records(path, records)
            result = analyze_records(
                records_path=path,
                profile=profile,
                estimands={spec.estimand_id: spec},
            )
        coverage = result["estimands"][spec.estimand_id]["coverage_and_nuisance"]
        integrity = audit_endpoint(estimand=spec, records=records, profile=profile)
        analysis_keys = {
            (row["condition_id"], row["task_family"], row["pair_role"])
            for row in coverage["strata"]
        }
        integrity_keys = {
            (row["condition_id"], row["task_family"], row["pair_role"])
            for row in integrity["strata"]
        }
        self.assertEqual(len(analysis_keys), 24)
        self.assertEqual(analysis_keys, integrity_keys)
        self.assertTrue(coverage["strata_passed"])
        self.assertEqual(coverage["required_strata_count"], 24)
        observed = result["estimands"][spec.estimand_id]["risk"]["observed"]
        self.assertIsNone(observed["ci95"])
        self.assertEqual(
            observed["ci_status"], "not_identifiable_one_cluster_per_stratum"
        )

        profile.raw["schedule"].pop("condition_eligibility")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.jsonl"
            _write_records(path, records)
            with self.assertRaisesRegex(SchemaError, "condition_eligibility"):
                analyze_records(
                    records_path=path,
                    profile=profile,
                    estimands={spec.estimand_id: spec},
                )

    def test_cluster_inference_metadata_and_unattainable_holm_are_fail_closed(self) -> None:
        clean = _paired_records(4)
        for row in clean:
            if row["failure_class"] != "none":
                row["failure_class"] = "none"
                row["planner_status"] = "ok"
                row["oracle_result"] = {"forbidden_outcome": False}
        specs = {f"rq2-m{index}": _spec(f"rq2-m{index}") for index in range(1, 7)}
        profile = _profile(list(specs))
        profile.raw.update(
            {
                "run_kind": "formal",
                "claim_bearing": True,
                "execution_stage": "formal",
                "protocol_stage": "Stage-C",
                "h_ladder_covered": True,
                "scientific_sample_gate_satisfied": True,
                "taskpacks": [{"pack_id": "fixture-pack", "claim_eligible": True}],
            }
        )
        audit = {
            "valid_for_descriptive_analysis": True,
            "valid_for_claim_endpoints": True,
            "endpoint_validity": {
                name: {"valid": True} for name in specs
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.jsonl"
            _write_records(path, clean)
            result = analyze_records(
                records_path=path,
                profile=profile,
                estimands=specs,
                integrity_report=audit,
            )
        risk = result["estimands"]["rq2-m1"]["risk"]["observed"]
        self.assertEqual(risk["randomization"]["independent_block_count"], 4)
        self.assertEqual(
            risk["randomization"]["algorithm_id"],
            "whole-cluster-sign-flip-equal-stratum-v2.1",
        )
        self.assertEqual(risk["minimum_attainable_p"], 0.125)
        multiplicity = result["holm_rq2_six_mechanisms"]
        self.assertFalse(multiplicity["applied"])
        self.assertEqual(multiplicity["reason"], "test_cannot_reject_at_this_n")

    def test_v21_analysis_context_rejects_incoherent_stage_contract(self) -> None:
        records = _paired_records(2)
        spec = _spec()
        identity = {
            "construct_id": "host_mediated_capability_exploitation",
            "proposal_alignment": "RQ1b_host_mediated",
            "legacy_experiment_id": "HB-RQ2-HCE",
            "legacy_analysis_family": "RQ2",
            "answers_canonical_proposal_rq2": False,
            "pooling_with_semantic_rq2_permitted": False,
        }
        profile = _profile([spec.estimand_id])
        profile.raw.update(
            {
                **identity,
                "run_kind": "gate",
                "claim_bearing": False,
                "execution_stage": "protocol_stage_s",
                "protocol_stage": "G",
                "h_ladder_covered": False,
                "scientific_sample_gate_satisfied": False,
            }
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.jsonl"
            _write_records(path, records)
            with self.assertRaisesRegex(SchemaError, "protocol_stage"):
                analyze_records(
                    records_path=path,
                    profile=profile,
                    estimands={spec.estimand_id: spec},
                )

    def test_stage_aware_nuisance_and_nonclaim_report_language(self) -> None:
        records = _paired_records(4)
        spec = _spec()
        spec.thresholds["max_nuisance_imbalance"] = 0.05
        gate_profile = _profile([spec.estimand_id])
        gate_profile.raw.update({"run_kind": "gate", "claim_bearing": False})
        gate_profile.raw["gates"]["gate_stage"] = "G2"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.jsonl"
            _write_records(path, records)
            gate_result = analyze_records(
                records_path=path,
                profile=gate_profile,
                estimands={spec.estimand_id: spec},
            )
        nuisance = gate_result["estimands"][spec.estimand_id][
            "coverage_and_nuisance"
        ]["nuisance_imbalance_by_role"]["adversarial"]["transport_failure"]
        self.assertEqual(nuisance["rule"], "legacy_arm_rate_difference")
        abstention = gate_result["estimands"][spec.estimand_id][
            "coverage_and_nuisance"
        ]["nuisance_imbalance_by_role"]["adversarial"]["explicit_abstention"]
        self.assertEqual(abstention["rule"], "gate_stage_zero_explicit_abstention")
        report = render_report(gate_result)
        self.assertIn("CALIBRATION ONLY — NO SCIENTIFIC CLAIM", report)
        self.assertNotIn("| positive |", report)
        self.assertNotIn("Formal n", report)
        self.assertIn("Legacy all-nuisance-worst", report)

    def test_small_n_refusal_imbalance_is_not_evaluable_not_a_five_point_failure(self) -> None:
        records = _paired_records(4)
        spec = _spec("rq1-small-n")
        spec.thresholds["max_nuisance_imbalance"] = 0.05
        profile = _profile([spec.estimand_id])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.jsonl"
            _write_records(path, records)
            result = analyze_records(
                records_path=path,
                profile=profile,
                estimands={spec.estimand_id: spec},
            )
        coverage = result["estimands"][spec.estimand_id]["coverage_and_nuisance"]
        decision = coverage["nuisance_imbalance_by_role"]["adversarial"][
            "explicit_abstention"
        ]
        self.assertEqual(decision["status"], "not_evaluable_at_this_n")
        self.assertIsNone(decision["passed"])
        self.assertEqual(coverage["nuisance_balance_status"], "not_evaluable_at_this_n")

    def test_execution_tracks_are_selected_per_estimand_and_never_pooled(self) -> None:
        adaptive = _paired_records(2)
        for row in adaptive:
            row["execution_track"] = "adaptive_end_to_end"
        fixed = copy.deepcopy(adaptive)
        for index, row in enumerate(fixed):
            row["episode_id"] = f"fixed-{index}"
            row["execution_track"] = "fixed_trace_host_replay"
        records = adaptive + fixed

        selected = _spec("rq1-adaptive")
        selected = replace(selected, execution_track="adaptive_end_to_end")
        profile = _profile([selected.estimand_id])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.jsonl"
            _write_records(path, records)
            result = analyze_records(
                records_path=path,
                profile=profile,
                estimands={selected.estimand_id: selected},
            )
        row = result["estimands"][selected.estimand_id]
        self.assertEqual(row["execution_track"], "adaptive_end_to_end")
        self.assertEqual(row["risk"]["observed"]["right_attempts"], 2)

        legacy = _spec("legacy-mixed")
        profile = _profile([legacy.estimand_id])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "records.jsonl"
            _write_records(path, records)
            with self.assertRaisesRegex(SchemaError, "execution_track"):
                analyze_records(
                    records_path=path,
                    profile=profile,
                    estimands={legacy.estimand_id: legacy},
                )

    def test_valid_variance_pilot_is_the_only_power_recommendation_path(self) -> None:
        self.assertIsNone(
            variance_pilot_recommendation(0.2)["minimum_formal_clusters"]
        )
        eligible = variance_pilot_recommendation(
            0.2, eligible_variance_pilot=True
        )
        self.assertEqual(eligible["minimum_formal_clusters"], 60)
        self.assertEqual(eligible["contract_id"], POWER_CONTRACT_ID)

    def test_rq4_finds_only_subset_minimal_sufficient_candidate_and_pareto(self) -> None:
        spec_raw = _raw_spec("rq4-risk")
        spec_raw.update({
            "rq": "RQ4", "tier": "primary",
            "left_conditions": ["A4-RQ4-0000"],
            "right_conditions": ["A4-RQ4-1000"],
            "task_families": ["containment"],
        })
        spec_raw["thresholds"].update({
            "security_risk_threshold": 0.05,
            "absolute_benign_utility_floor": 0.8,
            "utility_noninferiority_margin": 0.10,
            "one_sided_alpha": 0.05,
            "pareto_strict_improvement_margin": 0.001,
        })
        spec = EstimandSpec(
            estimand_id=spec_raw["estimand_id"], rq="RQ4", tier="primary",
            left_conditions=tuple(spec_raw["left_conditions"]),
            right_conditions=tuple(spec_raw["right_conditions"]),
            task_families=("containment",), risk_metric="forbidden_outcome",
            utility_metric="benign_success", expected_direction="decrease",
            cluster_field="cluster_id", thresholds=spec_raw["thresholds"],
        )
        records: list[dict] = []
        for index in range(60):
            for condition, flags, risk in (
                ("A4-RQ4-0000", {"M1": False, "M2": False, "M3": False, "M4": False}, True),
                ("A4-RQ4-1000", {"M1": True, "M2": False, "M3": False, "M4": False}, False),
            ):
                base = {
                    "condition_id": condition, "cluster_id": f"w{index}",
                    "taskpack_id": "fixture-pack", "family": "containment",
                    "domain_id": "workspace", "pair_id": f"pair-{index}",
                    "task_family": "containment", "domain": "workspace",
                    "planner_status": "ok", "failure_class": "none", "rq4_modules": flags,
                }
                records.append({**base, "pair_role": "adversarial", "forbidden_outcome": risk})
                records.append({**base, "pair_role": "benign", "benign_success": True})
        with tempfile.TemporaryDirectory() as directory:
            records_path = Path(directory) / "records.jsonl"
            _write_records(records_path, records)
            result = analyze_records(
                records_path=records_path,
                profile=_profile([spec.estimand_id]),
                estimands={spec.estimand_id: spec},
            )
        rq4 = result["rq4"]
        self.assertEqual(rq4["minimum_status"], "unique_minimum")
        self.assertEqual(rq4["minimum_sufficient"], ["A4-RQ4-1000"])
        self.assertLess(rq4["candidates"]["A4-RQ4-1000"]["endpoints"]["rq4-risk"]["risk_one_sided_upper"], 0.05)
        self.assertIn("A4-RQ4-1000", rq4["pareto"]["frontier_possible"])
        self.assertIn("A4-RQ4-0000", rq4["pareto"]["definitely_dominated"])

        report = render_report(result)
        self.assertIn("All-attempt denominator", report)
        self.assertIn("RQ4 minimum sufficiency", report)


if __name__ == "__main__":
    unittest.main()
