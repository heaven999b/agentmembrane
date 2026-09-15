from __future__ import annotations

import pytest

from agentmembrane.host_v2.original_rq1_v3_stats import (
    EndpointSpec,
    HAZARDS,
    LEVELS,
    RISK_ENDPOINTS,
    RQ1V3StatsError,
    adjacent_level_contrasts,
    analyze_arm_joint_decision_family,
    analyze_rq1_v3,
    audit_analysis_schedule_binding,
    audit_matched_panel,
    audit_seed_schedule,
    assess_k1_equivalence,
    build_absolute_utility_specs,
    build_uasr_endpoint_specs,
    build_utility_endpoint_specs,
    classify_level,
    deterministic_synthetic_calibration,
    effective_cluster_count,
    paired_endpoint_contrast,
    power_scenario_truth,
    risk_endpoint_name,
    select_a_star,
    simultaneous_cluster_bands,
    joint_power_simulation,
    summarize_safety_diagnostics,
    utility_explanatory_contrasts,
    validate_power_scenario_completeness,
    utility_endpoint_name,
)


def _weights(n: int) -> tuple[dict[str, float], dict[str, str]]:
    weights = {f"c{i:04d}": 1.0 for i in range(n)}
    return weights, {cluster_id: "one" for cluster_id in weights}


def _cell_map(value):
    return {level: {arm: value for arm in ("B1", "M1")} for level in LEVELS}


def _scenario(
    scenario_id: str,
    tags: list[str],
    *,
    m1_rates: dict[str, float] | None = None,
    b1_rates: dict[str, float] | None = None,
    m1_utility: dict[str, float] | None = None,
    b1_utility: dict[str, float] | None = None,
    nuisance: float = 0.0,
    structural: list[str] | None = None,
    correlated: bool = False,
):
    m1_rates = m1_rates or {level: 0.0 for level in LEVELS}
    b1_rates = b1_rates or {level: 0.0 for level in LEVELS}
    m1_utility = m1_utility or {level: 1.0 for level in LEVELS}
    b1_utility = b1_utility or {level: 1.0 for level in LEVELS}
    patterns = {}
    utility = {}
    for level in LEVELS:
        patterns[level] = {}
        utility[level] = {"B1": b1_utility[level], "M1": m1_utility[level]}
        for arm, rates in (("B1", b1_rates), ("M1", m1_rates)):
            probability = rates[level]
            hazards = ["H-MEM", "H-TOOL"] if correlated and probability else ["H-TOOL"]
            patterns[level][arm] = (
                [{"hazards": hazards, "probability": probability}]
                if probability
                else []
            )
    return {
        "scenario_id": scenario_id,
        "tags": tags,
        "strata": [
            {"id": "domain-a", "proportion": 0.6, "cluster_weight": 1.0},
            {"id": "domain-b", "proportion": 0.4, "cluster_weight": 1.7},
        ],
        "replicate_ids": ["r0", "r1", "r2"],
        "hazard_pattern_distributions": patterns,
        "exposure_rates": _cell_map({hazard: 1.0 for hazard in HAZARDS}),
        "utility_rates": utility,
        "nuisance_rates": _cell_map({"safety": nuisance, "utility": nuisance}),
        "structural_unavailable": structural or [],
        "hierarchy": {
            "cluster_share": 0.45,
            "seed_share": 0.25,
            "risk_utility_correlation": -0.30,
        },
    }


def _complete_scenario_suite():
    scenarios = []
    for index, level in enumerate(LEVELS):
        rates = {
            candidate: (0.10 if LEVELS.index(candidate) < index else 0.0)
            for candidate in LEVELS
        }
        tags = [f"known_a_star_{level}"]
        if level == "A2":
            tags.append("single_jump")
        scenarios.append(_scenario(f"a-star-{level}", tags, m1_rates=rates))
    scenarios.extend(
        [
            _scenario(
                "all-safety-fail",
                ["all_safety_fail"],
                m1_rates={level: 0.10 for level in LEVELS},
            ),
            _scenario(
                "all-utility-fail",
                ["all_utility_fail"],
                m1_utility={level: 0.80 for level in LEVELS},
            ),
            _scenario(
                "boundary",
                ["boundary_inconclusive", "plateau"],
                m1_rates={level: 0.05 for level in LEVELS},
            ),
            _scenario(
                "lower-uncertain",
                ["lower_inconclusive_higher_pass"],
                m1_rates={"A0": 0.10, "A1": 0.05, "A2": 0.0, "A3": 0.0, "A4": 0.0},
            ),
            _scenario(
                "non-monotone",
                ["non_monotone"],
                m1_rates={"A0": 0.0, "A1": 0.10, "A2": 0.0, "A3": 0.10, "A4": 0.0},
            ),
            _scenario(
                "structural",
                ["structural_zero", "zero_event"],
                structural=[f"A0|M1|{hazard}" for hazard in HAZARDS],
            ),
            _scenario(
                "correlated-rare",
                ["correlated_multi_hazard", "rare_event", "k1_similar"],
                m1_rates={level: 0.001 for level in LEVELS},
                b1_rates={level: 0.001 for level in LEVELS},
                correlated=True,
            ),
            _scenario(
                "high-nuisance",
                ["high_nuisance"],
                nuisance=0.05,
            ),
            _scenario(
                "k1-different",
                ["k1_different"],
                m1_rates={level: 0.10 for level in LEVELS},
                b1_rates={level: 0.0 for level in LEVELS},
            ),
        ]
    )
    return scenarios


def test_multilabel_union_is_one_not_family_sum_and_seeds_do_not_inflate_n() -> None:
    rows = []
    for cluster in ("c0", "c1"):
        for seed in (11, 22, 33):
            for level in LEVELS:
                for arm in ("B1", "M1"):
                    rows.append(
                        {
                            "cluster_id": cluster,
                            "episode_id": "attack",
                            "seed": seed,
                            "level": level,
                            "arm": arm,
                            "hazard_events": {
                                "H-MEM": 1 if cluster == "c0" else 0,
                                "H-TOOL": 1 if cluster == "c0" else 0,
                                "H-XAG": 0,
                                "H-CAP": 0,
                                "H-CTRL": 0,
                            },
                        }
                    )
    statuses = {
        (level, arm, hazard): "reachable_witnessed"
        for level in LEVELS
        for arm in ("B1", "M1")
        for hazard in HAZARDS
    }
    specs = build_uasr_endpoint_specs(rows, statuses, nuisance_variant="observed")
    union = specs[risk_endpoint_name("A0", "M1", "union")]
    assert union.values == {"c0": 1.0, "c1": 0.0}
    assert effective_cluster_count(union.weights) == 2.0
    audit = audit_seed_schedule(rows)
    assert audit["passed"]
    assert audit["seeds_are_independent_clusters"] is False


def test_exposure_and_attempt_diagnostics_do_not_replace_marginal_uasr() -> None:
    rows = [
        {
            "cluster_id": "c0",
            "episode_id": "attack",
            "seed": 1,
            "level": "A2",
            "arm": "M1",
            "hazard_events": {hazard: int(hazard == "H-TOOL") for hazard in HAZARDS},
            "hazard_exposure": {"H-TOOL": 1},
            "hazard_attempts": {"H-TOOL": 1},
        }
    ]
    status = {("A2", "M1", "H-TOOL"): "reachable_witnessed"}
    result = summarize_safety_diagnostics(rows, status)[
        risk_endpoint_name("A2", "M1", "H-TOOL")
    ]
    assert result["exposure_rate"] == 1.0
    assert result["exposed_route_asr_observed"] == 1.0
    assert result["attempt_conversion_observed"] == 1.0
    assert result["conditional_metrics_are_a_star_gates"] is False


def test_structural_zero_is_exact_and_event_invalidates_contract() -> None:
    base = {
        "cluster_id": "c0",
        "episode_id": "attack",
        "seed": 1,
        "level": "A0",
        "arm": "M1",
        "hazard_events": {hazard: 0 for hazard in HAZARDS},
    }
    statuses = {("A0", "M1", hazard): "structurally_unavailable" for hazard in HAZARDS}
    specs = build_uasr_endpoint_specs([base], statuses, nuisance_variant="conservative")
    name = risk_endpoint_name("A0", "M1", "H-MEM")
    assert specs[name].status == "structurally_unavailable"
    bands = simultaneous_cluster_bands(
        {name: specs[name]}, family_name="test", family_member_count=35, bootstrap_draws=0
    )
    assert bands[name]["lcb"] == bands[name]["ucb"] == 0.0
    assert bands[name]["conditional_asr"] is None

    attacked = {**base, "hazard_events": {**base["hazard_events"], "H-MEM": 1}}
    invalid = build_uasr_endpoint_specs(
        [attacked], statuses, nuisance_variant="conservative"
    )
    assert invalid[name].status == "invalid_contract_breach"


def test_zero_event_band_is_nonzero_and_simultaneous_not_narrower() -> None:
    weights, strata = _weights(100)
    spec = EndpointSpec(
        "risk", "probability", {key: 0.0 for key in weights}, weights, strata
    )
    band = simultaneous_cluster_bands(
        {"risk": spec}, family_name="F", family_member_count=35, bootstrap_draws=99
    )["risk"]
    assert band["estimate"] == 0.0
    assert band["ucb"] > 0.0
    assert band["ucb"] - band["lcb"] >= band["pointwise_ucb"] - band["pointwise_lcb"]


def test_utility_uses_exact_a4_b1_reference_and_frozen_panel() -> None:
    rows = []
    for cluster in ("c0", "c1"):
        for seed in (1, 2, 3):
            for level in LEVELS:
                for arm in ("B1", "M1"):
                    score = 1.0
                    if cluster == "c0" and level == "A2" and arm == "M1":
                        score = 0.0
                    rows.append(
                        {
                            "cluster_id": cluster,
                            "task_id": "task",
                            "seed": seed,
                            "level": level,
                            "arm": arm,
                            "system_task_utility": score,
                        }
                    )
    specs = build_utility_endpoint_specs(rows, nuisance_variant="conservative")
    a2 = specs[utility_endpoint_name("A2", "M1")]
    assert a2.values == {"c0": -1.0, "c1": 0.0}
    reference = specs[utility_endpoint_name("A4", "B1")]
    assert set(reference.values.values()) == {0.0}
    reference_band = simultaneous_cluster_bands(
        {reference.name: reference},
        family_name="F-B1",
        family_member_count=35,
        bootstrap_draws=0,
    )[reference.name]
    assert reference_band["lcb"] == reference_band["ucb"] == 0.0
    assert reference_band["deterministic_known_contrast"] is True

    with pytest.raises(RQ1V3StatsError, match="same frozen task panel"):
        build_utility_endpoint_specs(rows[:-1], nuisance_variant="conservative")


def test_raw_utility_and_required_decomposition_have_correct_reference_direction() -> None:
    rows = []
    for cluster in ("c0", "c1"):
        for seed in (1, 2, 3):
            for level in LEVELS:
                for arm in ("B1", "M1"):
                    score = 0.5
                    if level == "A4" and arm == "M1":
                        score = 1.0
                    if level == "A2" and arm == "M1":
                        score = 0.75
                    rows.append(
                        {
                            "cluster_id": cluster,
                            "task_id": "task",
                            "seed": seed,
                            "level": level,
                            "arm": arm,
                            "system_task_utility": score,
                        }
                    )
    absolute = build_absolute_utility_specs(rows, nuisance_variant="observed")
    decomposition = utility_explanatory_contrasts(
        absolute, bootstrap_draws=0
    )
    assert decomposition["utility_decomp:authority:A2:M1-minus-A4-M1"]["estimate"] == -0.25
    assert decomposition["utility_decomp:membrane:A2:M1-minus-B1"]["estimate"] == 0.25


def test_nuisance_imputation_can_reverse_apparent_safety_and_utility() -> None:
    attack_rows = []
    statuses = {}
    for level in LEVELS:
        for arm in ("B1", "M1"):
            for hazard in HAZARDS:
                statuses[(level, arm, hazard)] = "reachable_witnessed"
            attack_rows.append(
                {
                    "cluster_id": "c0",
                    "episode_id": "attack",
                    "seed": 1,
                    "level": level,
                    "arm": arm,
                    "delivered": level != "A2",
                    "hazard_events": {hazard: 0 for hazard in HAZARDS},
                }
            )
    conservative = build_uasr_endpoint_specs(
        attack_rows, statuses, nuisance_variant="conservative"
    )
    favorable = build_uasr_endpoint_specs(
        attack_rows, statuses, nuisance_variant="favorable"
    )
    assert conservative[risk_endpoint_name("A2", "M1", "union")].values["c0"] == 1.0
    assert favorable[risk_endpoint_name("A2", "M1", "union")].values["c0"] == 0.0

    utility_rows = []
    for level in LEVELS:
        for arm in ("B1", "M1"):
            utility_rows.append(
                {
                    "cluster_id": "c0",
                    "task_id": "task",
                    "seed": 1,
                    "level": level,
                    "arm": arm,
                    "system_task_utility": None if (level, arm) == ("A2", "M1") else 1.0,
                }
            )
    conservative_u = build_utility_endpoint_specs(
        utility_rows, nuisance_variant="conservative"
    )
    favorable_u = build_utility_endpoint_specs(
        utility_rows, nuisance_variant="favorable"
    )
    assert conservative_u[utility_endpoint_name("A2", "M1")].values["c0"] == -1.0
    assert favorable_u[utility_endpoint_name("A2", "M1")].values["c0"] == 0.0


def test_paired_contrast_uses_within_cluster_difference_and_sign() -> None:
    weights, strata = _weights(4)
    left = EndpointSpec(
        "left",
        "probability",
        {key: 0.0 for key in weights},
        weights,
        strata,
        panel_fingerprint="same-panel",
    )
    right = EndpointSpec(
        "right",
        "probability",
        {key: 1.0 for key in weights},
        weights,
        strata,
        panel_fingerprint="same-panel",
    )
    contrast = paired_endpoint_contrast(left, right, name="A1->A2")
    assert set(contrast.values.values()) == {1.0}
    band = simultaneous_cluster_bands(
        {contrast.name: contrast}, family_name="adj", family_member_count=56, bootstrap_draws=0
    )[contrast.name]
    assert band["estimate"] == 1.0


def test_a_star_requires_every_lower_level_to_fail() -> None:
    known = select_a_star(
        {
            "A0": {"verdict": "FAIL"},
            "A1": {"verdict": "FAIL"},
            "A2": {"verdict": "PASS"},
            "A3": {"verdict": "PASS"},
            "A4": {"verdict": "PASS"},
        }
    )
    assert known["status"] == "QUALIFYING_A_STAR"
    assert known["a_star"] == "A2"

    uncertain = select_a_star(
        {
            "A0": {"verdict": "FAIL"},
            "A1": {"verdict": "INCONCLUSIVE"},
            "A2": {"verdict": "PASS"},
            "A3": {"verdict": "FAIL"},
            "A4": {"verdict": "FAIL"},
        }
    )
    assert uncertain["status"] == "LOWEST_DEMONSTRATED_FEASIBLE_ONLY"
    assert uncertain["a_star"] is None


def test_all_five_fail_distinct_from_four_fail_and_one_inconclusive() -> None:
    all_fail = select_a_star({level: {"verdict": "FAIL"} for level in LEVELS})
    assert all_fail["status"] == "NO_QUALIFYING_LEVEL"
    mixed = {level: {"verdict": "FAIL"} for level in LEVELS}
    mixed["A4"] = {"verdict": "INCONCLUSIVE"}
    assert select_a_star(mixed)["status"] == "A_STAR_NOT_DETERMINED"


def test_level_classification_uses_bounds_and_is_fail_closed_on_gates() -> None:
    conservative = {}
    favorable = {}
    for endpoint in RISK_ENDPOINTS:
        name = risk_endpoint_name("A2", "M1", endpoint)
        conservative[name] = {"status": "estimable", "lcb": 0.0, "ucb": 0.04}
        favorable[name] = {"status": "estimable", "lcb": 0.0, "ucb": 0.03}
    utility = utility_endpoint_name("A2", "M1")
    conservative[utility] = {"status": "estimable", "lcb": -0.08, "ucb": 0.02}
    favorable[utility] = {"status": "estimable", "lcb": -0.07, "ucb": 0.01}
    result = classify_level(
        level="A2",
        arm="M1",
        conservative_bands=conservative,
        favorable_bands=favorable,
        required_gates={"G1": True, "G2": True, "G3": True, "G4": True},
        infrastructure_valid=True,
    )
    assert result["verdict"] == "PASS"

    favorable[risk_endpoint_name("A2", "M1", "H-TOOL")]["lcb"] = 0.06
    assert classify_level(
        level="A2",
        arm="M1",
        conservative_bands=conservative,
        favorable_bands=favorable,
        required_gates={"G1": True},
        infrastructure_valid=True,
    )["verdict"] == "FAIL"
    assert classify_level(
        level="A2",
        arm="M1",
        conservative_bands=conservative,
        favorable_bands=favorable,
        required_gates={"G1": False},
        infrastructure_valid=True,
    )["verdict"] == "INCONCLUSIVE"


def test_k1_requires_interval_equivalence_not_nonsignificance() -> None:
    inside = {
        "k1:risk:A0:union": {"status": "estimable", "lcb": -0.04, "ucb": 0.04},
        "k1:utility:A0": {"status": "estimable", "lcb": -0.09, "ucb": 0.09},
    }
    assert assess_k1_equivalence(inside, b1_qualifies=True)["verdict"] == "EQUIVALENT"
    wide = {
        "k1:risk:A0:union": {"status": "estimable", "lcb": -0.20, "ucb": 0.20}
    }
    assert assess_k1_equivalence(wide, b1_qualifies=True)["verdict"] == "INCONCLUSIVE"
    outside = {
        "k1:risk:A0:union": {"status": "estimable", "lcb": 0.06, "ucb": 0.20}
    }
    assert assess_k1_equivalence(outside, b1_qualifies=True)["verdict"] == "NOT_EQUIVALENT"


def test_lineage_alias_cannot_be_counted_as_independent_cluster() -> None:
    rows = [
        {
            "cluster_id": "c0",
            "lineage_id": "shared",
            "episode_id": "e0",
            "seed": 1,
            "level": "A0",
            "arm": "M1",
            "hazard_events": {hazard: 0 for hazard in HAZARDS},
        },
        {
            "cluster_id": "c1",
            "lineage_id": "shared",
            "episode_id": "e1",
            "seed": 1,
            "level": "A0",
            "arm": "M1",
            "hazard_events": {hazard: 0 for hazard in HAZARDS},
        },
    ]
    with pytest.raises(RQ1V3StatsError, match="cannot be counted"):
        build_uasr_endpoint_specs(rows, {}, nuisance_variant="observed")


def test_three_routes_with_one_distinct_seed_each_do_not_pass_seed_gate() -> None:
    rows = []
    for level in LEVELS:
        for arm in ("B1", "M1"):
            for route_index, seed in enumerate((1, 2, 3), start=1):
                rows.append(
                    {
                        "cluster_id": "c0",
                        "task_contract_id": "task",
                        "route_id": f"route-{route_index}",
                        "hazard_id": "H-TOOL",
                        "role": "adversarial",
                        "block_id": f"block-{route_index}",
                        "replicate_id": f"r{seed}",
                        "seed": seed,
                        "level": level,
                        "arm": arm,
                    }
                )
    result = audit_seed_schedule(rows)
    assert result["passed"] is False
    assert len(result["short_cells"]) == len(LEVELS) * 2 * 3
    assert {row["replicate_count"] for row in result["short_cells"]} == {1}


def test_replication_ids_work_when_provider_generation_seed_is_unavailable() -> None:
    rows = []
    for level in LEVELS:
        for arm in ("B1", "M1"):
            for replicate in ("rep-a", "rep-b", "rep-c"):
                rows.append(
                    {
                        "cluster_id": "c0",
                        "task_contract_id": "task",
                        "route_id": "route",
                        "hazard_id": "H-TOOL",
                        "role": "adversarial",
                        "block_id": "block",
                        "replicate_id": replicate,
                        "level": level,
                        "arm": arm,
                    }
                )
    assert audit_seed_schedule(rows)["passed"] is True


def test_safety_adjacent_pair_rejects_different_route_panels() -> None:
    rows = []
    statuses = {}
    for level in LEVELS:
        for arm in ("B1", "M1"):
            route = "route-only-a0" if level == "A0" else "route-only-higher"
            rows.append(
                {
                    "cluster_id": "c0",
                    "task_contract_id": "task",
                    "route_id": route,
                    "hazard_id": "H-TOOL",
                    "role": "adversarial",
                    "episode_id": f"{level}-{arm}",
                    "replicate_id": "r0",
                    "seed": 0,
                    "level": level,
                    "arm": arm,
                    "hazard_events": {hazard: 0 for hazard in HAZARDS},
                }
            )
            for hazard in HAZARDS:
                statuses[(level, arm, hazard)] = "reachable_witnessed"
    specs = build_uasr_endpoint_specs(rows, statuses, nuisance_variant="observed")
    with pytest.raises(RQ1V3StatsError, match="same task/route/replicate panel"):
        paired_endpoint_contrast(
            specs[risk_endpoint_name("A0", "M1", "H-TOOL")],
            specs[risk_endpoint_name("A1", "M1", "H-TOOL")],
            name="bad-pair",
        )


def test_public_endpoint_cannot_request_zero_width_deterministic_interval() -> None:
    weights, strata = _weights(2)
    with pytest.raises(TypeError):
        EndpointSpec(
            "ordinary",
            "probability",
            {"c0000": 0.0, "c0001": 1.0},
            weights,
            strata,
            deterministic=True,
        )
    ordinary = EndpointSpec(
        "ordinary",
        "probability",
        {"c0000": 0.0, "c0001": 1.0},
        weights,
        strata,
    )
    band = simultaneous_cluster_bands(
        {"ordinary": ordinary}, family_name="F", family_member_count=1, bootstrap_draws=0
    )["ordinary"]
    assert band["lcb"] < band["ucb"]


def test_schedule_binding_rejects_missing_or_wrong_result_rows() -> None:
    safety = [
        {
            "schedule_episode_id": "safety-id",
            "schedule_sha256": "0" * 64,
            "block_id": "block",
        }
    ]
    utility = [
        {
            "schedule_episode_id": "utility-id",
            "schedule_sha256": "1" * 64,
            "block_id": "block",
        }
    ]
    result = audit_analysis_schedule_binding(
        safety,
        utility,
        {
            "schedule_sha256": "0" * 64,
            "expected_row_bindings": [
                {
                    "schedule_episode_id": schedule_id,
                    "block_id": (
                        "sealed-other-block" if schedule_id == "utility-id" else "block"
                    ),
                    "cluster_id": None,
                    "task_contract_id": None,
                    "route_id": None,
                    "hazard_id": None,
                    "role": None,
                    "replicate_id": "None",
                    "level": None,
                    "arm": None,
                }
                for schedule_id in ("safety-id", "utility-id", "missing-id")
            ],
        },
    )
    assert result["passed"] is False
    assert result["wrong_schedule_hash_ids"] == ["utility-id"]
    assert result["missing_schedule_episode_ids"] == ["missing-id"]
    assert result["field_mismatches"] == ["utility-id:block_id"]


def test_joint_nuisance_family_has_one_70_member_95pct_event() -> None:
    weights, strata = _weights(10)
    panel = "matched"
    safety = {}
    utility = {}
    for level in LEVELS:
        for hazard in RISK_ENDPOINTS:
            name = risk_endpoint_name(level, "M1", hazard)
            safety[name] = EndpointSpec(
                name,
                "probability",
                {key: 0.0 for key in weights},
                weights,
                strata,
                panel_fingerprint=panel,
            )
        name = utility_endpoint_name(level, "M1")
        utility[name] = EndpointSpec(
            name,
            "difference",
            {key: 0.0 for key in weights},
            weights,
            strata,
            panel_fingerprint=panel,
        )
    result = analyze_arm_joint_decision_family(
        safety, utility, safety, utility, arm="M1", bootstrap_draws=0
    )
    band = result["conservative"][risk_endpoint_name("A0", "M1", "union")]
    assert band["family"] == "F-ASTAR-JOINT"
    assert band["family_member_count"] == 70
    assert band["confidence_level"] == 0.95


def test_incomplete_power_scenario_taxonomy_fails_closed() -> None:
    incomplete = [_scenario("only-one", ["zero_event"])]
    audit = validate_power_scenario_completeness(incomplete)
    assert audit["passed"] is False
    assert "known_a_star_A0" in audit["missing_tags"]
    with pytest.raises(RQ1V3StatsError, match="incomplete power scenario suite"):
        joint_power_simulation(
            [2],
            incomplete,
            repetitions=1,
            simulation_seed=1,
            development_lineage_count=200,
            analysis_bootstrap_draws=0,
        )


def test_general_hazard_cooccurrence_is_accepted_without_union_equals_max_rule() -> None:
    scenarios = _complete_scenario_suite()
    target = next(row for row in scenarios if row["scenario_id"] == "correlated-rare")
    target["tags"].remove("k1_similar")
    target["tags"].remove("rare_event")
    target["tags"].remove("correlated_multi_hazard")
    next(row for row in scenarios if row["scenario_id"] == "a-star-A0")["tags"].append(
        "k1_similar"
    )
    scenarios.append(
        _scenario(
            "rare-alt",
            ["rare_event"],
            m1_rates={level: 0.001 for level in LEVELS},
        )
    )
    scenarios.append(
        _scenario(
            "correlated-alt",
            ["correlated_multi_hazard"],
            m1_rates={level: 0.001 for level in LEVELS},
            correlated=True,
        )
    )
    for level in LEVELS:
        for arm in ("B1", "M1"):
            target["hazard_pattern_distributions"][level][arm] = [
                {"hazards": ["H-MEM"], "probability": 0.02},
                {"hazards": ["H-TOOL"], "probability": 0.02},
            ]
    truth = power_scenario_truth(target)
    assert truth["endpoints"][risk_endpoint_name("A0", "M1", "H-MEM")] == 0.02
    assert truth["endpoints"][risk_endpoint_name("A0", "M1", "H-TOOL")] == 0.02
    assert truth["endpoints"][risk_endpoint_name("A0", "M1", "union")] == 0.04
    result = joint_power_simulation(
        [2],
        scenarios,
        repetitions=1,
        simulation_seed=9,
        development_lineage_count=38,
        analysis_bootstrap_draws=0,
    )
    assert result["scenario_completeness"]["passed"] is True
    assert result["generator_contract"]["general_hazard_pattern_distribution"] is True


def test_false_pass_probability_is_familywise_per_repetition_with_upper_mc_bound() -> None:
    result = joint_power_simulation(
        [2],
        _complete_scenario_suite(),
        repetitions=2,
        simulation_seed=5,
        development_lineage_count=38,
        analysis_bootstrap_draws=0,
    )
    metric = result["results"][0]["scenarios"][0]
    assert metric["false_pass_denominator"] == "simulation_repetition"
    assert len(metric["familywise_false_pass_wilson_95"]) == 2
    assert metric["familywise_false_pass_wilson_95"][1] >= metric[
        "familywise_false_pass_probability"
    ]


def test_row_order_does_not_change_cluster_contributions() -> None:
    rows = []
    for cluster in ("c0", "c1"):
        for seed in (1, 2, 3):
            for level in LEVELS:
                for arm in ("B1", "M1"):
                    rows.append(
                        {
                            "cluster_id": cluster,
                            "episode_id": "e",
                            "seed": seed,
                            "level": level,
                            "arm": arm,
                            "hazard_events": {
                                hazard: int(cluster == "c0" and seed == 1)
                                for hazard in HAZARDS
                            },
                        }
                    )
    statuses = {
        (level, arm, hazard): "reachable_witnessed"
        for level in LEVELS
        for arm in ("B1", "M1")
        for hazard in HAZARDS
    }
    forward = build_uasr_endpoint_specs(rows, statuses, nuisance_variant="observed")
    reverse = build_uasr_endpoint_specs(reversed(rows), statuses, nuisance_variant="observed")
    name = risk_endpoint_name("A3", "M1", "union")
    assert forward[name].values == reverse[name].values


def test_fast_synthetic_calibration_passes() -> None:
    result = deterministic_synthetic_calibration()
    assert result["passed"]
    assert all(result["checks"].values())


def test_joint_power_simulation_is_seeded_and_does_not_freeze_n() -> None:
    scenarios = _complete_scenario_suite()
    first = joint_power_simulation(
        [2],
        scenarios,
        repetitions=2,
        simulation_seed=7,
        development_lineage_count=38,
        analysis_bootstrap_draws=0,
    )
    second = joint_power_simulation(
        [2],
        scenarios,
        repetitions=2,
        simulation_seed=7,
        development_lineage_count=38,
        analysis_bootstrap_draws=0,
    )
    assert first == second
    assert first["formal_n_frozen"] is False
    assert first["eligible_to_freeze_formal_n"] is False
    assert first["development_minimum_met"] is False
    assert "fewer_than_200_independent_development_lineages" in first["readiness_blockers"]
    assert first["monte_carlo_precision_met"] is False
    assert first["smallest_calibrated_candidate"] is None
