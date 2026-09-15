from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import replace
import json
from pathlib import Path

import pytest

from agentmembrane.host_v2.original_rq1_v3_banks import (
    REQUIRED_SEAL_ARTIFACTS,
    REQUIRED_SEAL_GATES,
    CandidateRecord,
    OriginalRQ1V3BankError,
    RouteApplicability,
    audit_bank_split,
    audit_matched_schedule,
    build_lineage_graph,
    build_matched_schedule,
    create_formal_seal,
    split_candidate_frame,
    verify_formal_seal,
)
from agentmembrane.host_v2.schema import sha256_json


def _hash(value: str) -> str:
    return sha256_json(value)


def _route(index: int, *, applicability: str = "applicable") -> RouteApplicability:
    applicable = applicability == "applicable"
    return RouteApplicability(
        hazard_id="H-TOOL",
        route_id="task-native-sensitive-effect",
        applicability=applicability,
        reason_code="task_native" if applicable else "operation_absent",
        required_legitimate_operation="call_tool" if applicable else None,
        required_visible_operations=("call_tool",) if applicable else (),
        first_reachable_level="A3" if applicable else None,
        reachability_status=(
            "reachable_witnessed" if applicable else "structurally_unavailable"
        ),
        reachability_witness_sha256=_hash(f"witness-{index}") if applicable else None,
        attack_template_lineage_id=f"attack-lineage-{index}" if applicable else None,
        fixed_terminal_event="backend_effect" if applicable else None,
        effect_target_sha256=_hash(f"target-{index}") if applicable else None,
        adjudication_version="fixture-v1",
    )


def _candidate(
    index: int,
    *,
    parameter_family: str | None = None,
    lineage_links: tuple[str, ...] = (),
    exposed: bool = False,
    tuned: bool = False,
    status: str = "eligible",
    route_status: str = "applicable",
) -> CandidateRecord:
    return CandidateRecord(
        candidate_id=f"candidate-{index}",
        cluster_id=f"cluster-{index}",
        source_dataset="fixture@1",
        source_task_id=f"task-{index}",
        source_payload_sha256=_hash(f"payload-{index}"),
        source_template_id=f"template-{index}",
        source_template_sha256=_hash(f"template-{index}"),
        parameter_family_id=parameter_family or f"parameters-{index}",
        normalized_task_contract_sha256=_hash(f"task-contract-{index}"),
        authorized_effect_target_sha256=_hash(f"authorized-{index}"),
        checker_contract_sha256=_hash(f"checker-{index}"),
        initial_state_sha256=_hash(f"initial-state-{index}"),
        domain="fixture-domain",
        utility_eligible=True,
        utility_stratum="fixture-stratum",
        route_applicability=(_route(index, applicability=route_status),),
        historical_exposure_component_id=f"exposure-{index}",
        prior_model_exposure=exposed,
        prior_human_tuning_exposure=tuned,
        eligibility_status=status,
        exclusion_reasons=() if status == "eligible" else ("review_incomplete",),
        source_program_sha256=_hash(f"program-{index}"),
        source_scenario_sha256=_hash(f"scenario-{index}"),
        generator_lineage_id=f"generator-{index}",
        benchmark_family_id=f"family-{index}",
        normalized_prompt_sha256=_hash(f"prompt-{index}"),
        prohibited_effect_target_family_sha256=_hash(f"prohibited-{index}"),
        twin_lineage_id=f"twin-{index}",
        paraphrase_lineage_id=f"paraphrase-{index}",
        checker_fixture_lineage_id=f"fixture-{index}",
        lineage_links=lineage_links,
    )


def _split_fixture():
    candidates = tuple(_candidate(index) for index in range(8))
    split = split_candidate_frame(
        candidates,
        formal_counts_by_stratum={"fixture-stratum": 3},
        development_counts_by_stratum=None,
        utility_target_masses={"fixture-stratum": 1.0},
        safety_target_masses={"H-TOOL:task-native-sensitive-effect": 1.0},
        selection_seed=901,
    )
    return candidates, split


def test_connected_lineage_grouping_is_transitive_and_content_derived() -> None:
    candidates = (
        _candidate(0, parameter_family="shared-parameters"),
        _candidate(
            1,
            parameter_family="shared-parameters",
            lineage_links=("candidate-2",),
        ),
        _candidate(2),
        _candidate(3),
    )
    first = build_lineage_graph(candidates)
    second = build_lineage_graph(tuple(reversed(candidates)))
    assert first.graph_sha256 == second.graph_sha256
    assert first.candidate_to_group["candidate-0"] == first.candidate_to_group["candidate-1"]
    assert first.candidate_to_group["candidate-1"] == first.candidate_to_group["candidate-2"]
    assert first.candidate_to_group["candidate-3"] != first.candidate_to_group["candidate-0"]
    assert first.candidate_to_group["candidate-0"].startswith("sha256:")


def test_split_is_deterministic_disjoint_weighted_and_old_exposure_is_dev_only() -> None:
    candidates = tuple(
        _candidate(
            index,
            exposed=index == 0,
            tuned=index == 1,
        )
        for index in range(8)
    )
    kwargs = dict(
        formal_counts_by_stratum={"fixture-stratum": 3},
        development_counts_by_stratum=None,
        utility_target_masses={"fixture-stratum": 1.0},
        safety_target_masses={"H-TOOL:task-native-sensitive-effect": 1.0},
        selection_seed=902,
        old_exposed_identifiers=("candidate-2", "exposure-3"),
    )
    first = split_candidate_frame(candidates, **kwargs)
    second = split_candidate_frame(tuple(reversed(candidates)), **kwargs)
    assert first.split_sha256 == second.split_sha256
    audit = audit_bank_split(first, candidates)
    assert audit["passed"], audit
    assert audit["formal_lineage_count"] == 3
    formal_ids = {
        row.candidate_id for row in first.assignments if row.bank_id == "formal_holdout"
    }
    assert not formal_ids & {"candidate-0", "candidate-1", "candidate-2", "candidate-3"}
    assert abs(sum(row.normalized_weight for row in first.utility_weights) - 1.0) < 1e-12
    assert abs(sum(row.normalized_weight for row in first.safety_weights) - 1.0) < 1e-12


def test_unresolved_candidate_is_excluded_not_silently_scored_as_safe() -> None:
    candidates = tuple(_candidate(index) for index in range(5)) + (
        _candidate(9, route_status="unresolved"),
    )
    split = split_candidate_frame(
        candidates,
        formal_counts_by_stratum={"fixture-stratum": 2},
        development_counts_by_stratum=None,
        utility_target_masses={"fixture-stratum": 1.0},
        safety_target_masses={"H-TOOL:task-native-sensitive-effect": 1.0},
        selection_seed=903,
    )
    assert "candidate-9" in split.excluded_candidate_ids
    assert "candidate-9" not in {row.candidate_id for row in split.assignments}


def test_matched_schedule_has_every_level_both_arms_three_seeds_and_only_applicable_routes() -> None:
    candidates, split = _split_fixture()
    formal_candidates = [
        candidate
        for candidate in candidates
        if any(
            row.candidate_id == candidate.candidate_id
            and row.bank_id == "formal_holdout"
            for row in split.assignments
        )
    ]
    schedule = build_matched_schedule(
        split,
        candidates,
        bank_id="formal_holdout",
        model_seeds=(11, 12, 13),
        schedule_randomization_seed=904,
        prompt_bundle_sha256=_hash("prompt-bundle"),
        surface_contract_sha256=_hash("surface-contract"),
    )
    audit = audit_matched_schedule(schedule, selected_candidates=formal_candidates)
    assert audit["passed"], audit
    assert len(schedule) == len(formal_candidates) * 3 * 5 * 2 * 2
    assert {row.original_authority_level for row in schedule} == {
        "A0",
        "A1",
        "A2",
        "A3",
        "A4",
    }
    assert {row.arm for row in schedule} == {"B1", "M1"}
    assert {row.model_seed for row in schedule} == {11, 12, 13}
    assert {row.replicate_id for row in schedule} == {"seed-11", "seed-12", "seed-13"}
    assert all(len(row.episode_id) == 64 for row in schedule)
    assert {row.track for row in schedule} == {"adaptive_end_to_end"}
    assert all(
        not row.expected_structural_exposure
        for row in schedule
        if row.pair_role == "adversarial" and row.authority_level in {"A0", "A1", "A2"}
    )
    assert all(
        row.expected_structural_exposure
        for row in schedule
        if row.pair_role == "adversarial" and row.authority_level in {"A3", "A4"}
    )
    for pair_id in {row.pair_id for row in schedule}:
        pair = sorted((row for row in schedule if row.pair_id == pair_id), key=lambda row: row.ordinal)
        assert pair[1].ordinal == pair[0].ordinal + 1
        assert {row.arm for row in pair} == {"B1", "M1"}


def test_schedule_rejects_conflated_selection_schedule_or_model_seeds() -> None:
    candidates, split = _split_fixture()
    with pytest.raises(OriginalRQ1V3BankError, match="must be distinct"):
        build_matched_schedule(
            split,
            candidates,
            bank_id="formal_holdout",
            model_seeds=(11, 12, 13),
            schedule_randomization_seed=901,
            prompt_bundle_sha256=_hash("prompt-bundle"),
            surface_contract_sha256=_hash("surface-contract"),
        )


def test_schedule_keeps_three_replications_when_provider_has_no_generation_seed() -> None:
    candidates, split = _split_fixture()
    schedule = build_matched_schedule(
        split,
        candidates,
        bank_id="formal_holdout",
        replicate_generation_seeds={"r1": None, "r2": None, "r3": None},
        schedule_randomization_seed=904,
        prompt_bundle_sha256=_hash("prompt-bundle"),
        surface_contract_sha256=_hash("surface-contract"),
    )
    assert audit_matched_schedule(schedule)["passed"]
    assert {row.replicate_id for row in schedule} == {"r1", "r2", "r3"}
    assert {row.generation_seed for row in schedule} == {None}


def test_formal_seal_is_deterministic_and_fails_closed_on_drift_or_missing_gate() -> None:
    candidates, split = _split_fixture()
    schedule = build_matched_schedule(
        split,
        candidates,
        bank_id="formal_holdout",
        model_seeds=(11, 12, 13),
        schedule_randomization_seed=904,
        prompt_bundle_sha256=_hash("prompt-bundle"),
        surface_contract_sha256=_hash("surface-contract"),
    )
    schedule_hash = audit_matched_schedule(schedule)["schedule_sha256"]
    weights_hash = sha256_json(
        {
            "utility": [row.to_dict() for row in split.utility_weights],
            "safety": [row.to_dict() for row in split.safety_weights],
        }
    )
    artifacts = {name: _hash(name) for name in REQUIRED_SEAL_ARTIFACTS}
    artifacts.update(
        {
            "candidate_frame": split.candidate_frame_sha256,
            "lineage_graph": split.lineage_graph.graph_sha256,
            "split_assignments": split.split_sha256,
            "bank_weights": weights_hash,
            "formal_schedule": schedule_hash,
        }
    )
    gates = {name: True for name in REQUIRED_SEAL_GATES}
    kwargs = dict(
        artifact_hashes=artifacts,
        prerequisite_gates=gates,
        custodian="fixture-custodian",
        locked_at="2026-09-06T10:00:00+08:00",
    )
    first = create_formal_seal(split, schedule, candidates, **kwargs)
    second = create_formal_seal(split, schedule, candidates, **kwargs)
    assert first == second
    assert first["formal_unsealed_at"] is None
    assert verify_formal_seal(first)["passed"]

    drifted = {**first, "custodian": "changed-after-lock"}
    assert not verify_formal_seal(drifted)["passed"]
    bad_gates = {**gates, "power": False}
    with pytest.raises(OriginalRQ1V3BankError, match="gates"):
        create_formal_seal(
            split,
            schedule,
            candidates,
            **(kwargs | {"prerequisite_gates": bad_gates}),
        )


def test_declared_lineage_mismatch_and_unwitnessed_applicable_route_fail_closed() -> None:
    with pytest.raises(OriginalRQ1V3BankError, match="reachable_witnessed"):
        replace(_route(0), reachability_status="candidate_requires_witness")
    mismatched = replace(_candidate(0), declared_lineage_group_id=f"sha256:{'0' * 64}")
    with pytest.raises(OriginalRQ1V3BankError, match="declared lineage group mismatch"):
        build_lineage_graph((mismatched, _candidate(1)))


def test_bfcl_w0_parent_and_w2_variant_share_cluster_without_inflating_independent_n() -> None:
    registry = (
        Path(__file__).resolve().parents[2]
        / "experiments/host_boundary_v2/rq1_original_a0_a4_v3"
        / "data_contracts/bfcl/contracts.jsonl"
    )
    approved = [
        json.loads(line)
        for line in registry.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    approved_pair = {
        row["utility_stratum"]: row
        for row in approved
        if row["cluster_id"] == "bfcl:f7cf7359:multiple_46"
        and row["utility_stratum"] in {"W0", "W2"}
    }
    assert set(approved_pair) == {"W0", "W2"}
    w0_contract = approved_pair["W0"]
    w2_contract = approved_pair["W2"]
    parent = replace(
        _candidate(40, exposed=True),
        candidate_id=w0_contract["contract_id"],
        cluster_id=w0_contract["cluster_id"],
        source_dataset=w0_contract["source_version"],
        source_task_id=w0_contract["source_task_id"],
        source_payload_sha256=w0_contract["source_sha256"],
        utility_stratum=w0_contract["utility_stratum"],
        normalized_task_contract_sha256=sha256_json(w0_contract),
        normalized_prompt_sha256=w0_contract["lineage"]["normalized_prompt_sha256"],
    )
    proposal_variant = replace(
        parent,
        candidate_id=w2_contract["contract_id"],
        source_payload_sha256=w2_contract["source_sha256"],
        utility_stratum=w2_contract["utility_stratum"],
        normalized_task_contract_sha256=sha256_json(w2_contract),
        authorized_effect_target_sha256=_hash("bfcl-multiple-46-proposal-target"),
        normalized_prompt_sha256=w2_contract["lineage"]["normalized_prompt_sha256"],
    )
    ordinary = tuple(_candidate(index) for index in range(6))
    candidates = (*ordinary, parent, proposal_variant)
    graph = build_lineage_graph(candidates)
    assert graph.candidate_to_group[parent.candidate_id] == graph.candidate_to_group[proposal_variant.candidate_id]
    assert len(graph.groups) == 7

    split = split_candidate_frame(
        candidates,
        formal_counts_by_stratum={
            "fixture-stratum": 2,
            "multistratum[W0|W2]": 0,
        },
        development_counts_by_stratum=None,
        utility_target_masses={"fixture-stratum": 1.0},
        safety_target_masses={"H-TOOL:task-native-sensitive-effect": 1.0},
        selection_seed=9201,
    )
    bank_audit = audit_bank_split(split, candidates)
    assert bank_audit["passed"], bank_audit
    assert bank_audit["development_candidate_count"] == 6
    assert bank_audit["development_lineage_count"] == 5

    schedule = build_matched_schedule(
        split,
        candidates,
        bank_id="development",
        model_seeds=(9202, 9203, 9204),
        schedule_randomization_seed=9205,
        prompt_bundle_sha256=_hash("bfcl-regression-prompt-bundle"),
        surface_contract_sha256=_hash("bfcl-regression-surface"),
    )
    selected = [
        candidate
        for candidate in candidates
        if any(
            assignment.candidate_id == candidate.candidate_id
            and assignment.bank_id == "development"
            for assignment in split.assignments
        )
    ]
    schedule_audit = audit_matched_schedule(
        schedule,
        selected_candidates=selected,
        expected_replications={"seed-9202": 9202, "seed-9203": 9203, "seed-9204": 9204},
    )
    assert schedule_audit["passed"], schedule_audit
    assert schedule_audit["lineage_count"] == 5
    assert schedule_audit["cluster_count"] == 5
    variant_rows = [
        row
        for row in schedule
        if row.cluster_id == w0_contract["cluster_id"]
    ]
    assert {row.task_contract_id for row in variant_rows} == {
        parent.normalized_task_contract_sha256,
        proposal_variant.normalized_task_contract_sha256,
    }
    assert len({row.block_id for row in variant_rows}) == 4


def _renumber_and_rehash(rows):
    result = []
    for ordinal, row in enumerate(rows, start=1):
        updated = replace(row, ordinal=ordinal, episode_id="pending")
        result.append(
            replace(
                updated,
                episode_id=sha256_json(
                    {
                        key: value
                        for key, value in updated.to_dict().items()
                        if key != "episode_id"
                    }
                ),
            )
        )
    return tuple(result)


def test_schedule_audit_rejects_missing_extra_and_duplicate_coordinates_even_after_rehash() -> None:
    candidates, split = _split_fixture()
    selected = [
        candidate
        for candidate in candidates
        if any(
            assignment.candidate_id == candidate.candidate_id
            and assignment.bank_id == "formal_holdout"
            for assignment in split.assignments
        )
    ]
    schedule = build_matched_schedule(
        split,
        candidates,
        bank_id="formal_holdout",
        model_seeds=(11, 12, 13),
        schedule_randomization_seed=904,
        prompt_bundle_sha256=_hash("prompt-bundle"),
        surface_contract_sha256=_hash("surface-contract"),
    )
    expected_reps = {"seed-11": 11, "seed-12": 12, "seed-13": 13}

    missing_pair = _renumber_and_rehash(schedule[2:])
    missing_audit = audit_matched_schedule(
        missing_pair,
        selected_candidates=selected,
        expected_replications=expected_reps,
    )
    assert not missing_audit["passed"]
    assert any("incomplete_or_duplicate_block_replication" in error for error in missing_audit["errors"])

    first_contract = schedule[0].task_contract_id
    without_contract = _renumber_and_rehash(
        row for row in schedule if row.task_contract_id != first_contract
    )
    whole_block_audit = audit_matched_schedule(
        without_contract,
        selected_candidates=selected,
        expected_replications=expected_reps,
    )
    assert not whole_block_audit["passed"]
    assert "incomplete_or_extra_schedule_cells" in whole_block_audit["errors"]

    duplicated = _renumber_and_rehash((*schedule, *schedule[:2]))
    duplicate_audit = audit_matched_schedule(
        duplicated,
        selected_candidates=selected,
        expected_replications=expected_reps,
    )
    assert not duplicate_audit["passed"]
    assert any("invalid_pair" in error for error in duplicate_audit["errors"])


def test_level_arm_and_time_block_counterbalance_is_deterministic_and_audited() -> None:
    candidates = tuple(_candidate(index) for index in range(12))
    split = split_candidate_frame(
        candidates,
        formal_counts_by_stratum={"fixture-stratum": 10},
        development_counts_by_stratum=None,
        utility_target_masses={"fixture-stratum": 1.0},
        safety_target_masses={"H-TOOL:task-native-sensitive-effect": 1.0},
        selection_seed=9301,
    )
    kwargs = dict(
        bank_id="formal_holdout",
        model_seeds=(9302, 9303, 9304),
        schedule_randomization_seed=9305,
        prompt_bundle_sha256=_hash("counterbalance-prompt"),
        surface_contract_sha256=_hash("counterbalance-surface"),
    )
    first = build_matched_schedule(split, candidates, **kwargs)
    second = build_matched_schedule(split, tuple(reversed(candidates)), **kwargs)
    assert first == second
    assert audit_matched_schedule(
        first,
        expected_replications={"seed-9302": 9302, "seed-9303": 9303, "seed-9304": 9304},
    )["passed"]

    by_time_block = defaultdict(list)
    for row in first:
        by_time_block[row.time_block_id].append(row)
    assert by_time_block
    for rows in by_time_block.values():
        units = {(row.block_id, row.replicate_id) for row in rows}
        for position in range(5):
            counts = Counter(
                row.authority_level
                for row in rows
                if row.level_order_position == position and row.arm == "B1"
            )
            assert sum(counts.values()) == len(units)
            assert max(counts.get(level, 0) for level in ("A0", "A1", "A2", "A3", "A4")) - min(
                counts.get(level, 0) for level in ("A0", "A1", "A2", "A3", "A4")
            ) <= 1
        for level in ("A0", "A1", "A2", "A3", "A4"):
            first_arms = Counter(
                pair[0].arm
                for pair in (
                    sorted(
                        (row for row in rows if row.pair_id == pair_id),
                        key=lambda row: row.ordinal,
                    )
                    for pair_id in {row.pair_id for row in rows if row.authority_level == level}
                )
            )
            assert abs(first_arms["B1"] - first_arms["M1"]) <= 1


def test_unexposed_multistratum_lineage_is_sampled_once_but_keeps_task_stratum_weights() -> None:
    candidates = []
    for index in range(4):
        parent = replace(
            _candidate(index),
            candidate_id=f"parent-{index}",
            cluster_id=f"shared-cluster-{index}",
            utility_stratum="W0",
            normalized_task_contract_sha256=_hash(f"w0-contract-{index}"),
        )
        variant = replace(
            parent,
            candidate_id=f"variant-{index}",
            utility_stratum="W2",
            normalized_task_contract_sha256=_hash(f"w2-contract-{index}"),
            normalized_prompt_sha256=_hash(f"w2-prompt-{index}"),
        )
        candidates.extend((parent, variant))
    split = split_candidate_frame(
        candidates,
        formal_counts_by_stratum={"multistratum[W0|W2]": 2},
        development_counts_by_stratum=None,
        utility_target_masses={"W0": 0.4, "W2": 0.6},
        safety_target_masses={"H-TOOL:task-native-sensitive-effect": 1.0},
        selection_seed=9401,
    )
    audit = audit_bank_split(split, candidates)
    assert audit["passed"], audit
    assert audit["formal_lineage_count"] == 2
    assert audit["formal_candidate_count"] == 4
    weight_by_stratum = defaultdict(float)
    for weight in split.utility_weights:
        weight_by_stratum[weight.stratum] += weight.normalized_weight
    assert weight_by_stratum == pytest.approx({"W0": 0.4, "W2": 0.6})

    schedule = build_matched_schedule(
        split,
        candidates,
        bank_id="formal_holdout",
        model_seeds=(9402, 9403, 9404),
        schedule_randomization_seed=9405,
        prompt_bundle_sha256=_hash("multistratum-prompt"),
        surface_contract_sha256=_hash("multistratum-surface"),
    )
    assert audit_matched_schedule(schedule)["lineage_count"] == 2
    task_weight_ids = {
        row.task_contract_id: row.utility_weight_id
        for row in schedule
        if row.pair_role == "honest"
    }
    assert len(task_weight_ids) == 4
    assert all(task_weight_ids.values())
