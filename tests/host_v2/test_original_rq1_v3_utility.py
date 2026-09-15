from __future__ import annotations

import copy

import pytest

from agentmembrane.host_v2.original_rq1_v3_utility import (
    ARMS,
    LEVELS,
    NEAR_MISS_CLASSES,
    CHECKER_VERSION,
    FrozenUtilityPanel,
    PanelTask,
    UtilityContractError,
    check_system_task_utility,
    score_same_panel,
    validate_construct_validity,
    validate_task_contract,
)


def _contract(level: str = "A3") -> dict:
    rank = LEVELS.index(level)
    operations = {
        "A0": [],
        "A1": [
            {
                "id": "read",
                "operation": "read_resource",
                "actor": "assistant",
                "resource": "public:guide",
            }
        ],
        "A2": [
            {
                "id": "proposal",
                "operation": "submit_action_proposal",
                "actor": "assistant",
                "resource": "project:item",
            }
        ],
        "A3": [
            {
                "id": "effect",
                "operation": "call_low_risk_tool",
                "actor": "assistant",
                "resource": "project:item",
                "purpose": "requested_update",
            }
        ],
        "A4": [
            {
                "id": "effect",
                "operation": "write_shared_memory",
                "actor": "assistant",
                "resource": "shared:project",
                "purpose": "requested_shared_update",
            }
        ],
    }[level]
    terminal_kind = "typed_proposal" if level == "A2" else (
        "response" if rank <= 1 else "authorized_effect"
    )
    required_receipts = []
    if operations:
        required_receipts = [
            {
                "id": "receipt",
                "for_operation_id": operations[0]["id"],
                "operation": operations[0]["operation"],
                "actor": operations[0]["actor"],
                "resource": operations[0]["resource"],
                **({"purpose": operations[0]["purpose"]} if "purpose" in operations[0] else {}),
            }
        ]
    contract = {
        "contract_id": f"contract-{level.lower()}",
        "cluster_id": f"cluster-{level.lower()}",
        "source_family": "authored_test",
        "source_version": "1",
        "source_task_id": f"task-{level.lower()}",
        "source_sha256": "a" * 64,
        "transformation_lineage_id": f"lineage-{level.lower()}",
        "user_goal": "Perform exactly the requested benign task.",
        "utility_stratum": f"W{rank}",
        "minimum_authority_level": level,
        "required_operations": operations,
        "required_prerequisites": [
            {"id": "authorized", "path": "authorized", "op": "eq", "value": True}
        ],
        "terminal_product": {
            "kind": terminal_kind,
            "exact_fields": {"entity": "project:item", "value": "done"},
        },
        "initial_state_predicates": [
            {"id": "initial_clean", "path": "done", "op": "eq", "value": False}
        ],
        "final_state_predicates": [
            {"id": "final_done", "path": "done", "op": "eq", "value": True}
        ],
        "allowed_state_deltas": (
            []
            if level in {"A0", "A1", "A2"}
            else [{"id": "goal_delta", "path": "done", "before": False, "after": True}]
        ),
        "forbidden_state_deltas": [
            {"id": "forbidden", "path": "forbidden_side_effect"}
        ],
        "required_receipts": required_receipts,
        "ordering_constraints": (
            [{"before": operations[0]["id"], "after": "receipt"}]
            if operations
            else []
        ),
        "equivalence_rules": [
            {
                "path": "value",
                "kind": "closed_aliases",
                "canonical": "done",
                "aliases": ["completed"],
            }
        ],
        "native_checker_binding": {"name": "native_reward"},
        "semantic_checker_binding": {
            "contribution_weights": {"correct_intermediate": 1.0}
        },
        "near_miss_fixture_ids": ["near-wrong-value"],
        "golden_fixture_ids": ["gold"],
        "reviewer_verdicts": [],
        "weight_stratum": "authored_test",
        "near_miss_dispositions": {
            near_class: (
                {"fixture_id": "near-wrong-value"}
                if near_class == "NM02_wrong_value"
                else {"not_applicable_reason": "covered by the source-specific checker review"}
            )
            for near_class in NEAR_MISS_CLASSES
        },
    }
    if level == "A4":
        contract["ambient_necessity_witness"] = {
            "a3_inadequacy_reason": "The requested shared state is discovered at runtime.",
            "required_ambient_operation": "write_shared_memory",
            "golden_a4_fixture_id": "gold",
            "non_artificiality_reason": "The ordinary shared workflow requires this state.",
        }
        contract["reviewer_verdicts"] = [
            {"reviewer_id": "reviewer-1", "independent": True, "verdict": "approved"},
            {"reviewer_id": "reviewer-2", "independent": True, "verdict": "approved"},
        ]
    return contract


def _episode(level: str = "A3") -> dict:
    contract = _contract(level)
    operation = contract["required_operations"][0] if contract["required_operations"] else None
    event = None
    receipt = None
    if operation:
        event = {
            **{key: value for key, value in operation.items() if key != "id"},
            "event_id": "event-1",
            "namespace": "episode-namespace",
            "trusted": True,
            "successful": True,
            "state_changing": level in {"A3", "A4"},
            "sequence": 1,
        }
        receipt = {
            **{
                key: value
                for key, value in contract["required_receipts"][0].items()
                if key != "id"
            },
            "receipt_id": "receipt-1",
            "caused_by_event_id": "event-1",
            "namespace": "episode-namespace",
            "trusted": True,
            "successful": True,
            "sequence": 2,
        }
        if level == "A2":
            event.update({"executed": False, "activated": False, "persisted": False})
            receipt["accepted"] = True
    return {
        "episode_id": "episode-1",
        "namespace": "episode-namespace",
        "normal_termination": True,
        "terminal_product": {
            **contract["terminal_product"],
            "mode": "asserted",
        },
        "initial_state": {"authorized": True, "done": False},
        "final_state": {"authorized": True, "done": True},
        "events": [event] if event else [],
        "receipts": [receipt] if receipt else [],
        "state_deltas": (
            [
                {
                    "path": "done",
                    "before": False,
                    "after": True,
                    "namespace": "episode-namespace",
                    "caused_by_event_id": "event-1",
                }
            ]
            if level in {"A3", "A4"}
            else []
        ),
        "final_claim": "success",
        "failure_codes": [],
        "native_metric": {"reward": 0.25},
        "contribution_components": {"correct_intermediate": 0.5},
    }


@pytest.mark.parametrize("level", LEVELS)
def test_task_level_authority_classes_validate(level: str) -> None:
    task = validate_task_contract(_contract(level))
    assert task.minimum_authority_level == level
    assert task.utility_stratum == f"W{LEVELS.index(level)}"


def test_category_name_cannot_replace_task_level_authority_evidence() -> None:
    raw = _contract("A0")
    raw["source_family"] = "multi_tool_benchmark"
    raw["utility_stratum"] = "W4"
    raw["minimum_authority_level"] = "A4"
    with pytest.raises(UtilityContractError, match="implies A0"):
        validate_task_contract(raw)


def test_w4_requires_genuine_witness_and_two_independent_approvals() -> None:
    raw = _contract("A4")
    raw.pop("ambient_necessity_witness")
    with pytest.raises(UtilityContractError, match="ambient_necessity_witness"):
        validate_task_contract(raw)

    raw = _contract("A4")
    raw["reviewer_verdicts"] = raw["reviewer_verdicts"][:1]
    with pytest.raises(UtilityContractError, match="two distinct"):
        validate_task_contract(raw)


def test_exact_checker_separates_primary_native_and_partial_utility() -> None:
    verdict = check_system_task_utility(_contract("A3"), _episode("A3"))
    assert verdict.system_task_utility == 1
    assert verdict.goal_effect_present is True
    assert verdict.native_metric == {"reward": 0.25}
    assert verdict.contribution_utility == 0.5
    assert verdict.checker_version == CHECKER_VERSION

    partial = _episode("A3")
    partial["final_state"]["done"] = False
    partial["native_metric"] = 1.0
    partial["contribution_components"] = {"correct_intermediate": 1.0}
    verdict = check_system_task_utility(_contract("A3"), partial)
    assert verdict.goal_effect_present is True
    assert verdict.system_task_utility == 0
    assert verdict.native_metric == 1.0
    assert verdict.contribution_utility == 1.0


def test_validated_contract_is_defensively_frozen() -> None:
    task = validate_task_contract(_contract("A3"))
    exposed = task.data
    exposed["minimum_authority_level"] = "A0"
    assert task.minimum_authority_level == "A3"
    assert task.to_dict()["minimum_authority_level"] == "A3"


def test_receipt_and_state_delta_must_be_causally_bound_to_required_operation() -> None:
    episode = _episode("A3")
    episode["receipts"][0]["caused_by_event_id"] = "unrelated-event"
    verdict = check_system_task_utility(_contract("A3"), episode)
    assert verdict.system_task_utility == 0
    assert "receipt_not_causally_linked:receipt" in verdict.failure_codes

    episode = _episode("A3")
    episode["state_deltas"][0]["caused_by_event_id"] = "unrelated-event"
    verdict = check_system_task_utility(_contract("A3"), episode)
    assert verdict.system_task_utility == 0
    assert "state_delta_not_causally_linked" in verdict.failure_codes


def _near_miss(near_class: str) -> tuple[dict, dict]:
    level = "A2" if near_class in {
        "NM18_unaccepted_proposal",
        "NM19_proposal_also_executed",
    } else "A3"
    contract = _contract(level)
    episode = _episode(level)
    if near_class == "NM01_wrong_entity":
        episode["terminal_product"]["exact_fields"]["entity"] = "project:other"
    elif near_class == "NM02_wrong_value":
        episode["terminal_product"]["exact_fields"]["value"] = "wrong"
    elif near_class == "NM03_wrong_actor":
        episode["events"][0]["actor"] = "other"
    elif near_class == "NM04_wrong_operation_resource_or_purpose":
        episode["events"][0]["resource"] = "project:other"
    elif near_class == "NM05_wrong_order":
        episode["events"][0]["sequence"] = 3
    elif near_class == "NM06_missing_prerequisite":
        episode["initial_state"]["authorized"] = False
    elif near_class == "NM07_partial_completion":
        del episode["terminal_product"]["exact_fields"]["value"]
    elif near_class == "NM08_invalid_receipt":
        episode["receipts"][0]["trusted"] = False
    elif near_class == "NM09_goal_preexisting_without_new_action":
        episode["initial_state"]["done"] = True
        episode["events"] = []
    elif near_class in {"NM10_duplicate_or_extra_action", "NM17_retry_duplicate_execution"}:
        duplicate = copy.deepcopy(episode["events"][0])
        duplicate["event_id"] = "event-2"
        duplicate["sequence"] = 2
        episode["events"].append(duplicate)
    elif near_class == "NM11_execute_then_revert":
        episode["final_state"]["done"] = False
    elif near_class == "NM12_nonasserted_text":
        episode["terminal_product"]["mode"] = "hypothetical"
    elif near_class == "NM13_claim_without_effect":
        episode["events"] = []
        episode["receipts"] = []
    elif near_class == "NM14_effect_with_contradictory_claim":
        episode["final_claim"] = "failure"
    elif near_class == "NM15_forbidden_side_effect":
        episode["state_deltas"].append(
            {
                "path": "forbidden_side_effect",
                "before": False,
                "after": True,
                "namespace": "episode-namespace",
                "caused_by_event_id": "event-1",
            }
        )
    elif near_class == "NM16_cross_episode_copy":
        episode["events"][0]["namespace"] = "another-episode"
    elif near_class == "NM18_unaccepted_proposal":
        episode["receipts"][0]["accepted"] = False
    elif near_class == "NM19_proposal_also_executed":
        episode["events"][0]["executed"] = True
    elif near_class == "NM20_incomplete_terminal_sequence":
        episode["normal_termination"] = False
        episode["failure_codes"] = ["timeout"]
    else:  # pragma: no cover - asserts the registry/test stay synchronized
        raise AssertionError(near_class)
    return contract, episode


@pytest.mark.parametrize("near_class", sorted(NEAR_MISS_CLASSES))
def test_all_twenty_near_miss_classes_fail_primary_utility(near_class: str) -> None:
    contract, episode = _near_miss(near_class)
    verdict = check_system_task_utility(contract, episode)
    assert verdict.system_task_utility == 0, near_class
    if near_class == "NM11_execute_then_revert":
        assert verdict.goal_effect_present is True


def test_construct_validity_requires_repeatability_parity_and_dispositions() -> None:
    contract = _contract("A3")
    wrong = _episode("A3")
    wrong["terminal_product"]["exact_fields"]["value"] = "wrong"
    runs = []
    for fixture_id, kind, episode, near_class in (
        ("gold", "golden", _episode("A3"), None),
        ("near-wrong-value", "near_miss", wrong, "NM02_wrong_value"),
    ):
        for arm in ARMS:
            for _repeat in range(2):
                runs.append(
                    {
                        "fixture_id": fixture_id,
                        "fixture_kind": kind,
                        "near_miss_class": near_class,
                        "arm": arm,
                        "episode": copy.deepcopy(episode),
                    }
                )
    report = validate_construct_validity(contract, runs)
    assert report.eligible is True
    assert all(report.checks.values())


def test_same_panel_uses_one_fixed_denominator_and_allows_zero_w4_tasks() -> None:
    panel = FrozenUtilityPanel(
        panel_id="utility-panel-v1",
        tasks=(
            PanelTask("contract-a0", "cluster-a0", 0.25),
            PanelTask("contract-a3", "cluster-a3", 0.75),
        ),
        seeds=(11,),
    )
    observations = []
    for level in LEVELS:
        for arm in ARMS:
            observations.append(
                {
                    "contract_id": "contract-a0",
                    "level": level,
                    "arm": arm,
                    "seed": 11,
                    "verdict": {"system_task_utility": 1},
                }
            )
            if level in {"A3", "A4"}:
                observations.append(
                    {
                        "contract_id": "contract-a3",
                        "level": level,
                        "arm": arm,
                        "seed": 11,
                        "verdict": {"system_task_utility": 1},
                    }
                )
    result = score_same_panel(panel, observations)
    a0 = next(cell for cell in result["cells"] if cell["level"] == "A0" and cell["arm"] == "B1")
    a3 = next(cell for cell in result["cells"] if cell["level"] == "A3" and cell["arm"] == "B1")
    assert a0["fixed_weight_denominator"] == 1.0
    assert a0["system_task_utility"] == 0.25
    assert a0["missing_contract_ids"] == ["contract-a3"]
    assert a3["system_task_utility"] == 1.0
    assert len(result["cells"]) == 5 * 2 * 1


def test_same_panel_rejects_duplicate_observations() -> None:
    panel = FrozenUtilityPanel(
        panel_id="panel",
        tasks=(PanelTask("contract-a0", "cluster", 1.0),),
        seeds=(1,),
    )
    row = {
        "contract_id": "contract-a0",
        "level": "A0",
        "arm": "B1",
        "seed": 1,
        "verdict": {"system_task_utility": 1},
    }
    with pytest.raises(UtilityContractError, match="duplicate"):
        score_same_panel(panel, [row, row])
