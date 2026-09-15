from __future__ import annotations

import copy
from dataclasses import replace

import pytest

from agentmembrane.host_v2.original_rq1_v3_conditions import (
    B1_REQUIRED_MECHANISMS,
    DEDICATED_ATTACK_ONLY_OPERATIONS,
    M1_CROSS_HOP_DELTA,
    ORIGINAL_RQ1_V3_AUTHORITY_CONTRACTS,
    ORIGINAL_RQ1_V3_COMPATIBILITY_MAPPING,
    ORIGINAL_RQ1_V3_LEVEL_ORDER,
    ORIGINAL_RQ1_V3_OPERATION_ADDITIONS,
    ORIGINAL_RQ1_V3_OPERATION_SCHEMAS,
    ORIGINAL_RQ1_V3_OPERATION_SETS,
    ORIGINAL_RQ1_V3_PROTECTION_PROFILES,
    ORIGINAL_RQ1_V3_STATE_ADDITIONS,
    ORIGINAL_RQ1_V3_STATE_SETS,
    AuthorityContractError,
    BaselineContractError,
    OriginalRQ1V3ConditionError,
    build_original_rq1_v3_formal_matrix,
    build_original_rq1_v3_pc0_matrix,
    canonical_json_bytes,
    clone_authority_contract,
    diff_authority_surfaces,
    public_affordance,
    public_affordance_bytes,
    public_request_errors,
    resolve_condition,
    resolved_admitted_operation_names,
    resolved_public_operation_schemas,
    resolved_state_capabilities,
    validate_authority_contracts,
    validate_original_rq1_v3_baselines,
    validate_original_rq1_v3_conditions,
    validate_surface_parity,
)


def _mutated_contracts(level: str, contract):
    result = dict(ORIGINAL_RQ1_V3_AUTHORITY_CONTRACTS)
    result[level] = contract
    return result


def test_exact_five_original_levels_and_private_compatibility_mapping() -> None:
    assert ORIGINAL_RQ1_V3_LEVEL_ORDER == ("A0", "A1", "A2", "A3", "A4")
    assert ORIGINAL_RQ1_V3_COMPATIBILITY_MAPPING == {
        "A0": ("A0", "H0", "S0"),
        "A1": ("A1", "H1", "S0"),
        "A2": ("A2", "H2", "S2"),
        "A3": ("A3", "H3", "S2"),
        "A4": ("A5", "H5", "S5"),
    }
    validate_authority_contracts()


def test_exact_operation_sets_and_adjacent_additions() -> None:
    for lower, higher in zip(ORIGINAL_RQ1_V3_LEVEL_ORDER, ORIGINAL_RQ1_V3_LEVEL_ORDER[1:]):
        diff = diff_authority_surfaces(lower, higher)
        assert diff["valid"] is True
        assert set(diff["added_operations"]) == ORIGINAL_RQ1_V3_OPERATION_ADDITIONS[(lower, higher)]
        assert diff["removed_operations"] == []
        assert diff["changed_retained_schema_hashes"] == []
        assert diff["lower_request_domain_is_subset"] is True


def test_exact_state_sets_and_adjacent_additions() -> None:
    for lower, higher in zip(ORIGINAL_RQ1_V3_LEVEL_ORDER, ORIGINAL_RQ1_V3_LEVEL_ORDER[1:]):
        diff = diff_authority_surfaces(lower, higher)
        assert set(diff["added_state_classes"]) == ORIGINAL_RQ1_V3_STATE_ADDITIONS[(lower, higher)]
        assert diff["removed_state_classes"] == []


def test_a3_retains_every_a2_operation_and_s2_state() -> None:
    assert ORIGINAL_RQ1_V3_OPERATION_SETS["A2"] < ORIGINAL_RQ1_V3_OPERATION_SETS["A3"]
    assert ORIGINAL_RQ1_V3_STATE_SETS["A2"] < ORIGINAL_RQ1_V3_STATE_SETS["A3"]
    assert "submit_memory_proposal" in ORIGINAL_RQ1_V3_OPERATION_SETS["A3"]
    assert ORIGINAL_RQ1_V3_COMPATIBILITY_MAPPING["A3"][2] == "S2"


def test_a4_contains_only_original_ambient_additions_and_no_attack_endpoints() -> None:
    assert (
        ORIGINAL_RQ1_V3_OPERATION_SETS["A4"] - ORIGINAL_RQ1_V3_OPERATION_SETS["A3"]
        == {"call_tool", "read_shared_memory", "write_shared_memory", "send_message"}
    )
    assert ORIGINAL_RQ1_V3_OPERATION_SETS["A4"].isdisjoint(DEDICATED_ATTACK_ONLY_OPERATIONS)


def test_all_operation_schemas_are_closed_and_exclude_trusted_fields() -> None:
    trusted = {
        "approved", "trusted", "active", "persistent", "executed", "issuer",
        "actor", "delegable", "authority_level", "condition_id", "protection_arm",
    }
    for schema in ORIGINAL_RQ1_V3_OPERATION_SCHEMAS.values():
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) <= set(schema["properties"])
        assert set(schema["properties"]).isdisjoint(trusted)


def test_three_a2_proposals_are_distinct_closed_and_remain_inert_at_higher_levels() -> None:
    proposal_operations = {
        "submit_evidence_candidate",
        "submit_memory_proposal",
        "submit_action_proposal",
    }
    for level in ("A2", "A3", "A4"):
        condition = resolve_condition(level, "B1")
        assert proposal_operations <= resolved_admitted_operation_names(condition)
        schemas = resolved_public_operation_schemas(condition)
        assert all(schemas[name]["additionalProperties"] is False for name in proposal_operations)
        assert {"proposal_immutable", "proposal_inert"} <= condition.authority.lifetime_rules
    assert not ({"active", "persistent", "executed"} & set(
        ORIGINAL_RQ1_V3_OPERATION_SCHEMAS["submit_memory_proposal"]["properties"]
    ))


def test_a3_scoped_contract_is_fully_bound_nondelegable_and_task_limited() -> None:
    contract = resolve_condition("A3", "B1").authority
    assert {
        "principal", "operation_set", "resource_scope", "purpose", "task_id",
        "issued_at", "expires_at", "delegable",
    } == contract.capability_binding_fields
    assert {"task_bound", "short_lived", "non_delegable", "revoked_on_task_end", "checked_at_use"} <= contract.lifetime_rules
    assert resolved_admitted_operation_names(resolve_condition("A3", "M1")).isdisjoint(
        {"delegate_capability", "renew_capability", "mint_capability", "mutate_capability_scope"}
    )


def test_public_read_domain_replays_and_scoped_read_only_begins_at_a3() -> None:
    for level in ("A1", "A2", "A3", "A4"):
        condition = resolve_condition(level, "B1")
        assert public_request_errors(condition, "read_resource", {"resource": "public:guide"}) == ()
    for level in ("A1", "A2"):
        errors = public_request_errors(
            resolve_condition(level, "B1"),
            "read_resource",
            {"resource": "project:document", "capability_id": "opaque-cap"},
        )
        assert any("require A3/A4" in item for item in errors)
    for level in ("A3", "A4"):
        assert public_request_errors(
            resolve_condition(level, "B1"),
            "read_resource",
            {"resource": "project:document", "capability_id": "opaque-cap"},
        ) == ()


def test_schema_validation_rejects_unknown_missing_and_trusted_fields() -> None:
    condition = resolve_condition("A2", "M1")
    assert public_request_errors(
        condition,
        "submit_evidence_candidate",
        {"claim": "c", "evidence_refs": ["public:e1"]},
    ) == ()
    missing = public_request_errors(
        condition,
        "submit_evidence_candidate",
        {"claim": "c"},
    )
    assert any("missing required" in item for item in missing)
    unexpected = public_request_errors(
        condition,
        "submit_evidence_candidate",
        {"claim": "c", "evidence_refs": [], "approved": True},
    )
    assert any("undeclared" in item for item in unexpected)
    assert any("trusted fields" in item for item in unexpected)


def test_formal_matrix_is_exactly_five_by_two_and_excludes_pc0() -> None:
    rows = build_original_rq1_v3_formal_matrix()
    assert len(rows) == 10
    assert [(row.level, row.arm) for row in rows] == [
        (level, arm) for level in ORIGINAL_RQ1_V3_LEVEL_ORDER for arm in ("B1", "M1")
    ]
    assert all(row.formal_eligible for row in rows)
    assert all(row.arm != "PC0" for row in rows)


def test_pc0_is_development_only_and_cannot_enter_formal_resolver() -> None:
    rows = build_original_rq1_v3_pc0_matrix(("A2", "A3"))
    assert [(row.level, row.arm) for row in rows] == [("A2", "PC0"), ("A3", "PC0")]
    assert not any(row.formal_eligible for row in rows)
    with pytest.raises(BaselineContractError, match="development-only"):
        resolve_condition("A2", "PC0", formal=True)


def test_b1_is_strong_conventional_and_m1_is_exact_union_delta() -> None:
    validate_original_rq1_v3_baselines()
    profiles = ORIGINAL_RQ1_V3_PROTECTION_PROFILES
    assert profiles["B1"].enabled_mechanisms == B1_REQUIRED_MECHANISMS
    assert profiles["M1"].enabled_mechanisms == B1_REQUIRED_MECHANISMS | M1_CROSS_HOP_DELTA
    assert profiles["M1"].enabled_mechanisms - profiles["B1"].enabled_mechanisms == M1_CROSS_HOP_DELTA
    assert {"terminal_reference_monitor", "exact_capability_binding", "trusted_memory_gate", "sensitive_tool_gate", "trusted_control_plane_gate"} <= B1_REQUIRED_MECHANISMS


def test_b1_m1_and_pc0_public_surfaces_are_byte_identical_within_level() -> None:
    for level in ORIGINAL_RQ1_V3_LEVEL_ORDER:
        payloads = {
            public_affordance_bytes(resolve_condition(level, arm))
            for arm in ("PC0", "B1", "M1")
        }
        assert len(payloads) == 1


def test_public_surface_has_no_private_arm_condition_or_compatibility_labels() -> None:
    payload = public_affordance(resolve_condition("A4", "M1"))
    serialized = canonical_json_bytes(payload).decode("utf-8")
    for forbidden in (
        "condition_id", "protection_arm", "enabled_mechanisms", '"M1"',
        '"A4"', '"A5"', '"H5"', '"S5"', "oracle_target",
    ):
        assert forbidden not in serialized


def test_resolved_schema_is_a_defensive_copy() -> None:
    condition = resolve_condition("A1", "B1")
    schemas = resolved_public_operation_schemas(condition)
    schemas["read_resource"]["required"].clear()
    assert ORIGINAL_RQ1_V3_OPERATION_SCHEMAS["read_resource"]["required"] == ["resource"]
    assert resolved_public_operation_schemas(condition)["read_resource"]["required"] == ["resource"]
    assert resolved_state_capabilities(condition) == frozenset()


def test_mutation_a3_s0_mapping_is_rejected() -> None:
    mutant = clone_authority_contract("A3", compatibility_state_surface="S0")
    with pytest.raises(AuthorityContractError, match="compatibility mapping"):
        validate_authority_contracts(_mutated_contracts("A3", mutant))


def test_mutation_a3_drops_memory_proposal_is_rejected() -> None:
    source = clone_authority_contract("A3")
    names = source.operation_names - {"submit_memory_proposal"}
    schemas = {name: schema for name, schema in source.operation_schemas.items() if name in names}
    mutant = replace(source, operation_names=names, operation_schemas=schemas)
    with pytest.raises(AuthorityContractError, match="operation set"):
        validate_authority_contracts(_mutated_contracts("A3", mutant))


def test_mutation_a3_drops_a2_state_is_rejected() -> None:
    source = clone_authority_contract("A3")
    mutant = replace(source, state_capabilities=source.state_capabilities - {"inert_memory_proposals"})
    with pytest.raises(AuthorityContractError, match="state set"):
        validate_authority_contracts(_mutated_contracts("A3", mutant))


def test_mutation_attack_only_operation_is_rejected() -> None:
    source = clone_authority_contract("A2")
    schemas = copy.deepcopy(dict(source.operation_schemas))
    schemas["execute_proposal"] = {
        "type": "object", "properties": {}, "required": [], "additionalProperties": False
    }
    mutant = replace(source, operation_names=source.operation_names | {"execute_proposal"}, operation_schemas=schemas)
    with pytest.raises(AuthorityContractError, match="operation set|attack-only"):
        validate_authority_contracts(_mutated_contracts("A2", mutant))


def test_mutation_retained_schema_is_rejected() -> None:
    source = clone_authority_contract("A3")
    schemas = copy.deepcopy(dict(source.operation_schemas))
    schemas["read_resource"]["properties"]["extra"] = {"type": "string"}
    mutant = replace(source, operation_schemas=schemas)
    with pytest.raises(AuthorityContractError, match="schema differs|invalid cumulative"):
        validate_authority_contracts(_mutated_contracts("A3", mutant))


def test_mutation_scoped_binding_or_lifetime_is_rejected() -> None:
    source = clone_authority_contract("A3")
    binding_mutant = replace(source, capability_binding_fields=source.capability_binding_fields - {"purpose"})
    with pytest.raises(AuthorityContractError, match="binding"):
        validate_authority_contracts(_mutated_contracts("A3", binding_mutant))
    lifetime_mutant = replace(source, lifetime_rules=source.lifetime_rules - {"non_delegable"})
    with pytest.raises(AuthorityContractError, match="lifetime"):
        validate_authority_contracts(_mutated_contracts("A3", lifetime_mutant))


def test_mutation_pc0_formal_or_weak_b1_is_rejected() -> None:
    pc0_formal = dict(ORIGINAL_RQ1_V3_PROTECTION_PROFILES)
    pc0_formal["PC0"] = replace(pc0_formal["PC0"], formal_eligible=True)
    with pytest.raises(BaselineContractError, match="development-only"):
        validate_original_rq1_v3_baselines(pc0_formal)
    weak_b1 = dict(ORIGINAL_RQ1_V3_PROTECTION_PROFILES)
    weak_b1["B1"] = replace(
        weak_b1["B1"],
        enabled_mechanisms=weak_b1["B1"].enabled_mechanisms - {"terminal_reference_monitor"},
    )
    with pytest.raises(BaselineContractError, match="missing conventional controls"):
        validate_original_rq1_v3_baselines(weak_b1)


def test_mutation_m1_gets_more_than_exact_delta_is_rejected() -> None:
    profiles = dict(ORIGINAL_RQ1_V3_PROTECTION_PROFILES)
    profiles["M1"] = replace(
        profiles["M1"], enabled_mechanisms=profiles["M1"].enabled_mechanisms | {"hidden_reviewer"}
    )
    with pytest.raises(BaselineContractError, match="exactly the frozen cross-hop delta"):
        validate_original_rq1_v3_baselines(profiles)


def test_mutation_arm_specific_public_field_or_label_is_rejected() -> None:
    rows = tuple(resolve_condition("A2", arm) for arm in ("B1", "M1"))

    def leaking_surface(condition):
        payload = public_affordance(condition)
        payload["arm"] = condition.arm
        return payload

    with pytest.raises(OriginalRQ1V3ConditionError, match="private keys"):
        validate_surface_parity(rows, surface_builder=leaking_surface)


def test_formal_matrix_validator_rejects_missing_duplicate_and_pc0_cells() -> None:
    rows = build_original_rq1_v3_formal_matrix()
    with pytest.raises(OriginalRQ1V3ConditionError, match="formal matrix cells differ"):
        validate_original_rq1_v3_conditions(rows[:-1], formal=True)
    with pytest.raises(OriginalRQ1V3ConditionError, match="duplicate condition cell"):
        validate_original_rq1_v3_conditions(rows + (rows[0],), formal=True)
    with pytest.raises(OriginalRQ1V3ConditionError, match="development-only arm"):
        validate_original_rq1_v3_conditions(
            rows + (resolve_condition("A0", "PC0"),), formal=True, require_complete=False
        )
