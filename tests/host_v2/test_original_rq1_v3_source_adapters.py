from __future__ import annotations

import copy
from dataclasses import replace
import json
from pathlib import Path

import pytest

from agentmembrane.host_v2.original_rq1_v3_source_adapters import (
    DEFAULT_CONTRACT_ROOT,
    RuntimeEvidenceAuthority,
    SourceAdapterError,
    build_development_source_coverage,
    build_development_source_scenarios,
    execute_development_source_scenario,
    load_bound_source_adapter,
    load_source_contract,
)
from agentmembrane.host_v2.schema import sha256_json


ROOT = Path(__file__).resolve().parents[2]
AUTHORITY_KEY = b"rq1-v3-source-adapter-test-key-32"


def _jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _authority() -> RuntimeEvidenceAuthority:
    return RuntimeEvidenceAuthority("test-evaluator", AUTHORITY_KEY)


def _identity(adapter) -> dict:
    return adapter.binding.identity


def _model(adapter, *, response: dict | None, final_claim: str | None = "success") -> dict:
    return {
        **_identity(adapter),
        "response": copy.deepcopy(response),
        "final_claim": final_claim,
    }


def _native(adapter, metric: object) -> dict:
    return {**_identity(adapter), "native_metric": copy.deepcopy(metric)}


def _issue(authority: RuntimeEvidenceAuthority, payload: dict):
    return authority.issue(
        payload,
        ledger_verified=True,
        verified_receipt_ids=[row["receipt_id"] for row in payload["receipts"]],
        initial_state_sha256=sha256_json(payload["initial_state"]),
        final_state_sha256=sha256_json(payload["final_state"]),
    )


def _runtime_payload(adapter, episode: dict, *, terminal_from_runtime: bool) -> dict:
    return {
        **_identity(adapter),
        "episode_id": episode["episode_id"],
        "namespace": episode["namespace"],
        "normal_termination": episode["normal_termination"],
        "terminal_product": (
            copy.deepcopy(episode["terminal_product"])
            if terminal_from_runtime
            else None
        ),
        "initial_state": copy.deepcopy(episode["initial_state"]),
        "final_state": copy.deepcopy(episode["final_state"]),
        "events": copy.deepcopy(episode["events"]),
        "receipts": copy.deepcopy(episode["receipts"]),
        "state_deltas": copy.deepcopy(episode["state_deltas"]),
        "failure_codes": copy.deepcopy(episode["failure_codes"]),
    }


def _effect_episode(contract: dict, fixture_id: str, source_key: str) -> dict:
    namespace = f"development:{source_key}:{fixture_id}"
    events: list[dict] = []
    receipts: list[dict] = []
    event_by_operation: dict[str, str] = {}
    receipt_by_operation = {
        item["for_operation_id"]: item for item in contract["required_receipts"]
    }
    sequence = 1
    for operation in contract["required_operations"]:
        event_id = f"event:{operation['id']}"
        event_by_operation[operation["id"]] = event_id
        event = {
            key: copy.deepcopy(value)
            for key, value in operation.items()
            if key not in {"id", "min_count", "max_count"}
        }
        event.update(
            {
                "event_id": event_id,
                "namespace": namespace,
                "trusted": True,
                "successful": True,
                "sequence": sequence,
            }
        )
        events.append(event)
        sequence += 1
        requirement = receipt_by_operation[operation["id"]]
        receipt = {
            key: copy.deepcopy(value)
            for key, value in requirement.items()
            if key not in {"id", "for_operation_id", "min_count", "max_count"}
        }
        receipt.update(
            {
                "receipt_id": f"receipt:{requirement['id']}",
                "caused_by_event_id": event_id,
                "namespace": namespace,
                "trusted": True,
                "successful": True,
                "sequence": sequence,
            }
        )
        receipts.append(receipt)
        sequence += 1

    if source_key == "agentdojo":
        state_changing = [row for row in events if row.get("state_changing") is True]
        assert state_changing
        initial_state = {
            "authorized": True,
            "source_available": True,
            "goal_present": False,
        }
        final_state = {
            "authorized": True,
            "source_available": True,
            "goal_present": True,
        }
        state_deltas = [
            {
                "path": "goal_present",
                "before": False,
                "after": True,
                "namespace": namespace,
                "caused_by_event_id": state_changing[-1]["event_id"],
            }
        ]
        native_metric = {"source": "AgentDojo", "utility": True}
    else:
        initial_hash = next(
            item["value"]
            for item in contract["initial_state_predicates"]
            if item["id"] == "source-snapshot"
        )
        effect_ids = [
            item["path"].split(".")[-1] for item in contract["allowed_state_deltas"]
        ]
        initial_state = {
            "authorized": True,
            "task_visible": True,
            "source_initial_state_sha256": initial_hash,
            "effects": {effect_id: False for effect_id in effect_ids},
        }
        final_state = {
            "authorized": True,
            "task_visible": True,
            "source_initial_state_sha256": initial_hash,
            "effects": {effect_id: True for effect_id in effect_ids},
        }
        state_deltas = []
        for delta in contract["allowed_state_deltas"]:
            effect_id = delta["path"].split(".")[-1]
            state_deltas.append(
                {
                    "path": delta["path"],
                    "before": delta["before"],
                    "after": delta["after"],
                    "namespace": namespace,
                    "caused_by_event_id": event_by_operation[f"op-{effect_id}"],
                }
            )
        native_metric = {"source": "tau2", "reward": 1.0}

    return {
        "episode_id": fixture_id,
        "namespace": namespace,
        "normal_termination": True,
        "terminal_product": {
            **copy.deepcopy(contract["terminal_product"]),
            "mode": "asserted",
        },
        "initial_state": initial_state,
        "final_state": final_state,
        "events": events,
        "receipts": receipts,
        "state_deltas": state_deltas,
        "failure_codes": [],
        "native_metric": native_metric,
    }


def _set_path(value: dict, path: str, replacement: object) -> None:
    current: object = value
    parts = path.split(".")
    for part in parts[:-1]:
        current = current[int(part)] if isinstance(current, list) else current[part]
    if isinstance(current, list):
        current[int(parts[-1])] = replacement
    else:
        current[parts[-1]] = replacement


def test_bfcl_local_golden_round_trips_through_strict_adapter() -> None:
    golden = _jsonl(DEFAULT_CONTRACT_ROOT / "bfcl" / "golden_episodes.jsonl")[0]
    authority = _authority()
    adapter = load_bound_source_adapter(
        "bfcl", golden["contract_id"], runtime_authority=authority
    )
    source_episode = golden["episode"]
    evidence = _issue(
        authority,
        _runtime_payload(adapter, source_episode, terminal_from_runtime=False),
    )
    adapted = adapter.normalize(
        model_output=_model(
            adapter,
            response=source_episode["terminal_product"]["exact_fields"],
            final_claim=source_episode["final_claim"],
        ),
        native_output=_native(adapter, source_episode["native_metric"]),
        runtime_evidence=evidence,
    )

    assert adapted.episode == source_episode
    assert adapted.score().system_task_utility == 1
    assert adapted.formal_eligible is False


def test_bfcl_local_near_miss_stays_failed_even_with_perfect_native_score() -> None:
    golden = _jsonl(DEFAULT_CONTRACT_ROOT / "bfcl" / "golden_episodes.jsonl")[0]
    plan = json.loads(
        (DEFAULT_CONTRACT_ROOT / "bfcl" / "fixture_plan.json").read_text(encoding="utf-8")
    )
    contract_plan = next(
        row for row in plan["contracts"] if row["contract_id"] == golden["contract_id"]
    )
    assert "NM02_wrong_value" in contract_plan["near_miss_fixture_ids"]
    authority = _authority()
    adapter = load_bound_source_adapter(
        "bfcl", golden["contract_id"], runtime_authority=authority
    )
    source_episode = golden["episode"]
    wrong = copy.deepcopy(source_episode["terminal_product"]["exact_fields"])
    wrong["value"] = "definitely-wrong"
    evidence = _issue(
        authority,
        _runtime_payload(adapter, source_episode, terminal_from_runtime=False),
    )
    adapted = adapter.normalize(
        model_output=_model(adapter, response=wrong),
        native_output=_native(adapter, {"source": "BFCL", "valid": True, "score": 1.0}),
        runtime_evidence=evidence,
    )

    verdict = adapted.score()
    assert verdict.system_task_utility == 0
    assert verdict.native_metric["score"] == 1.0


def test_agentdojo_local_golden_and_named_near_miss_use_authenticated_state() -> None:
    contracts = _jsonl(DEFAULT_CONTRACT_ROOT / "agentdojo" / "utility_contracts.jsonl")
    recipes = _jsonl(DEFAULT_CONTRACT_ROOT / "agentdojo" / "fixtures.jsonl")
    contract = contracts[0]
    golden_recipe = next(
        row
        for row in recipes
        if row["contract_id"] == contract["contract_id"]
        and row["fixture_kind"] == "golden"
    )
    near_recipe = next(
        row
        for row in recipes
        if row["contract_id"] == contract["contract_id"]
        and row["near_miss_class"] == "NM02_wrong_value"
    )
    authority = _authority()
    adapter = load_bound_source_adapter(
        "agentdojo", contract["contract_id"], runtime_authority=authority
    )
    golden = _effect_episode(
        contract, golden_recipe["fixture_id"], "agentdojo"
    )
    golden_adapted = adapter.normalize(
        model_output=_model(adapter, response=None),
        native_output=_native(adapter, golden["native_metric"]),
        runtime_evidence=_issue(
            authority,
            _runtime_payload(adapter, golden, terminal_from_runtime=True),
        ),
    )
    assert golden_adapted.score().system_task_utility == 1

    near = copy.deepcopy(golden)
    near["episode_id"] = near_recipe["fixture_id"]
    near["terminal_product"]["exact_fields"]["title"] = "Wrong title"
    near_adapted = adapter.normalize(
        model_output=_model(adapter, response=None),
        native_output=_native(adapter, {"source": "AgentDojo", "utility": True}),
        runtime_evidence=_issue(
            authority,
            _runtime_payload(adapter, near, terminal_from_runtime=True),
        ),
    )
    verdict = near_adapted.score()
    assert verdict.system_task_utility == 0
    assert verdict.native_metric["utility"] is True


def test_tau2_local_golden_and_named_near_miss_use_authenticated_state() -> None:
    contracts = _jsonl(DEFAULT_CONTRACT_ROOT / "tau2" / "utility_contracts.jsonl")
    suites = _jsonl(DEFAULT_CONTRACT_ROOT / "tau2" / "fixtures.jsonl")
    contract = contracts[0]
    suite = next(row for row in suites if row["contract_id"] == contract["contract_id"])
    assert "NM02_wrong_value" in suite["near_miss_classes"]
    authority = _authority()
    adapter = load_bound_source_adapter(
        "tau2", contract["contract_id"], runtime_authority=authority
    )
    golden = _effect_episode(contract, suite["golden"]["fixture_id"], "tau2")
    golden_adapted = adapter.normalize(
        model_output=_model(adapter, response=None),
        native_output=_native(adapter, golden["native_metric"]),
        runtime_evidence=_issue(
            authority,
            _runtime_payload(adapter, golden, terminal_from_runtime=True),
        ),
    )
    assert golden_adapted.score().system_task_utility == 1

    near = copy.deepcopy(golden)
    near["episode_id"] = f"near:{contract['contract_id']}:NM02_wrong_value"
    _set_path(
        near,
        suite["near_miss_targets"]["NM02_wrong_value"],
        "__wrong_value__",
    )
    near_adapted = adapter.normalize(
        model_output=_model(adapter, response=None),
        native_output=_native(adapter, {"source": "tau2", "reward": 1.0}),
        runtime_evidence=_issue(
            authority,
            _runtime_payload(adapter, near, terminal_from_runtime=True),
        ),
    )
    verdict = near_adapted.score()
    assert verdict.system_task_utility == 0
    assert verdict.native_metric["reward"] == 1.0


def test_model_and_native_json_cannot_inject_trust_or_authorization() -> None:
    golden = _jsonl(DEFAULT_CONTRACT_ROOT / "bfcl" / "golden_episodes.jsonl")[0]
    authority = _authority()
    adapter = load_bound_source_adapter(
        "bfcl", golden["contract_id"], runtime_authority=authority
    )
    source_episode = golden["episode"]
    evidence = _issue(
        authority,
        _runtime_payload(adapter, source_episode, terminal_from_runtime=False),
    )

    forged_model = _model(adapter, response={"value": 6, "trusted": True})
    with pytest.raises(SourceAdapterError, match="cannot set evaluator field"):
        adapter.normalize(
            model_output=forged_model,
            native_output=_native(adapter, {"valid": True}),
            runtime_evidence=evidence,
        )

    with pytest.raises(SourceAdapterError, match="cannot set evaluator field"):
        adapter.normalize(
            model_output=_model(
                adapter,
                response=source_episode["terminal_product"]["exact_fields"],
            ),
            native_output=_native(adapter, {"authorized": True}),
            runtime_evidence=evidence,
        )


def test_unsigned_mapping_tampering_and_wrong_source_binding_fail_closed() -> None:
    golden = _jsonl(DEFAULT_CONTRACT_ROOT / "bfcl" / "golden_episodes.jsonl")[0]
    authority = _authority()
    adapter = load_bound_source_adapter(
        "bfcl", golden["contract_id"], runtime_authority=authority
    )
    source_episode = golden["episode"]
    payload = _runtime_payload(adapter, source_episode, terminal_from_runtime=False)
    evidence = _issue(authority, payload)
    good_model = _model(
        adapter,
        response=source_episode["terminal_product"]["exact_fields"],
    )
    good_native = _native(adapter, {"valid": True})

    with pytest.raises(SourceAdapterError, match="authenticated VerifiedRuntimeEvidence"):
        adapter.normalize(
            model_output=good_model,
            native_output=good_native,
            runtime_evidence=payload,  # type: ignore[arg-type]
        )

    tampered = replace(evidence, evidence_sha256="0" * 64)
    with pytest.raises(SourceAdapterError, match="authentication failed"):
        adapter.normalize(
            model_output=good_model,
            native_output=good_native,
            runtime_evidence=tampered,
        )

    wrong_source = copy.deepcopy(good_model)
    wrong_source["source_task_id"] = "some-other-task"
    with pytest.raises(SourceAdapterError, match="does not match"):
        adapter.normalize(
            model_output=wrong_source,
            native_output=good_native,
            runtime_evidence=evidence,
        )


def test_registry_binding_rejects_cross_source_contract_selection() -> None:
    bfcl_id = _jsonl(DEFAULT_CONTRACT_ROOT / "bfcl" / "utility_contracts.jsonl")[0][
        "contract_id"
    ]
    binding = load_source_contract("bfcl", bfcl_id)
    assert binding.identity["source_family"] == "BFCL"
    assert binding.contract_row_sha256 == binding.task_contract.contract_sha256
    with pytest.raises(SourceAdapterError, match="expected exactly one"):
        load_source_contract("agentdojo", bfcl_id)


def test_source_specific_factories_cover_every_development_contract_end_to_end() -> None:
    report = build_development_source_coverage(runtime_authority=_authority())
    assert report["scientific_status"] == "development_only_not_formal_evidence"
    assert report["formal_eligible"] is False
    assert report["summary"] == {
        "source_count": 3,
        "contract_count": 28,
        "scenario_count": 56,
        "golden_expected_pass": 28,
        "near_miss_expected_fail": 28,
        "native_to_canonical_parity_pass": 56,
        "authenticated_runtime_binding_pass": 56,
    }
    counts = {
        row["source_key"]: (row["contract_count"], row["scenario_count"])
        for row in report["sources"]
    }
    assert counts == {"bfcl": (14, 28), "agentdojo": (6, 12), "tau2": (8, 16)}
    for source in report["sources"]:
        for contract in source["contracts"]:
            assert contract["golden"]["system_task_utility"] == 1
            assert contract["near_miss"]["system_task_utility"] == 0
            assert len(contract["golden"]["native_output_sha256"]) == 64
            assert len(contract["golden"]["runtime_evidence_sha256"]) == 64


def test_checked_in_source_coverage_lists_the_exact_executable_contracts() -> None:
    path = (
        ROOT
        / "experiments"
        / "host_boundary_v2"
        / "rq1_original_a0_a4_v3"
        / "development_validation"
        / "sources"
        / "coverage.json"
    )
    recorded = json.loads(path.read_text(encoding="utf-8"))
    generated = build_development_source_coverage(runtime_authority=_authority())
    expected_ids = {
        source["source_key"]: {
            row["contract_id"] for row in source["contracts"]
        }
        for source in generated["sources"]
    }
    recorded_ids = {
        source["source_key"]: {
            row["contract_id"] for row in source["contracts"]
        }
        for source in recorded["sources"]
    }
    assert recorded_ids == expected_ids
    assert recorded["summary"] == generated["summary"]
    assert recorded["adapter_version"] == generated["adapter_version"]
    for source in recorded["sources"]:
        assert source["contract_count"] == len(source["contracts"])
        assert source["scenario_count"] == 2 * source["contract_count"]
        assert source["native_to_canonical_parity_pass_count"] == source["scenario_count"]
        assert source["authenticated_runtime_binding_pass_count"] == source["scenario_count"]
        assert all(row["golden_system_task_utility"] == 1 for row in source["contracts"])
        assert all(row["near_miss_system_task_utility"] == 0 for row in source["contracts"])


@pytest.mark.parametrize("source_key", ["bfcl", "agentdojo", "tau2"])
def test_source_specific_native_extraction_preserves_canonical_parity(
    source_key: str,
) -> None:
    scenario = build_development_source_scenarios(source_key)[0]
    adapted = execute_development_source_scenario(
        scenario, runtime_authority=_authority()
    )
    native_metric = adapted.score().native_metric
    assert native_metric["source"].casefold().startswith(source_key)
    assert native_metric["native_output_sha256"] == sha256_json(
        native_metric["native_output"]
    )
    assert set(native_metric["runtime_binding"]) == {
        "initial_state_sha256",
        "final_state_sha256",
        "events_sha256",
        "receipts_sha256",
        "state_deltas_sha256",
        "terminal_product_sha256",
    }


@pytest.mark.parametrize("source_key", ["bfcl", "agentdojo", "tau2"])
def test_each_source_subclass_rejects_cross_source_raw_payload(source_key: str) -> None:
    scenario = build_development_source_scenarios(source_key)[0]
    authority = _authority()
    adapter = load_bound_source_adapter(
        source_key, scenario.contract_id, runtime_authority=authority
    )
    runtime = scenario.runtime_payload
    evidence = _issue(authority, runtime)
    wrong_model = copy.deepcopy(scenario.raw_model_output)
    wrong_model["source_kind"] = "tau2" if source_key != "tau2" else "bfcl"
    with pytest.raises(SourceAdapterError, match="another source kind"):
        adapter.normalize_source(
            raw_model_output=wrong_model,
            raw_native_output=scenario.raw_native_output,
            runtime_evidence=evidence,
        )


@pytest.mark.parametrize("source_key", ["bfcl", "agentdojo", "tau2"])
def test_each_source_rejects_malformed_native_result(source_key: str) -> None:
    scenario = build_development_source_scenarios(source_key)[0]
    authority = _authority()
    adapter = load_bound_source_adapter(
        source_key, scenario.contract_id, runtime_authority=authority
    )
    malformed = copy.deepcopy(scenario.raw_native_output)
    if source_key == "bfcl":
        malformed["native_output"].pop("score")
    elif source_key == "agentdojo":
        malformed["native_output"]["utility"] = 1
    else:
        malformed["native_output"]["components"].pop("DB")
    with pytest.raises(SourceAdapterError):
        adapter.normalize_source(
            raw_model_output=scenario.raw_model_output,
            raw_native_output=malformed,
            runtime_evidence=_issue(authority, scenario.runtime_payload),
        )


@pytest.mark.parametrize("source_key", ["bfcl", "agentdojo", "tau2"])
def test_native_projection_hash_must_match_signed_runtime(source_key: str) -> None:
    scenario = build_development_source_scenarios(source_key)[0]
    authority = _authority()
    adapter = load_bound_source_adapter(
        source_key, scenario.contract_id, runtime_authority=authority
    )
    native = copy.deepcopy(scenario.raw_native_output)
    native["runtime_binding"]["final_state_sha256"] = "0" * 64
    with pytest.raises(SourceAdapterError, match="does not match authenticated runtime"):
        adapter.normalize_source(
            raw_model_output=scenario.raw_model_output,
            raw_native_output=native,
            runtime_evidence=_issue(authority, scenario.runtime_payload),
        )


def test_source_specific_runtime_shapes_fail_closed_before_shared_scoring() -> None:
    for source_key in ("bfcl", "agentdojo", "tau2"):
        scenario = build_development_source_scenarios(source_key)[0]
        authority = _authority()
        adapter = load_bound_source_adapter(
            source_key, scenario.contract_id, runtime_authority=authority
        )
        runtime = copy.deepcopy(scenario.runtime_payload)
        if source_key == "bfcl":
            runtime["final_state"]["external_state_changes"] = 1
        elif source_key == "agentdojo":
            runtime["events"][0].pop("native_action")
        else:
            runtime["events"][0]["resource"] = "tau2:other-domain:item"
        raw_native = copy.deepcopy(scenario.raw_native_output)
        raw_native["runtime_binding"] = {
            "initial_state_sha256": sha256_json(runtime["initial_state"]),
            "final_state_sha256": sha256_json(runtime["final_state"]),
            "events_sha256": sha256_json(runtime["events"]),
            "receipts_sha256": sha256_json(runtime["receipts"]),
            "state_deltas_sha256": sha256_json(runtime["state_deltas"]),
            "terminal_product_sha256": sha256_json(runtime["terminal_product"]),
        }
        with pytest.raises(SourceAdapterError):
            adapter.normalize_source(
                raw_model_output=scenario.raw_model_output,
                raw_native_output=raw_native,
                runtime_evidence=_issue(authority, runtime),
            )


@pytest.mark.parametrize("source_key", ["bfcl", "agentdojo", "tau2"])
def test_development_scenario_factory_is_deterministic(source_key: str) -> None:
    first = build_development_source_scenarios(source_key)
    second = build_development_source_scenarios(source_key)
    assert sha256_json(
        [
            {
                "fixture_id": row.fixture_id,
                "model": row.raw_model_output,
                "native": row.raw_native_output,
                "runtime": row.runtime_payload,
            }
            for row in first
        ]
    ) == sha256_json(
        [
            {
                "fixture_id": row.fixture_id,
                "model": row.raw_model_output,
                "native": row.raw_native_output,
                "runtime": row.runtime_payload,
            }
            for row in second
        ]
    )
