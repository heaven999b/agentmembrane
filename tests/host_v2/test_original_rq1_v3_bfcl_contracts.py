from __future__ import annotations

import copy
import hashlib
import json
import math
from pathlib import Path

from agentmembrane.host_v2.schema import sha256_json
from agentmembrane.host_v2.original_rq1_v3_utility import (
    CHECKER_VERSION,
    check_system_task_utility,
    validate_construct_validity,
    validate_task_contract,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_DIR = (
    REPO_ROOT
    / "experiments/host_boundary_v2/rq1_original_a0_a4_v3/data_contracts/bfcl"
)
OLD_BANK = (
    REPO_ROOT
    / "experiments/host_boundary_v2/rq1_original_a0_a4_v2/banks/v1"
)
COMMIT = "f7cf7359b7ac615a0b294831c5ba2bc95ee4a000"


def _jsonl(path: Path) -> list[dict[str, object]]:
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    assert all(isinstance(row, dict) for row in rows)
    return rows


def _file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _exact_record(path: Path, task_id: str) -> dict[str, object]:
    rows = [
        json.loads(line)
        for line in path.read_text().splitlines()
        if line.strip() and json.loads(line).get("id") == task_id
    ]
    assert len(rows) == 1
    return rows[0]


def _normalized_prompt_sha(text: str) -> str:
    normalized = " ".join(text.split()).casefold()
    return hashlib.sha256(normalized.encode()).hexdigest()


def _set_path(value: dict[str, object], path: str, replacement: object) -> None:
    current = value
    parts = path.split(".")
    for part in parts[:-1]:
        current = current[part]
    current[parts[-1]] = replacement


def _apply_mutation(episode: dict[str, object], mutation: dict[str, object]) -> dict[str, object]:
    result = copy.deepcopy(episode)
    operation = mutation["op"]
    if operation == "identity":
        return result
    if operation == "add_ignored_raw_response_variant":
        result["raw_response_variant"] = mutation["value"]
    elif operation == "replace_terminal_exact_fields":
        result["terminal_product"]["exact_fields"] = copy.deepcopy(mutation["value"])
    elif operation == "append_unrequired_state_changing_event":
        result["events"].append(
            {
                "event_id": "unrequired-event",
                "operation": "call_tool",
                "namespace": result["namespace"],
                "trusted": True,
                "successful": True,
                "state_changing": True,
                "sequence": 1,
            }
        )
    elif operation == "set_initial_state":
        _set_path(result["initial_state"], mutation["path"], mutation["value"])
    elif operation == "remove_first_terminal_exact_field":
        fields = result["terminal_product"]["exact_fields"]
        fields.pop(next(iter(fields)))
    elif operation == "set_terminal_mode":
        result["terminal_product"]["mode"] = mutation["value"]
    elif operation == "append_forbidden_external_state_delta":
        result["state_deltas"].append(
            {
                "path": "external_state",
                "before": False,
                "after": True,
                "state_changing": True,
                "namespace": result["namespace"],
                "caused_by_event_id": "unrequired-event",
            }
        )
    elif operation == "append_cross_episode_state_delta":
        result["state_deltas"].append(
            {
                "path": "external_state",
                "before": False,
                "after": True,
                "state_changing": True,
                "namespace": "another-episode",
                "caused_by_event_id": "unrequired-event",
            }
        )
    elif operation == "set_abnormal_termination":
        result["normal_termination"] = False
        result["failure_codes"] = [mutation["failure_code"]]
    elif operation == "set_first_event_field":
        result["events"][0][mutation["field"]] = mutation["value"]
    elif operation == "set_first_receipt_field":
        result["receipts"][0][mutation["field"]] = mutation["value"]
    elif operation == "duplicate_first_event":
        duplicate = copy.deepcopy(result["events"][0])
        duplicate["event_id"] = mutation["event_id"]
        duplicate["sequence"] = 2
        result["events"].append(duplicate)
    elif operation == "set_final_state":
        _set_path(result["final_state"], mutation["path"], mutation["value"])
    elif operation == "remove_events_and_receipts":
        result["events"] = []
        result["receipts"] = []
    elif operation == "set_final_claim":
        result["final_claim"] = mutation["value"]
    elif operation == "append_forbidden_proposed_execution_delta":
        result["state_deltas"].append(
            {
                "path": "proposed_action.executed",
                "before": False,
                "after": True,
                "state_changing": True,
                "namespace": result["namespace"],
                "caused_by_event_id": result["events"][0]["event_id"],
            }
        )
    else:  # pragma: no cover - keeps the data-driven mutation registry closed
        raise AssertionError(f"unknown fixture mutation {operation!r}")
    return result


def test_contracts_are_task_level_and_complete() -> None:
    contracts = _jsonl(CONTRACT_DIR / "contracts.jsonl")
    assert len(contracts) == 14
    assert len({row["contract_id"] for row in contracts}) == len(contracts)

    required = {
        "contract_id",
        "cluster_id",
        "source_family",
        "source_version",
        "source_task_id",
        "source_sha256",
        "transformation_lineage_id",
        "displayed_user_request",
        "utility_stratum",
        "minimum_authority_level",
        "minimum_authority_justification",
        "required_operations",
        "required_prerequisites",
        "terminal_product",
        "initial_state_predicates",
        "final_state_predicates",
        "allowed_state_deltas",
        "forbidden_state_deltas",
        "required_receipts",
        "ordering_constraints",
        "equivalence_rules",
        "primary_checker_binding",
        "native_checker_binding",
        "near_miss_profile_id",
        "near_miss_fixture_ids",
        "golden_fixture_ids",
        "reviewer_verdicts",
        "weight_stratum",
        "lineage",
        "exposure",
        "source_binding",
    }
    lineage_required = {
        "source_family_key",
        "source_task_key",
        "source_template_keys",
        "normalized_prompt_sha256",
        "fixture_keys",
        "evaluator_keys",
        "transformation_lineage_id",
        "parent_lineage_ids",
        "variant_lineage_ids",
        "historical_exposure_keys",
    }
    for row in contracts:
        assert required <= row.keys()
        assert row["source_family"] == "BFCL"
        assert row["source_version"] == f"BFCL@{COMMIT}"
        assert row["contract_status"] == (
            "offline_construct_validated_pending_independent_and_source_adapter_review"
        )
        assert lineage_required <= row["lineage"].keys()
        verdicts = {item["role"]: item["verdict"] for item in row["reviewer_verdicts"]}
        assert verdicts == {
            "contract_author": "pass",
            "independent_task_reviewer": "pending",
        }


def test_runtime_projections_pass_the_shared_utility_contract_validator() -> None:
    source_contracts = {
        row["contract_id"]: row for row in _jsonl(CONTRACT_DIR / "contracts.jsonl")
    }
    projections = _jsonl(CONTRACT_DIR / "utility_contracts.jsonl")
    assert len(projections) == len(source_contracts)
    for raw in projections:
        validated = validate_task_contract(raw)
        assert validated.contract_id in source_contracts
        full = source_contracts[validated.contract_id]
        assert validated.cluster_id == full["cluster_id"]
        assert validated.utility_stratum == full["utility_stratum"]
        assert validated.minimum_authority_level == full["minimum_authority_level"]
        assert validated.data["source_sha256"] == full["source_sha256"]


def test_every_source_and_checker_binding_is_byte_locked() -> None:
    contracts = _jsonl(CONTRACT_DIR / "contracts.jsonl")
    for row in contracts:
        binding = row["source_binding"]
        question_path = REPO_ROOT / binding["question_path"]
        assert question_path.is_file()
        assert _file_sha(question_path) == binding["question_container_sha256"]
        question = _exact_record(question_path, row["source_task_id"])
        assert sha256_json(question) == binding["question_record_sha256"]

        answer = None
        if binding["ground_truth_path"] is not None:
            answer_path = REPO_ROOT / binding["ground_truth_path"]
            assert answer_path.is_file()
            assert _file_sha(answer_path) == binding["ground_truth_container_sha256"]
            answer = _exact_record(answer_path, row["source_task_id"])
            assert sha256_json(answer) == binding["ground_truth_record_sha256"]

        combined = {"question": question, "ground_truth": answer, "commit": COMMIT}
        assert sha256_json(combined) == row["source_sha256"]
        assert binding["combined_source_sha256"] == row["source_sha256"]
        assert _normalized_prompt_sha(row["displayed_user_request"]) == row["lineage"][
            "normalized_prompt_sha256"
        ]

        native = row["native_checker_binding"]
        checker_path = REPO_ROOT / native["checker_path"]
        assert checker_path.is_file()
        assert _file_sha(checker_path) == native["checker_sha256"]
        assert row["primary_checker_binding"]["native_bfcl_score_cannot_override"]


def test_reviewed_manifest_frame_is_fully_accounted_for() -> None:
    old_rows: dict[str, dict[str, object]] = {}
    for filename in ("development_manifest.json", "formal_holdout_manifest.json"):
        manifest = json.loads((OLD_BANK / filename).read_text())
        for row in manifest["clusters"]:
            if row["source_family"] == "BFCL":
                assert row["source_task_id"] not in old_rows
                old_rows[row["source_task_id"]] = row
    assert len(old_rows) == 50

    contracts = _jsonl(CONTRACT_DIR / "contracts.jsonl")
    originals = {
        row["source_task_id"]
        for row in contracts
        if row["transformation_lineage_id"] is None
    }
    transforms = [row for row in contracts if row["transformation_lineage_id"]]
    exclusions = _jsonl(CONTRACT_DIR / "exclusions.jsonl")
    excluded = {row["source_task_id"] for row in exclusions}

    assert len(originals) == 12
    assert len(transforms) == 2
    assert len(exclusions) == 38
    assert originals.isdisjoint(excluded)
    assert originals | excluded == set(old_rows)
    assert {row["source_task_id"] for row in transforms} <= originals
    assert all(row["reason_code"] and row["reason"] for row in exclusions)
    assert all(row["source_sha256"] == old_rows[row["source_task_id"]]["source_sha256"] for row in exclusions)


def test_category_names_never_determine_authority() -> None:
    contracts = _jsonl(CONTRACT_DIR / "contracts.jsonl")
    originals = [row for row in contracts if row["transformation_lineage_id"] is None]
    assert all(row["utility_stratum"] == "W0" for row in originals)
    assert all(row["minimum_authority_level"] == "A0" for row in originals)
    assert any(row["source_task_id"].startswith("multiple_") for row in originals)
    assert any(row["source_task_id"].startswith("simple_python_") for row in originals)

    transformed = [row for row in contracts if row["transformation_lineage_id"]]
    assert all(row["utility_stratum"] == "W2" for row in transformed)
    assert all(row["minimum_authority_level"] == "A2" for row in transformed)
    assert all("inert ActionProposal" in row["displayed_user_request"] for row in transformed)
    assert all("Do not execute it." in row["displayed_user_request"] for row in transformed)


def test_expected_answers_and_proposals_are_exact() -> None:
    contracts = {row["contract_id"]: row for row in _jsonl(CONTRACT_DIR / "contracts.jsonl")}
    assert contracts["bfcl-multiple_46-original-response-v1"]["terminal_product"][
        "exact_fields"
    ]["value"] == ["Alice", "Jack", "Sam"]
    assert contracts["bfcl-multiple_101-original-response-v1"]["terminal_product"][
        "exact_fields"
    ]["value"] == math.gcd(12, 18)
    assert contracts["bfcl-multiple_42-original-response-v1"]["terminal_product"][
        "exact_fields"
    ]["value"] == (2 * 300 + 3 * 400) / 5
    assert contracts["bfcl-simple_python_11-original-response-v1"]["terminal_product"][
        "exact_fields"
    ]["value"] == 10 * 5 / 2
    assert math.isclose(
        contracts["bfcl-simple_python_222-original-response-v1"]["terminal_product"][
            "exact_fields"
        ]["value"],
        70 / 1.8**2,
    )
    assert contracts["bfcl-simple_python_339-original-response-v1"]["terminal_product"][
        "exact_fields"
    ]["exact_fraction"] == "6/4165"

    for contract_id in (
        "bfcl-multiple_46-action-proposal-v1",
        "bfcl-multiple_101-action-proposal-v1",
    ):
        row = contracts[contract_id]
        product = row["terminal_product"]
        assert product["kind"] == "typed_proposal"
        assert product["exact_fields"]["proposal_type"] == "ActionProposal"
        assert product["exact_fields"]["accepted"] is True
        assert product["exact_fields"]["executed"] is False
        assert row["required_operations"] == ["submit_action_proposal"]
        assert row["required_receipts"][0]["trusted"] is True


def test_near_miss_profiles_cover_all_twenty_classes() -> None:
    document = json.loads((CONTRACT_DIR / "checker_profiles.json").read_text())
    expected = {f"NM{number:02d}" for number in range(1, 21)}
    assert set(document["near_miss_catalog"]) == expected
    for profile in document["profiles"].values():
        applicable = set(profile["applicable_near_miss_fixture_ids"])
        not_applicable = set(profile["not_applicable"])
        assert applicable.isdisjoint(not_applicable)
        assert applicable | not_applicable == expected


def test_historical_exposure_blocks_formal_use() -> None:
    for row in _jsonl(CONTRACT_DIR / "contracts.jsonl"):
        assert row["formal_eligibility"] == "development_only_historical_exposure"
        assert row["exposure"]["design_process_exposed"] is True
        assert row["exposure"]["v3_partition_requirement"] == "development_only"
        assert row["lineage"]["historical_exposure_keys"]

    report = (CONTRACT_DIR / "REPORT.md").read_text()
    assert "12 have a defensible exact original-task contract" in report
    assert "38 are explicitly excluded" in report
    assert "0 rows are eligible for the new formal holdout" in report


def test_materialized_fixtures_pass_shared_construct_validity_runtime() -> None:
    raw_contracts = {
        row["contract_id"]: row
        for row in _jsonl(CONTRACT_DIR / "utility_contracts.jsonl")
    }
    golden = {
        row["contract_id"]: row["episode"]
        for row in _jsonl(CONTRACT_DIR / "golden_episodes.jsonl")
    }
    plan = json.loads((CONTRACT_DIR / "fixture_plan.json").read_text())
    report = json.loads((CONTRACT_DIR / "construct_validity.json").read_text())
    reported = {row["contract_id"]: row for row in report["per_contract"]}

    assert plan["expanded_counts"] == {
        "contracts": 14,
        "equivalent_fixtures": 14,
        "golden_fixtures": 14,
        "near_miss_fixtures": 146,
        "total_fixture_runs": 696,
        "total_fixtures": 174,
    }
    expanded_runs = 0
    for contract_plan in plan["contracts"]:
        contract_id = contract_plan["contract_id"]
        raw = raw_contracts[contract_id]
        profile = plan["profiles"][contract_plan["profile_id"]]
        cases = [
            (
                contract_plan["golden_fixture_id"],
                "golden",
                None,
                {"op": "identity"},
            ),
            (
                contract_plan["equivalent_fixture_id"],
                "equivalent",
                None,
                profile["equivalent_mutation"],
            ),
        ]
        for near_class, mutation in profile["near_miss_mutations"].items():
            cases.append(
                (
                    contract_plan["near_miss_fixture_ids"][near_class],
                    "near_miss",
                    near_class,
                    mutation,
                )
            )

        fixture_runs = []
        for fixture_id, fixture_kind, near_class, mutation in cases:
            episode = _apply_mutation(golden[contract_id], mutation)
            for arm in plan["arms"]:
                for _repeat in range(1, plan["repeats_per_arm"] + 1):
                    fixture_runs.append(
                        {
                            "fixture_id": fixture_id,
                            "fixture_kind": fixture_kind,
                            "near_miss_class": near_class,
                            "arm": arm,
                            "episode": episode,
                        }
                    )

        result = validate_construct_validity(raw, fixture_runs)
        assert result.eligible, (contract_id, result.failures)
        assert result.checks == reported[contract_id]["checks"]
        assert reported[contract_id]["construct_validity_eligible"] is True
        assert reported[contract_id]["fixture_counts"]["expanded_runs"] == len(
            fixture_runs
        )
        expanded_runs += len(fixture_runs)

    assert expanded_runs == 696
    assert report["checker_version"] == CHECKER_VERSION
    assert report["summary"]["all_construct_validity_reports_eligible"] is True
    assert report["release_status"]["source_task_g3_release"] == "BLOCKED"
    assert report["release_status"]["formal_eligibility"] == (
        "FORBIDDEN_HISTORICAL_EXPOSURE"
    )


def test_w2_below_a2_evidence_is_recomputed_and_paired() -> None:
    contracts = {
        row["contract_id"]: validate_task_contract(row)
        for row in _jsonl(CONTRACT_DIR / "utility_contracts.jsonl")
        if row["minimum_authority_level"] == "A2"
    }
    rows = _jsonl(CONTRACT_DIR / "below_a2_evidence.jsonl")
    assert len(contracts) == 2
    assert len(rows) == 16
    expected_cells = {
        (contract_id, level, arm, repeat)
        for contract_id in contracts
        for level in ("A0", "A1")
        for arm in ("B1", "M1")
        for repeat in (1, 2)
    }
    assert {
        (row["contract_id"], row["attempted_level"], row["arm"], row["repeat"])
        for row in rows
    } == expected_cells

    for row in rows:
        verdict = check_system_task_utility(
            contracts[row["contract_id"]], row["episode"]
        ).to_dict()
        assert verdict == row["verdict"]
        assert verdict["system_task_utility"] == 0
        assert "missing_required_operation:proposal" in verdict["failure_codes"]
        assert "missing_required_receipt:acceptance" in verdict["failure_codes"]
        assert "proposal_not_accepted" in verdict["failure_codes"]


def test_construct_validity_report_locks_every_input_artifact() -> None:
    report = json.loads((CONTRACT_DIR / "construct_validity.json").read_text())
    for name, expected_sha in report["artifact_sha256"].items():
        assert _file_sha(CONTRACT_DIR / name) == expected_sha
    assert report["scientific_status"] == (
        "development_only_offline_construct_validation"
    )
    assert report["formal_result"] is False
    assert report["model_calls"] == 0
    assert report["network_calls"] == 0
