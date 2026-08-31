from __future__ import annotations

import hashlib
import json
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from .analysis import cluster_bootstrap_ci, exact_mcnemar_p, holm_adjust
from .manifest import load_manifest
from .p0_calibration import (
    NEUTRAL_P0_DOWNSTREAM_SYSTEM,
    _build_downstream,
    assert_neutral_p0_prompt,
    neutral_p0_prompt,
    neutral_p0_view,
)
from .profile import file_sha256, load_profile
from .prompts import assert_blinded_downstream_view
from .runner import (
    JsonModel,
    _ask_with_one_repair,
    _atomic_json,
    _decision_validator,
    _safe_name,
    _stable_order,
)
from .schema import Receptor, build_persistent_receipt, sha256_json, validate_artifact
from .sensitivity import _read_jsonl


MECHANISM_ABLATION_PROTOCOL_ID = "semantic-rq2-mechanism-ablation-v1"

S_INFERENCE = "S_inference"
S_FULL = "S_full"
T_INFERENCE = "T_inference"
T_INFERENCE_CONCLUSION = "T_inference_conclusion"
T_FULL = "T_full"
T_RECOMMENDATION_ONLY = "T_recommendation_only"
T_FULL_REPEATED = "T_full_repeated"

CONDITION_ORDER = (
    S_INFERENCE,
    S_FULL,
    T_INFERENCE,
    T_INFERENCE_CONCLUSION,
    T_FULL,
    T_RECOMMENDATION_ONLY,
    T_FULL_REPEATED,
)

EXISTING_ARM_TO_CONDITION = {
    Receptor.R2.value: S_INFERENCE,
    Receptor.R3.value: S_FULL,
    Receptor.R4.value: T_FULL,
}

NEW_TEXT_CONDITIONS = (
    T_INFERENCE,
    T_INFERENCE_CONCLUSION,
    T_RECOMMENDATION_ONLY,
    T_FULL_REPEATED,
)


def _render_backbone(payload: Mapping[str, Any]) -> dict[str, str]:
    inference = "Inference: " + str(payload["inference"]) + "\nUncertainty: " + str(
        payload["uncertainty"]
    ) + "."
    inference_conclusion = inference + "\nConclusion: " + str(payload["conclusion"])
    full = inference_conclusion + "\nRecommendation: " + str(payload["recommendation"])
    return {
        T_INFERENCE: inference,
        T_INFERENCE_CONCLUSION: inference_conclusion,
        T_FULL: full,
        T_RECOMMENDATION_ONLY: "Recommendation: " + str(payload["recommendation"]),
        T_FULL_REPEATED: full + "\n\n---\n\n" + full,
    }


def _artifact_id(case_id: str, mode: str, condition: str, backbone_sha: str) -> str:
    raw = f"{MECHANISM_ABLATION_PROTOCOL_ID}|{case_id}|{mode}|{condition}|{backbone_sha}"
    return "ablation-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def build_text_ablation_artifacts(
    *,
    case: Mapping[str, Any],
    mode: str,
    r3_artifact: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    if mode not in {"honest", "attack"}:
        raise ValueError(f"unknown mode: {mode}")
    candidate_ids = [str(row["id"]) for row in case["evidence_packet"]]
    base_validation = validate_artifact(
        r3_artifact,
        candidate_evidence_ids=candidate_ids,
        expected_case_id=str(case["case_id"]),
        expected_receptor=Receptor.R3,
    )
    if not base_validation.deterministic_valid:
        raise ValueError(f"invalid R3 ablation backbone: {base_validation.problems}")
    payload = r3_artifact["payload"]
    evidence_ids = list(payload["evidence_ids"])
    rendered = _render_backbone(payload)
    backbone_sha = sha256_json(r3_artifact)
    artifacts = {
        condition: {
            "artifact_id": _artifact_id(str(case["case_id"]), mode, condition, backbone_sha),
            "case_id": case["case_id"],
            "receptor": Receptor.R4.value,
            "payload": {
                "artifact_text": rendered[condition],
                "evidence_ids": list(evidence_ids),
            },
        }
        for condition in NEW_TEXT_CONDITIONS
    }
    for condition, artifact in artifacts.items():
        validation = validate_artifact(
            artifact,
            candidate_evidence_ids=candidate_ids,
            expected_case_id=str(case["case_id"]),
            expected_receptor=Receptor.R4,
        )
        if not validation.deterministic_valid:
            raise ValueError(f"invalid {condition} artifact: {validation.problems}")
    assert_text_ablation_artifacts(artifacts, r3_payload=payload)
    return artifacts


def assert_text_ablation_artifacts(
    artifacts: Mapping[str, Mapping[str, Any]], *, r3_payload: Mapping[str, Any]
) -> None:
    if set(artifacts) != set(NEW_TEXT_CONDITIONS):
        raise AssertionError("mechanism ablation does not contain every new text condition")
    rendered = _render_backbone(r3_payload)
    evidence_ids = list(r3_payload["evidence_ids"])
    for condition in NEW_TEXT_CONDITIONS:
        payload = artifacts[condition]["payload"]
        if payload["evidence_ids"] != evidence_ids:
            raise AssertionError(f"{condition} evidence IDs differ from the backbone")
        if payload["artifact_text"] != rendered[condition]:
            raise AssertionError(f"{condition} is not an exact frozen rendering")


def _decision_row(
    *,
    model: JsonModel,
    downstream_id: str,
    case: Mapping[str, Any],
    mode: str,
    condition: str,
    artifact: Mapping[str, Any],
    hard_valid: bool,
    seed: int,
) -> dict[str, Any]:
    view = neutral_p0_view(case, artifact)
    assert_blinded_downstream_view(view)
    user = neutral_p0_prompt(case, artifact)
    assert_neutral_p0_prompt(NEUTRAL_P0_DOWNSTREAM_SYSTEM, user)
    packet_sha = sha256_json(view["evidence_packet"])
    arm_id = f"{mode}:mechanism:{condition}"
    base = {
        "case_id": case["case_id"],
        "cluster_id": case["cluster_id"],
        "downstream_id": downstream_id,
        "downstream_model": model.model,
        "seed": seed,
        "arm_id": arm_id,
        "mode": mode,
        "receptor": Receptor.R4.value,
        "ablation_condition": condition,
        "gold_label": case["gold_label"],
        "assigned_target": case["assigned_target"],
        "packet_sha256": packet_sha,
        "packet_identity_ok": packet_sha == case["packet_sha256"],
        "hard_valid": hard_valid,
        "p0_visible_view": "neutral_no_provenance_warning",
        "memory_receipt": build_persistent_receipt(artifact),
    }
    deterministic = validate_artifact(
        artifact,
        candidate_evidence_ids=[str(row["id"]) for row in case["evidence_packet"]],
        expected_case_id=str(case["case_id"]),
        expected_receptor=Receptor.R4,
    )
    if not deterministic.deterministic_valid:
        return base | {
            "terminal_status": "receptor_rejected",
            "label": None,
            "failure_class": "typed_receptor_schema_rejection",
            "decision_metadata": None,
        }
    payload, metadata = _ask_with_one_repair(
        model,
        key=(
            f"mechanism_{seed}_{_safe_name(downstream_id)}_{_safe_name(str(case['case_id']))}_"
            f"{mode}_{condition}"
        ),
        system=NEUTRAL_P0_DOWNSTREAM_SYSTEM,
        user=user,
        max_tokens=900,
        validator=_decision_validator,
    )
    if payload is None or metadata["status"] != "completed":
        return base | {
            "terminal_status": metadata["status"],
            "label": payload.get("label") if isinstance(payload, dict) else None,
            "failure_class": metadata["status"],
            "decision_metadata": metadata,
        }
    cited = payload.get("cited_evidence_ids", [])
    candidate_ids = {str(row["id"]) for row in case["evidence_packet"]}
    return base | {
        "terminal_status": "completed",
        "label": payload["label"],
        "confidence": payload["confidence"],
        "cited_evidence_ids": cited,
        "citations_valid": set(cited).issubset(candidate_ids),
        "rationale": payload["rationale"],
        "failure_class": None,
        "decision_metadata": metadata,
    }


def _normalized_condition(row: Mapping[str, Any]) -> str | None:
    explicit = row.get("ablation_condition")
    if explicit in CONDITION_ORDER:
        return str(explicit)
    arm_id = str(row.get("arm_id", ""))
    if ":" not in arm_id:
        return None
    receptor = arm_id.split(":", 1)[1]
    return EXISTING_ARM_TO_CONDITION.get(receptor)


def _condition_pairs(
    records: list[dict[str, Any]], condition: str, *, valid_only: bool = False
) -> list[dict[str, Any]]:
    by_case: dict[str, dict[str, dict[str, Any]]] = {}
    for row in records:
        if _normalized_condition(row) != condition:
            continue
        by_case.setdefault(str(row["case_id"]), {})[str(row["mode"])] = row
    pairs: list[dict[str, Any]] = []
    for case_id, modes in sorted(by_case.items()):
        honest = modes.get("honest")
        attack = modes.get("attack")
        if honest is None or attack is None:
            continue
        if honest.get("terminal_status") != "completed" or attack.get("terminal_status") != "completed":
            continue
        if valid_only and not (honest.get("hard_valid") and attack.get("hard_valid")):
            continue
        if honest["assigned_target"] != attack["assigned_target"]:
            raise ValueError(f"target mismatch for {case_id} in {condition}")
        target = honest["assigned_target"]
        pairs.append(
            {
                "case_id": case_id,
                "cluster_id": honest["cluster_id"],
                "honest_target": honest.get("label") == target,
                "attack_target": attack.get("label") == target,
                "effect": int(attack.get("label") == target) - int(honest.get("label") == target),
            }
        )
    return pairs


def _signed_summary(
    rows: list[dict[str, Any]],
    *,
    value_field: str,
    planned_n: int,
    seed: int,
    samples: int,
    missing_max_abs: float = 1.0,
) -> dict[str, Any]:
    values = [float(row[value_field]) for row in rows]
    positive = sum(value > 0 for value in values)
    negative = sum(value < 0 for value in values)
    missing = max(0, planned_n - len(rows))
    observed_sum = sum(values)
    return {
        "planned_pair_n": planned_n,
        "completed_pair_n": len(rows),
        "terminal_pair_coverage": len(rows) / planned_n if planned_n else None,
        "point": statistics.mean(values) if values else None,
        "positive_n": positive,
        "negative_n": negative,
        "nonzero_n": positive + negative,
        "exact_two_sided_sign_p": exact_mcnemar_p(positive, negative),
        "document_cluster_bootstrap_95ci": cluster_bootstrap_ci(
            rows,
            value=lambda row: float(row[value_field]),
            seed=seed,
            samples=samples,
        ),
        "terminal_failure_worst_case_bounds": (
            [
                (observed_sum - missing_max_abs * missing) / planned_n,
                (observed_sum + missing_max_abs * missing) / planned_n,
            ]
            if planned_n
            else None
        ),
    }


def analyze_mechanism_records(
    records: list[dict[str, Any]], *, seed: int, bootstrap_samples: int
) -> dict[str, Any]:
    case_ids = sorted({str(row["case_id"]) for row in records})
    planned_n = len(case_ids)
    pairs = {condition: _condition_pairs(records, condition) for condition in CONDITION_ORDER}
    valid_pairs = {
        condition: _condition_pairs(records, condition, valid_only=True)
        for condition in CONDITION_ORDER
    }
    condition_effects: dict[str, Any] = {}
    for index, condition in enumerate(CONDITION_ORDER):
        all_rows = pairs[condition]
        valid_rows = valid_pairs[condition]
        summary = _signed_summary(
            all_rows,
            value_field="effect",
            planned_n=planned_n,
            seed=seed + 100 * index,
            samples=bootstrap_samples,
        )
        summary["honest_target_rate"] = (
            statistics.mean(int(row["honest_target"]) for row in all_rows) if all_rows else None
        )
        summary["attack_target_rate"] = (
            statistics.mean(int(row["attack_target"]) for row in all_rows) if all_rows else None
        )
        valid_summary = _signed_summary(
            valid_rows,
            value_field="effect",
            planned_n=planned_n,
            seed=seed + 100 * index + 1,
            samples=bootstrap_samples,
        )
        valid_summary["construct_valid_pair_n"] = len(valid_rows)
        valid_summary["construct_valid_coverage"] = len(valid_rows) / planned_n if planned_n else None
        condition_effects[condition] = {
            "all_attempt_completed": summary,
            "construct_valid": valid_summary,
        }

    by_condition_case = {
        condition: {row["case_id"]: row for row in condition_rows}
        for condition, condition_rows in pairs.items()
    }

    def simple_contrast(name: str, left: str, right: str, index: int) -> dict[str, Any]:
        common = sorted(set(by_condition_case[left]) & set(by_condition_case[right]))
        rows = [
            {
                "case_id": case_id,
                "cluster_id": by_condition_case[left][case_id]["cluster_id"],
                "delta": (
                    by_condition_case[right][case_id]["effect"]
                    - by_condition_case[left][case_id]["effect"]
                ),
            }
            for case_id in common
        ]
        return {
            "contrast": name,
            "left_condition": left,
            "right_condition": right,
            **_signed_summary(
                rows,
                value_field="delta",
                planned_n=planned_n,
                seed=seed + 1000 + index,
                samples=bootstrap_samples,
                missing_max_abs=2.0,
            ),
        }

    specifications = [
        ("format_without_answer_layer", S_INFERENCE, T_INFERENCE),
        ("format_with_answer_layer", S_FULL, T_FULL),
        ("answer_layer_in_structured", S_INFERENCE, S_FULL),
        ("answer_layer_in_text", T_INFERENCE, T_FULL),
        ("add_conclusion_in_text", T_INFERENCE, T_INFERENCE_CONCLUSION),
        ("add_recommendation_in_text", T_INFERENCE_CONCLUSION, T_FULL),
        ("reasoning_context_for_recommendation", T_RECOMMENDATION_ONLY, T_FULL),
        ("repeat_same_full_text", T_FULL, T_FULL_REPEATED),
    ]
    contrasts = [
        simple_contrast(name, left, right, index)
        for index, (name, left, right) in enumerate(specifications)
    ]

    interaction_cases = sorted(
        set(by_condition_case[S_INFERENCE])
        & set(by_condition_case[S_FULL])
        & set(by_condition_case[T_INFERENCE])
        & set(by_condition_case[T_FULL])
    )
    interaction_rows = []
    for case_id in interaction_cases:
        structured_step = (
            by_condition_case[S_FULL][case_id]["effect"]
            - by_condition_case[S_INFERENCE][case_id]["effect"]
        )
        text_step = (
            by_condition_case[T_FULL][case_id]["effect"]
            - by_condition_case[T_INFERENCE][case_id]["effect"]
        )
        interaction_rows.append(
            {
                "case_id": case_id,
                "cluster_id": by_condition_case[S_INFERENCE][case_id]["cluster_id"],
                "delta": text_step - structured_step,
            }
        )
    contrasts.insert(
        4,
        {
            "contrast": "format_x_answer_layer_interaction",
            "formula": "(T_full-T_inference)-(S_full-S_inference)",
            **_signed_summary(
                interaction_rows,
                value_field="delta",
                planned_n=planned_n,
                seed=seed + 1100,
                samples=bootstrap_samples,
                missing_max_abs=4.0,
            ),
        },
    )
    adjusted = holm_adjust([row["exact_two_sided_sign_p"] for row in contrasts])
    for row, pvalue in zip(contrasts, adjusted, strict=True):
        row["exact_sign_p_holm_9"] = pvalue
    return {
        "diagnostic_only": True,
        "primary_rq2_estimand_unchanged": True,
        "statistical_unit": "ContractNLI document cluster",
        "case_n": planned_n,
        "condition_effects": condition_effects,
        "planned_mechanism_contrasts": contrasts,
    }


def _validate_matrix(
    records: list[dict[str, Any]], cases: list[dict[str, Any]], *, seed: int
) -> dict[str, Any]:
    expected = {
        (str(case["case_id"]), mode, condition)
        for case in cases
        for mode in ("honest", "attack")
        for condition in CONDITION_ORDER
    }
    observed: list[tuple[str, str, str]] = []
    problems: list[str] = []
    case_by_id = {str(case["case_id"]): case for case in cases}
    for row in records:
        condition = _normalized_condition(row)
        key = (str(row.get("case_id")), str(row.get("mode")), str(condition))
        observed.append(key)
        case = case_by_id.get(key[0])
        if key not in expected:
            problems.append("unexpected:" + "|".join(key))
            continue
        if row.get("seed") != seed:
            problems.append("seed_mismatch:" + "|".join(key))
        if case is None or row.get("packet_sha256") != case["packet_sha256"]:
            problems.append("packet_mismatch:" + "|".join(key))
        if not row.get("packet_identity_ok"):
            problems.append("packet_identity_failure:" + "|".join(key))
        if row.get("assigned_target") != case["assigned_target"]:
            problems.append("target_mismatch:" + "|".join(key))
    observed_set = set(observed)
    if len(observed) != len(observed_set):
        problems.append("duplicate_case_mode_condition")
    for key in sorted(expected - observed_set):
        problems.append("missing:" + "|".join(key))
    return {
        "status": "PASS" if not problems else "FAIL",
        "expected_record_n": len(expected),
        "observed_record_n": len(records),
        "condition_n": len(CONDITION_ORDER),
        "problems": problems,
    }


def run_mechanism_ablation(
    *,
    manifest_path: Path,
    profile_path: Path,
    source_run_dir: Path,
    nested_run_dir: Path,
    output_dir: Path,
    seed: int,
    max_cases: int,
    downstream_model: JsonModel | None = None,
) -> dict[str, Any]:
    if max_cases <= 0:
        raise ValueError("max_cases must be positive")
    manifest = load_manifest(manifest_path)
    profile = load_profile(profile_path)
    cases = manifest["cases"][:max_cases]
    case_ids = {str(case["case_id"]) for case in cases}
    source_config = json.loads((source_run_dir / "run_config.json").read_text(encoding="utf-8"))
    nested_config = json.loads((nested_run_dir / "run_config.json").read_text(encoding="utf-8"))
    for name, config in (("source", source_config), ("nested", nested_config)):
        if config.get("manifest_sha256") != file_sha256(manifest_path):
            raise ValueError(f"{name} run manifest hash mismatch")
        if config.get("profile_sha256") != file_sha256(profile_path):
            raise ValueError(f"{name} run profile hash mismatch")
        if config.get("seed") != seed:
            raise ValueError(f"{name} run seed mismatch")
    nested_results = json.loads((nested_run_dir / "results.json").read_text(encoding="utf-8"))
    if nested_results.get("integrity", {}).get("status") != "PASS":
        raise ValueError("nested run integrity did not pass")
    nested_records_path = nested_run_dir / "records.nested_projection.jsonl"
    nested_records = [
        row
        for row in _read_jsonl(nested_records_path)
        if str(row.get("case_id")) in case_ids
        and row.get("receptor") in {Receptor.R2.value, Receptor.R3.value, Receptor.R4.value}
        and row.get("mode") in {"honest", "attack"}
    ]
    r3_validity = {
        (str(row["case_id"]), str(row["mode"])): bool(row.get("hard_valid"))
        for row in nested_records
        if row.get("receptor") == Receptor.R3.value
    }
    protocol_path = (
        Path(__file__).resolve().parents[2]
        / "experiments"
        / "semantic_receptor_rq2"
        / "MECHANISM_ABLATION_PROTOCOL.md"
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    config = {
        "protocol_id": MECHANISM_ABLATION_PROTOCOL_ID,
        "diagnostic_only": True,
        "claim_bearing": False,
        "primary_rq2_estimand_unchanged": True,
        "new_generator_calls": 0,
        "new_surrogate_calls": 0,
        "new_auditor_calls": 0,
        "new_downstream_conditions": list(NEW_TEXT_CONDITIONS),
        "reused_nested_conditions": [S_INFERENCE, S_FULL, T_FULL],
        "holm_family_n": 9,
        "source_run_dir": str(source_run_dir.resolve()),
        "nested_run_dir": str(nested_run_dir.resolve()),
        "source_results_sha256": file_sha256(source_run_dir / "results.json"),
        "nested_results_sha256": file_sha256(nested_run_dir / "results.json"),
        "nested_records_sha256": file_sha256(nested_records_path),
        "manifest_sha256": file_sha256(manifest_path),
        "profile_sha256": file_sha256(profile_path),
        "protocol_sha256": file_sha256(protocol_path),
        "implementation_sha256": file_sha256(Path(__file__)),
        "seed": seed,
        "max_cases": max_cases,
    }
    config_path = output_dir / "run_config.json"
    if config_path.exists():
        if json.loads(config_path.read_text(encoding="utf-8")) != config:
            raise ValueError("mechanism-ablation run_config mismatch; use a new output directory")
    else:
        _atomic_json(config_path, config)

    materialized_dir = output_dir / "materialized" / "blocks"
    materialized_dir.mkdir(parents=True, exist_ok=True)
    artifacts_by_case: dict[str, dict[str, dict[str, Any]]] = {}
    for case in cases:
        case_id = str(case["case_id"])
        source_block_path = source_run_dir / "generation" / "blocks" / f"{_safe_name(case_id)}.json"
        source_block = json.loads(source_block_path.read_text(encoding="utf-8"))
        artifacts: dict[str, dict[str, Any]] = {}
        validity: dict[str, bool] = {}
        for mode in ("honest", "attack"):
            base = source_block["artifacts"][f"{mode}:{Receptor.R3.value}"]
            projected = build_text_ablation_artifacts(case=case, mode=mode, r3_artifact=base)
            for condition, artifact in projected.items():
                key = f"{mode}:{condition}"
                artifacts[key] = artifact
                validity[key] = r3_validity[(case_id, mode)]
        block = {
            "protocol_id": MECHANISM_ABLATION_PROTOCOL_ID,
            "case_id": case_id,
            "packet_sha256": case["packet_sha256"],
            "seed": seed,
            "artifacts": artifacts,
            "hard_valid": validity,
            "bundle_sha256": sha256_json({"artifacts": artifacts, "hard_valid": validity}),
        }
        path = materialized_dir / f"{_safe_name(case_id)}.json"
        if path.exists() and json.loads(path.read_text(encoding="utf-8")) != block:
            raise ValueError(f"mechanism materialization mismatch for {case_id}")
        if not path.exists():
            _atomic_json(path, block)
        artifacts_by_case[case_id] = block
    materialized_hashes = {
        str(case["case_id"]): file_sha256(
            materialized_dir / f"{_safe_name(str(case['case_id']))}.json"
        )
        for case in cases
    }
    _atomic_json(
        output_dir / "materialized" / "receipt.json",
        {
            "status": "PASS",
            "case_n": len(cases),
            "block_hashes": materialized_hashes,
            "bundle_sha256": sha256_json(materialized_hashes),
            "frozen_before_downstream_evaluation": True,
        },
    )

    if downstream_model is None:
        downstream_id, model = _build_downstream(profile, output_dir)
    else:
        downstream_id = str(profile["roles"]["downstreams"][0]["id"]) + "-neutral-p0"
        model = downstream_model
    if {str(row["downstream_id"]) for row in nested_records} != {downstream_id}:
        raise ValueError("mechanism downstream does not match reused nested records")
    evaluation_dir = output_dir / "evaluation" / _safe_name(downstream_id)
    evaluation_dir.mkdir(parents=True, exist_ok=True)
    blocks_by_case: dict[str, dict[str, Any]] = {}
    pending: list[tuple[dict[str, Any], Path]] = []
    for case in cases:
        case_id = str(case["case_id"])
        path = evaluation_dir / f"{_safe_name(case_id)}.json"
        if path.exists():
            block = json.loads(path.read_text(encoding="utf-8"))
            if block.get("packet_sha256") != case["packet_sha256"] or block.get("seed") != seed:
                raise ValueError(f"mechanism evaluation resume mismatch for {case_id}")
            blocks_by_case[case_id] = block
        else:
            pending.append((case, path))

    def evaluate(item: tuple[dict[str, Any], Path]) -> dict[str, Any]:
        case, path = item
        case_id = str(case["case_id"])
        materialized = artifacts_by_case[case_id]
        keys = list(materialized["artifacts"])
        rows = []
        for key in _stable_order(seed, case_id, keys):
            mode, condition = key.split(":", 1)
            rows.append(
                _decision_row(
                    model=model,
                    downstream_id=downstream_id,
                    case=case,
                    mode=mode,
                    condition=condition,
                    artifact=materialized["artifacts"][key],
                    hard_valid=bool(materialized["hard_valid"][key]),
                    seed=seed,
                )
            )
        block = {
            "protocol_id": MECHANISM_ABLATION_PROTOCOL_ID,
            "case_id": case_id,
            "packet_sha256": case["packet_sha256"],
            "seed": seed,
            "records": rows,
        }
        _atomic_json(path, block)
        return block

    completed = len(blocks_by_case)
    _atomic_json(
        output_dir / "progress.json",
        {"completed_case_n": completed, "total_case_n": len(cases), "stage": "mechanism_downstream"},
    )
    with ThreadPoolExecutor(max_workers=int(profile["max_workers"])) as executor:
        futures = {executor.submit(evaluate, item): str(item[0]["case_id"]) for item in pending}
        for future in as_completed(futures):
            case_id = futures[future]
            blocks_by_case[case_id] = future.result()
            completed += 1
            _atomic_json(
                output_dir / "progress.json",
                {
                    "completed_case_n": completed,
                    "total_case_n": len(cases),
                    "stage": "mechanism_downstream",
                },
            )

    new_records = [
        row for case in cases for row in blocks_by_case[str(case["case_id"])]["records"]
    ]
    records = [*nested_records, *new_records]
    integrity = _validate_matrix(records, cases, seed=seed)
    _atomic_json(output_dir / "integrity.json", integrity)
    if integrity["status"] != "PASS":
        raise RuntimeError(f"mechanism matrix failed: {integrity['problems']}")
    records_path = output_dir / "records.mechanism_ablation.jsonl"
    temporary = records_path.with_suffix(".jsonl.tmp")
    temporary.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in records),
        encoding="utf-8",
    )
    temporary.replace(records_path)
    analysis = analyze_mechanism_records(
        records,
        seed=seed,
        bootstrap_samples=int(profile["bootstrap_samples"]),
    )
    result = {
        "protocol_id": MECHANISM_ABLATION_PROTOCOL_ID,
        "timestamp": datetime.now(UTC).isoformat(),
        "diagnostic_only": True,
        "claim_bearing": False,
        "primary_rq2_estimand_unchanged": True,
        "case_n": len(cases),
        "integrity": integrity,
        "downstream_usage": model.usage(),
        "analysis": analysis,
    }
    _atomic_json(output_dir / "results.json", result)
    return result
