from __future__ import annotations

import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from .analysis import analyze_records
from .manifest import load_manifest
from .p0_calibration import _build_downstream, _neutral_decision_row
from .profile import file_sha256, load_profile
from .runner import JsonModel, _atomic_json, _safe_name, _stable_order, validate_record_matrix
from .schema import RECEPTOR_ORDER, Receptor, canonical_json, sha256_json, validate_artifact
from .sensitivity import _read_jsonl


NESTED_PROJECTION_PROTOCOL_ID = "semantic-rq2-nested-r3-projection-diagnostic-v1"
_R2_DIRECTNESS_RE = re.compile(
    r"\b(?:entailment|contradiction|label|answer|choose|select|recommend)\b",
    re.IGNORECASE,
)
_CONFIDENCE_FROM_UNCERTAINTY = {"low": "high", "medium": "medium", "high": "low"}


def _nested_artifact_id(case_id: str, mode: str, receptor: Receptor, base_sha: str) -> str:
    value = f"{NESTED_PROJECTION_PROTOCOL_ID}|{case_id}|{mode}|{receptor.value}|{base_sha}"
    return "nested-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


def project_r3_backbone(
    *,
    case: Mapping[str, Any],
    mode: str,
    r3_artifact: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    if mode not in {"honest", "attack"}:
        raise ValueError(f"unknown mode: {mode}")
    validation = validate_artifact(
        r3_artifact,
        candidate_evidence_ids=[str(row["id"]) for row in case["evidence_packet"]],
        expected_case_id=str(case["case_id"]),
        expected_receptor=Receptor.R3,
    )
    if not validation.deterministic_valid:
        raise ValueError(f"invalid R3 backbone: {validation.problems}")
    base = dict(r3_artifact["payload"])
    inference = str(base["inference"])
    if _R2_DIRECTNESS_RE.search(inference):
        raise ValueError("R3 backbone inference exceeds the projected R2 directness ceiling")
    evidence_ids = list(base["evidence_ids"])
    uncertainty = str(base["uncertainty"])
    base_sha = sha256_json(r3_artifact)
    payloads: dict[Receptor, dict[str, Any]] = {
        Receptor.R0: {"evidence_ids": list(evidence_ids)},
        Receptor.R1: {
            "evidence_ids": list(evidence_ids),
            "annotations": [
                {
                    "evidence_id": evidence_id,
                    "relevance": 1.0,
                    "confidence": _CONFIDENCE_FROM_UNCERTAINTY[uncertainty],
                }
                for evidence_id in evidence_ids
            ],
        },
        Receptor.R2: {
            "evidence_ids": list(evidence_ids),
            "inference": inference,
            "uncertainty": uncertainty,
        },
        Receptor.R3: dict(base),
        Receptor.R4: {
            "artifact_text": (
                "Inference: "
                + inference
                + "\nUncertainty: "
                + uncertainty
                + ".\nConclusion: "
                + str(base["conclusion"])
                + "\nRecommendation: "
                + str(base["recommendation"])
            ),
            "evidence_ids": list(evidence_ids),
        },
    }
    artifacts = {
        receptor.value: {
            "artifact_id": _nested_artifact_id(str(case["case_id"]), mode, receptor, base_sha),
            "case_id": case["case_id"],
            "receptor": receptor.value,
            "payload": payloads[receptor],
        }
        for receptor in RECEPTOR_ORDER
    }
    for receptor in RECEPTOR_ORDER:
        projected = artifacts[receptor.value]
        result = validate_artifact(
            projected,
            candidate_evidence_ids=[str(row["id"]) for row in case["evidence_packet"]],
            expected_case_id=str(case["case_id"]),
            expected_receptor=receptor,
        )
        if not result.deterministic_valid:
            raise ValueError(f"invalid {receptor.value} projection: {result.problems}")
    assert_nested_projection(artifacts)
    return artifacts


def assert_nested_projection(artifacts: Mapping[str, Mapping[str, Any]]) -> None:
    if set(artifacts) != {receptor.value for receptor in RECEPTOR_ORDER}:
        raise AssertionError("nested projection does not contain the complete R0--R4 ladder")
    payloads = {key: value["payload"] for key, value in artifacts.items()}
    r0 = payloads[Receptor.R0.value]
    r1 = payloads[Receptor.R1.value]
    r2 = payloads[Receptor.R2.value]
    r3 = payloads[Receptor.R3.value]
    r4 = payloads[Receptor.R4.value]
    if not (
        r0["evidence_ids"]
        == r1["evidence_ids"]
        == r2["evidence_ids"]
        == r3["evidence_ids"]
        == r4["evidence_ids"]
    ):
        raise AssertionError("evidence IDs differ across nested receptors")
    if r2["inference"] != r3["inference"] or r2["uncertainty"] != r3["uncertainty"]:
        raise AssertionError("R2 is not an exact projection of the R3 inference core")
    exact_fragments = (
        "Inference: " + str(r3["inference"]),
        "Uncertainty: " + str(r3["uncertainty"]) + ".",
        "Conclusion: " + str(r3["conclusion"]),
        "Recommendation: " + str(r3["recommendation"]),
    )
    if r4["artifact_text"] != "\n".join(exact_fragments):
        raise AssertionError("R4 is not the frozen lossless R3 serialization")


def materialize_nested_block(
    *,
    case: Mapping[str, Any],
    source_generation_block: Mapping[str, Any],
    source_r3_validity: Mapping[str, bool],
    seed: int,
) -> dict[str, Any]:
    artifacts: dict[str, dict[str, Any]] = {}
    hard_valid: dict[str, bool] = {}
    base_hashes: dict[str, str] = {}
    for mode in ("honest", "attack"):
        base_arm = f"{mode}:{Receptor.R3.value}"
        base = source_generation_block["artifacts"].get(base_arm)
        if not isinstance(base, Mapping):
            raise ValueError(f"missing source R3 backbone: {base_arm}")
        base_hashes[mode] = sha256_json(base)
        projections = project_r3_backbone(case=case, mode=mode, r3_artifact=base)
        for receptor in RECEPTOR_ORDER:
            arm = f"{mode}:{receptor.value}"
            artifacts[arm] = projections[receptor.value]
            hard_valid[arm] = bool(source_r3_validity[base_arm])
    return {
        "protocol_id": NESTED_PROJECTION_PROTOCOL_ID,
        "case_id": case["case_id"],
        "case_packet_sha256": case["packet_sha256"],
        "seed": seed,
        "source_r3_artifact_sha256": base_hashes,
        "projection_invariant": "one_R3_backbone_per_mode_losslessly_projected_across_R0_R4",
        "artifacts": artifacts,
        "hard_valid": hard_valid,
        "bundle_sha256": sha256_json({"artifacts": artifacts, "hard_valid": hard_valid}),
    }


def run_nested_projection_diagnostic(
    *,
    manifest_path: Path,
    profile_path: Path,
    source_run_dir: Path,
    neutral_run_dir: Path,
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
    neutral_config = json.loads((neutral_run_dir / "run_config.json").read_text(encoding="utf-8"))
    for name, config in (("source", source_config), ("neutral", neutral_config)):
        if config.get("manifest_sha256") != file_sha256(manifest_path):
            raise ValueError(f"{name} run manifest hash mismatch")
        if config.get("profile_sha256") != file_sha256(profile_path):
            raise ValueError(f"{name} run profile hash mismatch")
        if config.get("seed") != seed:
            raise ValueError(f"{name} run seed mismatch")
    neutral_results = json.loads((neutral_run_dir / "results.json").read_text(encoding="utf-8"))
    if neutral_results.get("integrity", {}).get("status") != "PASS":
        raise ValueError("neutral run integrity did not pass")
    neutral_records_path = neutral_run_dir / "records.neutral_p0.jsonl"
    all_neutral_records = [
        row for row in _read_jsonl(neutral_records_path) if str(row.get("case_id")) in case_ids
    ]
    frozen_controls = [
        row
        for row in all_neutral_records
        if row.get("arm_id") in {"E_evidence_only", "C_explicit_recommendation_ceiling"}
    ]
    r3_validity = {
        (str(row["case_id"]), str(row["arm_id"])): bool(row.get("hard_valid"))
        for row in all_neutral_records
        if row.get("arm_id")
        in {f"honest:{Receptor.R3.value}", f"attack:{Receptor.R3.value}"}
    }
    for case in cases:
        for mode in ("honest", "attack"):
            key = (str(case["case_id"]), f"{mode}:{Receptor.R3.value}")
            if key not in r3_validity:
                raise ValueError(f"missing frozen R3 validity: {key}")

    protocol_path = (
        Path(__file__).resolve().parents[2]
        / "experiments"
        / "semantic_receptor_rq2"
        / "NESTED_PROJECTION_DIAGNOSTIC_PROTOCOL.md"
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    config = {
        "protocol_id": NESTED_PROJECTION_PROTOCOL_ID,
        "diagnostic_only": True,
        "claim_bearing": False,
        "primary_rq2_estimand_unchanged": True,
        "single_content_backbone_per_case_and_mode": f"source_{Receptor.R3.value}",
        "new_generator_calls": 0,
        "new_surrogate_calls": 0,
        "validity_policy": "inherit_broad_source_fidelity_only_from_admitted_R3_backbone",
        "source_run_dir": str(source_run_dir.resolve()),
        "neutral_run_dir": str(neutral_run_dir.resolve()),
        "source_results_sha256": file_sha256(source_run_dir / "results.json"),
        "source_generation_receipt_sha256": file_sha256(source_run_dir / "generation" / "receipt.json"),
        "neutral_results_sha256": file_sha256(neutral_run_dir / "results.json"),
        "neutral_records_sha256": file_sha256(neutral_records_path),
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
            raise ValueError("nested-projection run_config mismatch; use a new output directory")
    else:
        _atomic_json(config_path, config)

    materialized_dir = output_dir / "materialized" / "blocks"
    materialized_dir.mkdir(parents=True, exist_ok=True)
    nested_by_case: dict[str, dict[str, Any]] = {}
    for case in cases:
        case_id = str(case["case_id"])
        path = materialized_dir / f"{_safe_name(case_id)}.json"
        source_path = source_run_dir / "generation" / "blocks" / f"{_safe_name(case_id)}.json"
        source_block = json.loads(source_path.read_text(encoding="utf-8"))
        block = materialize_nested_block(
            case=case,
            source_generation_block=source_block,
            source_r3_validity={
                f"{mode}:{Receptor.R3.value}": r3_validity[(case_id, f"{mode}:{Receptor.R3.value}")]
                for mode in ("honest", "attack")
            },
            seed=seed,
        )
        if path.exists() and json.loads(path.read_text(encoding="utf-8")) != block:
            raise ValueError(f"nested materialization mismatch for {case_id}")
        if not path.exists():
            _atomic_json(path, block)
        nested_by_case[case_id] = block
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
    if {str(row["downstream_id"]) for row in frozen_controls} != {downstream_id}:
        raise ValueError("nested downstream does not match frozen neutral controls")
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
                raise ValueError(f"nested evaluation resume mismatch for {case_id}")
            blocks_by_case[case_id] = block
        else:
            pending.append((case, path))

    def evaluate(item: tuple[dict[str, Any], Path]) -> dict[str, Any]:
        case, path = item
        case_id = str(case["case_id"])
        nested = nested_by_case[case_id]
        rows = []
        for arm_id in _stable_order(seed, case_id, list(nested["artifacts"])):
            rows.append(
                _neutral_decision_row(
                    model=model,
                    downstream_id=downstream_id,
                    case=case,
                    arm_id=arm_id,
                    artifact=nested["artifacts"][arm_id],
                    hard_valid=bool(nested["hard_valid"][arm_id]),
                    seed=seed,
                )
            )
        block = {
            "protocol_id": NESTED_PROJECTION_PROTOCOL_ID,
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
        {"completed_case_n": completed, "total_case_n": len(cases), "stage": "nested_downstream"},
    )
    with ThreadPoolExecutor(max_workers=int(profile["max_workers"])) as executor:
        futures = {executor.submit(evaluate, item): str(item[0]["case_id"]) for item in pending}
        for future in as_completed(futures):
            case_id = futures[future]
            blocks_by_case[case_id] = future.result()
            completed += 1
            _atomic_json(
                output_dir / "progress.json",
                {"completed_case_n": completed, "total_case_n": len(cases), "stage": "nested_downstream"},
            )

    records = [
        *frozen_controls,
        *(row for case in cases for row in blocks_by_case[str(case["case_id"])]["records"]),
    ]
    integrity = validate_record_matrix(records, cases=cases, downstream_ids=[downstream_id], seed=seed)
    _atomic_json(output_dir / "integrity.json", integrity)
    if integrity["status"] != "PASS":
        raise RuntimeError(f"nested matrix failed: {integrity['problems']}")
    records_path = output_dir / "records.nested_projection.jsonl"
    temporary = records_path.with_suffix(".jsonl.tmp")
    temporary.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in records),
        encoding="utf-8",
    )
    temporary.replace(records_path)
    analysis = analyze_records(
        records,
        seed=seed,
        bootstrap_samples=int(profile["bootstrap_samples"]),
    )
    result = {
        "protocol_id": NESTED_PROJECTION_PROTOCOL_ID,
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

