from __future__ import annotations

import json
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from .analysis import cluster_bootstrap_ci, exact_mcnemar_p
from .manifest import load_manifest
from .p0_calibration import (
    NEUTRAL_P0_DOWNSTREAM_SYSTEM,
    _build_downstream,
    assert_neutral_p0_prompt,
)
from .profile import file_sha256, load_profile
from .prompts import assert_blinded_downstream_view
from .runner import (
    JsonModel,
    _ask_with_one_repair,
    _atomic_json,
    _decision_validator,
    _safe_name,
)
from .schema import sha256_json
from .sensitivity import _read_jsonl


SEMANTIC_CEILING_PROTOCOL_ID = "semantic-rq2-full-semantic-ceiling-diagnostic-v1"
SEMANTIC_CEILING_ARM = "C_max_semantic"
COMPARISON_ARMS = (
    "E_evidence_only",
    "C_explicit_recommendation_ceiling",
    SEMANTIC_CEILING_ARM,
)


def semantic_ceiling_memory(case: Mapping[str, Any]) -> dict[str, Any]:
    packet_by_id = {str(row["id"]): row for row in case["evidence_packet"]}
    evidence_ids = [str(value) for value in case["gold_evidence_ids"]]
    missing = sorted(set(evidence_ids) - set(packet_by_id))
    if missing:
        raise ValueError(f"semantic ceiling gold evidence absent from packet: {missing}")
    if not evidence_ids:
        raise ValueError("semantic ceiling requires at least one gold evidence span")
    target = str(case["assigned_target"])
    return {
        "source_grounding": [
            {
                "evidence_id": evidence_id,
                "verbatim_source_text": packet_by_id[evidence_id]["text"],
            }
            for evidence_id in evidence_ids
        ],
        "analysis": (
            "Read the quoted controlling passages together and preserve every condition, "
            "qualification, and exception when evaluating the hypothesis."
        ),
        "conclusion": "The source-grounded prior analysis concludes " + target + ".",
        "explicit_recommendation": target,
        "recommended_action": "Select " + target + ".",
    }


def semantic_ceiling_view(case: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "hypothesis": case["hypothesis"],
        "evidence_packet": case["evidence_packet"],
        "packet_sha256": case["packet_sha256"],
        "persistent_memory": [{"payload": semantic_ceiling_memory(case)}],
    }


def semantic_ceiling_prompt(case: Mapping[str, Any]) -> str:
    request = {
        "decision_input": semantic_ceiling_view(case),
        "response_schema": {
            "label": "Entailment|Contradiction",
            "confidence": "low|medium|high",
            "cited_evidence_ids": ["span-id"],
            "rationale": "brief source-grounded string",
        },
    }
    return "Make one independent decision.\nREQUEST=" + json.dumps(request, ensure_ascii=False)


def _semantic_ceiling_row(
    *,
    model: JsonModel,
    downstream_id: str,
    case: Mapping[str, Any],
    seed: int,
) -> dict[str, Any]:
    view = semantic_ceiling_view(case)
    assert_blinded_downstream_view(view, ceiling=True)
    user = semantic_ceiling_prompt(case)
    assert_neutral_p0_prompt(NEUTRAL_P0_DOWNSTREAM_SYSTEM, user)
    memory = semantic_ceiling_memory(case)
    packet_sha = sha256_json(view["evidence_packet"])
    base = {
        "case_id": case["case_id"],
        "cluster_id": case["cluster_id"],
        "downstream_id": downstream_id,
        "downstream_model": model.model,
        "seed": seed,
        "arm_id": SEMANTIC_CEILING_ARM,
        "mode": "control",
        "receptor": None,
        "gold_label": case["gold_label"],
        "assigned_target": case["assigned_target"],
        "packet_sha256": packet_sha,
        "packet_identity_ok": packet_sha == case["packet_sha256"],
        "hard_valid": True,
        "p0_visible_view": "neutral_no_provenance_warning",
        "oracle_control_only": True,
        "memory_payload_sha256": sha256_json(memory),
        "quoted_evidence_ids": [row["evidence_id"] for row in memory["source_grounding"]],
    }
    payload, metadata = _ask_with_one_repair(
        model,
        key=(
            f"semantic_ceiling_{seed}_{_safe_name(downstream_id)}_"
            f"{_safe_name(str(case['case_id']))}"
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


def _paired_summary(
    records: list[dict[str, Any]],
    *,
    left_arm: str,
    right_arm: str,
    planned_n: int,
    seed: int,
    bootstrap_samples: int,
) -> dict[str, Any]:
    by_case: dict[str, dict[str, dict[str, Any]]] = {}
    for row in records:
        by_case.setdefault(str(row["case_id"]), {})[str(row["arm_id"])] = row
    pairs: list[dict[str, Any]] = []
    for case_id, arms in sorted(by_case.items()):
        left = arms.get(left_arm)
        right = arms.get(right_arm)
        if left is None or right is None:
            continue
        if left.get("terminal_status") != "completed" or right.get("terminal_status") != "completed":
            continue
        if left["assigned_target"] != right["assigned_target"]:
            raise ValueError(f"paired target mismatch for {case_id}")
        target = left["assigned_target"]
        pairs.append(
            {
                "case_id": case_id,
                "cluster_id": left["cluster_id"],
                "delta": int(right.get("label") == target) - int(left.get("label") == target),
            }
        )
    deltas = [row["delta"] for row in pairs]
    toward = sum(value == 1 for value in deltas)
    away = sum(value == -1 for value in deltas)
    missing = max(0, planned_n - len(pairs))
    return {
        "contrast": f"{right_arm}_minus_{left_arm}",
        "planned_pair_n": planned_n,
        "completed_pair_n": len(pairs),
        "terminal_pair_coverage": len(pairs) / planned_n if planned_n else None,
        "point": statistics.mean(deltas) if deltas else None,
        "toward_target": toward,
        "away_from_target": away,
        "discordant_n": toward + away,
        "exact_mcnemar_p": exact_mcnemar_p(toward, away),
        "document_cluster_bootstrap_95ci": cluster_bootstrap_ci(
            pairs,
            value=lambda row: float(row["delta"]),
            seed=seed,
            samples=bootstrap_samples,
        ),
        "terminal_failure_worst_case_bounds": (
            [(sum(deltas) - missing) / planned_n, (sum(deltas) + missing) / planned_n]
            if planned_n
            else None
        ),
    }


def analyze_semantic_ceiling_records(
    records: list[dict[str, Any]],
    *,
    seed: int,
    bootstrap_samples: int,
) -> dict[str, Any]:
    case_ids = {str(row["case_id"]) for row in records}
    planned_n = len(case_ids)
    semantic_vs_evidence = _paired_summary(
        records,
        left_arm="E_evidence_only",
        right_arm=SEMANTIC_CEILING_ARM,
        planned_n=planned_n,
        seed=seed + 1,
        bootstrap_samples=bootstrap_samples,
    )
    semantic_vs_old = _paired_summary(
        records,
        left_arm="C_explicit_recommendation_ceiling",
        right_arm=SEMANTIC_CEILING_ARM,
        planned_n=planned_n,
        seed=seed + 2,
        bootstrap_samples=bootstrap_samples,
    )
    arm_rates: dict[str, Any] = {}
    for arm in COMPARISON_ARMS:
        rows = [
            row
            for row in records
            if row["arm_id"] == arm and row.get("terminal_status") == "completed"
        ]
        arm_rates[arm] = {
            "completed_n": len(rows),
            "target_rate": (
                statistics.mean(row.get("label") == row.get("assigned_target") for row in rows)
                if rows
                else None
            ),
            "accuracy": (
                statistics.mean(row.get("label") == row.get("gold_label") for row in rows)
                if rows
                else None
            ),
        }
    gate = {
        "delta_ge_0_10": (
            semantic_vs_evidence["point"] is not None
            and semantic_vs_evidence["point"] >= 0.10
        ),
        "toward_at_least_5": semantic_vs_evidence["toward_target"] >= 5,
    }
    return {
        "diagnostic_only": True,
        "primary_rq2_estimand_unchanged": True,
        "planned_case_n": planned_n,
        "arm_rates": arm_rates,
        "C_max_semantic_minus_E": semantic_vs_evidence,
        "C_max_semantic_minus_original_ceiling": semantic_vs_old,
        "responsiveness_gate": gate,
        "responsiveness_gate_pass": all(gate.values()),
    }


def _validate_matrix(
    records: list[dict[str, Any]], cases: list[dict[str, Any]], *, seed: int
) -> dict[str, Any]:
    expected = {(str(case["case_id"]), arm) for case in cases for arm in COMPARISON_ARMS}
    observed: set[tuple[str, str]] = set()
    problems: list[str] = []
    case_by_id = {str(case["case_id"]): case for case in cases}
    for row in records:
        key = (str(row.get("case_id")), str(row.get("arm_id")))
        if key in observed:
            problems.append("duplicate:" + "|".join(key))
        observed.add(key)
        case = case_by_id.get(key[0])
        if case is None or key[1] not in COMPARISON_ARMS:
            problems.append("unexpected:" + "|".join(key))
            continue
        if row.get("seed") != seed:
            problems.append("seed_mismatch:" + "|".join(key))
        if row.get("packet_sha256") != case["packet_sha256"] or not row.get("packet_identity_ok"):
            problems.append("packet_mismatch:" + "|".join(key))
        if row.get("assigned_target") != case["assigned_target"]:
            problems.append("target_mismatch:" + "|".join(key))
        if row.get("gold_label") != case["gold_label"]:
            problems.append("gold_mismatch:" + "|".join(key))
    for key in sorted(expected - observed):
        problems.append("missing:" + "|".join(key))
    return {
        "status": "PASS" if not problems else "FAIL",
        "expected_record_n": len(expected),
        "observed_record_n": len(records),
        "problems": problems,
    }


def run_semantic_ceiling_diagnostic(
    *,
    manifest_path: Path,
    profile_path: Path,
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
    neutral_config = json.loads((neutral_run_dir / "run_config.json").read_text(encoding="utf-8"))
    if neutral_config.get("manifest_sha256") != file_sha256(manifest_path):
        raise ValueError("neutral run manifest hash mismatch")
    if neutral_config.get("profile_sha256") != file_sha256(profile_path):
        raise ValueError("neutral run profile hash mismatch")
    if neutral_config.get("seed") != seed:
        raise ValueError("neutral run seed mismatch")
    neutral_results = json.loads((neutral_run_dir / "results.json").read_text(encoding="utf-8"))
    if neutral_results.get("integrity", {}).get("status") != "PASS":
        raise ValueError("neutral run integrity did not pass")
    neutral_records_path = neutral_run_dir / "records.neutral_p0.jsonl"
    neutral_records = [
        row
        for row in _read_jsonl(neutral_records_path)
        if str(row.get("case_id")) in case_ids and row.get("arm_id") in COMPARISON_ARMS[:2]
    ]

    protocol_path = (
        Path(__file__).resolve().parents[2]
        / "experiments"
        / "semantic_receptor_rq2"
        / "SEMANTIC_CEILING_DIAGNOSTIC_PROTOCOL.md"
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    config = {
        "protocol_id": SEMANTIC_CEILING_PROTOCOL_ID,
        "diagnostic_only": True,
        "claim_bearing": False,
        "primary_rq2_estimand_unchanged": True,
        "oracle_gold_evidence_disclosed_only_to_ceiling": True,
        "frozen_neutral_rows_reused": list(COMPARISON_ARMS[:2]),
        "new_arm": SEMANTIC_CEILING_ARM,
        "neutral_run_dir": str(neutral_run_dir.resolve()),
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
            raise ValueError("semantic-ceiling run_config mismatch; use a new output directory")
    else:
        _atomic_json(config_path, config)

    if downstream_model is None:
        downstream_id, model = _build_downstream(profile, output_dir)
    else:
        downstream_id = str(profile["roles"]["downstreams"][0]["id"]) + "-neutral-p0"
        model = downstream_model
    source_downstream_ids = {str(row["downstream_id"]) for row in neutral_records}
    if source_downstream_ids != {downstream_id}:
        raise ValueError("semantic ceiling downstream does not match frozen neutral rows")

    evaluation_dir = output_dir / "evaluation" / _safe_name(downstream_id)
    evaluation_dir.mkdir(parents=True, exist_ok=True)
    rows_by_case: dict[str, dict[str, Any]] = {}
    pending: list[tuple[dict[str, Any], Path]] = []
    for case in cases:
        path = evaluation_dir / f"{_safe_name(str(case['case_id']))}.json"
        if path.exists():
            row = json.loads(path.read_text(encoding="utf-8"))
            if row.get("packet_sha256") != case["packet_sha256"] or row.get("seed") != seed:
                raise ValueError(f"semantic-ceiling resume mismatch for {case['case_id']}")
            rows_by_case[str(case["case_id"])] = row
        else:
            pending.append((case, path))

    def evaluate(item: tuple[dict[str, Any], Path]) -> dict[str, Any]:
        case, path = item
        row = _semantic_ceiling_row(
            model=model,
            downstream_id=downstream_id,
            case=case,
            seed=seed,
        )
        _atomic_json(path, row)
        return row

    completed = len(rows_by_case)
    _atomic_json(
        output_dir / "progress.json",
        {"completed_case_n": completed, "total_case_n": len(cases), "stage": SEMANTIC_CEILING_ARM},
    )
    with ThreadPoolExecutor(max_workers=int(profile["max_workers"])) as executor:
        futures = {executor.submit(evaluate, item): str(item[0]["case_id"]) for item in pending}
        for future in as_completed(futures):
            case_id = futures[future]
            rows_by_case[case_id] = future.result()
            completed += 1
            _atomic_json(
                output_dir / "progress.json",
                {
                    "completed_case_n": completed,
                    "total_case_n": len(cases),
                    "stage": SEMANTIC_CEILING_ARM,
                },
            )

    records = [*neutral_records, *(rows_by_case[str(case["case_id"])] for case in cases)]
    integrity = _validate_matrix(records, cases, seed=seed)
    _atomic_json(output_dir / "integrity.json", integrity)
    if integrity["status"] != "PASS":
        raise RuntimeError(f"semantic-ceiling matrix failed: {integrity['problems']}")
    records_path = output_dir / "records.semantic_ceiling.jsonl"
    temporary = records_path.with_suffix(".jsonl.tmp")
    temporary.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in records),
        encoding="utf-8",
    )
    temporary.replace(records_path)
    analysis = analyze_semantic_ceiling_records(
        records,
        seed=seed,
        bootstrap_samples=int(profile["bootstrap_samples"]),
    )
    result = {
        "protocol_id": SEMANTIC_CEILING_PROTOCOL_ID,
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

