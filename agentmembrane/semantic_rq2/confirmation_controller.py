from __future__ import annotations

import hashlib
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

from .confirmation_analysis import (
    analyze_confirmation_records,
    write_confirmation_json,
    write_confirmation_report,
)
from .focused_ablation import run_focused_interaction_confirmation
from .manifest import load_manifest, validate_manifest
from .p0_calibration import run_neutral_p0_calibration
from .profile import file_sha256, implementation_hash, load_profile, offline_preflight
from .runner import _atomic_json, run_experiment
from .schema import sha256_json
from .semantic_ceiling import run_semantic_ceiling_diagnostic
from .sensitivity import run_relaxed_reaudit


CONTROLLER_PROTOCOL_ID = "semantic-rq2-confirmation-controller-v1"


def _stable_key(seed: int, value: str) -> str:
    return hashlib.sha256(f"{seed}|{value}".encode("utf-8")).hexdigest()


def build_checkpoint_manifest(
    *,
    full_manifest_path: Path,
    output_path: Path,
    document_clusters: int,
    seed: int,
) -> dict[str, Any]:
    """Build a complete-cluster execution prefix from the frozen full manifest."""

    if document_clusters <= 0:
        raise ValueError("document_clusters must be positive")
    full = load_manifest(full_manifest_path)
    full_check = validate_manifest(full, exact_baseline_shape=True)
    if not full_check["valid"]:
        raise ValueError(f"full manifest invalid: {full_check['problems']}")
    by_cluster: dict[str, list[dict[str, Any]]] = {}
    for case in full["cases"]:
        by_cluster.setdefault(str(case["cluster_id"]), []).append(case)
    ordered = sorted(by_cluster, key=lambda value: _stable_key(seed, value))
    if document_clusters >= len(ordered):
        raise ValueError("checkpoint must be smaller than the full manifest")
    selected = set(ordered[:document_clusters])
    cases = [case for case in full["cases"] if str(case["cluster_id"]) in selected]

    checkpoint = dict(full)
    checkpoint["sampling"] = dict(full["sampling"])
    checkpoint["sampling"].update(
        {
            "document_clusters": document_clusters,
            "planned_case_n": len(cases),
            "rule": (
                str(full["sampling"]["rule"])
                + "; execution checkpoint takes hash-first complete selected clusters"
            ),
        }
    )
    checkpoint["execution_checkpoint"] = {
        "controller_protocol_id": CONTROLLER_PROTOCOL_ID,
        "full_manifest_sha256": file_sha256(full_manifest_path),
        "full_manifest_content_sha256": full["content_sha256"],
        "document_clusters": document_clusters,
        "case_n": len(cases),
        "seed": seed,
        "promotion_uses_integrity_only": True,
        "checkpoint_outcomes_not_used_for_protocol_changes": True,
    }
    checkpoint["cases"] = cases
    checkpoint.pop("content_sha256", None)
    checkpoint["content_sha256"] = sha256_json(checkpoint)
    check = validate_manifest(checkpoint, exact_baseline_shape=False)
    if not check["valid"]:
        raise ValueError(f"checkpoint manifest invalid: {check['problems']}")
    if check["case_n"] != document_clusters * 2 or check["cluster_n"] != document_clusters:
        raise AssertionError("checkpoint manifest is not a complete two-case cluster prefix")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(checkpoint, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return checkpoint


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _records_integrity(
    path: Path,
    *,
    expected_n: int,
    minimum_completed_rate: float = 0.95,
) -> dict[str, Any]:
    rows = _read_jsonl(path)
    completed = sum(row.get("terminal_status") == "completed" for row in rows)
    packet_identity = sum(bool(row.get("packet_identity_ok")) for row in rows)
    completed_rate = completed / len(rows) if rows else 0.0
    result = {
        "path": str(path.resolve()),
        "record_n": len(rows),
        "expected_n": expected_n,
        "completed_n": completed,
        "completed_rate": completed_rate,
        "packet_identity_n": packet_identity,
        "pass": (
            len(rows) == expected_n
            and completed_rate >= minimum_completed_rate
            and packet_identity == len(rows)
        ),
    }
    return result


def evaluate_checkpoint_integrity(root_dir: Path, *, case_n: int) -> dict[str, Any]:
    """Promote using engineering integrity only; never read an effect estimate."""

    canary = root_dir / "canary"
    source = json.loads((canary / "source" / "results.json").read_text(encoding="utf-8"))
    source_fidelity = json.loads(
        (canary / "source_fidelity" / "results.json").read_text(encoding="utf-8")
    )
    neutral = json.loads(
        (canary / "neutral_p0" / "results.json").read_text(encoding="utf-8")
    )
    ceiling = json.loads(
        (canary / "semantic_ceiling" / "results.json").read_text(encoding="utf-8")
    )
    focused = json.loads(
        (canary / "focused_interaction" / "results.json").read_text(encoding="utf-8")
    )
    stage_integrity = {
        "source_generation": source.get("generation_receipt", {}).get("status") == "PASS",
        "source_matrix": source.get("evaluation_integrity", {}).get("status") == "PASS",
        "source_fidelity_audit": source_fidelity.get("audit_receipt", {}).get("status") == "PASS",
        "source_fidelity_matrix": source_fidelity.get("integrity", {}).get("status") == "PASS",
        "neutral_p0_matrix": neutral.get("integrity", {}).get("status") == "PASS",
        "neutral_warning_absent": neutral.get("visible_provenance_warning_absent") is True,
        "semantic_ceiling_matrix": ceiling.get("integrity", {}).get("status") == "PASS",
        "focused_matrix": focused.get("integrity", {}).get("status") == "PASS",
    }
    record_checks = {
        "source": _records_integrity(
            canary / "source" / "records.jsonl", expected_n=12 * case_n
        ),
        "source_fidelity": _records_integrity(
            canary / "source_fidelity" / "records.relaxed.jsonl",
            expected_n=12 * case_n,
        ),
        "neutral_p0": _records_integrity(
            canary / "neutral_p0" / "records.neutral_p0.jsonl",
            expected_n=12 * case_n,
        ),
        "semantic_ceiling": _records_integrity(
            canary / "semantic_ceiling" / "records.semantic_ceiling.jsonl",
            expected_n=3 * case_n,
        ),
        "focused_interaction": _records_integrity(
            canary / "focused_interaction" / "records.focused_interaction.jsonl",
            expected_n=8 * case_n,
        ),
    }
    validity_rates = {
        arm: float(row["rate"])
        for arm, row in source_fidelity.get("relaxed_validity_by_arm", {}).items()
    }
    minimum_validity_rate = min(validity_rates.values()) if validity_rates else 0.0
    passed = (
        all(stage_integrity.values())
        and all(row["pass"] for row in record_checks.values())
        and minimum_validity_rate >= 0.80
    )
    return {
        "status": "PASS" if passed else "FAIL",
        "case_n": case_n,
        "promotion_basis": "engineering_integrity_only",
        "outcome_effects_inspected_for_promotion": False,
        "stage_integrity": stage_integrity,
        "record_checks": record_checks,
        "source_fidelity_validity_rates": validity_rates,
        "minimum_source_fidelity_artifact_rate": minimum_validity_rate,
        "minimum_required_rate": 0.80,
    }


def _promote_cache(source_stage: Path, destination_stage: Path) -> dict[str, Any]:
    source = source_stage / "cache"
    destination = destination_stage / "cache"
    if not source.is_dir():
        raise ValueError(f"cache source missing: {source}")
    copied = 0
    verified_existing = 0
    for path in sorted(source.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(source)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if file_sha256(path) != file_sha256(target):
                raise ValueError(f"cache promotion collision: {target}")
            verified_existing += 1
        else:
            shutil.copy2(path, target)
            copied += 1
    return {
        "source": str(source.resolve()),
        "destination": str(destination.resolve()),
        "copied_file_n": copied,
        "verified_existing_file_n": verified_existing,
        "only_role_local_cache_promoted": True,
    }


def _run_stage(
    *,
    root_dir: Path,
    name: str,
    completed: list[str],
    callback: Callable[[], Any],
) -> Any:
    _atomic_json(
        root_dir / "controller_status.json",
        {
            "protocol_id": CONTROLLER_PROTOCOL_ID,
            "status": "RUNNING",
            "current_stage": name,
            "completed_stages": completed,
            "updated_at": datetime.now(UTC).isoformat(),
        },
    )
    result = callback()
    completed.append(name)
    return result


def run_confirmation_controller(
    *,
    full_manifest_path: Path,
    checkpoint_manifest_path: Path,
    profile_path: Path,
    root_dir: Path,
    seed: int,
    checkpoint_case_n: int = 50,
) -> dict[str, Any]:
    if checkpoint_case_n != 50:
        raise ValueError("the frozen controller checkpoint is exactly 50 cases")
    full_manifest = load_manifest(full_manifest_path)
    checkpoint_manifest = load_manifest(checkpoint_manifest_path)
    profile = load_profile(profile_path)
    if len(full_manifest["cases"]) != 200:
        raise ValueError("full manifest must contain exactly 200 cases")
    if len(checkpoint_manifest["cases"]) != checkpoint_case_n:
        raise ValueError("checkpoint manifest case count mismatch")
    if seed not in profile.get("seeds", []):
        raise ValueError("seed is not frozen in profile")
    if offline_preflight(
        manifest_path=full_manifest_path, profile_path=profile_path, formal=False
    )["status"] != "PASS":
        raise ValueError("full offline preflight failed")
    if offline_preflight(
        manifest_path=checkpoint_manifest_path, profile_path=profile_path, formal=False
    )["status"] != "PASS":
        raise ValueError("checkpoint offline preflight failed")

    repository_root = Path(__file__).resolve().parents[2]
    main_protocol = repository_root / "experiments" / "semantic_receptor_rq2" / "FULL_200_CONFIRMATORY_PROTOCOL.md"
    focused_protocol = repository_root / "experiments" / "semantic_receptor_rq2" / "FOCUSED_INTERACTION_CONFIRMATION_PROTOCOL.md"
    root_dir.mkdir(parents=True, exist_ok=True)
    config = {
        "protocol_id": CONTROLLER_PROTOCOL_ID,
        "full_manifest_sha256": file_sha256(full_manifest_path),
        "checkpoint_manifest_sha256": file_sha256(checkpoint_manifest_path),
        "profile_sha256": file_sha256(profile_path),
        "main_protocol_sha256": file_sha256(main_protocol),
        "focused_protocol_sha256": file_sha256(focused_protocol),
        "implementation_sha256": implementation_hash(),
        "seed": seed,
        "checkpoint_case_n": checkpoint_case_n,
        "full_case_n": 200,
        "checkpoint_promotion_basis": "engineering_integrity_only",
    }
    config_path = root_dir / "controller_config.json"
    if config_path.exists():
        if json.loads(config_path.read_text(encoding="utf-8")) != config:
            raise ValueError("controller_config mismatch; use a new root directory")
    else:
        _atomic_json(config_path, config)

    canary = root_dir / "canary"
    full = root_dir / "full"
    completed: list[str] = []
    try:
        _run_stage(
            root_dir=root_dir,
            name="canary_source",
            completed=completed,
            callback=lambda: run_experiment(
                manifest_path=checkpoint_manifest_path,
                profile_path=profile_path,
                run_dir=canary / "source",
                seed=seed,
                formal=False,
            ),
        )
        _run_stage(
            root_dir=root_dir,
            name="canary_source_fidelity",
            completed=completed,
            callback=lambda: run_relaxed_reaudit(
                manifest_path=checkpoint_manifest_path,
                profile_path=profile_path,
                source_run_dir=canary / "source",
                output_dir=canary / "source_fidelity",
                seed=seed,
                post_pilot_sensitivity_only=False,
            ),
        )
        _run_stage(
            root_dir=root_dir,
            name="canary_neutral_p0",
            completed=completed,
            callback=lambda: run_neutral_p0_calibration(
                manifest_path=checkpoint_manifest_path,
                profile_path=profile_path,
                source_run_dir=canary / "source",
                validity_stage_dir=canary / "source_fidelity",
                output_dir=canary / "neutral_p0",
                seed=seed,
                max_cases=checkpoint_case_n,
                validity_records_filename="records.relaxed.jsonl",
                post_pilot_sensitivity_only=False,
            ),
        )
        _run_stage(
            root_dir=root_dir,
            name="canary_semantic_ceiling",
            completed=completed,
            callback=lambda: run_semantic_ceiling_diagnostic(
                manifest_path=checkpoint_manifest_path,
                profile_path=profile_path,
                neutral_run_dir=canary / "neutral_p0",
                output_dir=canary / "semantic_ceiling",
                seed=seed,
                max_cases=checkpoint_case_n,
            ),
        )
        _run_stage(
            root_dir=root_dir,
            name="canary_focused_interaction",
            completed=completed,
            callback=lambda: run_focused_interaction_confirmation(
                manifest_path=checkpoint_manifest_path,
                profile_path=profile_path,
                source_run_dir=canary / "source",
                neutral_run_dir=canary / "neutral_p0",
                output_dir=canary / "focused_interaction",
                seed=seed,
                max_cases=checkpoint_case_n,
            ),
        )
        checkpoint = _run_stage(
            root_dir=root_dir,
            name="checkpoint_integrity_gate",
            completed=completed,
            callback=lambda: evaluate_checkpoint_integrity(
                root_dir, case_n=checkpoint_case_n
            ),
        )
        _atomic_json(root_dir / "checkpoint_integrity.json", checkpoint)
        if checkpoint["status"] != "PASS":
            raise RuntimeError("50-case engineering checkpoint failed")

        promotions = {
            stage: _promote_cache(canary / stage, full / stage)
            for stage in (
                "source",
                "source_fidelity",
                "neutral_p0",
                "semantic_ceiling",
                "focused_interaction",
            )
        }
        _atomic_json(root_dir / "cache_promotion_receipt.json", promotions)
        completed.append("cache_promotion")

        _run_stage(
            root_dir=root_dir,
            name="full_source",
            completed=completed,
            callback=lambda: run_experiment(
                manifest_path=full_manifest_path,
                profile_path=profile_path,
                run_dir=full / "source",
                seed=seed,
                formal=False,
            ),
        )
        _run_stage(
            root_dir=root_dir,
            name="full_source_fidelity",
            completed=completed,
            callback=lambda: run_relaxed_reaudit(
                manifest_path=full_manifest_path,
                profile_path=profile_path,
                source_run_dir=full / "source",
                output_dir=full / "source_fidelity",
                seed=seed,
                post_pilot_sensitivity_only=False,
            ),
        )
        _run_stage(
            root_dir=root_dir,
            name="full_neutral_p0",
            completed=completed,
            callback=lambda: run_neutral_p0_calibration(
                manifest_path=full_manifest_path,
                profile_path=profile_path,
                source_run_dir=full / "source",
                validity_stage_dir=full / "source_fidelity",
                output_dir=full / "neutral_p0",
                seed=seed,
                max_cases=200,
                validity_records_filename="records.relaxed.jsonl",
                post_pilot_sensitivity_only=False,
            ),
        )
        _run_stage(
            root_dir=root_dir,
            name="full_semantic_ceiling",
            completed=completed,
            callback=lambda: run_semantic_ceiling_diagnostic(
                manifest_path=full_manifest_path,
                profile_path=profile_path,
                neutral_run_dir=full / "neutral_p0",
                output_dir=full / "semantic_ceiling",
                seed=seed,
                max_cases=200,
            ),
        )
        focused_result = _run_stage(
            root_dir=root_dir,
            name="full_focused_interaction",
            completed=completed,
            callback=lambda: run_focused_interaction_confirmation(
                manifest_path=full_manifest_path,
                profile_path=profile_path,
                source_run_dir=full / "source",
                neutral_run_dir=full / "neutral_p0",
                output_dir=full / "focused_interaction",
                seed=seed,
                max_cases=200,
            ),
        )
        neutral_records = _read_jsonl(full / "neutral_p0" / "records.neutral_p0.jsonl")
        confirmation_analysis = analyze_confirmation_records(
            neutral_records,
            bootstrap_seed=seed,
            bootstrap_samples=int(profile["bootstrap_samples"]),
        )
        analysis_dir = root_dir / "analysis"
        write_confirmation_json(
            analysis_dir / "confirmation_analysis.json", confirmation_analysis
        )
        write_confirmation_report(
            analysis_dir / "CONFIRMATION_REPORT.md", confirmation_analysis
        )
        result = {
            "protocol_id": CONTROLLER_PROTOCOL_ID,
            "status": "PASS",
            "completed_at": datetime.now(UTC).isoformat(),
            "case_n": 200,
            "document_cluster_n": 100,
            "checkpoint": checkpoint,
            "confirmation_analysis_path": str(
                (analysis_dir / "confirmation_analysis.json").resolve()
            ),
            "focused_results_path": str(
                (full / "focused_interaction" / "results.json").resolve()
            ),
            "semantic_ceiling_results_path": str(
                (full / "semantic_ceiling" / "results.json").resolve()
            ),
            "focused_integrity": focused_result["integrity"],
            "claim_bearing": False,
        }
        _atomic_json(root_dir / "controller_results.json", result)
        _atomic_json(
            root_dir / "controller_status.json",
            {
                "protocol_id": CONTROLLER_PROTOCOL_ID,
                "status": "PASS",
                "current_stage": None,
                "completed_stages": completed + ["confirmation_analysis"],
                "updated_at": datetime.now(UTC).isoformat(),
            },
        )
        return result
    except Exception as error:
        _atomic_json(
            root_dir / "controller_status.json",
            {
                "protocol_id": CONTROLLER_PROTOCOL_ID,
                "status": "FAILED",
                "current_stage": completed[-1] if completed else None,
                "completed_stages": completed,
                "error_type": type(error).__name__,
                "error": str(error),
                "updated_at": datetime.now(UTC).isoformat(),
            },
        )
        raise
