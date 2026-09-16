#!/usr/bin/env python3
"""Verify the public RQ2 evidence bundle and its headline claims."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "results" / "semantic_rq2_confirmation_20260901"
MANIFEST = BUNDLE / "artifact_manifest.json"


def _load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError(f"expected JSON object: {path}")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _close(actual: object, expected: float, *, label: str) -> None:
    if type(actual) not in {int, float} or not math.isclose(
        float(actual), expected, rel_tol=0.0, abs_tol=1e-15
    ):
        raise ValueError(f"{label} mismatch: {actual!r}")


def audit(root: Path = ROOT) -> dict:
    bundle = root / "results" / "semantic_rq2_confirmation_20260901"
    manifest_path = bundle / "artifact_manifest.json"
    errors: list[str] = []
    try:
        manifest = _load(manifest_path)
        if manifest.get("schema_version") != "agentmembrane-rq2-public-evidence-bundle/1":
            raise ValueError("artifact manifest schema mismatch")
        if manifest.get("based_on_git_commit") != "64d0061731f419e6c1188ea298d132bb9f2c4e0c":
            raise ValueError("artifact manifest base commit mismatch")
        if manifest.get("evidence_level") != "engineering" or manifest.get("claim_bearing") is not False:
            raise ValueError("evidence label mismatch")
        if manifest.get("hash_algorithm") != "sha256" or manifest.get("hash_scope") != "raw_file_bytes":
            raise ValueError("artifact hash contract mismatch")
        artifacts = manifest.get("artifacts")
        if type(artifacts) is not list or len(artifacts) != 10:
            raise ValueError("artifact manifest must contain exactly 10 entries")
        seen: set[str] = set()
        for row in artifacts:
            if type(row) is not dict or type(row.get("path")) is not str:
                raise ValueError("invalid artifact row")
            relative = row["path"]
            if relative in seen or Path(relative).is_absolute() or ".." in Path(relative).parts:
                raise ValueError(f"unsafe or duplicate artifact path: {relative}")
            seen.add(relative)
            path = root / relative
            if not path.is_file() or path.is_symlink():
                raise ValueError(f"missing artifact: {relative}")
            if path.stat().st_size != row.get("bytes"):
                raise ValueError(f"artifact size mismatch: {relative}")
            if _sha256(path) != row.get("sha256"):
                raise ValueError(f"artifact sha256 mismatch: {relative}")

        commitments = manifest.get("withheld_commitments")
        if type(commitments) is not list or len(commitments) != 2:
            raise ValueError("withheld manifest commitments mismatch")

        controller = _load(bundle / "controller_config.json")
        if controller.get("protocol_id") != "semantic-rq2-confirmation-controller-v1":
            raise ValueError("controller protocol mismatch")
        bindings = {
            "main_protocol_sha256": root / "experiments/semantic_receptor_rq2/FULL_200_CONFIRMATORY_PROTOCOL.md",
            "focused_protocol_sha256": root / "experiments/semantic_receptor_rq2/FOCUSED_INTERACTION_CONFIRMATION_PROTOCOL.md",
            "profile_sha256": root / "experiments/semantic_receptor_rq2/profiles/engineering_confirmation_200_v3.json",
        }
        for key, path in bindings.items():
            if controller.get(key) != _sha256(path):
                raise ValueError(f"controller binding mismatch: {key}")
        commitment_hashes = {row.get("sha256") for row in commitments if type(row) is dict}
        expected_commitments = {
            controller.get("full_manifest_sha256"),
            controller.get("checkpoint_manifest_sha256"),
        }
        if commitment_hashes != expected_commitments:
            raise ValueError("withheld commitments do not match controller bindings")

        preflights = [
            _load(root / "experiments/semantic_receptor_rq2/preflight_confirmation200_v3.json"),
            _load(root / "experiments/semantic_receptor_rq2/preflight_confirmation50_checkpoint_v3.json"),
        ]
        expected_cases = [200, 50]
        expected_clusters = [100, 25]
        expected_manifest_hashes = [
            controller.get("full_manifest_sha256"),
            controller.get("checkpoint_manifest_sha256"),
        ]
        for preflight, case_n, cluster_n, manifest_hash in zip(
            preflights, expected_cases, expected_clusters, expected_manifest_hashes, strict=True
        ):
            checks = preflight.get("checks", {})
            shape = checks.get("manifest", {})
            if preflight.get("status") != "PASS" or preflight.get("problems") != []:
                raise ValueError(f"preflight did not pass for {case_n} cases")
            if shape.get("case_n") != case_n or shape.get("cluster_n") != cluster_n:
                raise ValueError(f"preflight shape mismatch for {case_n} cases")
            if checks.get("manifest_sha256") != manifest_hash:
                raise ValueError(f"preflight manifest hash mismatch for {case_n} cases")
            if checks.get("profile_sha256") != controller.get("profile_sha256"):
                raise ValueError(f"preflight profile hash mismatch for {case_n} cases")
            if checks.get("implementation_sha256") != controller.get("implementation_sha256"):
                raise ValueError(f"preflight implementation hash mismatch for {case_n} cases")
            if checks.get("zero_paid_calls") is not True:
                raise ValueError(f"preflight paid-call invariant failed for {case_n} cases")

        analysis = _load(bundle / "confirmation_analysis.json")
        if analysis.get("analysis_id") != "semantic-rq2-full-confirmation-analysis-v1":
            raise ValueError("analysis id mismatch")
        seed = analysis["per_downstream"]["openai-terra-neutral-p0"]["seed_results"]["20260901"]
        primary = seed["primary_gamma_r2"]["source_fidelity_valid"]
        robust = seed["primary_gamma_r2"]["all_attempt_robustness"]
        headline = manifest.get("headline_source", {})
        if headline.get("path") != "results/semantic_rq2_confirmation_20260901/confirmation_analysis.json":
            raise ValueError("headline source path mismatch")
        if headline.get("json_pointer") != "/per_downstream/openai-terra-neutral-p0/seed_results/20260901/primary_gamma_r2/source_fidelity_valid":
            raise ValueError("headline JSON pointer mismatch")
        if headline.get("scale") != 100 or headline.get("round_decimals") != 1:
            raise ValueError("headline display transform mismatch")
        if primary.get("completed_case_n") != 191 or primary.get("completed_document_cluster_n") != 99:
            raise ValueError("primary analysis denominator mismatch")
        _close(primary.get("case_weighted_point"), 0.14659685863874344, label="primary point")
        if primary.get("document_cluster_bootstrap_95ci") != [0.0855614973262032, 0.20833333333333334]:
            raise ValueError("primary confidence interval mismatch")
        _close(primary.get("exact_two_sided_document_cluster_sign_p"), 2.2361520677804947e-05, label="primary p")
        _close(headline.get("expected_raw_point"), primary["case_weighted_point"], label="manifest headline point")
        if headline.get("expected_raw_ci") != primary["document_cluster_bootstrap_95ci"]:
            raise ValueError("manifest headline confidence interval mismatch")
        _close(
            headline.get("expected_p"),
            primary["exact_two_sided_document_cluster_sign_p"],
            label="manifest headline p",
        )
        if headline.get("expected_case_n") != primary["completed_case_n"]:
            raise ValueError("manifest headline case count mismatch")
        if headline.get("expected_cluster_n") != primary["completed_document_cluster_n"]:
            raise ValueError("manifest headline cluster count mismatch")
        _close(robust.get("case_weighted_point"), 0.135, label="all-attempt point")

        focused = _load(bundle / "focused_interaction_results.json")
        if focused.get("claim_bearing") is not False or focused.get("integrity", {}).get("status") != "PASS":
            raise ValueError("focused result evidence label or integrity mismatch")
        focused_analysis = focused.get("analysis", {})
        if focused_analysis.get("result_label") != "focused_interaction_not_confirmed":
            raise ValueError("focused result label mismatch")
        _close(focused_analysis["primary_interaction"]["all_attempt_completed"].get("point"), -0.005, label="focused all-attempt point")
        _close(focused_analysis["primary_interaction"]["construct_valid"].get("point"), 0.0, label="focused valid point")

        ceiling = _load(bundle / "semantic_ceiling_results.json")
        if ceiling.get("diagnostic_only") is not True or ceiling.get("claim_bearing") is not False:
            raise ValueError("semantic ceiling evidence label mismatch")
        if ceiling.get("integrity", {}).get("status") != "PASS":
            raise ValueError("semantic ceiling integrity mismatch")
        ceiling_analysis = ceiling.get("analysis", {})
        if ceiling_analysis.get("responsiveness_gate_pass") is not True:
            raise ValueError("semantic ceiling responsiveness mismatch")
        _close(ceiling_analysis["C_max_semantic_minus_E"].get("point"), 0.12, label="semantic ceiling point")
    except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        errors.append(str(exc))

    return {
        "schema_version": "agentmembrane-rq2-public-bundle-audit/1",
        "bundle_id": "semantic-rq2-confirmation200-train-v3-20260901",
        "artifact_count": 10,
        "headline_primary_gamma_r2_pp": 14.7,
        "claim_bearing": False,
        "passed": not errors,
        "errors": errors,
    }


def main() -> int:
    result = audit()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
