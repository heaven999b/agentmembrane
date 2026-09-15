"""The supported JSON command-line interface for Host-Boundary V2.

Every completed invocation writes exactly one JSON object to stdout.  Human
diagnostics and argument errors go to stderr.  Provider-consuming execution is
reachable only through an exact resolved profile and the recomputed frozen-gate
checks in :mod:`agentmembrane.host_v2.campaign`.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, is_dataclass
from enum import Enum
import json
import os
from pathlib import Path
import sys
from typing import Any, Callable, Iterable, Mapping, Sequence

from .analysis import analyze_records, load_estimands, render_report
from .cache import RunLock, RunStateStore
from .campaign import (
    aggregate_campaign,
    build_g1_gate_result_from_g0,
    build_g2_gate_result_from_g0_g1,
    preflight_campaign,
    resume_campaign,
    run_campaign,
    validate_frozen_gates,
    validate_gate_result_for_profile,
)
from .integrity import audit_run
from .profiles import (
    CampaignSpec,
    ResolvedProfile,
    freeze_profile,
    load_campaign,
    load_profile,
    load_resolved_profile,
    resolve_profile,
    resolve_g0_bootstrap_profile,
    validate_estimand_cell_coverage,
    validate_g0_bootstrap_authorization,
    validate_provider_launch_authorization,
)
from .runner import execute_run, preflight, prepare_run, resume_run, suspend_run
from .schema import (
    IntegrityError,
    RunKind,
    RunState,
    SchemaError,
    atomic_write_json,
    canonical_json_bytes,
    load_json,
    sha256_bytes,
    sha256_json,
    validate_json,
)
from .taskpacks import load_taskpack, verify_taskpack


Handler = Callable[[argparse.Namespace], tuple[dict[str, Any], int]]
_SCALE_AUTHORIZATION = "scale-authorization.json"


class _UsageError(ValueError):
    pass


class _JsonArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _UsageError(message)


def _jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return _jsonable(asdict(value))
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item) for item in value]
    return value


def _emit(value: Mapping[str, Any]) -> None:
    print(
        json.dumps(
            _jsonable(dict(value)),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ),
        file=sys.stdout,
    )


def _immutable_bytes(path: Path, payload: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if path.read_bytes() != payload:
            raise IntegrityError(f"refusing to overwrite unequal artifact {path}")
        return
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _immutable_json(path: Path, value: Any) -> None:
    _immutable_bytes(path, canonical_json_bytes(value))


def _load_profile_any(path: Path) -> ResolvedProfile | Any:
    value = load_json(Path(path).resolve())
    return (
        load_resolved_profile(path)
        if "resolution" in value
        else load_profile(path)
    )


def _load_run_profile(run_dir: Path) -> tuple[dict[str, Any], ResolvedProfile]:
    root = Path(run_dir).resolve()
    manifest = load_json(root / "run-manifest.json")
    local_path = root / str(manifest.get("resolved_profile_path", ""))
    raw = load_json(local_path)
    validate_json(raw, schema_name="resolved_profile")
    if sha256_bytes(local_path.read_bytes()) != manifest.get("resolved_profile_sha256"):
        raise IntegrityError("run-local resolved profile fingerprint changed")
    source_path = Path(str(manifest.get("profile_source_path", local_path))).resolve()
    return manifest, ResolvedProfile(
        raw=raw,
        source_path=source_path,
        resolved_path=local_path,
    )


def _provider_launch_authorization_for_profile(
    profile: ResolvedProfile,
) -> dict[str, Any]:
    """Use raw predecessor gates for G1/G2 and global launch locks elsewhere."""

    resolution = profile.raw.get("resolution", {})
    uses_raw_predecessor_gate = bool(
        resolution.get("resolution_mode") == "gate_result"
        and profile.raw.get("run_kind") == RunKind.GATE.value
        and profile.raw.get("claim_bearing") is False
        and profile.raw.get("gates", {}).get("gate_stage") in {"G1", "G2"}
    )
    return (
        validate_frozen_gates(profile)
        if uses_raw_predecessor_gate
        else validate_provider_launch_authorization(profile)
    )


def _strict_run_preflight(
    profile: ResolvedProfile,
    *,
    campaign: CampaignSpec | None = None,
    verifier_approval_path: Path | None = None,
) -> dict[str, Any]:
    static = preflight(profile=profile, campaign=campaign)
    resolution = profile.raw.get("resolution", {})
    model_stratum = {
        "passed": bool(
            profile.raw.get("model", {}).get("requested_id")
            == resolution.get("resolved_model_id")
            and profile.raw.get("model", {}).get("provider_route_id")
            == resolution.get("provider_route_id")
        ),
        "checks": {
            "requested_equals_resolved_model": (
                profile.raw.get("model", {}).get("requested_id")
                == resolution.get("resolved_model_id")
            ),
            "provider_route_exact": (
                profile.raw.get("model", {}).get("provider_route_id")
                == resolution.get("provider_route_id")
            ),
        },
    }
    model_stratum["errors"] = [
        f"{name} failed"
        for name, passed in model_stratum["checks"].items()
        if not passed
    ]
    uses_raw_predecessor_gate = bool(
        resolution.get("resolution_mode") == "gate_result"
        and profile.raw.get("run_kind") == RunKind.GATE.value
        and profile.raw.get("gates", {}).get("gate_stage") in {"G1", "G2"}
    )
    gates = (
        validate_frozen_gates(profile)
        if profile.raw["run_kind"] == RunKind.FORMAL.value
        or profile.raw["claim_bearing"] is True
        or uses_raw_predecessor_gate
        else {"passed": True, "checks": {}, "errors": []}
    )
    cells = validate_estimand_cell_coverage(profile)
    launch_authorization = _provider_launch_authorization_for_profile(profile)
    scaled_formal = bool(
        profile.raw["run_kind"] == RunKind.FORMAL.value
        or profile.raw["claim_bearing"] is True
    )
    if scaled_formal and campaign is not None:
        campaign_report = preflight_campaign(
            campaign.path,
            verifier_approval_path=verifier_approval_path,
        )
        scale_authorization = {
            "passed": campaign_report["formal_run_permitted"],
            "checks": {
                "campaign_preflight": campaign_report["passed"],
                "blinded_verifier_approval": campaign_report["checks"].get(
                    "blinded_verifier_approval", False
                ),
            },
            "errors": list(campaign_report["errors"]),
            "campaign": campaign_report,
        }
    elif scaled_formal:
        scale_authorization = {
            "passed": False,
            "checks": {
                "campaign_preflight": False,
                "blinded_verifier_approval": False,
            },
            "errors": [
                "scaled formal execution requires --campaign and a blinded verifier approval"
            ],
        }
    else:
        scale_authorization = {
            "passed": True,
            "checks": {},
            "errors": [],
            "not_applicable": True,
        }
    passed = (
        static.passed
        and model_stratum["passed"]
        and gates["passed"]
        and cells["passed"]
        and launch_authorization["passed"]
        and scale_authorization["passed"]
    )
    return {
        "passed": passed,
        "static": {
            "passed": static.passed,
            "checks": static.checks,
            "details": static.details,
        },
        "frozen_gates": gates,
        "estimand_cell_coverage": cells,
        "provider_launch_authorization": launch_authorization,
        "model_stratum": model_stratum,
        "scale_authorization": scale_authorization,
        "errors": list(static.details.get("errors", []))
        + list(gates.get("errors", []))
        + list(model_stratum.get("errors", []))
        + list(cells.get("errors", []))
        + list(launch_authorization.get("errors", []))
        + list(scale_authorization.get("errors", [])),
    }


def _preflight_artifact(profile: Any, report: Mapping[str, Any]) -> dict[str, Any]:
    raw = profile.raw
    resolution = raw.get("resolution", {})
    details = report["static"]["details"]
    taskpack_hashes = details.get("taskpack_hashes", {})
    formal = bool(
        report["passed"]
        and raw.get("run_kind") == RunKind.FORMAL.value
        and raw.get("claim_bearing") is True
        and report["frozen_gates"].get("passed") is True
        and report["model_stratum"].get("passed") is True
        and report["scale_authorization"].get("passed") is True
    )
    failed = [
        name
        for name, passed in {
            **report["static"]["checks"],
            **report["frozen_gates"].get("checks", {}),
            **report["provider_launch_authorization"].get("checks", {}),
            **report["model_stratum"].get("checks", {}),
            **report["scale_authorization"].get("checks", {}),
        }.items()
        if not passed
    ]
    return {
        "schema_version": 1,
        "protocol_id": raw.get("protocol_id"),
        "profile_id": raw.get("profile_id"),
        "source_sha256": resolution.get("implementation_sha256"),
        "dataset_lock_sha256": sha256_json(taskpack_hashes),
        "schedule_sha256": details.get("schedule_sha256"),
        "provider": resolution.get(
            "provider_route_id", raw.get("model", {}).get("provider_route_id")
        ),
        "model": resolution.get(
            "resolved_model_id", raw.get("model", {}).get("requested_id")
        ),
        "decision": "PASS" if report["passed"] else "STOP",
        "formal_run_permitted": formal,
        "failed_gate_ids": sorted(set(failed)),
        "gates": {
            "static": _jsonable(report["static"]),
            "frozen": _jsonable(report["frozen_gates"]),
            "model_stratum": _jsonable(report["model_stratum"]),
            "scale_authorization": _jsonable(report["scale_authorization"]),
            "provider_launch_authorization": _jsonable(
                report["provider_launch_authorization"]
            ),
        },
    }


def _cmd_taskpack_verify(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    root = Path(args.root).resolve()
    report = verify_taskpack(load_taskpack(root))
    return {"ok": True, "command": "taskpack.verify", "root": str(root), "report": report}, 0


def _cmd_profile_resolve(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    profile = load_profile(Path(args.profile))
    if args.g0_bootstrap_authorization:
        authorization_path = Path(args.g0_bootstrap_authorization).resolve()
        authorization = load_json(authorization_path)
        workers = (
            authorization.get("selected_workers")
            if args.selected_workers is None else args.selected_workers
        )
        blocks = (
            authorization.get("selected_max_inflight_blocks")
            if args.selected_max_inflight_blocks is None
            else args.selected_max_inflight_blocks
        )
        bootstrap_report = validate_g0_bootstrap_authorization(
            profile,
            selected_workers=workers,
            selected_max_inflight_blocks=blocks,
            authorization_path=authorization_path,
        )
        if not bootstrap_report["passed"]:
            raise IntegrityError(
                "G0 bootstrap authorization STOP: "
                + "; ".join(bootstrap_report["errors"])
            )
        resolved = resolve_g0_bootstrap_profile(
            profile,
            selected_workers=workers,
            selected_max_inflight_blocks=blocks,
            authorization_path=authorization_path,
        )
        output = Path(args.out).resolve()
        digest = freeze_profile(resolved, output)
        return {
            "ok": True,
            "command": "profile.resolve",
            "profile_id": resolved.raw["profile_id"],
            "output_path": str(output),
            "resolved_profile_sha256": digest,
            "requested_model_id": resolved.raw["model"]["requested_id"],
            "resolved_model_id": resolved.raw["resolution"]["resolved_model_id"],
            "bootstrap_validation": bootstrap_report,
        }, 0
    gate_path = Path(args.gate_result).resolve()
    gate = load_json(gate_path)
    validate_json(gate, schema_name="gate_result")
    workers = gate["selected_workers"] if args.selected_workers is None else args.selected_workers
    blocks = (
        gate["selected_max_inflight_blocks"]
        if args.selected_max_inflight_blocks is None
        else args.selected_max_inflight_blocks
    )
    if (workers, blocks) != (
        gate["selected_workers"], gate["selected_max_inflight_blocks"]
    ):
        raise IntegrityError("CLI concurrency overrides must equal the frozen gate selection")
    gate_report = validate_gate_result_for_profile(profile, gate_path)
    if not gate_report["passed"]:
        raise IntegrityError("gate result STOP: " + "; ".join(gate_report["errors"]))
    resolved = resolve_profile(
        profile,
        selected_workers=workers,
        selected_max_inflight_blocks=blocks,
        gate_result_path=gate_path,
    )
    output = Path(args.out).resolve()
    digest = freeze_profile(resolved, output)
    return {
        "ok": True,
        "command": "profile.resolve",
        "profile_id": resolved.raw["profile_id"],
        "output_path": str(output),
        "resolved_profile_sha256": digest,
        "requested_model_id": resolved.raw["model"]["requested_id"],
        "resolved_model_id": resolved.raw["resolution"]["resolved_model_id"],
        "gate_validation": gate_report,
    }, 0


def _cmd_preflight(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    profile = _load_profile_any(Path(args.profile))
    campaign = load_campaign(Path(args.campaign)) if args.campaign else None
    if isinstance(profile, ResolvedProfile):
        report = _strict_run_preflight(
            profile,
            campaign=campaign,
            verifier_approval_path=(
                Path(args.verifier_approval) if args.verifier_approval else None
            ),
        )
    else:
        static = preflight(profile=profile, campaign=campaign)
        report = {
            "passed": static.passed,
            "static": {
                "passed": static.passed,
                "checks": static.checks,
                "details": static.details,
            },
            "frozen_gates": {
                "passed": False,
                "checks": {"resolved_profile": False},
                "errors": ["a frozen resolved profile is required before execution"],
            },
            "model_stratum": {
                "passed": False,
                "checks": {"resolved_model_identity": False},
                "errors": ["exact model identity requires a frozen resolved profile"],
            },
            "scale_authorization": {
                "passed": False,
                "checks": {"resolved_profile": False},
                "errors": ["scale authorization requires a frozen resolved profile"],
            },
            "errors": list(static.details.get("errors", [])),
        }
    artifact = _preflight_artifact(profile, report)
    if args.out:
        _immutable_json(Path(args.out).resolve(), artifact)
    return {
        "ok": report["passed"],
        "command": "preflight",
        "report": artifact,
        "output_path": str(Path(args.out).resolve()) if args.out else None,
    }, 0 if report["passed"] else 2


def _cmd_prepare(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    profile = load_resolved_profile(Path(args.resolved_profile))
    kind = RunKind(profile.raw["run_kind"])
    if args.run_kind is not None and RunKind(args.run_kind) is not kind:
        raise IntegrityError("--run-kind may not override the frozen profile")
    campaign = load_campaign(Path(args.campaign)) if args.campaign else None
    report = _strict_run_preflight(
        profile,
        campaign=campaign,
        verifier_approval_path=(
            Path(args.verifier_approval) if args.verifier_approval else None
        ),
    )
    if not report["passed"]:
        raise IntegrityError("preflight STOP: " + "; ".join(report["errors"]))
    manifest = prepare_run(
        profile=profile,
        run_dir=Path(args.run_dir),
        run_kind=kind,
    )
    if kind is RunKind.FORMAL:
        assert campaign is not None and args.verifier_approval
        approval_path = Path(args.verifier_approval).resolve()
        _immutable_json(
            Path(args.run_dir).resolve() / _SCALE_AUTHORIZATION,
            {
                "schema_version": 1,
                "campaign_id": campaign.raw["campaign_id"],
                "campaign_path": str(campaign.path.resolve()),
                "campaign_sha256": sha256_bytes(campaign.path.read_bytes()),
                "verifier_approval_path": str(approval_path),
                "verifier_approval_sha256": sha256_bytes(approval_path.read_bytes()),
                "profile_id": profile.raw["profile_id"],
                "resolved_profile_sha256": manifest["resolved_profile_sha256"],
                "run_identity_sha256": manifest["run_identity_sha256"],
                "stage_sequence": [
                    "code_closure",
                    "freeze_prepaid_estimands_denominator_prompts_oracles_and_splits",
                    "zero_token_preflight_and_scripted_assay",
                    "small_real_api_g0_g1_smoke",
                    "nonclaim_20_cluster_variance_pilot",
                    "treatment_blinded_verifier_audit",
                    "freeze_formal_n_and_complete_schedule_once",
                    "large_scale_execution",
                ],
            },
        )
    return {
        "ok": True,
        "command": "prepare",
        "run_dir": str(Path(args.run_dir).resolve()),
        "manifest": manifest,
        "preflight": report,
    }, 0


def _ensure_scripted_prepared(args: argparse.Namespace) -> Path:
    run_dir = Path(args.run_dir).resolve()
    state_path = run_dir / "run-state.json"
    if state_path.exists():
        manifest, profile = _load_run_profile(run_dir)
        if manifest.get("run_kind") != RunKind.SCRIPTED.value:
            raise IntegrityError("scripted execute refuses a non-scripted run")
        if profile.raw["run_kind"] != RunKind.SCRIPTED.value:
            raise IntegrityError("run-local profile is not scripted")
        return run_dir
    if not args.resolved_profile:
        raise IntegrityError("an unprepared scripted run requires --resolved-profile")
    profile = load_resolved_profile(Path(args.resolved_profile))
    if profile.raw["run_kind"] != RunKind.SCRIPTED.value:
        raise IntegrityError("scripted execute accepts only run_kind=scripted")
    report = _strict_run_preflight(profile)
    if not report["passed"]:
        raise IntegrityError("scripted preflight STOP: " + "; ".join(report["errors"]))
    prepare_run(profile=profile, run_dir=run_dir, run_kind=RunKind.SCRIPTED)
    return run_dir


def _cmd_scripted_execute(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    run_dir = _ensure_scripted_prepared(args)
    result = execute_run(run_dir)
    return {
        "ok": True,
        "command": "scripted.execute",
        "result": result,
    }, 0


def _validate_scale_authorization(
    run_dir: Path, manifest: Mapping[str, Any], profile: ResolvedProfile
) -> dict[str, Any]:
    path = Path(run_dir).resolve() / _SCALE_AUTHORIZATION
    authorization = load_json(path)
    required = {
        "schema_version",
        "campaign_id",
        "campaign_path",
        "campaign_sha256",
        "verifier_approval_path",
        "verifier_approval_sha256",
        "profile_id",
        "resolved_profile_sha256",
        "run_identity_sha256",
        "stage_sequence",
    }
    if set(authorization) != required:
        raise IntegrityError("scale authorization schema is not exact")
    campaign_path = Path(str(authorization["campaign_path"])).resolve()
    approval_path = Path(str(authorization["verifier_approval_path"])).resolve()
    if (
        authorization["schema_version"] != 1
        or authorization["profile_id"] != profile.raw["profile_id"]
        or authorization["resolved_profile_sha256"]
        != manifest.get("resolved_profile_sha256")
        or authorization["run_identity_sha256"] != manifest.get("run_identity_sha256")
        or authorization["campaign_sha256"] != sha256_bytes(campaign_path.read_bytes())
        or authorization["verifier_approval_sha256"]
        != sha256_bytes(approval_path.read_bytes())
        or authorization["stage_sequence"]
        != [
            "code_closure",
            "freeze_prepaid_estimands_denominator_prompts_oracles_and_splits",
            "zero_token_preflight_and_scripted_assay",
            "small_real_api_g0_g1_smoke",
            "nonclaim_20_cluster_variance_pilot",
            "treatment_blinded_verifier_audit",
            "freeze_formal_n_and_complete_schedule_once",
            "large_scale_execution",
        ]
    ):
        raise IntegrityError("scale authorization no longer binds the exact run inputs")
    campaign = load_campaign(campaign_path)
    if authorization["campaign_id"] != campaign.raw["campaign_id"]:
        raise IntegrityError("scale authorization belongs to another campaign")
    report = _strict_run_preflight(
        profile,
        campaign=campaign,
        verifier_approval_path=approval_path,
    )
    if not report["passed"] or not report["scale_authorization"]["passed"]:
        raise IntegrityError("blinded verifier approval no longer permits scaled execution")
    return report


def _cmd_execute(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    run_dir = Path(args.run_dir).resolve()
    manifest, profile = _load_run_profile(run_dir)
    if manifest.get("run_kind") != RunKind.SCRIPTED.value:
        launch = _provider_launch_authorization_for_profile(profile)
        if not launch["passed"]:
            raise IntegrityError(
                "provider launch authorization STOP: " + "; ".join(launch["errors"])
            )
    if manifest.get("run_kind") == RunKind.FORMAL.value:
        _validate_scale_authorization(run_dir, manifest, profile)
    result = execute_run(run_dir)
    return {"ok": True, "command": "execute", "result": result}, 0


def _cmd_resume(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    run_dir = Path(args.run_dir).resolve()
    manifest, profile = _load_run_profile(run_dir)
    if manifest.get("run_kind") != RunKind.SCRIPTED.value:
        launch = _provider_launch_authorization_for_profile(profile)
        if not launch["passed"]:
            raise IntegrityError(
                "provider launch authorization STOP: " + "; ".join(launch["errors"])
            )
    if manifest.get("run_kind") == RunKind.FORMAL.value:
        _validate_scale_authorization(run_dir, manifest, profile)
    result = resume_run(run_dir)
    return {"ok": True, "command": "resume", "result": result}, 0


def _cmd_suspend(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    suspend_run(Path(args.run_dir), reason=args.reason)
    return {
        "ok": True,
        "command": "suspend",
        "run_dir": str(Path(args.run_dir).resolve()),
    }, 0


def _audit_and_transition(run_dir: Path) -> tuple[Any, RunState]:
    root = Path(run_dir).resolve()
    report = audit_run(root)
    _immutable_json(root / "integrity.json", report.to_dict())
    manifest, profile = _load_run_profile(root)
    valid = (
        report.valid_for_claim_endpoints
        if manifest.get("run_kind") == RunKind.FORMAL.value
        and profile.raw.get("claim_bearing") is True
        else report.valid_for_descriptive_analysis
    )
    target = RunState.AUDITED_VALID if valid else RunState.AUDITED_INVALID
    store = RunStateStore(root)
    state = RunState(store.load()["state"])
    if state is RunState.COMPLETE:
        with RunLock(root) as lock:
            store.transition(target, lock=lock)
        state = target
    elif state is not target:
        raise IntegrityError(
            f"run state {state.value} disagrees with recomputed audit {target.value}"
        )
    return report, state


def _cmd_audit(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    root = Path(args.run_dir).resolve()
    report, state = _audit_and_transition(root)
    return {
        "ok": True,
        "command": "audit",
        "run_dir": str(root),
        "state": state.value,
        "integrity": report.to_dict(),
    }, 0


def _cmd_analyze(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    root = Path(args.run_dir).resolve()
    state = RunState(load_json(root / "run-state.json")["state"])
    if state not in {RunState.AUDITED_VALID, RunState.AUDITED_INVALID}:
        raise IntegrityError("analysis requires a completed integrity audit")
    current_audit = audit_run(root)
    if not current_audit.valid_for_descriptive_analysis:
        raise IntegrityError("run is not valid for descriptive analysis")
    _, profile = _load_run_profile(root)
    estimands_path = (profile.source_path.parent / profile.raw["estimands_path"]).resolve()
    registry = load_estimands(estimands_path)
    try:
        estimands = {name: registry[name] for name in profile.raw["estimand_ids"]}
    except KeyError as exc:
        raise IntegrityError(f"frozen estimand is missing: {exc}") from exc
    if set(estimands) != set(profile.raw["estimand_ids"]):
        raise IntegrityError("analysis estimands do not exactly match the frozen profile")
    result = analyze_records(
        records_path=root / "records.jsonl",
        profile=profile,
        estimands=estimands,
        integrity_report=current_audit,
    )
    report = render_report(result)
    _immutable_json(root / "results.json", result)
    _immutable_bytes(root / "report.md", report.encode("utf-8"))
    return {
        "ok": True,
        "command": "analyze",
        "run_dir": str(root),
        "results": result,
        "results_sha256": sha256_bytes(canonical_json_bytes(result)),
    }, 0


def _cmd_campaign_preflight(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    report = preflight_campaign(
        Path(args.campaign),
        verifier_approval_path=(
            Path(args.verifier_approval) if args.verifier_approval else None
        ),
    )
    if args.out:
        _immutable_json(Path(args.out).resolve(), report)
    return {
        "ok": report["passed"],
        "command": "campaign.preflight",
        "report": report,
        "output_path": str(Path(args.out).resolve()) if args.out else None,
    }, 0 if report["passed"] else 2


def _cmd_campaign_run(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    result = run_campaign(
        campaign_path=Path(args.campaign),
        runs_root=Path(args.runs_root),
        verifier_approval_path=(
            Path(args.verifier_approval) if args.verifier_approval else None
        ),
    )
    return {"ok": True, "command": "campaign.run", "result": result}, 0


def _cmd_campaign_resume(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    result = resume_campaign(Path(args.runs_root))
    return {"ok": True, "command": "campaign.resume", "result": result}, 0


def _cmd_campaign_aggregate(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    if getattr(args, "campaign", None):
        expected = load_campaign(Path(args.campaign)).raw["campaign_id"]
        manifest = load_json(Path(args.runs_root).resolve() / "campaign-manifest.json")
        if manifest.get("campaign_id") != expected:
            raise IntegrityError("aggregate campaign argument differs from the runs root")
    result = aggregate_campaign(Path(args.runs_root))
    return {"ok": True, "command": "campaign.aggregate", "result": result}, 0


def _cmd_gate_build_result(args: argparse.Namespace) -> tuple[dict[str, Any], int]:
    profile = load_profile(Path(args.target_profile).resolve())
    stage = profile.raw.get("gates", {}).get("gate_stage")
    if stage == "G1":
        if args.g1_run_dir:
            raise IntegrityError("G1 gate construction accepts only --g0-run-dir")
        artifact = build_g1_gate_result_from_g0(
            target_profile=profile,
            run_dir=Path(args.g0_run_dir).resolve(),
        )
    elif stage == "G2":
        if not args.g1_run_dir:
            raise IntegrityError("G2 gate construction requires --g1-run-dir")
        artifact = build_g2_gate_result_from_g0_g1(
            target_profile=profile,
            g0_run_dir=Path(args.g0_run_dir).resolve(),
            g1_run_dir=Path(args.g1_run_dir).resolve(),
        )
    else:
        raise IntegrityError("gate result construction supports only G1 or G2 targets")
    output = Path(args.out).resolve()
    _immutable_json(output, artifact)
    report = validate_gate_result_for_profile(profile, output)
    return {
        "ok": report["passed"],
        "command": "gate.build-result",
        "output_path": str(output),
        "gate_result_sha256": sha256_bytes(output.read_bytes()),
        "validation": report,
    }, 0 if report["passed"] else 2


def _set_handler(parser: argparse.ArgumentParser, handler: Handler) -> None:
    parser.set_defaults(_handler=handler)


def _add_taskpack_verify(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--root", "--taskpack", dest="root", required=True)
    _set_handler(parser, _cmd_taskpack_verify)


def _add_gate_build_result(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--target-profile", required=True)
    parser.add_argument("--g0-run-dir", required=True)
    parser.add_argument("--g1-run-dir")
    parser.add_argument("--out", required=True)
    _set_handler(parser, _cmd_gate_build_result)


def _add_profile_resolve(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", required=True)
    authorization = parser.add_mutually_exclusive_group(required=True)
    authorization.add_argument("--gate-result")
    authorization.add_argument("--g0-bootstrap-authorization")
    parser.add_argument("--out", required=True)
    parser.add_argument("--selected-workers", type=int)
    parser.add_argument("--selected-max-inflight-blocks", type=int)
    _set_handler(parser, _cmd_profile_resolve)


def _add_preflight(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", required=True)
    parser.add_argument("--campaign")
    parser.add_argument("--verifier-approval")
    parser.add_argument("--out")
    _set_handler(parser, _cmd_preflight)


def _add_prepare(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--resolved-profile", required=True)
    parser.add_argument("--run-dir", required=True)
    parser.add_argument("--run-kind", choices=[item.value for item in RunKind])
    parser.add_argument("--campaign")
    parser.add_argument("--verifier-approval")
    _set_handler(parser, _cmd_prepare)


def _add_scripted_execute(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--resolved-profile")
    parser.add_argument("--run-dir", required=True)
    _set_handler(parser, _cmd_scripted_execute)


def _add_run_dir(parser: argparse.ArgumentParser, handler: Handler) -> None:
    parser.add_argument("--run-dir", required=True)
    _set_handler(parser, handler)


def _add_campaign_preflight(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--campaign", required=True)
    parser.add_argument("--verifier-approval")
    parser.add_argument("--out")
    _set_handler(parser, _cmd_campaign_preflight)


def _add_campaign_run(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--campaign", required=True)
    parser.add_argument("--runs-root", required=True)
    parser.add_argument("--verifier-approval")
    _set_handler(parser, _cmd_campaign_run)


def _add_campaign_resume(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--runs-root", required=True)
    _set_handler(parser, _cmd_campaign_resume)


def _add_campaign_aggregate(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--runs-root", required=True)
    parser.add_argument("--campaign")
    _set_handler(parser, _cmd_campaign_aggregate)


def build_parser() -> argparse.ArgumentParser:
    parser = _JsonArgumentParser(prog="python3 -m agentmembrane.host_v2.cli")
    commands = parser.add_subparsers(dest="command", required=True)

    # Structured command groups requested by the V2 interface.
    taskpack = commands.add_parser("taskpack")
    taskpack_actions = taskpack.add_subparsers(dest="taskpack_action", required=True)
    _add_taskpack_verify(taskpack_actions.add_parser("verify"))

    profile = commands.add_parser("profile")
    profile_actions = profile.add_subparsers(dest="profile_action", required=True)
    _add_profile_resolve(profile_actions.add_parser("resolve"))

    scripted = commands.add_parser("scripted")
    scripted_actions = scripted.add_subparsers(dest="scripted_action", required=True)
    _add_scripted_execute(scripted_actions.add_parser("execute"))

    gate = commands.add_parser("gate")
    gate_actions = gate.add_subparsers(dest="gate_action", required=True)
    _add_gate_build_result(gate_actions.add_parser("build-result"))

    campaign = commands.add_parser("campaign")
    campaign_actions = campaign.add_subparsers(dest="campaign_action", required=True)
    _add_campaign_preflight(campaign_actions.add_parser("preflight"))
    _add_campaign_run(campaign_actions.add_parser("run"))
    _add_campaign_resume(campaign_actions.add_parser("resume"))
    _add_campaign_aggregate(campaign_actions.add_parser("aggregate"))

    # Flat aliases preserve the architecture examples and are intentionally
    # equivalent to the structured commands above.
    _add_taskpack_verify(commands.add_parser("taskpack-verify"))
    _add_gate_build_result(commands.add_parser("gate-build-result"))
    _add_profile_resolve(commands.add_parser("profile-resolve", aliases=["freeze"]))
    _add_preflight(commands.add_parser("preflight"))
    _add_prepare(commands.add_parser("prepare"))
    _add_scripted_execute(commands.add_parser("scripted-execute"))
    _add_run_dir(commands.add_parser("execute", aliases=["run"]), _cmd_execute)
    _add_run_dir(commands.add_parser("resume"), _cmd_resume)
    suspend = commands.add_parser("suspend")
    suspend.add_argument("--run-dir", required=True)
    suspend.add_argument("--reason", required=True)
    _set_handler(suspend, _cmd_suspend)
    _add_run_dir(commands.add_parser("audit"), _cmd_audit)
    _add_run_dir(commands.add_parser("analyze"), _cmd_analyze)
    _add_campaign_preflight(commands.add_parser("campaign-preflight"))
    _add_campaign_run(commands.add_parser("campaign-run"))
    _add_campaign_resume(commands.add_parser("campaign-resume"))
    _add_campaign_aggregate(commands.add_parser("campaign-aggregate", aliases=["aggregate"]))
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
        handler: Handler = args._handler
        payload, exit_code = handler(args)
    except (_UsageError, SchemaError, IntegrityError, OSError, ValueError, KeyError) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        _emit(
            {
                "ok": False,
                "error": {"type": type(exc).__name__, "message": str(exc)},
            }
        )
        return 2
    except Exception as exc:  # normalize unexpected command boundaries, no traceback on stdout
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        _emit(
            {
                "ok": False,
                "error": {"type": type(exc).__name__, "message": str(exc)},
            }
        )
        return 1
    _emit(payload)
    return exit_code


if __name__ == "__main__":  # pragma: no cover - exercised through ``main`` in tests
    raise SystemExit(main())


__all__ = ["build_parser", "main"]
