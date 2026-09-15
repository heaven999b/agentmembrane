"""Read-only scoring and optional bounded semantic audit of sealed v4/v5 runs.

The independent gold/selection/configuration are saved before judge calls.
Default invocation never loads credentials or calls any model. Judge opinions
are diagnostic evidence, not permission to narrow uncertified score bounds.
"""
import argparse
import json
from pathlib import Path
from ..rq1_collab_v1.audit import _write_new, canonical, strict_loads, file_hash


def _write(path, value):
    _write_new(Path(path), canonical(value) + b"\n")


def run_score(run_dir, seal_hash, output, *, judge_config_path=None,
              execute_judges=False, inventory_path=None, semantic_judges=None,
              match=False):
    from ..rq1_scorecard_v5.core import digest
    from ..rq1_scorecard_v5.workflow import _audited_judges
    from .pipeline import evaluate
    from .semantic_audit import prepare_closed, execute_audit

    source, target = Path(run_dir).resolve(), Path(output).resolve()
    if (source / "artifacts/evidence-v5.json").is_file():
        from ..rq1_collab_v5.evaluation import read_evidence
        from ..rq1_collab_v5.workflow import code_fingerprint
    else:
        from ..rq1_collab_v4.evaluation import read_evidence
        from ..rq1_collab_v4.workflow import code_fingerprint
    if target == source or target.is_relative_to(source):
        raise ValueError("score_output_must_be_outside_sealed_execution")
    if target.exists():
        raise FileExistsError("score_output_already_exists")
    if semantic_judges is not None and (judge_config_path is not None or execute_judges):
        raise ValueError("choose_injected_or_live_judges")
    if bool(judge_config_path) != bool(execute_judges) or (execute_judges and inventory_path is None):
        raise ValueError("live_judges_require_config_flag_and_inventory")
    if inventory_path is not None and not execute_judges:
        raise ValueError("inventory_without_live_judges")
    cfg = None
    if execute_judges:
        from ..rq1_scorecard_v5.judge_provider import validate_config
        cfg = validate_config(strict_loads(Path(judge_config_path).read_bytes()))
    identities = ([{"id": j["id"], "model": j["profile"]["model"]} for j in cfg["judges"]] if cfg else
                  [{"id": j["id"], "model": j["model"]} for j in semantic_judges] if semantic_judges is not None else None)
    data = read_evidence(source, seal_hash)
    report = evaluate(data)
    plan = prepare_closed(source, seal_hash, judge_configs=identities, match=match)
    audit_dir = target.with_name(target.name + ".audit")
    audit_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
    fingerprint = code_fingerprint()
    _write(audit_dir / "scoring-manifest.json", {"schema_version": "rq1-measurement-workflow/1",
        "run_dir": str(source), "execution_seal_sha256": seal_hash,
        "source_evidence_sha256": digest(data), "score_code_sha256": fingerprint,
        "judge_configuration": cfg, "judge_configuration_sha256": digest(cfg) if cfg else None,
        "injected_callbacks": semantic_judges is not None, "execute_judges": execute_judges,
        "planned_completion_invocations": plan["planned_completion_invocations"],
        "existing_scores_replaced": False, "automatic_retry": False, "formal_ready": False})
    _write(audit_dir / "semantic-plan.json", plan)
    _write(audit_dir / "calibration-lock.json", plan["gold_lock"])
    _write(audit_dir / "mechanical-score-before-judges.json", report)
    pool, journal, errors, audit = None, [], [], None
    try:
        if execute_judges:
            from ..rq1_scorecard_v5.judge_provider import JudgePool
            inventory = strict_loads(Path(inventory_path).read_bytes())
            pool = JudgePool(cfg, inventory, audit_dir / "judge-transport")
            semantic_judges = pool.entries()
        wrapped = _audited_judges(semantic_judges, audit_dir, journal) if semantic_judges is not None else None
        audit = execute_audit(plan, wrapped)
        if pool is not None:
            pool.assert_log_safe(audit)
        _write(audit_dir / "semantic-audit.json", audit)
    except Exception as exc:
        errors.append({"stage": "semantic_audit", "error_type": type(exc).__name__,
                       "reason": "audit_failed_original_mechanical_bounds_retained"})
    transport = pool.summary() if pool is not None else {"configured": False, "model_calls": 0,
                                                        "injected_callbacks": semantic_judges is not None}
    if pool is not None and transport["stopped_after_failure"]:
        errors.append({"stage": "judge_transport", "reason": "stopped_after_failure_no_retry"})
    if code_fingerprint() != fingerprint:
        errors.append({"stage": "scoring_code", "reason": "code_changed_during_audit"})
    phase_reports = [phase for row in (audit or {}).get("rows", []) for phase in row.get("phases", {}).values()]
    valid_votes = sum(v["status"] == "valid" for phase in phase_reports for v in phase["votes"])
    rejected_votes = sum(v["status"] != "valid" for phase in phase_reports for v in phase["votes"])
    diagnostic_status = "diagnostic_with_rejections" if rejected_votes else "diagnostic_completed"
    # No call to a judge can alter the original deterministic component scores.
    report["measurement_quality"] = {
        "schema_version": "rq1-measurement-quality/1", "audit_dir": str(audit_dir),
        "status": "needs_review" if errors else diagnostic_status if semantic_judges is not None else "applicability_only_no_judges",
        "source_evidence_sha256": digest(data), "plan_sha256": plan["plan_sha256"],
        "calibration_lock_sha256": plan["gold_lock"]["lock_sha256"],
        "completion_invocations": audit["completion_invocations"] if audit is not None else len(journal),
        "judge_transport": transport, "semantic_accuracy_certified": False,
        "valid_vote_slots": valid_votes, "rejected_or_failed_vote_slots": rejected_votes,
        "stable_diagnostic_fields": sum(f["status"] == "stable_diagnostic" for phase in phase_reports for f in phase["fields"]),
        "format_sensitivity": audit["format_sensitivity"] if audit is not None else {"status": "NOT_RUN"},
        "existing_score_points_changed_by_judges": False, "errors": errors,
        "independent_heldout_calibration_completed": False, "formal_ready": False}
    if pool is not None:
        pool.assert_log_safe(report)
    _write(target, report)
    status = {"status": report["measurement_quality"]["status"], "output": str(target),
        "report_sha256": file_hash(target), "audit_dir": str(audit_dir),
        "model_calls": transport.get("model_calls"), "completion_invocations": report["measurement_quality"]["completion_invocations"],
        "errors": errors, "formal_ready": False}
    _write(audit_dir / "status.json", status)
    return status


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--run', required=True)
    p.add_argument('--seal-hash', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--judge-config')
    p.add_argument('--execute-judges', action='store_true')
    p.add_argument('--inventory')
    p.add_argument('--match', action='store_true', help='Add a separate six-slot reference-matching phase')
    args = p.parse_args()
    result = run_score(args.run, args.seal_hash, args.output,
        judge_config_path=args.judge_config, execute_judges=args.execute_judges,
        inventory_path=args.inventory, match=args.match)
    print(json.dumps(result))
    return 1 if result['errors'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
