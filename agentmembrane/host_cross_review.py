from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from .proxy import LocalProxyClient, ProxyError, parse_json_object


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REVIEW_ROOT = PROJECT_ROOT / "experiments" / "host_boundary_v1" / "reviews"
SOURCE_FILES = (
    "docs/AGENTMEMBRANE_REVISED_PROPOSAL_2026-08-27.md",
    "experiments/host_boundary_v1/plan.md",
    "experiments/host_boundary_v1/SMOKE_GATE.md",
    "experiments/host_boundary_v1/coordination/audits/rq_coverage.md",
    "experiments/host_boundary_v1/coordination/audits/integrity_stats.md",
    "experiments/host_boundary_v1/coordination/audits/integrity_stats_r2.md",
    "experiments/host_boundary_v1/coordination/audits/integrity_stats_r3.md",
    "experiments/host_boundary_v1/coordination/audits/attack_surface.md",
    "experiments/host_boundary_v1/coordination/audits/attack_surface_r2.md",
    "experiments/host_boundary_v1/formal_profile.json",
    "agentmembrane/host_benchmark.py",
    "agentmembrane/host_experiment.py",
    "agentmembrane/host_integrity.py",
    "tests/test_host_benchmark.py",
    "tests/test_host_experiment.py",
    "tests/test_proxy.py",
)


def _atomic_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


def source_bundle() -> tuple[str, str]:
    sections = []
    hasher = hashlib.sha256()
    for relative in SOURCE_FILES:
        path = PROJECT_ROOT / relative
        data = path.read_bytes()
        hasher.update(relative.encode("utf-8"))
        hasher.update(data)
        sections.append(f"\n===== FILE: {relative} =====\n{data.decode('utf-8')}\n")
    return "".join(sections), hasher.hexdigest()


def _review_schema() -> dict[str, Any]:
    return {
        "review_id": "string",
        "round": "integer",
        "reviewer_role": "challenger|evaluator",
        "verdict": "revise|ready_for_smoke|ready_for_full_experiment|stop",
        "rq_coverage": {
            "RQ1": "implemented|partial|missing",
            "RQ2": "implemented|partial|missing",
            "RQ3": "implemented|partial|missing",
            "RQ4": "implemented|partial|missing",
        },
        "concerns": [
            {
                "issue_id": "stable identifier, preserve earlier IDs",
                "severity": "low|medium|high|fatal",
                "status": "open|partially_resolved|resolved|demonstrated",
                "claim": "exact issue",
                "evidence_or_logic": "file/function and reasoning",
                "cheapest_check": "specific test or inspection",
                "reversal_condition": "what would close it",
                "recommended_change": "minimal change",
            }
        ],
        "must_fix_before_paid_run": ["issue IDs"],
        "optional_improvements": ["issue IDs"],
        "strictness_audit": {
            "risks_measurement_collapse": ["specific mechanisms only"],
            "risks_false_positive": ["specific mechanisms only"],
            "denominator_policy_ok": "boolean",
        },
        "transport_failure_audit": {
            "observed_and_worst_case_reported": "boolean",
            "claim_stable_across_bounds": "boolean|not_yet_estimable",
        },
        "summary": "short evidence-based synthesis",
    }


def run_challenger(*, model: str, round_number: int, review_root: Path) -> dict[str, Any]:
    bundle, source_sha = source_bundle()
    prior_path = review_root / f"round-{round_number - 1}" / "gpt-evaluator.json"
    prior = prior_path.read_text(encoding="utf-8") if prior_path.exists() else "No prior round."
    system = (
        "You are the strict adversarial methods reviewer for an AI-agent security experiment. "
        "Apply a high scientific bar, but do not demand impossible purity or change thresholds to manufacture a null. "
        "Find concrete construct, oracle, baseline, statistics, coverage, and proposal-alignment failures. "
        "Do not write code. Return one strict JSON object and no markdown. Preserve prior issue IDs when applicable."
    )
    user = json.dumps(
        {
            "task": "Audit whether this candidate implementation satisfies the proposal and is ready for paid smoke/full experiment.",
            "round": round_number,
            "reviewer_stance": "strict challenger (Claude role)",
            "required_schema": _review_schema(),
            "prior_evaluator": prior,
            "source_sha256": source_sha,
            "source_bundle": bundle,
        },
        ensure_ascii=False,
    )
    client = LocalProxyClient.from_local_config(timeout_seconds=300)
    completion = client.complete(
        model=model,
        system=system,
        user=user,
        max_completion_tokens=5000,
        retries=2,
    )
    parsed = parse_json_object(completion.text)
    artifact = {
        "artifact_type": "cross_model_challenger_review",
        "reviewer_type": "cross_model",
        "independence_group": "anthropic-via-local-proxy",
        "model": model,
        "round": round_number,
        "created_at": datetime.now(UTC).isoformat(),
        "source_sha256": source_sha,
        "usage": {
            "input_tokens": completion.input_tokens,
            "output_tokens": completion.output_tokens,
            "total_tokens": completion.total_tokens,
            "latency_ms": completion.latency_ms,
        },
        "review": parsed,
        "raw_response": completion.text,
    }
    output = review_root / f"round-{round_number}" / "claude-challenger.json"
    _atomic_json(output, artifact)
    return artifact


def run_evaluator(
    *,
    model: str,
    round_number: int,
    review_root: Path,
    challenger_path: Path | None = None,
) -> dict[str, Any]:
    bundle, source_sha = source_bundle()
    challenger_path = challenger_path or (
        review_root / f"round-{round_number}" / "claude-challenger.json"
    )
    if not challenger_path.exists():
        raise ValueError("challenger_review_missing")
    challenger_text = challenger_path.read_text(encoding="utf-8")
    try:
        challenger: Any = json.loads(challenger_text)
    except json.JSONDecodeError:
        challenger = {
            "artifact_type": "local_independent_audit",
            "reviewer_type": "independent_subagent",
            "content": challenger_text,
        }
    system = (
        "You are the pragmatic evaluator for an AI-agent security experiment. Review the strict challenger's findings "
        "against the actual proposal and code. Use a permissive but scientifically honest bar: retain real signals, "
        "do not require zero leakage where the construct does not require it, and never relax an oracle or denominator "
        "just to improve results. Classify which issues truly block paid smoke or full execution. Do not write code. "
        "Return one strict JSON object and no markdown."
    )
    user = json.dumps(
        {
            "task": "Resolve the challenger review and identify the minimal mandatory revision set.",
            "round": round_number,
            "reviewer_stance": "pragmatic evaluator (GPT role)",
            "required_schema": _review_schema(),
            "challenger_artifact": challenger,
            "source_sha256": source_sha,
            "source_bundle": bundle,
        },
        ensure_ascii=False,
    )
    client = LocalProxyClient.from_local_config(timeout_seconds=300)
    completion = client.complete(
        model=model,
        system=system,
        user=user,
        max_completion_tokens=5000,
        retries=2,
    )
    parsed = parse_json_object(completion.text)
    artifact = {
        "artifact_type": "cross_model_evaluator_review",
        "reviewer_type": "cross_model",
        "independence_group": "openai-via-local-proxy",
        "model": model,
        "round": round_number,
        "created_at": datetime.now(UTC).isoformat(),
        "source_sha256": source_sha,
        "challenger_path": (
            str(challenger_path.relative_to(PROJECT_ROOT))
            if challenger_path.is_relative_to(PROJECT_ROOT)
            else str(challenger_path)
        ),
        "usage": {
            "input_tokens": completion.input_tokens,
            "output_tokens": completion.output_tokens,
            "total_tokens": completion.total_tokens,
            "latency_ms": completion.latency_ms,
        },
        "review": parsed,
        "raw_response": completion.text,
    }
    output = review_root / f"round-{round_number}" / "gpt-evaluator.json"
    _atomic_json(output, artifact)
    return artifact


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cross-model review loop for host-boundary code")
    parser.add_argument("role", choices=("challenger", "evaluator"))
    parser.add_argument("--round", type=int, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--review-root", type=Path, default=DEFAULT_REVIEW_ROOT)
    parser.add_argument("--challenger-path", type=Path)
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        if args.role == "challenger":
            artifact = run_challenger(
                model=args.model,
                round_number=args.round,
                review_root=args.review_root,
            )
        else:
            artifact = run_evaluator(
                model=args.model,
                round_number=args.round,
                review_root=args.review_root,
                challenger_path=args.challenger_path,
            )
        print(json.dumps(artifact, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ProxyError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
