from __future__ import annotations

import argparse
import hashlib
import json
import time
import urllib.error
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agentmembrane.proxy import load_local_proxy_settings


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = (
    PROJECT_ROOT
    / "experiments"
    / "host_boundary_v2"
    / "reviews"
    / "rq2-independent-calibration-20260830"
)

SOURCE_FILES = (
    "HANDOFF_2026-08-30.md",
    "docs/PROPOSAL.md",
    "experiments/host_boundary_v2/PROTOCOL_RQ2.md",
    "experiments/host_boundary_v2/PROTOCOL_SEMANTIC_B2.md",
    "experiments/host_boundary_v2/STATISTICAL_PLAN.md",
    "experiments/host_boundary_v2/DATA_SOURCES.md",
    "agentmembrane/host_v2/analysis.py",
    "agentmembrane/host_v2/integrity.py",
    "agentmembrane/host_v2/oracle.py",
    "agentmembrane/host_v2/schedule.py",
    "agentmembrane/host_v2/controlled_taskpack.py",
    "agentmembrane/host_v2/full_inventory.py",
    "agentmembrane/host_v2/taskpack_build.py",
    "agentmembrane/host_v2/runner.py",
    "experiments/host_boundary_v2/config/estimands.json",
    "experiments/host_boundary_v2/config/model-policy.json",
    "experiments/host_boundary_v2/config/rq_coverage_manifest.json",
    "experiments/host_boundary_v2/config/launch-policy.json",
    "outputs/host_v2_rq2_g2_terra_medium_20260830_r14/resolved-profile.json",
    "outputs/host_v2_rq2_g2_terra_medium_20260830_r14/report.md",
    "outputs/host_v2_rq2_g2_terra_medium_20260830_r14/integrity.json",
    "tests/host_v2/test_analysis.py",
    "tests/host_v2/test_integrity.py",
    "tests/host_v2/test_oracle.py",
    "tests/host_v2/test_schedule.py",
    "tests/host_v2/test_controlled_taskpack.py",
    "tests/host_v2/test_full_inventory.py",
    "tests/host_v2/test_taskpack_build.py",
)

COMPACT_SOURCE_SPECS: tuple[str | tuple[str, int, int], ...] = (
    "docs/PROPOSAL.md",
    "experiments/host_boundary_v2/PROTOCOL_RQ2.md",
    "experiments/host_boundary_v2/STATISTICAL_PLAN.md",
    ("agentmembrane/host_v2/analysis.py", 1, 150),
    ("agentmembrane/host_v2/analysis.py", 240, 300),
    ("agentmembrane/host_v2/analysis.py", 540, 1100),
    ("agentmembrane/host_v2/analysis.py", 1340, 1630),
    ("agentmembrane/host_v2/integrity.py", 260, 560),
    ("agentmembrane/host_v2/oracle.py", 1, 120),
    ("agentmembrane/host_v2/oracle.py", 650, 990),
    ("agentmembrane/host_v2/schedule.py", 1, 240),
    ("agentmembrane/host_v2/schedule.py", 300, 520),
    ("agentmembrane/host_v2/controlled_taskpack.py", 1, 120),
    ("agentmembrane/host_v2/controlled_taskpack.py", 400, 750),
    ("experiments/host_boundary_v2/config/estimands.json", 520, 760),
    "experiments/host_boundary_v2/config/model-policy.json",
    "experiments/host_boundary_v2/config/rq_coverage_manifest.json",
    "experiments/host_boundary_v2/config/launch-policy.json",
    "data/host_boundary_v2/packs/controlled-v2/public_pack_readiness_audit.json",
    "outputs/host_v2_rq2_g2_terra_medium_20260830_r14/resolved-profile.json",
    "outputs/host_v2_rq2_g2_terra_medium_20260830_r14/report.md",
    "outputs/host_v2_rq2_g2_terra_medium_20260830_r14/integrity.json",
    "tests/host_v2/test_analysis.py",
    "tests/host_v2/test_integrity.py",
    "tests/host_v2/test_oracle.py",
    "tests/host_v2/test_schedule.py",
    "tests/host_v2/test_controlled_taskpack.py",
)

# A request-size-controlled profile for routes that time out on the broader
# compact bundle. It retains every RQ2 definition and result artifact needed
# for construct/methods review, but narrows implementation and test context to
# the exact code paths named by the frozen concerns. Full-file hashes remain in
# the manifest for every slice, so reviewers and later agents can detect drift.
LEAN_SOURCE_SPECS: tuple[str | tuple[str, int, int], ...] = (
    ("docs/PROPOSAL.md", 40, 180),
    "experiments/host_boundary_v2/PROTOCOL_RQ2.md",
    ("experiments/host_boundary_v2/PROTOCOL_SEMANTIC_B2.md", 1, 140),
    "experiments/host_boundary_v2/STATISTICAL_PLAN.md",
    ("agentmembrane/host_v2/analysis.py", 1, 110),
    ("agentmembrane/host_v2/analysis.py", 430, 490),
    ("agentmembrane/host_v2/analysis.py", 840, 1045),
    ("agentmembrane/host_v2/analysis.py", 1160, 1385),
    ("agentmembrane/host_v2/integrity.py", 140, 180),
    ("agentmembrane/host_v2/integrity.py", 240, 590),
    ("agentmembrane/host_v2/oracle.py", 1, 105),
    ("agentmembrane/host_v2/oracle.py", 730, 1010),
    ("agentmembrane/host_v2/schedule.py", 1, 135),
    ("agentmembrane/host_v2/schedule.py", 300, 475),
    ("agentmembrane/host_v2/controlled_taskpack.py", 215, 455),
    ("experiments/host_boundary_v2/config/estimands.json", 520, 930),
    "experiments/host_boundary_v2/config/model-policy.json",
    "data/host_boundary_v2/packs/controlled-v2/public_pack_readiness_audit.json",
    "outputs/host_v2_rq2_g2_terra_medium_20260830_r14/resolved-profile.json",
    "outputs/host_v2_rq2_g2_terra_medium_20260830_r14/report.md",
    "outputs/host_v2_rq2_g2_terra_medium_20260830_r14/integrity.json",
    ("tests/host_v2/test_analysis.py", 1, 220),
    ("tests/host_v2/test_integrity.py", 140, 285),
    ("tests/host_v2/test_oracle.py", 360, 575),
    ("tests/host_v2/test_schedule.py", 55, 130),
    ("tests/host_v2/test_controlled_taskpack.py", 235, 285),
    ("tests/host_v2/test_controlled_taskpack.py", 470, 515),
)

SYSTEM_PROMPT = """You are an independent principal methods-and-code reviewer for an AI-agent security experiment. Your output will be handed directly to coding agents. Audit the supplied RQ2 proposal definitions, implementation, task/data flow, oracle semantics, frozen estimands, coverage and nuisance logic, tests, calibration results, and formal-public-dataset readiness. Be strict about construct validity, reproducibility, statistical validity, and non-post-hoc analysis. Do not assume the handoff's diagnoses are correct: verify them against code and artifacts. Do not write or execute code. Do not refer to any other model's review; this review must be independent. Never recommend changing a metric, threshold, oracle, task, or denominator merely to improve an observed result. Distinguish instrument repair from outcome-driven rescue. Return detailed Markdown, with concrete instructions usable by coding agents."""

USER_TASK = """Produce an independent, coding-agent-ready calibration review of AgentMembrane RQ2 before any substantive repair.

Non-negotiable scope rules:
1. Keep Semantic RQ2 (the proposal's Evidence -> Inference -> Recommendation -> Free-form receptor boundary) distinct from Host-action RQ2 (six host-mediated capability-exploitation mechanisms). Decide how naming/protocol alignment should be repaired without pretending they are the same construct.
2. Verify the two reported analysis concerns from first principles: condition_eligibility not entering analysis coverage strata; and host_mediated_forbidden_outcome covering only a subset of route-qualified mechanism successes. Do not mechanically replace the primary metric with attack_success. Specify the scientifically correct construct and component-field design.
3. Audit protected-arm explicit-abstention imbalance. Refusal is not host containment. Recommend a principled estimand/gate/sensitivity treatment, not threshold relaxation.
4. Audit the full formal-results chain. Existing r14 is synthetic, nonclaim calibration. Public AgentDojo/tau2 formal rows are reportedly zero. State exactly what must exist before a formal real/public-dataset result can be claimed.
5. Preserve frozen/history semantics: any repair changes the implementation hash and requires new run identities; old r14 must not be relabeled.

For every issue, include all of these fields:
- Issue ID and title
- Verdict: accept as bug / needs evidence / reject premise / design decision
- Severity: fatal, high, medium, or low
- Whether it blocks offline repair, smoke/calibration, or formal experiment
- Affected RQ2 claim/construct
- Concrete evidence with repository-relative file paths and functions/classes/config/data fields
- Root cause
- Exact recommended code/config/documentation change, preferably pseudocode or a compact pseudo-diff
- Unit/integration/regression tests to add or change
- Acceptance criteria
- Risks, dependencies, and migration/reproducibility consequences

Then provide:
A. A proposal/protocol alignment decision.
B. An issue-by-issue implementation order with file ownership boundaries suitable for up to five parallel coding agents.
C. A validation matrix: 234-test non-regression, new tests, scripted/zero-token assay, G0/G1/G2 gates, integrity/analysis checks, and formal-public-run gate.
D. A formal experiment readiness checklist including immutable dataset source/version/hash/license, task transformation mapping, native reset/tool/checker parity, held-out split, independent workflow clusters, sample/power tier, seed/model/reasoning/temperature/token/retry/concurrency settings, raw logs/cache/run manifests, and statistical outputs.
E. A final verdict distinguishing: safe to repair offline; safe to rerun calibration; safe to run formal public data; and safe to make an RQ2 claim.

The attached source bundle is authoritative. Quote code sparingly and cite paths/functions precisely."""


def _source_bundle(
    source_specs: tuple[str | tuple[str, int, int], ...],
) -> tuple[str, list[dict[str, Any]], str]:
    sections: list[str] = []
    manifest: list[dict[str, Any]] = []
    digest = hashlib.sha256()
    for spec in source_specs:
        if isinstance(spec, tuple):
            relative, line_start, line_end = spec
        else:
            relative, line_start, line_end = spec, None, None
        path = PROJECT_ROOT / relative
        full_payload = path.read_bytes()
        full_sha256 = hashlib.sha256(full_payload).hexdigest()
        if line_start is None:
            payload = full_payload
            label = relative
        else:
            lines = full_payload.decode("utf-8").splitlines(keepends=True)
            payload = "".join(lines[line_start - 1 : line_end]).encode("utf-8")
            label = f"{relative}#L{line_start}-L{line_end}"
        sha256 = hashlib.sha256(payload).hexdigest()
        manifest_row: dict[str, Any] = {
            "path": relative,
            "bytes": len(payload),
            "sha256": sha256,
            "full_file_sha256": full_sha256,
        }
        if line_start is not None:
            manifest_row.update({"line_start": line_start, "line_end": line_end})
        manifest.append(manifest_row)
        digest.update(label.encode("utf-8"))
        digest.update(b"\0")
        digest.update(payload)
        sections.append(
            f"\n\n===== BEGIN SOURCE: {label} (sha256={sha256}) =====\n"
            + payload.decode("utf-8")
            + f"\n===== END SOURCE: {label} =====\n"
        )
    return "".join(sections), manifest, digest.hexdigest()


def _request(
    path: str,
    payload: dict[str, Any],
    *,
    timeout_seconds: float,
    anthropic_compatible: bool,
) -> dict[str, Any]:
    base_url, api_key, _ = load_local_proxy_settings()
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "X-Session-ID": "agentmembrane-rq2-independent-review",
    }
    if anthropic_compatible:
        headers.update(
            {
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            }
        )
    else:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(
        f"{base_url}/{path.lstrip('/')}",
        data=body,
        method="POST",
        headers=headers,
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        value = json.loads(response.read().decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("proxy response must be an object")
    return value


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True, choices=("gpt-5.6-sol", "claude-opus-5"))
    parser.add_argument("--max-completion-tokens", type=int, default=18000)
    parser.add_argument("--timeout-seconds", type=float, default=1800.0)
    parser.add_argument(
        "--bundle-profile", choices=("full", "compact", "lean"), default="compact"
    )
    args = parser.parse_args()

    source_specs: tuple[str | tuple[str, int, int], ...]
    if args.bundle_profile == "full":
        source_specs = SOURCE_FILES
    elif args.bundle_profile == "compact":
        source_specs = COMPACT_SOURCE_SPECS
    else:
        source_specs = LEAN_SOURCE_SPECS
    bundle, manifest, bundle_sha256 = _source_bundle(source_specs)
    model_settings: dict[str, Any] = {
        "temperature": 0,
        "max_completion_tokens": args.max_completion_tokens,
    }
    if args.model == "gpt-5.6-sol":
        # The live proxy rejects the repository's stale ``ultra`` label and
        # advertises ``max`` as the highest accepted effort for this model.
        model_settings["reasoning_effort"] = "max"
    else:
        model_settings["reasoning_effort"] = "concrete_provider_default"

    prompt_record = {
        "artifact_type": "rq2_independent_review_prompt",
        "independence_rule": "no_other_reviewer_output_in_context",
        "model": args.model,
        "provider_route_id": "local-cli-proxy",
        "created_at": datetime.now(UTC).isoformat(),
        "model_settings": model_settings,
        "bundle_profile": args.bundle_profile,
        "source_bundle_sha256": bundle_sha256,
        "source_manifest": manifest,
        "system_prompt": SYSTEM_PROMPT,
        "user_task": USER_TASK,
    }
    artifact_stem = f"{args.model}-{args.bundle_profile}"
    prompt_path = REVIEW_ROOT / f"{artifact_stem}-prompt.json"
    _atomic_write(prompt_path, json.dumps(prompt_record, ensure_ascii=False, indent=2) + "\n")

    if args.model == "gpt-5.6-sol":
        path = "chat/completions"
        anthropic_compatible = False
        payload: dict[str, Any] = {
            "model": args.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": USER_TASK + bundle},
            ],
            "temperature": 0,
            "max_completion_tokens": args.max_completion_tokens,
            "stream": False,
        }
        payload["reasoning_effort"] = "max"
    else:
        # The OpenAI-compatible Claude adapter forces upstream max_tokens=32000.
        # The native-compatible endpoint preserves this explicit bounded cap.
        path = "messages"
        anthropic_compatible = True
        payload = {
            "model": args.model,
            "system": SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": USER_TASK + bundle}],
            "temperature": 0,
            "max_tokens": args.max_completion_tokens,
            "stream": False,
        }

    started_at = datetime.now(UTC).isoformat()
    started = time.monotonic()
    try:
        response = _request(
            path,
            payload,
            timeout_seconds=args.timeout_seconds,
            anthropic_compatible=anthropic_compatible,
        )
    except urllib.error.HTTPError as exc:
        body = exc.read()
        error_record = {
            **prompt_record,
            "started_at": started_at,
            "finished_at": datetime.now(UTC).isoformat(),
            "http_status": exc.code,
            "error_body_sha256": hashlib.sha256(body).hexdigest(),
        }
        _atomic_write(
            REVIEW_ROOT / f"{artifact_stem}-error.json",
            json.dumps(error_record, ensure_ascii=False, indent=2) + "\n",
        )
        raise

    if args.model == "gpt-5.6-sol":
        choices = response.get("choices", [])
        text = choices[0].get("message", {}).get("content") if choices else None
    else:
        content = response.get("content", [])
        text = "".join(
            block.get("text", "")
            for block in content
            if isinstance(block, dict) and block.get("type") == "text"
        )
    if not isinstance(text, str) or not text.strip():
        raise RuntimeError("empty review response")
    usage = response.get("usage", {})
    artifact = {
        "artifact_type": "rq2_independent_model_review",
        "independence_rule": "no_other_reviewer_output_in_context",
        "model": args.model,
        "provider_route_id": "local-cli-proxy",
        "requested_model_settings": model_settings,
        "source_bundle_sha256": bundle_sha256,
        "source_manifest": manifest,
        "prompt_path": str(prompt_path.relative_to(PROJECT_ROOT)),
        "started_at": started_at,
        "finished_at": datetime.now(UTC).isoformat(),
        "latency_ms": round((time.monotonic() - started) * 1000),
        "response_model": response.get("model"),
        "usage": usage if isinstance(usage, dict) else {},
        "response_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "raw_response": text,
    }
    _atomic_write(
        REVIEW_ROOT / f"{artifact_stem}-review.json",
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n",
    )
    _atomic_write(REVIEW_ROOT / f"{artifact_stem}-review.md", text.rstrip() + "\n")
    print(
        json.dumps(
            {
                "ok": True,
                "model": args.model,
                "source_bundle_sha256": bundle_sha256,
                "response_sha256": artifact["response_sha256"],
                "usage": artifact["usage"],
                "latency_ms": artifact["latency_ms"],
                "review_path": str((REVIEW_ROOT / f"{artifact_stem}-review.md").relative_to(PROJECT_ROOT)),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
