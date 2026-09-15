from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agentmembrane.proxy import load_local_proxy_settings


PROJECT_ROOT = Path(__file__).resolve().parents[1]
REVIEW_ROOT = (
    PROJECT_ROOT
    / "experiments"
    / "host_boundary_v2"
    / "reviews"
    / "rq1-architecture-20260831"
)


COMMON_SYSTEM = """You are an independent principal architect and methods reviewer for AgentMembrane canonical proposal RQ1: the A0-A5 authority/admission boundary. This is not the RQ1b host-mediated six-mechanism subtrack and not Semantic RQ2. Review only the supplied bounded work package. Give coding-agent-ready findings grounded in repository paths and symbols. Separate minimum scientifically sufficient repairs from optional strengthening. For every blocker state whether it blocks offline implementation, scripted zero-token assay, paid model smoke, or formal/public claim. Do not require formal-scale power, a second model, or perfect task purity merely to permit engineering work. Refusal is never host containment. Do not recommend outcome-driven metric, oracle, denominator, or threshold changes. Do not write or execute code."""


PARTS: dict[str, dict[str, Any]] = {
    "construct_identity": {
        "sources": (
            ("docs/PROPOSAL.md", 100, 165),
            ("docs/PROPOSAL.md", 470, 555),
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 1, 105),
            "experiments/host_boundary_v2/config/profiles/rq1-g0-gate.template.json",
            "experiments/host_boundary_v2/config/profiles/rq1-primary-formal.template.json",
            ("experiments/host_boundary_v2/config/rq_coverage_manifest.json", 1, 110),
        ),
        "task": """Freeze only the canonical RQ1 construct and version contract. Resolve A0-A4 versus A0-A5, define stable machine identity distinct from RQ1b, classify each adjacent contrast as primary or descriptive, decide when a global ladder/A* is identifiable versus only family-specific boundaries, and audit whether current rq1 templates actually target canonical RQ1. Return minimum doc/config repairs, tests, and stage-specific blockers.""",
    },
    "estimands_strictness": {
        "sources": (
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 219, 265),
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 333, 392),
            ("experiments/host_boundary_v2/STATISTICAL_PLAN.md", 1, 155),
            ("experiments/host_boundary_v2/STATISTICAL_PLAN.md", 225, 232),
            ("experiments/host_boundary_v2/config/estimands.json", 1, 535),
        ),
        "task": """Audit only canonical RQ1 estimands, denominators, utility definitions, independent units, power and strictness. Separate deterministic invariants, finite fixed-benchmark evidence, paid smoke and population claims. Calibrate the 20pp signal threshold, utility noninferiority, 5pp refusal imbalance, 20/60/100 cluster rules and second-model requirement. Specify family-specific risk/utility estimands and what can or cannot justify a safe boundary or A*.""",
    },
    "admission_surface": {
        "sources": (
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 20, 105),
            "agentmembrane/kernel.py",
            ("agentmembrane/host_v2/conditions.py", 1, 240),
            ("agentmembrane/host_v2/conditions.py", 356, 430),
            ("agentmembrane/host_v2/conditions.py", 652, 735),
            ("agentmembrane/host_v2/conditions.py", 885, 945),
        ),
        "task": """Design only the canonical RQ1 admission request, A0-A5 visible surface and capability-token contract. Require host-owned identity, opaque handles, operation/resource/purpose/lease/expiry/delegation/revocation binding and condition blindness. Audit whether A2 is truly proposal-only and whether current capability kernel is connected to the formal host. Give exact interfaces and counterexample tests.""",
    },
    "capability_lifecycle": {
        "sources": (
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 82, 149),
            ("agentmembrane/host_v2/host.py", 268, 430),
            ("agentmembrane/host_v2/host.py", 639, 945),
            ("agentmembrane/host_v2/host.py", 1360, 1580),
        ),
        "task": """Audit only capability binding and lifecycle host semantics for canonical RQ1: identity/operation/resource/purpose/delegability, self-grant, renewal, scope replacement, expiry/revocation/termination, queue/proposal/memory carryover and fresh approval. Find in-place mutation or provenance bugs, define immutable baseline and causal trusted events, and give minimum repairs plus deterministic tests. Do not discuss model sampling.""",
    },
    "taskpack_core": {
        "sources": (
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 105, 149),
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 265, 323),
            ("agentmembrane/host_v2/taskpack_build.py", 650, 990),
            ("agentmembrane/host_v2/taskpacks.py", 1, 220),
        ),
        "task": """Design only the nonclaim canonical RQ1 core bank and zero-token assay. Cover F0-F5, twelve binding/lifecycle contrasts, A5-C0, benign/adversarial twins, same visible interface, fixed-trace versus adaptive metadata, eligibility, authorship, provenance, splits and positive controls. Specify a minimum sentinel bank for engineering without pretending it has 10 independent pairs per family or formal power.""",
    },
    "public_data": {
        "sources": (
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 149, 175),
            ("agentmembrane/host_v2/full_inventory.py", 1, 220),
            ("agentmembrane/host_v2/public_adapters.py", 1, 260),
            "experiments/host_boundary_v2/public_readiness_v2.1/decision.json",
            "experiments/host_boundary_v2/reviews/rq2-independent-calibration-20260830/rq2-partial-hydration-logical-integrity-gate-report.md",
        ),
        "task": """Audit only canonical RQ1 public-data readiness. Assess tau2, AgentDojo and missing BFCL; distinguish real model API plus local simulator from production data; identify reusable runtime evidence versus zero executed parity; handle dataless tau2 paths; specify the minimum new derived pack, mapping, native utility and derived security evidence needed for a nonclaim public smoke and later formal rows.""",
    },
    "oracle_endpoints": {
        "sources": (
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 175, 220),
            ("agentmembrane/host_v2/oracle.py", 80, 220),
            ("agentmembrane/host_v2/oracle.py", 1040, 1300),
            ("agentmembrane/host_v2/oracle.py", 1450, 1590),
        ),
        "task": """Audit only canonical RQ1 trusted endpoints. Separate direct unauthorized, host-mediated, composite and lifecycle carryover; exact prohibited terminal effect from canonical-route purity; contribution/system utility; F0 response-only bookkeeping; and causal use after self-grant/renew/scope mutation. Avoid both route-overstrict false negatives and text/attempt false positives. Return exact oracle fields and mutation tests.""",
    },
    "oracle_attack_endpoints": {
        "sources": (
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 175, 205),
            ("agentmembrane/host_v2/oracle.py", 80, 190),
            ("agentmembrane/host_v2/oracle.py", 1375, 1690),
        ),
        "task": """Audit only the four canonical RQ1 trusted attack endpoints: direct unauthorized, host-mediated, composite, and lifecycle carryover. Check that every endpoint requires an exact trusted terminal effect and the correct actor/lineage/time witness, that the union field is complete, and that self-grant/renew/scope-mutation count only after causal use. Return only minimum field semantics and high-value mutation tests. Do not discuss utility, sampling, public data, or model prompts.""",
    },
    "oracle_f0_utility": {
        "sources": (
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 202, 220),
            ("agentmembrane/host_v2/oracle.py", 1050, 1180),
            ("agentmembrane/host_v2/oracle.py", 1725, 1790),
        ),
        "task": """Audit only canonical RQ1 benign utility and F0 response-only handling. Distinguish system-task utility from level-appropriate contribution utility; decide which bookkeeping/control events F0 must ignore and which host actions/effects must fail it; preserve artifact/event binding without requiring a host event for terminal text. Return exact minimum semantics and mutation tests. Do not discuss attack-route attribution or statistics.""",
    },
    "oracle_route_strictness": {
        "sources": (
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 175, 205),
            ("agentmembrane/host_v2/oracle.py", 800, 930),
            ("agentmembrane/host_v2/oracle.py", 1375, 1425),
            ("agentmembrane/host_v2/oracle.py", 1680, 1725),
        ),
        "task": """Audit only whether canonical-route purity is improperly coupled to all-attempt attack success. Specify which exact terminal-effect endpoints must remain monotone despite harmless extra actions, and which fixed-trace/mechanism-attribution endpoints may require an ordered pure route. Guard against text-only claims, partial attempts, wrong tuples, and unrelated effects. Return the smallest code contract and decisive counterexample tests. Do not discuss utility, data, or sample size.""",
    },
    "analysis_strictness": {
        "sources": (
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 219, 265),
            ("agentmembrane/host_v2/analysis.py", 80, 220),
            ("agentmembrane/host_v2/analysis.py", 1000, 1220),
            ("agentmembrane/host_v2/integrity.py", 240, 590),
        ),
        "task": """Audit only canonical RQ1 analysis/integrity. Define all-assigned risk, activation, success-given-attempt, denial-given-attempt, independent benign utility, eligibility parity, whole-workflow clusters, finite versus population inference, nuisance/refusal bounds and small-n not-evaluable behavior. Identify incomplete metric unions or overstrict gates and specify exact tests/report safeguards.""",
    },
    "runner_lifecycle": {
        "sources": (
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 20, 63),
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 202, 218),
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 265, 333),
            ("agentmembrane/host_v2/planner.py", 260, 380),
            ("agentmembrane/host_v2/planner.py", 580, 690),
            ("agentmembrane/host_v2/runner.py", 1400, 1720),
        ),
        "task": """Audit only canonical RQ1 planner/runner execution. Cover live op/args schema validation, condition-blind planner inputs, interleaved deterministic lifecycle transitions with later model actions, fixed-trace versus adaptive tracks, F0 terminal artifacts, cache/retry semantics and bounded smoke scheduling. Return minimum interfaces/tests; do not authorize paid execution.""",
    },
    "public_validation": {
        "sources": (
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 289, 381),
            ("agentmembrane/host_v2/public_checker_parity.py", 500, 640),
            ("agentmembrane/host_v2/agentdojo_adapter.py", 1000, 1242),
            ("agentmembrane/host_v2/tau2_adapter.py", 1080, 1312),
            ("agentmembrane/host_v2/public_readiness.py", 1, 180),
            "experiments/host_boundary_v2/config/launch-policy.json",
            "experiments/host_boundary_v2/public_readiness_v2.1/decision.json",
        ),
        "task": """Audit only the public parity and launch DAG for canonical RQ1. Separate native utility from AgentMembrane-derived security, require terminal model-output capture, cleanup/reset and applicable mutation cases, handle tau2 NL assertions, and calibrate 100% deterministic parity versus small-n smoke. Give precise offline, zero-token, bounded paid-smoke and formal/public gates; do not authorize 990 episodes.""",
    },
    "contract_statistics": {
        "sources": (
            ("docs/PROPOSAL.md", 100, 165),
            ("docs/PROPOSAL.md", 470, 555),
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 1, 105),
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 219, 265),
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 346, 392),
            ("experiments/host_boundary_v2/STATISTICAL_PLAN.md", 1, 155),
            ("experiments/host_boundary_v2/STATISTICAL_PLAN.md", 225, 232),
            ("experiments/host_boundary_v2/config/estimands.json", 1, 535),
            "experiments/host_boundary_v2/config/profiles/rq1-g0-gate.template.json",
            "experiments/host_boundary_v2/config/profiles/rq1-primary-formal.template.json",
            ("experiments/host_boundary_v2/config/rq_coverage_manifest.json", 1, 110),
        ),
        "task": """Audit and design only the canonical RQ1 construct, versioning, conditions, estimands, sampling units, thresholds, and report language. Resolve the A0-A4 versus A0-A5 documentation conflict; define stable construct/stage identifiers; decide which adjacent contrasts are primary versus descriptive; determine when a global ladder or A* is identifiable versus only family-specific Pareto boundaries; separate system-task utility from level-appropriate contribution utility; and calibrate strictness so deterministic invariants, paid smoke, and formal population claims use different gates. Explicitly assess whether current rq1-g0 and formal templates are construct-valid. Return an acceptance contract and exact config/doc changes, with do-not-change constraints.""",
    },
    "capability_host": {
        "sources": (
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 20, 149),
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 175, 220),
            "agentmembrane/kernel.py",
            ("agentmembrane/host_v2/conditions.py", 1, 240),
            ("agentmembrane/host_v2/conditions.py", 356, 430),
            ("agentmembrane/host_v2/conditions.py", 652, 735),
            ("agentmembrane/host_v2/conditions.py", 885, 945),
            ("agentmembrane/host_v2/host.py", 140, 430),
            ("agentmembrane/host_v2/host.py", 639, 945),
            ("agentmembrane/host_v2/host.py", 1360, 1580),
            ("tests/host_v2/test_host.py", 1, 220),
        ),
        "task": """Audit and design the canonical RQ1 admission/capability host. Specify an explicit admission request and opaque signed capability handle contract binding host-owned principal, operation, canonicalized resource, declared purpose, lease, expiry, delegation depth, revocation epoch, and immutable issuance provenance. Cover A0 response-only, A1 read, A2 proposal-only, A3 scoped nondelegable, A4 delegation, A5 ambient; deterministic time; renew/scope replacement; revoke/termination; queued work, proposals, and memory artifacts; reset and condition blindness. Identify current false-authorize/false-deny bugs, including model-supplied actor/purpose and in-place grant mutation. Provide interfaces, migration steps, ownership boundaries, counterexample/property tests, and scripted acceptance criteria.""",
    },
    "taskpack_data": {
        "sources": (
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 105, 175),
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 265, 381),
            ("agentmembrane/host_v2/taskpack_build.py", 650, 990),
            ("agentmembrane/host_v2/full_inventory.py", 1, 220),
            ("agentmembrane/host_v2/taskpacks.py", 1, 220),
            ("agentmembrane/host_v2/public_adapters.py", 1, 260),
            ("tests/host_v2/test_taskpack_build.py", 1, 338),
            ("tests/host_v2/test_full_inventory.py", 280, 370),
            "experiments/host_boundary_v2/public_readiness_v2.1/decision.json",
        ),
        "task": """Audit and design canonical RQ1 taskpacks and data mapping. Define the minimum independently authored core bank for F0-F5 and the twelve binding/lifecycle contrasts, benign/adversarial twins, common-support requirements, fixed-trace versus adaptive tracks, eligibility and split-disjointness keys, positive controls, exact taskpack provenance, and nonclaim smoke subsets. Assess tau2, AgentDojo, and missing BFCL honestly. Specify what can be deferred, what requires a new versioned derived pack, how authored attack twins must be labeled, and what evidence is needed before adapter-verified or formal rows become nonzero. Avoid turning deterministic invariants into a 60/100-cluster burden. Return concrete builder/test/data contracts and staged acceptance gates.""",
    },
    "oracle_analysis": {
        "sources": (
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 175, 265),
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 333, 345),
            ("agentmembrane/host_v2/oracle.py", 80, 220),
            ("agentmembrane/host_v2/oracle.py", 1040, 1590),
            ("agentmembrane/host_v2/analysis.py", 80, 220),
            ("agentmembrane/host_v2/analysis.py", 1000, 1220),
            ("agentmembrane/host_v2/integrity.py", 240, 590),
            ("tests/host_v2/test_oracle.py", 1, 220),
            ("tests/host_v2/test_analysis.py", 1, 220),
        ),
        "task": """Audit and design canonical RQ1 trusted endpoints and analysis. Separate direct unauthorized, host-mediated, composite, and lifecycle-carryover outcomes; exact terminal tuple from route purity; contribution and system utility; all-assigned risk, activation, success-given-attempt, and denial-given-attempt. Fix F0 response-only semantics and ensure completion bookkeeping is not mistaken for host access. Define family-specific metrics, eligibility parity across schedule/integrity/analysis, whole-workflow clustering, finite-benchmark versus population inference, nuisance/refusal sensitivity, and strictness checks that allow equivalent successful routes but never text-only or partial attempts. State exact code/test changes and stage-specific claim gates.""",
    },
    "runner_validation": {
        "sources": (
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 20, 63),
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 202, 218),
            ("experiments/host_boundary_v2/PROTOCOL_RQ1.md", 265, 392),
            ("agentmembrane/host_v2/planner.py", 260, 380),
            ("agentmembrane/host_v2/planner.py", 580, 690),
            ("agentmembrane/host_v2/runner.py", 1400, 1720),
            ("agentmembrane/host_v2/public_checker_parity.py", 500, 640),
            ("agentmembrane/host_v2/agentdojo_adapter.py", 1000, 1242),
            ("agentmembrane/host_v2/tau2_adapter.py", 1080, 1312),
            ("agentmembrane/host_v2/public_readiness.py", 1, 250),
            "experiments/host_boundary_v2/config/launch-policy.json",
            "experiments/host_boundary_v2/public_readiness_v2.1/decision.json",
            "experiments/host_boundary_v2/reviews/rq2-independent-calibration-20260830/rq2-partial-hydration-logical-integrity-gate-report.md",
        ),
        "task": """Audit and design canonical RQ1 execution and validation. Cover live operation argument-schema validation, interleaved deterministic lifecycle transitions with model actions, fixed-trace host replay versus adaptive end-to-end runs, public adapter selection/bridge, native utility and derived security checker separation, terminal model-output capture, cleanup/reset, parity cases, dataless hydration, launch flags, caching, retries, and bounded paid smoke. Calibrate gates: 100% only for deterministic applicable cases; small-n refusal imbalance must be descriptive/not-evaluable rather than an automatic 5pp failure; corpus-wide perturbation coverage may use explicit N/A. Return the minimum offline-to-zero-token-to-paid-smoke-to-public-formal DAG and exact tests. Do not authorize a 990-episode run.""",
    },
}


def _bundle(specs: tuple[str | tuple[str, int, int], ...]) -> tuple[str, list[dict[str, Any]], str]:
    sections: list[str] = []
    manifest: list[dict[str, Any]] = []
    digest = hashlib.sha256()
    for spec in specs:
        if isinstance(spec, tuple):
            relative, start, end = spec
        else:
            relative, start, end = spec, None, None
        path = PROJECT_ROOT / relative
        full = path.read_bytes()
        if start is None:
            payload = full
            label = relative
        else:
            payload = "".join(full.decode("utf-8").splitlines(keepends=True)[start - 1 : end]).encode("utf-8")
            label = f"{relative}#L{start}-L{end}"
        row: dict[str, Any] = {
            "path": relative,
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "full_file_sha256": hashlib.sha256(full).hexdigest(),
        }
        if start is not None:
            row.update({"line_start": start, "line_end": end})
        manifest.append(row)
        digest.update(json.dumps(row, sort_keys=True).encode("utf-8"))
        digest.update(payload)
        sections.append(f"\n===== BEGIN SOURCE: {label} =====\n{payload.decode('utf-8')}\n===== END SOURCE: {label} =====\n")
    return "".join(sections), manifest, digest.hexdigest()


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def _request(part: str, payload: dict[str, Any], *, timeout_seconds: float) -> dict[str, Any]:
    base_url, api_key, _ = load_local_proxy_settings()
    request = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "X-Session-ID": f"agentmembrane-rq1-{part}-review",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        value = json.loads(response.read().decode("utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("proxy response must be an object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--part", required=True, choices=tuple(PARTS))
    parser.add_argument("--max-completion-tokens", type=int, default=3500)
    parser.add_argument("--timeout-seconds", type=float, default=600.0)
    parser.add_argument("--reasoning-effort", choices=("medium", "high", "xhigh", "max"), default="high")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    definition = PARTS[args.part]
    bundle, manifest, bundle_sha = _bundle(definition["sources"])
    bundle_bytes = len(bundle.encode("utf-8"))
    if bundle_bytes > 90_000:
        raise RuntimeError(f"part exceeds 90000-byte disclosure cap: {bundle_bytes}")
    if args.dry_run:
        print(json.dumps({"part": args.part, "bundle_bytes": bundle_bytes, "source_count": len(manifest), "source_bundle_sha256": bundle_sha}))
        return 0

    prompt_path = REVIEW_ROOT / f"gpt-5.6-sol-{args.part}-prompt.json"
    review_json = REVIEW_ROOT / f"gpt-5.6-sol-{args.part}-review.json"
    review_md = REVIEW_ROOT / f"gpt-5.6-sol-{args.part}-review.md"
    if review_json.exists() and not args.force:
        raise RuntimeError(f"review artifact already exists: {review_json}")

    prompt_record = {
        "artifact_type": "rq1_partitioned_architecture_prompt",
        "independence_rule": "bounded_part_only_no_other_review_output",
        "part": args.part,
        "model": "gpt-5.6-sol",
        "provider_route_id": "local-cli-proxy",
        "created_at": datetime.now(UTC).isoformat(),
        "model_settings": {"temperature": 0, "reasoning_effort": args.reasoning_effort, "max_completion_tokens": args.max_completion_tokens},
        "source_bundle_sha256": bundle_sha,
        "source_manifest": manifest,
        "system_prompt": COMMON_SYSTEM,
        "user_task": definition["task"],
    }
    _atomic_write(prompt_path, json.dumps(prompt_record, ensure_ascii=False, indent=2) + "\n")
    payload = {
        "model": "gpt-5.6-sol",
        "messages": [
            {"role": "system", "content": COMMON_SYSTEM},
            {"role": "user", "content": definition["task"] + bundle},
        ],
        "temperature": 0,
        "reasoning_effort": args.reasoning_effort,
        "max_completion_tokens": args.max_completion_tokens,
        "stream": False,
    }
    started_at = datetime.now(UTC).isoformat()
    started = time.monotonic()
    try:
        response = _request(args.part, payload, timeout_seconds=args.timeout_seconds)
    except urllib.error.HTTPError as exc:
        body = exc.read()
        _atomic_write(
            REVIEW_ROOT / f"gpt-5.6-sol-{args.part}-error.json",
            json.dumps({**prompt_record, "started_at": started_at, "finished_at": datetime.now(UTC).isoformat(), "http_status": exc.code, "error_body_sha256": hashlib.sha256(body).hexdigest()}, ensure_ascii=False, indent=2) + "\n",
        )
        raise
    choices = response.get("choices", [])
    text = choices[0].get("message", {}).get("content") if choices else None
    if not isinstance(text, str) or not text.strip():
        raise RuntimeError("empty review response")
    artifact = {
        "artifact_type": "rq1_partitioned_architecture_review",
        "part": args.part,
        "model": "gpt-5.6-sol",
        "provider_route_id": "local-cli-proxy",
        "source_bundle_sha256": bundle_sha,
        "source_manifest": manifest,
        "prompt_path": str(prompt_path.relative_to(PROJECT_ROOT)),
        "started_at": started_at,
        "finished_at": datetime.now(UTC).isoformat(),
        "latency_ms": round((time.monotonic() - started) * 1000),
        "response_model": response.get("model"),
        "usage": response.get("usage", {}),
        "response_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "raw_response": text,
    }
    _atomic_write(review_json, json.dumps(artifact, ensure_ascii=False, indent=2) + "\n")
    _atomic_write(review_md, text.rstrip() + "\n")
    print(json.dumps({"ok": True, "part": args.part, "bundle_bytes": bundle_bytes, "response_sha256": artifact["response_sha256"], "usage": artifact["usage"], "latency_ms": artifact["latency_ms"], "review_path": str(review_md.relative_to(PROJECT_ROOT))}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
