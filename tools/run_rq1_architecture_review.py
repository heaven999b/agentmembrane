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
    / "rq1-architecture-20260830"
)


SOURCE_SPECS: tuple[str | tuple[str, int, int], ...] = (
    ("docs/PROPOSAL.md", 100, 165),
    ("docs/PROPOSAL.md", 470, 555),
    "experiments/host_boundary_v2/PROTOCOL_RQ1.md",
    ("experiments/host_boundary_v2/STATISTICAL_PLAN.md", 1, 155),
    ("experiments/host_boundary_v2/STATISTICAL_PLAN.md", 225, 232),
    ("experiments/host_boundary_v2/config/estimands.json", 1, 535),
    "experiments/host_boundary_v2/config/profiles/rq1-g0-gate.template.json",
    "experiments/host_boundary_v2/config/profiles/rq1-primary-formal.template.json",
    "experiments/host_boundary_v2/config/launch-policy.json",
    ("experiments/host_boundary_v2/config/rq_coverage_manifest.json", 1, 110),
    ("agentmembrane/kernel.py", 1, 180),
    ("agentmembrane/host_v2/conditions.py", 1, 80),
    ("agentmembrane/host_v2/conditions.py", 356, 430),
    ("agentmembrane/host_v2/conditions.py", 652, 735),
    ("agentmembrane/host_v2/conditions.py", 885, 945),
    ("agentmembrane/host_v2/host.py", 268, 430),
    ("agentmembrane/host_v2/host.py", 639, 860),
    ("agentmembrane/host_v2/host.py", 1380, 1580),
    ("agentmembrane/host_v2/oracle.py", 80, 160),
    ("agentmembrane/host_v2/oracle.py", 1450, 1580),
    ("agentmembrane/host_v2/taskpack_build.py", 650, 990),
    "experiments/host_boundary_v2/public_readiness_v2.1/decision.json",
)


SYSTEM_PROMPT = """You are an independent principal architect and methods reviewer for an AI-agent security experiment. Review AgentMembrane proposal RQ1 Authority/Admission Boundary only. Produce a coding-agent-ready architecture, not code. Verify repository evidence rather than trusting status prose. Preserve historical artifacts, avoid outcome-driven metric changes, and distinguish deterministic host-enforcement evidence from adaptive end-to-end model behavior. Do not conflate canonical RQ1 authority ladder with the RQ1b host-mediated six-mechanism subtrack. Be exact about capability security, lifecycle semantics, construct validity, statistical validity, public-benchmark adapters, native checker parity, and launch gates. Quote source sparingly and cite repository-relative paths and symbols precisely. Do not call tools or claim to have executed anything."""


USER_TASK = """Design the minimum complete, scientifically defensible implementation architecture for AgentMembrane canonical RQ1.

This is a pre-implementation architecture review. Formal public-data gaps may block a formal claim, but they must not automatically block offline implementation or a deterministic scripted assay. First decide what already exists, what is reusable, what is merely a template, and what is missing. Explicitly audit the current RQ1 G0 template's use of the six Host-mediated/RQ1b controlled families and determine whether it is construct-valid for canonical RQ1.

Your deliverable must contain:
1. A precise RQ1 claim boundary and a machine-readable construct/stage naming decision.
2. A condition/contrast design covering A0-C1 through A5-C1, A5-C0 only as a positive control, and all twelve binding/lifecycle contrasts without changing more than one intended variable per contrast.
3. A model-facing admission/capability architecture: opaque signed handles, principal/operation/resource/purpose/lease/expiry/delegation/revocation binding, deterministic clock, queue/proposal/artifact lifecycle, reset semantics, and condition-blind observations.
4. A taskpack architecture for independently authored benign/adversarial twins, scripted fixed-trace assay, adaptive real-model smoke, and public AgentDojo/tau2 mapping. State whether BFCL is actually available or must be deferred.
5. Exact trusted-event and oracle endpoints for risk and benign utility. Refusal/abstention must never count as containment. State how to avoid an oracle so strict that valid benign work or equivalent successful routes collapse coverage, and how to avoid a permissive oracle that credits text claims or partial attempts.
6. Frozen estimands, denominators, eligibility, cluster unit, descriptive versus confirmatory inference, power/sampling constraints, and a strictness audit naming both false-negative and false-positive risks.
7. A dependency-ordered implementation plan split across at most five non-overlapping coding-agent ownership zones, with exact files/interfaces and merge order.
8. Unit/integration/property/mutation tests and staged gates: offline, zero-token scripted assay, small adaptive smoke, public native checker parity, then bounded real API run. Give concrete pass/fail criteria, but flag any existing threshold that is scientifically unjustified or too strict/loose.
9. A public-data/API readiness decision that accounts for current tau2 dataless placeholders and zero formal rows. Never treat reconstructed logical integrity as executed native parity.
10. Explicit do-not-change constraints, migration/versioning rules, and a final four-way verdict: safe to implement offline; safe for zero-token assay; safe for paid smoke; safe for formal/public claim.

For every blocker include evidence, root cause, minimum scientifically sufficient repair, optional strengthening, tests, acceptance criteria, and exactly which stage it blocks: offline implementation, scripted calibration, paid smoke, or formal claim. Do not demand zero leakage, perfect task purity, or formal-scale sampling merely to permit engineering work. Do not recommend a 990-episode run until the instrument, independent units, adapters, parity, and power contract genuinely justify it."""


def _source_bundle() -> tuple[str, list[dict[str, Any]], str]:
    sections: list[str] = []
    manifest: list[dict[str, Any]] = []
    digest = hashlib.sha256()
    for spec in SOURCE_SPECS:
        if isinstance(spec, tuple):
            relative, start, end = spec
        else:
            relative, start, end = spec, None, None
        path = PROJECT_ROOT / relative
        full_payload = path.read_bytes()
        full_sha = hashlib.sha256(full_payload).hexdigest()
        if start is None:
            payload = full_payload
            label = relative
        else:
            lines = full_payload.decode("utf-8").splitlines(keepends=True)
            payload = "".join(lines[start - 1 : end]).encode("utf-8")
            label = f"{relative}#L{start}-L{end}"
        row: dict[str, Any] = {
            "path": relative,
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "full_file_sha256": full_sha,
        }
        if start is not None:
            row.update({"line_start": start, "line_end": end})
        manifest.append(row)
        digest.update(json.dumps(row, sort_keys=True).encode("utf-8"))
        digest.update(payload)
        sections.append(
            f"\n===== BEGIN SOURCE: {label} =====\n"
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
    headers = {
        "Content-Type": "application/json",
        "X-Session-ID": "agentmembrane-rq1-architecture-review",
    }
    if anthropic_compatible:
        headers.update({"x-api-key": api_key, "anthropic-version": "2023-06-01"})
    else:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(
        f"{base_url}/{path.lstrip('/')}",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
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
    parser.add_argument("--max-completion-tokens", type=int, default=7000)
    parser.add_argument("--timeout-seconds", type=float, default=1800.0)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    bundle, manifest, bundle_sha = _source_bundle()
    bundle_bytes = len(bundle.encode("utf-8"))
    if bundle_bytes > 150_000:
        raise RuntimeError(f"source bundle exceeds 150000-byte disclosure cap: {bundle_bytes}")
    if args.dry_run:
        print(json.dumps({"bundle_bytes": bundle_bytes, "source_count": len(manifest), "source_bundle_sha256": bundle_sha}))
        return 0
    settings: dict[str, Any] = {
        "temperature": 0,
        "max_completion_tokens": args.max_completion_tokens,
    }
    if args.model == "gpt-5.6-sol":
        settings["reasoning_effort"] = "max"

    prompt_record = {
        "artifact_type": "rq1_independent_architecture_prompt",
        "independence_rule": "no_other_reviewer_output_in_context",
        "model": args.model,
        "provider_route_id": "local-cli-proxy",
        "created_at": datetime.now(UTC).isoformat(),
        "model_settings": settings,
        "source_bundle_sha256": bundle_sha,
        "source_manifest": manifest,
        "system_prompt": SYSTEM_PROMPT,
        "user_task": USER_TASK,
    }
    stem = args.model
    prompt_path = REVIEW_ROOT / f"{stem}-prompt.json"
    review_path = REVIEW_ROOT / f"{stem}-review.json"
    if review_path.exists() and not args.force:
        raise RuntimeError(f"review artifact already exists: {review_path}")
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
            "reasoning_effort": "max",
            "stream": False,
        }
    else:
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
        error = {
            **prompt_record,
            "started_at": started_at,
            "finished_at": datetime.now(UTC).isoformat(),
            "http_status": exc.code,
            "error_body_sha256": hashlib.sha256(body).hexdigest(),
        }
        _atomic_write(
            REVIEW_ROOT / f"{stem}-error.json",
            json.dumps(error, ensure_ascii=False, indent=2) + "\n",
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

    artifact = {
        "artifact_type": "rq1_independent_architecture_review",
        "independence_rule": "no_other_reviewer_output_in_context",
        "model": args.model,
        "provider_route_id": "local-cli-proxy",
        "requested_model_settings": settings,
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
    _atomic_write(
        review_path,
        json.dumps(artifact, ensure_ascii=False, indent=2) + "\n",
    )
    _atomic_write(REVIEW_ROOT / f"{stem}-review.md", text.rstrip() + "\n")
    print(
        json.dumps(
            {
                "ok": True,
                "model": args.model,
                "source_bundle_sha256": bundle_sha,
                "response_sha256": artifact["response_sha256"],
                "usage": artifact["usage"],
                "latency_ms": artifact["latency_ms"],
                "review_path": str((REVIEW_ROOT / f"{stem}-review.md").relative_to(PROJECT_ROOT)),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
