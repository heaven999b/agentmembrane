"""Bounded generation checks for the registered models, not research episodes.

Only an innocuous constant prompt is submitted. No model substitution, native
tool, retry, secret-bearing response body, or experimental task is involved.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import time
from pathlib import Path

from ..rq1_collab_v1.audit import canonical, strict_loads, _write_new
from ..rq1_collab_v1.providers import ProviderFailure, response_error_metadata, safe_response_metadata
from ..rq1_collab_v3.contract import DEFAULT_MODELS
from ..rq1_collab_v3.proxy_transport import dedicated_proxy_transport


def _write(path, value):
    _write_new(Path(path), canonical(value) + b"\n")


def build_probe_payload(profile):
    return {**profile, "max_completion_tokens": 512, "stream": False,
               "store": False, "n": 1,
               "messages": [{"role": "user", "content": "Reply with only the word OK."}]}


def probe_profile(profile, transport):
    body = canonical(build_probe_payload(profile))
    result = {"requested_profile": profile, "probe_max_completion_tokens": 512,
              "request_sha256": hashlib.sha256(body).hexdigest(),
              "generation_verified": False, "automatic_substitution": False,
              "research_samples": 0, "native_tool_calls": 0,
              "transport_invocations": 0}
    try:
        transport.prepare()
        result["transport_invocations"] = 1
        response = transport(body)
        result.update(http_status=response.status, body_complete=response.body_complete)
        if transport.contains_credential(response.body):
            return {**result, "status": "response_quarantined"}
        result["response_sha256"] = hashlib.sha256(response.body).hexdigest()
        result["response_metadata"] = safe_response_metadata(getattr(response, "response_metadata", {}))
        if not response.body_complete:
            return {**result, "status": "incomplete_response"}
        if response.status != 200:
            # Never log arbitrary gateway error messages or returned endpoints.
            result["response_metadata"].update(response_error_metadata(response.body))
            return {**result, "status": "gateway_error", "error_code":
                    result["response_metadata"].get("error_code", "unclassified_gateway_error")}
        value = strict_loads(response.body)
        if type(value) is not dict:
            return {**result, "status": "invalid_response"}
        model = value.get("model")
        if type(model) is str and re.fullmatch(r"[A-Za-z0-9_.:/-]{1,256}", model):
            result["returned_model"] = model
        if model != profile["model"]:
            return {**result, "status": "returned_model_mismatch"}
        choices = value.get("choices")
        if type(choices) is not list or len(choices) != 1 or type(choices[0]) is not dict:
            return {**result, "status": "invalid_response"}
        choice = choices[0]
        message = choice.get("message")
        content = message.get("content") if type(message) is dict else None
        result["generation_verified"] = type(content) is str and bool(content.strip())
        result["expected_reply"] = type(content) is str and content.strip() == "OK"
        usage = value.get("usage", {})
        if type(usage) is dict:
            result["reported_usage"] = {k: usage[k] for k in ("prompt_tokens", "completion_tokens", "total_tokens")
                                         if type(usage.get(k)) is int and usage[k] >= 0}
        result["status"] = "generation_observed" if result["generation_verified"] else "no_text_generation"
        # The returned model identifier is transport evidence, not cryptographic
        # proof of the provider's internal model identity or its full tool API.
        result["model_identity_independently_attested"] = False
        return result
    except ProviderFailure as exc:
        return {**result, "status": "transport_failed", "failure": exc.audit_metadata()}
    except Exception as exc:
        return {**result, "status": "invalid_response_or_transport", "error_type": type(exc).__name__}


def run(output, *, execute_live=False, factory=None):
    if not execute_live:
        raise ValueError("explicit_live_probe_required")
    root = Path(output)
    root.mkdir(parents=True, exist_ok=False, mode=0o700)
    _write(root / "allocation.json", {"schema_version": "rq1-model-probe-allocation/1",
        "profiles": DEFAULT_MODELS, "created_at_unix": time.time(),
        "prompt": "Reply with only the word OK.", "max_completion_tokens_per_request": 512,
        "max_requests": 3, "native_tools": False, "research_samples": 0, "automatic_retry": False})
    factory = factory or (lambda: dedicated_proxy_transport(timeout_seconds=30))
    rows = []
    for actor, profile in DEFAULT_MODELS.items():
        _write(root / (actor + "-started.json"), {"actor": actor, "profile": profile, "started_at_unix": time.time()})
        try:
            result = probe_profile(profile, factory())
        except Exception as exc:
            result = {"status": "setup_failed", "error_type": type(exc).__name__,
                      "generation_verified": False, "transport_invocations": 0}
        row = {"actor": actor, **result}
        _write(root / (actor + "-result.json"), row)
        rows.append(row)
    summary = {"schema_version": "rq1-model-probe/1", "rows": rows,
        "generation_verified": all(r["generation_verified"] for r in rows),
        "transport_invocations": sum(r["transport_invocations"] for r in rows),
        "research_samples": 0, "formal_ready": False, "automatic_substitution": False}
    _write(root / "summary.json", summary)
    return summary


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True)
    p.add_argument("--execute-live", action="store_true")
    args = p.parse_args()
    result = run(args.output, execute_live=args.execute_live)
    print(canonical(result).decode())
    return 0 if result["generation_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
