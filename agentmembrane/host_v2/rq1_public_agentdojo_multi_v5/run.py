"""Command-line orchestration for the frozen RQ1 v5 production run."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ..schema import canonical_json_bytes
from .analysis import analyze_executor_namespace
from .executor import (
    build_authorization_document,
    build_profile_document,
    execute_canary_v5,
    execute_continuation_v5,
)
from .gate import run_zero_token_integration_gate


REPO_ROOT = Path(__file__).resolve().parents[3]
OUTPUT_ROOT = REPO_ROOT / "experiments/host_boundary_v2/rq1_public_agentdojo_multi_v5/runs"
GATE_PATH = REPO_ROOT / "experiments/host_boundary_v2/rq1_public_agentdojo_multi_v5/zero_token_gate.json"


def _write_gate(value: dict[str, Any]) -> None:
    payload = canonical_json_bytes(value) + b"\n"
    GATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    if GATE_PATH.exists():
        if GATE_PATH.read_bytes() != payload:
            raise RuntimeError("persisted v5 gate differs from live gate")
    else:
        GATE_PATH.write_bytes(payload)


def _documents(namespace: str) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    gate = run_zero_token_integration_gate()
    _write_gate(gate)
    profile = build_profile_document(REPO_ROOT, gate_receipt=gate)
    authorization = build_authorization_document(profile=profile, namespace=namespace)
    return gate, profile, authorization


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("gate")
    canary = sub.add_parser("canary")
    canary.add_argument("namespace")
    continuation = sub.add_parser("continue")
    continuation.add_argument("namespace")
    analysis = sub.add_parser("analyze")
    analysis.add_argument("namespace")
    args = parser.parse_args()

    if args.command == "gate":
        gate = run_zero_token_integration_gate()
        _write_gate(gate)
        result: Any = gate
    elif args.command == "canary":
        gate, profile, authorization = _documents(args.namespace)
        result = execute_canary_v5(
            repo_root=REPO_ROOT,
            output_root=OUTPUT_ROOT,
            namespace=args.namespace,
            gate_receipt=gate,
            profile=profile,
            authorization=authorization,
        )
    elif args.command == "continue":
        gate, profile, authorization = _documents(args.namespace)
        result = execute_continuation_v5(
            repo_root=REPO_ROOT,
            namespace_path=OUTPUT_ROOT / args.namespace,
            gate_receipt=gate,
            profile=profile,
            authorization=authorization,
        )
    else:
        result = analyze_executor_namespace(OUTPUT_ROOT / args.namespace)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
