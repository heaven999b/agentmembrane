"""Run the zero-model CLIProxy lifecycle rehearsal for RQ1 three-tier.

This command starts the exact route-bound local proxy, performs one readiness
inventory request, stops it, removes its secret root, and writes a create-only
receipt.  It makes no generation call, allocates no research cell, and cannot
be counted as RQ1 evidence.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[1]
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

from agentmembrane.host_v2.rq1_three_tier_formal_v1.gate import (
    code_bundle_sha256,
)
from agentmembrane.host_v2.rq1_three_tier_formal_v1.proxy_lifecycle import (
    rehearse_bound_proxy_lifecycle,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--route-binding", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    receipt = rehearse_bound_proxy_lifecycle(
        route_binding_path=args.route_binding,
        code_bundle_sha256=code_bundle_sha256(),
        output=args.output,
    )
    print(json.dumps({
        "receipt": str(args.output.resolve()),
        "receipt_sha256": receipt["receipt_sha256"],
        "generation_calls": 0,
        "formal_actor_calls": 0,
        "research_sample_count": 0,
        "cleanup_completed": True,
    }, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
