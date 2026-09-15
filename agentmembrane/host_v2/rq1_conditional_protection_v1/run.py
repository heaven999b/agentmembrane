"""CLI for the zero-model RQ1 conditional protection supplement."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from ..schema import canonical_json_bytes
from .baseline import run_baseline, validate_report


REPO_ROOT = Path(__file__).resolve().parents[3]
OUTPUT_ROOT = REPO_ROOT / "experiments/host_boundary_v2/rq1_conditional_protection_v1/runs"


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise RuntimeError("conditional report must be an object")
    return value


def _write_new(path: Path, value: dict[str, Any]) -> None:
    payload = canonical_json_bytes(value) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=False)
    path.write_bytes(payload)


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    execute = sub.add_parser("execute")
    execute.add_argument("namespace")
    validate = sub.add_parser("validate")
    validate.add_argument("report", type=Path)
    args = parser.parse_args()

    if args.command == "execute":
        output = OUTPUT_ROOT / args.namespace / "report.json"
        if output.parent.exists():
            raise RuntimeError("conditional namespace already exists")
        result = run_baseline(repo_root=REPO_ROOT)
        _write_new(output, result)
    else:
        result = validate_report(_read(args.report), repo_root=REPO_ROOT)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
