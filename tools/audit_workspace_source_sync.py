#!/usr/bin/env python3
"""Verify that publishable source in a private workspace is in this checkout.

The comparison is deliberately one-way: the public checkout may contain release
audits and bootstrap helpers that the data workspace does not need. Private run
launchers and tests that can resume an archived campaign are outside the public
source set and must be listed explicitly below instead of disappearing silently.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


PUBLIC_ROOT = Path(__file__).resolve().parents[1]
PRIVATE_EXCLUSIONS = {
    "tests/test_rq1_large_campaign_runner.py": (
        "archived diagnostic campaign continuation test; depends on private route "
        "and sealed run artifacts and is forbidden from the formal campaign"
    ),
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def selected_files(root: Path) -> dict[str, Path]:
    selected: dict[str, Path] = {}
    for top in ("agentmembrane", "tests"):
        base = root / top
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if (not path.is_file() or path.is_symlink()
                    or "__pycache__" in path.parts
                    or path.suffix in {".pyc", ".pyo"}):
                continue
            relative = path.relative_to(root).as_posix()
            if relative not in PRIVATE_EXCLUSIONS:
                selected[relative] = path
    tools = root / "tools"
    if tools.is_dir():
        for path in tools.glob("*.py"):
            if path.is_file() and not path.is_symlink():
                selected[path.relative_to(root).as_posix()] = path
    return selected


def audit(private_root: Path) -> dict:
    private = selected_files(private_root)
    missing: list[str] = []
    different: list[str] = []
    for relative, source in sorted(private.items()):
        public = PUBLIC_ROOT / relative
        if not public.is_file() or public.is_symlink():
            missing.append(relative)
        elif digest(source) != digest(public):
            different.append(relative)
    exclusions_present = {
        relative: reason
        for relative, reason in PRIVATE_EXCLUSIONS.items()
        if (private_root / relative).is_file()
    }
    body = {
        "schema_version": "agentmembrane-workspace-source-sync-audit/1",
        "private_publishable_file_count": len(private),
        "public_match_count": len(private) - len(missing) - len(different),
        "missing_public_files": missing,
        "content_mismatches": different,
        "explicit_private_exclusions": exclusions_present,
        "raw_data_compared": False,
        "runtime_artifacts_compared": False,
    }
    return {**body, "passed": not missing and not different}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-workspace", required=True, type=Path)
    args = parser.parse_args()
    root = args.private_workspace.resolve()
    if not root.is_dir() or root == PUBLIC_ROOT:
        raise SystemExit("a distinct private workspace directory is required")
    result = audit(root)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
