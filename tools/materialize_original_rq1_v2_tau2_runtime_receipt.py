#!/usr/bin/env python3
"""Materialize a reproducible receipt for the frozen tau2 knowledge runtime."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess


REPO_ROOT = Path(__file__).resolve().parents[1]
RUNTIME = (
    REPO_ROOT
    / "experiments/host_boundary_v2/runtime_envs/"
    "tau2-py3123-lock-62d3a8c4807b-knowledge-frozen-v1"
)
CHECKOUT = REPO_ROOT / "data/host_boundary_v2/upstream/tau2-bench-a2c0247-runtime"
RECEIPT = (
    REPO_ROOT
    / "experiments/host_boundary_v2/runtime_envs/receipts/"
    "tau2-py3123-lock-62d3a8c4807b-knowledge-frozen-v1.json"
)
EXPECTED_COMMIT = "a2c024725189473d2d7cea3a5cfdbcc67478e41f"
MODULES = ("tau2", "rank_bm25", "numpy", "litellm", "openai", "pydantic")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_manifest(root: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if "__pycache__" in relative.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        rows[str(relative)] = _sha(path)
    return rows


def _probe() -> dict:
    program = r'''
import importlib
import importlib.metadata
import json
import platform
import sys

names = ("tau2", "rank_bm25", "numpy", "litellm", "openai", "pydantic")
rows = {}
for name in names:
    module = importlib.import_module(name)
    distribution = "rank-bm25" if name == "rank_bm25" else name
    rows[name] = {
        "origin": str(module.__file__),
        "version": importlib.metadata.version(distribution),
    }
installed = sorted(
    {
        (dist.metadata.get("Name") or "").casefold(): dist.version
        for dist in importlib.metadata.distributions()
        if dist.metadata.get("Name")
    }.items()
)
print(json.dumps({
    "executable": sys.executable,
    "python_version": platform.python_version(),
    "modules": rows,
    "installed_distributions": installed,
}, sort_keys=True))
'''
    output = subprocess.check_output(
        [str(RUNTIME / "bin/python"), "-c", program],
        cwd=REPO_ROOT,
        text=True,
    )
    return json.loads(output)


def main() -> int:
    if not (RUNTIME / "bin/python").is_file():
        raise SystemExit(f"missing frozen runtime: {RUNTIME}")
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=CHECKOUT, text=True
    ).strip()
    if commit != EXPECTED_COMMIT:
        raise SystemExit(f"unexpected tau2 commit: {commit}")
    tracked_status = subprocess.check_output(
        ["git", "status", "--short", "--untracked-files=no"],
        cwd=CHECKOUT,
        text=True,
    ).strip()
    if tracked_status:
        raise SystemExit("frozen tau2 checkout has tracked-file drift")

    probe = _probe()
    runtime_prefix = str(RUNTIME.resolve()) + "/"
    checkout_prefix = str(CHECKOUT.resolve()) + "/"
    origins_ok = all(
        row["origin"].startswith(runtime_prefix)
        or (name == "tau2" and row["origin"].startswith(checkout_prefix))
        for name, row in probe["modules"].items()
    )
    if not origins_ok:
        raise SystemExit("a critical import resolved outside the frozen runtime")
    if probe["modules"]["rank_bm25"]["version"] != "0.2.2":
        raise SystemExit("rank-bm25 version is not the lockfile version")

    tree = _tree_manifest(RUNTIME)
    tree_sha256 = hashlib.sha256(
        json.dumps(tree, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    receipt = {
        "schema_version": 1,
        "artifact_type": "original_rq1_tau2_frozen_runtime_receipt",
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scientific_status": "development_runtime_provenance",
        "formal_holdout_touched": False,
        "runtime": str(RUNTIME),
        "construction": {
            "tool": "uv sync",
            "arguments": ["--frozen", "--extra", "knowledge", "--no-dev"],
            "uv_version": subprocess.check_output(
                [
                    str(
                        REPO_ROOT
                        / "experiments/host_boundary_v2/runtime_envs/"
                        "bootstrap-uv-0.8.17-py312/bin/uv"
                    ),
                    "--version",
                ],
                text=True,
            ).strip(),
        },
        "checkout": str(CHECKOUT),
        "checkout_commit": commit,
        "checkout_tracked_clean": True,
        "pyproject_sha256": _sha(CHECKOUT / "pyproject.toml"),
        "uv_lock_sha256": _sha(CHECKOUT / "uv.lock"),
        "probe": probe,
        "critical_import_origins_valid": origins_ok,
        "rank_bm25_module_sha256": _sha(
            Path(probe["modules"]["rank_bm25"]["origin"])
        ),
        "runtime_tree_file_count_excluding_bytecode": len(tree),
        "runtime_tree_sha256_excluding_bytecode": tree_sha256,
        "runtime_tree_manifest": tree,
    }
    RECEIPT.parent.mkdir(parents=True, exist_ok=True)
    with RECEIPT.open("x", encoding="utf-8") as handle:
        json.dump(receipt, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    print(RECEIPT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
