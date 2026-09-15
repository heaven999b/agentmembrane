"""Mode-explicit selector for the versioned public four-cell overlay.

``rq2`` is intentionally a byte-level selector: it parses and hashes only the
new overlay/configuration plus the exact immutable public source files.  It
does not import or inspect the existing active RQ1 implementation.  ``rq1`` is
an opaque locator only and likewise performs no inspection of that stack.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence


SELECTOR_ID = "agentmembrane-public-four-cell-mode-selector-v1"
OVERLAY_PREFIX = Path("agentmembrane/host_v2/public_four_cell_v1")
CONFIG_PREFIX = Path("experiments/host_boundary_v2/public_four_cell_v1/config")
UPSTREAM_PREFIX = Path("data/host_boundary_v2/packs/agentdojo-v0.1.35-v1")
EXPECTED_CONFIG_FILES = (
    "authorization.json",
    "derived-pack.json",
    "eligibility.json",
    "materialization-manifest.json",
    "model-visible-input.json",
    "profile.json",
    "prompt-authority-manifest.json",
    "run-chain-manifest.json",
)
IMMUTABLE_UPSTREAM_FILES = (
    "manifest.json",
    "tasks.jsonl",
    "fixtures/agentdojo-v1-banking-u3-i1-adversarial.json",
    "fixtures/agentdojo-v1-banking-u3-i1-benign.json",
    "oracles/agentdojo-v1-banking-u3-i1.json",
)
FORBIDDEN_SHARED_PATH_FRAGMENTS = (
    "agentmembrane/host_v2/planner.py",
    "agentmembrane/host_v2/runner.py",
    "agentmembrane/host_v2/cache.py",
    "agentmembrane/host_v2/public_canary.py",
    "agentmembrane/host_v2/public_host_bridge.py",
    "agentmembrane/host_v2/conditions.py",
    "agentmembrane/host_v2/analysis.py",
    "agentmembrane/host_v2/schedule.py",
    "agentmembrane/host_v2/schema.py",
    "agentmembrane/host_v2/integrity.py",
    "agentmembrane/proxy.py",
    "experiments/host_boundary_v2/config/conditions.json",
    "experiments/host_boundary_v2/config/prompts/",
)


class SelectionError(ValueError):
    """Raised when the requested selector mode escapes its byte boundary."""


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _repo_file(repo_root: Path, relative: Path, *, label: str) -> Path:
    if relative.is_absolute() or ".." in relative.parts:
        raise SelectionError(f"{label} must be repository-relative")
    root = Path(repo_root).resolve()
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise SelectionError(f"{label} escapes the repository") from exc
    if not path.is_file():
        raise SelectionError(f"{label} is missing: {relative.as_posix()}")
    return path


def _binding(repo_root: Path, relative: Path, *, label: str) -> dict[str, str]:
    path = _repo_file(repo_root, relative, label=label)
    return {"path": relative.as_posix(), "sha256": _sha256(path.read_bytes())}


def _json_object(repo_root: Path, relative: Path, *, label: str) -> dict[str, Any]:
    path = _repo_file(repo_root, relative, label=label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SelectionError(f"cannot parse {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise SelectionError(f"{label} must contain a JSON object")
    return value


def _reject_shared_path(value: Any, *, label: str) -> None:
    """Inspect already-parsed strings without opening any referenced file."""

    if isinstance(value, str):
        if any(fragment in value for fragment in FORBIDDEN_SHARED_PATH_FRAGMENTS):
            raise SelectionError(f"{label} references forbidden shared active bytes")
        return
    if isinstance(value, Mapping):
        for key, child in value.items():
            _reject_shared_path(child, label=f"{label}.{key}")
        return
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _reject_shared_path(child, label=f"{label}[{index}]")


def _rq1_selection() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "artifact_type": "agentmembrane_mode_selection",
        "selector_id": SELECTOR_ID,
        "mode": "rq1",
        "execution_authorized": False,
        "selection_kind": "opaque_locator_only",
        "opaque_locator": "agentmembrane://host-v2/rq1/current-active-stack",
        "byte_bindings": [],
        "dependency_audit": {
            "shared_rq1_bytes_parsed": False,
            "shared_rq1_bytes_hashed": False,
            "shared_rq1_modules_imported": False,
            "opaque_delegation_only": True,
        },
    }


def _rq2_selection(repo_root: Path) -> dict[str, Any]:
    root = Path(repo_root).resolve()
    config_bindings = [
        _binding(root, CONFIG_PREFIX / name, label=f"RQ2 config {name}")
        for name in EXPECTED_CONFIG_FILES
    ]
    overlay_paths = tuple(
        sorted(
            path.relative_to(root)
            for path in (root / OVERLAY_PREFIX).glob("*.py")
            if path.is_file()
        )
    )
    if not overlay_paths:
        raise SelectionError("RQ2 overlay contains no Python files")
    overlay_bindings = [
        _binding(root, relative, label=f"RQ2 overlay {relative.name}")
        for relative in overlay_paths
    ]
    upstream_bindings = [
        _binding(root, UPSTREAM_PREFIX / relative, label=f"immutable upstream {relative}")
        for relative in IMMUTABLE_UPSTREAM_FILES
    ]

    profile = _json_object(root, CONFIG_PREFIX / "profile.json", label="RQ2 profile")
    authorization = _json_object(
        root, CONFIG_PREFIX / "authorization.json", label="RQ2 authorization"
    )
    manifest = _json_object(
        root,
        CONFIG_PREFIX / "materialization-manifest.json",
        label="RQ2 materialization manifest",
    )
    for label, document in (
        ("profile", profile),
        ("authorization", authorization),
        ("materialization_manifest", manifest),
    ):
        if document.get("execution_authorized") is not False:
            raise SelectionError(f"RQ2 {label} does not fail closed")
        _reject_shared_path(document, label=label)

    implementation_bindings = profile.get("implementation_bindings")
    if not isinstance(implementation_bindings, Mapping):
        raise SelectionError("RQ2 profile lacks implementation_bindings")
    overlay_bound_paths = {row["path"] for row in overlay_bindings}
    for name, row in implementation_bindings.items():
        if not isinstance(row, Mapping) or row.get("path") not in overlay_bound_paths:
            raise SelectionError(
                f"RQ2 implementation binding {name!r} is outside the versioned overlay"
            )
        actual = next(
            binding for binding in overlay_bindings if binding["path"] == row["path"]
        )
        if row.get("sha256") != actual["sha256"]:
            raise SelectionError(f"RQ2 implementation binding {name!r} drifted")

    declared = manifest.get("documents")
    if not isinstance(declared, Mapping):
        raise SelectionError("RQ2 materialization manifest lacks document bindings")
    config_by_name = {Path(row["path"]).name: row for row in config_bindings}
    for name in set(EXPECTED_CONFIG_FILES) - {"materialization-manifest.json"}:
        row = declared.get(name)
        if not isinstance(row, Mapping) or row.get("sha256") != config_by_name[name]["sha256"]:
            raise SelectionError(f"RQ2 config binding drifted: {name}")

    return {
        "schema_version": 1,
        "artifact_type": "agentmembrane_mode_selection",
        "selector_id": SELECTOR_ID,
        "mode": "rq2",
        "execution_authorized": False,
        "selection_kind": "versioned_public_four_cell_byte_binding",
        "byte_bindings": {
            "overlay": overlay_bindings,
            "config": config_bindings,
            "immutable_upstream_public_data": upstream_bindings,
        },
        "dependency_audit": {
            "shared_rq1_bytes_parsed": False,
            "shared_rq1_bytes_hashed": False,
            "shared_rq1_modules_imported": False,
            "bound_scope_exact": [
                OVERLAY_PREFIX.as_posix(),
                CONFIG_PREFIX.as_posix(),
                *[(UPSTREAM_PREFIX / relative).as_posix() for relative in IMMUTABLE_UPSTREAM_FILES],
            ],
            "forbidden_shared_reference_count": 0,
        },
    }


def select_mode(*, mode: str, repo_root: Path) -> dict[str, Any]:
    """Select ``rq1`` opaquely or bind the isolated ``rq2`` overlay bytes."""

    if mode == "rq1":
        return _rq1_selection()
    if mode == "rq2":
        return _rq2_selection(Path(repo_root))
    raise SelectionError("mode must be exactly 'rq1' or 'rq2'")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("rq1", "rq2"), required=True)
    parser.add_argument("--repo-root", type=Path, required=True)
    arguments = parser.parse_args(argv)
    result = select_mode(mode=arguments.mode, repo_root=arguments.repo_root)
    print(_canonical_json_bytes(result).decode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["SELECTOR_ID", "SelectionError", "main", "select_mode"]
