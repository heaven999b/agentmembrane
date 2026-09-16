#!/usr/bin/env python3
"""Fail closed when the public AgentMembrane checkout is unsafe or incomplete."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
STUDY_REGISTRY = ROOT / "studies" / "registry.json"
MAX_TRACKED_BYTES = 10 * 1024 * 1024
SAFE_TEXT_SUFFIXES = {
    ".csv", ".html", ".json", ".md", ".py", ".sh", ".toml", ".txt",
    ".yaml", ".yml",
}
SAFE_TEXT_FILENAMES = {".gitignore"}
# Add a repository-relative path here only after a human verifies that the
# binary is necessary, redistributable, and contains no local/private state.
ALLOWED_BINARY_FILES: frozenset[str] = frozenset()
FORBIDDEN_PATH_PARTS = {
    ".env", "__pycache__", ".pytest_cache", "runtime_envs", "site-packages",
}
FORBIDDEN_FILENAMES = {
    "local-attestation.json", "route-runtime-binding.json",
}
PRIVATE_METADATA_TOKENS = {
    "account", "auth", "credential", "provider", "proxy", "route",
}
PRIVATE_METADATA_SUFFIXES = {".json", ".yaml", ".yml"}
FORBIDDEN_PREFIXES = (
    "outputs/", "data/official/", "data/host_boundary_v2/",
)
SECRET_PATTERNS = {
    "absolute_macos_user_path": re.compile(re.escape("/" + "Users/")),
    "absolute_windows_user_path": re.compile(r"[A-Za-z]:\\Users\\"),
    "github_classic_token": re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    "github_fine_grained_token": re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    # Require a token boundary so ordinary identifiers such as
    # ``task-native-...`` are not misclassified as API keys.
    "openai_style_key": re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}"),
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "bearer_token": re.compile(r"Bearer\s+[A-Za-z0-9._~-]{24,}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "account_specific_label": re.compile(
        r"(?<![A-Za-z0-9_])" + "sub" + r"[0-9]+(?![A-Za-z0-9_])", re.I
    ),
    "account_specific_handle": re.compile(r"(?<![A-Za-z0-9_])" + "yihaiwen" + r"9(?![A-Za-z0-9_])", re.I),
    "account_specific_person_name": re.compile("衣" + "海文"),
    "private_proxy_endpoint": re.compile(
        r"(?:127\.0\.0\.1|localhost|\[::1\]):" + "831" + "7", re.I
    ),
    "private_proxy_credential_env": re.compile(r"\bRQ1_" + r"LIVE_PROXY_KEY\b"),
    "private_proxy_label": re.compile(r"\bcli_" + r"proxy_pool\b"),
}
MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\((<[^>]+>|[^)\s]+)(?:\s+['\"][^'\"]+['\"])?\)")
REQUIRED_CONSTRUCT_IDS = {
    "authority_admission_boundary",
    "host_mediated_capability_exploitation",
    "semantic_receptor_expressiveness",
    "memory_promotion_boundary",
    "authority_semantic_relationship",
}
ALLOWED_STUDY_STATUS = {"planned", "engineering", "diagnostic", "formal", "archived"}
ALLOWED_EVIDENCE_LEVEL = {"none", "engineering", "diagnostic", "formal"}


def tracked_files() -> list[Path]:
    proc = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True,
        stdout=subprocess.PIPE,
    )
    return [ROOT / item.decode("utf-8") for item in proc.stdout.split(b"\0") if item]


def validate_weekly_structure(errors: list[str]) -> list[str]:
    weekly = ROOT / "weekly_reports"
    try:
        index = (weekly / "README.md").read_text(encoding="utf-8")
        entries = list(weekly.iterdir())
    except (OSError, UnicodeDecodeError) as exc:
        errors.append(f"weekly report structure is unreadable: {type(exc).__name__}")
        return []
    weeks = sorted(
        (p.name for p in entries if p.is_dir() and re.fullmatch(r"week\d+", p.name)),
        key=lambda value: int(value[4:]),
    )
    expected = [f"week{i}" for i in range(1, 10)]
    if weeks != expected:
        errors.append(f"weekly directories are {weeks}, expected {expected}")
    for week in weeks:
        if f"[{week}/](./{week}/)" not in index and f"[{week.title()}](./{week}/)" not in index:
            errors.append(f"weekly index does not link {week}")
        if not (weekly / week / "README.md").is_file():
            errors.append(f"{week} has no README.md")
        if not list((weekly / week).glob(f"{week}_report_*.md")):
            errors.append(f"{week} has no dated report document")

    return weeks


def validate_markdown_links(files: list[Path], errors: list[str]) -> None:
    """Reject broken repository-relative links in every tracked Markdown file."""
    for doc in (path for path in files if path.suffix.lower() == ".md"):
        try:
            content = doc.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            # The main file pass reports missing or non-UTF-8 content once.
            continue
        for match in MARKDOWN_LINK.finditer(content):
            raw = match.group(1).strip("<>")
            if raw.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target_text = unquote(raw.split("#", 1)[0])
            if not target_text:
                continue
            target = (doc.parent / target_text).resolve()
            if not target.exists():
                errors.append(f"broken markdown link: {doc.relative_to(ROOT)} -> {raw}")


def validate_study_registry(
    errors: list[str],
    *,
    root: Path = ROOT,
    registry_path: Path | None = None,
) -> list[str]:
    """Validate canonical construct identity and repository-relative links."""
    path = registry_path or root / "studies" / "registry.json"
    try:
        registry = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        errors.append(f"study registry is unreadable: {type(exc).__name__}")
        return []
    if type(registry) is not dict:
        errors.append("study registry must be a JSON object")
        return []
    if registry.get("schema_version") != "agentmembrane-study-registry/1":
        errors.append("study registry schema mismatch")
    if registry.get("identity_key") != ["program_lineage", "construct_id"]:
        errors.append("study registry identity key mismatch")
    proposal = registry.get("canonical_proposal")
    if proposal != "docs/PROPOSAL.md" or not (root / str(proposal)).is_file():
        errors.append("study registry canonical proposal is missing")

    constructs = registry.get("constructs")
    if type(constructs) is not list:
        errors.append("study registry constructs must be a list")
        return []
    identities: set[tuple[str, str]] = set()
    ids: list[str] = []
    rows_by_id: dict[str, dict] = {}
    for index, row in enumerate(constructs):
        label = f"study registry construct {index}"
        if type(row) is not dict:
            errors.append(f"{label} must be an object")
            continue
        lineage = row.get("program_lineage")
        construct_id = row.get("construct_id")
        if type(lineage) is not str or type(construct_id) is not str:
            errors.append(f"{label} has invalid identity")
            continue
        identity = (lineage, construct_id)
        if identity in identities:
            errors.append(f"duplicate study registry identity: {lineage}/{construct_id}")
        identities.add(identity)
        ids.append(construct_id)
        rows_by_id[construct_id] = row
        if row.get("status") not in ALLOWED_STUDY_STATUS:
            errors.append(f"invalid status for construct {construct_id}")
        if row.get("evidence_level") not in ALLOWED_EVIDENCE_LEVEL:
            errors.append(f"invalid evidence level for construct {construct_id}")
        if type(row.get("claim_bearing")) is not bool:
            errors.append(f"invalid claim-bearing flag for construct {construct_id}")
        if not re.fullmatch(r"\d+\.\d+\.\d+", str(row.get("construct_version", ""))):
            errors.append(f"invalid construct version for {construct_id}")
        if type(row.get("rq_label")) is not str or type(row.get("proposal_alignment")) is not str:
            errors.append(f"invalid proposal mapping for construct {construct_id}")

        path_groups = row.get("paths")
        if type(path_groups) is not dict:
            errors.append(f"paths must be an object for construct {construct_id}")
            continue
        for group in ("code", "tests", "protocols", "results", "reports", "reproduce"):
            values = path_groups.get(group)
            if type(values) is not list or any(type(value) is not str for value in values):
                errors.append(f"invalid {group} paths for construct {construct_id}")
                continue
            for relative in values:
                candidate = Path(relative)
                if candidate.is_absolute() or ".." in candidate.parts:
                    errors.append(f"unsafe registry path for construct {construct_id}: {relative}")
                    continue
                resolved = (root / candidate).resolve()
                try:
                    resolved.relative_to(root.resolve())
                except ValueError:
                    errors.append(f"escaping registry path for construct {construct_id}: {relative}")
                    continue
                if not resolved.exists():
                    errors.append(f"missing registry path for construct {construct_id}: {relative}")

        aliases = row.get("legacy_aliases")
        if type(aliases) is not list or any(
            type(alias) is not dict
            or type(alias.get("label")) is not str
            or type(alias.get("meaning")) is not str
            for alias in aliases
        ):
            errors.append(f"invalid legacy aliases for construct {construct_id}")
        forbidden = row.get("pooling_forbidden_with")
        if type(forbidden) is not list or any(type(value) is not str for value in forbidden):
            errors.append(f"invalid pooling policy for construct {construct_id}")

    if set(ids) != REQUIRED_CONSTRUCT_IDS:
        errors.append(
            "study registry construct set mismatch: "
            + ", ".join(sorted(set(ids)))
        )
    for construct_id, row in rows_by_id.items():
        forbidden = row.get("pooling_forbidden_with", [])
        if type(forbidden) is not list:
            continue
        for other in forbidden:
            if other not in rows_by_id:
                errors.append(f"unknown pooling exclusion for {construct_id}: {other}")
            elif construct_id not in rows_by_id[other].get("pooling_forbidden_with", []):
                errors.append(f"asymmetric pooling exclusion: {construct_id} / {other}")
        if row.get("status") == "planned":
            paths = row.get("paths", {})
            if row.get("evidence_level") != "none" or row.get("claim_bearing") is not False:
                errors.append(f"planned construct has an evidence claim: {construct_id}")
            if type(paths) is dict and any(paths.get(group) for group in ("results", "reports")):
                errors.append(f"planned construct has published evidence paths: {construct_id}")
    return sorted(set(ids))


def main() -> int:
    errors: list[str] = []
    files = tracked_files()
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        if path.is_symlink():
            errors.append(f"tracked symbolic link requires explicit review: {relative}")
            continue
        if any(part in FORBIDDEN_PATH_PARTS for part in path.relative_to(ROOT).parts):
            errors.append(f"forbidden tracked path: {relative}")
            continue
        if path.name in FORBIDDEN_FILENAMES:
            errors.append(f"private runtime binding is tracked: {relative}")
            continue
        tokens = {token for token in re.split(r"[-_.]+", path.stem.casefold()) if token}
        if path.suffix.casefold() in PRIVATE_METADATA_SUFFIXES and tokens & PRIVATE_METADATA_TOKENS:
            errors.append(f"private route/account metadata filename is tracked: {relative}")
            continue
        if relative.startswith(FORBIDDEN_PREFIXES):
            errors.append(f"private data path is tracked: {relative}")
            continue
        if not path.is_file():
            errors.append(f"tracked path is missing: {relative}")
            continue
        try:
            size = path.stat().st_size
        except OSError as exc:
            errors.append(f"tracked path is unreadable: {relative} ({type(exc).__name__})")
            continue
        if size > MAX_TRACKED_BYTES:
            errors.append(f"tracked file exceeds 10 MiB: {relative} ({size} bytes)")
        if size > MAX_TRACKED_BYTES:
            continue
        if relative in ALLOWED_BINARY_FILES:
            continue
        if path.suffix.casefold() not in SAFE_TEXT_SUFFIXES and path.name not in SAFE_TEXT_FILENAMES:
            errors.append(f"unreviewed tracked file type: {relative}")
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except OSError as exc:
            errors.append(f"tracked file is unreadable: {relative} ({type(exc).__name__})")
            continue
        except UnicodeDecodeError:
            errors.append(f"tracked file is not UTF-8 text and is not binary-allowlisted: {relative}")
            continue
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(content):
                errors.append(f"{label} in {relative}")

    weeks = validate_weekly_structure(errors)
    validate_markdown_links(files, errors)
    construct_ids = validate_study_registry(errors)
    result = {
        "schema_version": "agentmembrane-public-repository-audit/3",
        "tracked_file_count": len(files),
        "weekly_reports": weeks,
        "construct_ids": construct_ids,
        "passed": not errors,
        "errors": sorted(set(errors)),
    }
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
