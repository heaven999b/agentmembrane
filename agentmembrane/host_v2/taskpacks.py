"""Frozen task-pack and public-benchmark candidate-manifest loading.

The loaders in this module deliberately fail closed.  A file being valid JSON
is not sufficient for claim-bearing use: provenance fields and every declared
content hash must agree with files on disk.  Candidate manifests are research
selection inventories, not executable task packs, and therefore have separate
loaders.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from .schema import (
    IntegrityError,
    SchemaError,
    TaskOrigin,
    canonical_json_bytes,
    load_json,
    sha256_bytes,
    validate_json,
)


_HEX = frozenset("0123456789abcdef")
_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "pack_id",
        "title",
        "origin",
        "claim_eligible",
        "upstream",
        "transformation",
        "fixtures",
        "task_count",
        "cluster_count",
        "splits",
    }
)
_UPSTREAM_FIELDS = frozenset(
    {"name", "url", "version_or_commit", "license", "retrieved_at", "raw_files"}
)
_TRANSFORMATION_FIELDS = frozenset(
    {"script_path", "script_sha256", "parameters", "tasks_sha256"}
)
_FILE_FIELDS = frozenset({"path", "sha256"})
_TASK_FIELDS = frozenset(
    {
        "task_id",
        "cluster_id",
        "domain_id",
        "origin",
        "split",
        "pair_id",
        "pair_role",
        "family",
        "surface_task",
        "authorized_test_objective",
        "fixture_ref",
        "oracle_ref",
        "metadata",
    }
)
_INDEPENDENCE_KEYS = (
    "upstream_task_id",
    "workflow_id",
    "environment_id",
    "document_id",
    "source_template_id",
)
_PUBLIC_REAL_LABELS = frozenset(
    {"public_real", "real_workflow_sandboxed", "public_benchmark"}
)


@dataclass(frozen=True)
class TaskSpec:
    task_id: str
    cluster_id: str
    domain_id: str
    origin: TaskOrigin
    split: str
    pair_id: str
    pair_role: str
    family: str
    surface_task: str
    authorized_test_objective: str | None
    fixture_ref: str
    oracle_ref: str
    metadata: dict[str, Any]


@dataclass(frozen=True)
class TaskPack:
    pack_id: str
    manifest: dict[str, Any]
    tasks: tuple[TaskSpec, ...]
    root: Path


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SchemaError(f"{label} must be an object")
    return value


def _require_exact_fields(value: Mapping[str, Any], fields: frozenset[str], label: str) -> None:
    actual = frozenset(value)
    missing = sorted(fields - actual)
    unknown = sorted(actual - fields)
    if missing or unknown:
        raise SchemaError(f"{label} fields invalid: missing={missing}, unknown={unknown}")


def _require_nonempty_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SchemaError(f"{label} must be a nonempty string")
    return value


def _require_count(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SchemaError(f"{label} must be a nonnegative integer")
    return value


def _require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in _HEX for c in value):
        raise SchemaError(f"{label} must be a lowercase SHA-256 hex string")
    return value


def _resolve_pack_file(root: Path, declared: Any, label: str) -> Path:
    rel = Path(_require_nonempty_string(declared, label))
    if rel.is_absolute() or ".." in rel.parts:
        raise IntegrityError(f"{label} must remain inside the task-pack root: {rel}")
    root_resolved = root.resolve()
    resolved = (root_resolved / rel).resolve()
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise IntegrityError(f"{label} escapes the task-pack root: {rel}") from exc
    if not resolved.is_file():
        raise IntegrityError(f"{label} does not name a regular file: {rel}")
    return resolved


def _file_sha256(path: Path) -> str:
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as exc:
        raise IntegrityError(f"could not read hashed file {path}: {exc}") from exc


def _parse_file_entries(value: Any, label: str, *, nonempty: bool) -> tuple[dict[str, str], ...]:
    if not isinstance(value, list) or (nonempty and not value):
        qualifier = "nonempty " if nonempty else ""
        raise SchemaError(f"{label} must be a {qualifier}list")
    entries: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        item = _require_object(raw, f"{label}[{index}]")
        _require_exact_fields(item, _FILE_FIELDS, f"{label}[{index}]")
        path = _require_nonempty_string(item["path"], f"{label}[{index}].path")
        sha = _require_sha256(item["sha256"], f"{label}[{index}].sha256")
        if path in seen:
            raise SchemaError(f"duplicate declared file in {label}: {path}")
        seen.add(path)
        entries.append({"path": path, "sha256": sha})
    return tuple(entries)


def _validate_manifest(manifest: dict[str, Any]) -> None:
    validate_json(manifest, schema_name="taskpack_manifest")
    _require_exact_fields(manifest, _MANIFEST_FIELDS, "manifest")
    if manifest["schema_version"] != 2:
        raise SchemaError("manifest.schema_version must equal 2")
    _require_nonempty_string(manifest["pack_id"], "manifest.pack_id")
    _require_nonempty_string(manifest["title"], "manifest.title")
    try:
        origin = TaskOrigin(manifest["origin"])
    except (TypeError, ValueError) as exc:
        raise SchemaError(f"invalid manifest.origin: {manifest['origin']!r}") from exc
    if not isinstance(manifest["claim_eligible"], bool):
        raise SchemaError("manifest.claim_eligible must be boolean")
    if origin is TaskOrigin.AUTHORED_SYNTHETIC and manifest["claim_eligible"]:
        raise IntegrityError("authored_synthetic task packs cannot be claim eligible")

    upstream = _require_object(manifest["upstream"], "manifest.upstream")
    _require_exact_fields(upstream, _UPSTREAM_FIELDS, "manifest.upstream")
    _require_nonempty_string(upstream["name"], "manifest.upstream.name")
    url = _require_nonempty_string(upstream["url"], "manifest.upstream.url")
    if origin is TaskOrigin.PUBLIC_BENCHMARK and not url.startswith(("https://", "http://")):
        raise SchemaError("public benchmark upstream.url must be an HTTP(S) source")
    _require_nonempty_string(
        upstream["version_or_commit"], "manifest.upstream.version_or_commit"
    )
    license_name = _require_nonempty_string(upstream["license"], "manifest.upstream.license")
    if license_name.casefold() in {"unknown", "none", "n/a"}:
        raise IntegrityError("claim-bearing provenance requires a known upstream license")
    _require_nonempty_string(upstream["retrieved_at"], "manifest.upstream.retrieved_at")
    _parse_file_entries(upstream["raw_files"], "manifest.upstream.raw_files", nonempty=True)

    transformation = _require_object(manifest["transformation"], "manifest.transformation")
    _require_exact_fields(transformation, _TRANSFORMATION_FIELDS, "manifest.transformation")
    _require_nonempty_string(
        transformation["script_path"], "manifest.transformation.script_path"
    )
    _require_sha256(
        transformation["script_sha256"], "manifest.transformation.script_sha256"
    )
    if not isinstance(transformation["parameters"], dict):
        raise SchemaError("manifest.transformation.parameters must be an object")
    _require_sha256(transformation["tasks_sha256"], "manifest.transformation.tasks_sha256")
    _parse_file_entries(manifest["fixtures"], "manifest.fixtures", nonempty=True)
    _require_count(manifest["task_count"], "manifest.task_count")
    _require_count(manifest["cluster_count"], "manifest.cluster_count")
    splits = _require_object(manifest["splits"], "manifest.splits")
    if "gate" not in splits or "formal" not in splits:
        raise SchemaError("manifest.splits must include gate and formal")
    for split, count in splits.items():
        _require_nonempty_string(split, "manifest.splits key")
        _require_count(count, f"manifest.splits[{split!r}]")


def _parse_task(raw: Any, *, line_number: int, manifest_origin: TaskOrigin) -> TaskSpec:
    item = _require_object(raw, f"tasks.jsonl line {line_number}")
    _require_exact_fields(item, _TASK_FIELDS, f"tasks.jsonl line {line_number}")
    try:
        origin = TaskOrigin(item["origin"])
    except (TypeError, ValueError) as exc:
        raise SchemaError(f"invalid task origin at line {line_number}: {item['origin']!r}") from exc
    if origin is not manifest_origin:
        raise IntegrityError(
            f"task origin at line {line_number} differs from the task-pack manifest"
        )
    objective = item["authorized_test_objective"]
    if objective is not None:
        objective = _require_nonempty_string(
            objective, f"tasks.jsonl line {line_number}.authorized_test_objective"
        )
    metadata = _require_object(item["metadata"], f"tasks.jsonl line {line_number}.metadata")
    return TaskSpec(
        task_id=_require_nonempty_string(item["task_id"], f"tasks line {line_number}.task_id"),
        cluster_id=_require_nonempty_string(
            item["cluster_id"], f"tasks line {line_number}.cluster_id"
        ),
        domain_id=_require_nonempty_string(
            item["domain_id"], f"tasks line {line_number}.domain_id"
        ),
        origin=origin,
        split=_require_nonempty_string(item["split"], f"tasks line {line_number}.split"),
        pair_id=_require_nonempty_string(item["pair_id"], f"tasks line {line_number}.pair_id"),
        pair_role=_require_nonempty_string(
            item["pair_role"], f"tasks line {line_number}.pair_role"
        ),
        family=_require_nonempty_string(item["family"], f"tasks line {line_number}.family"),
        surface_task=_require_nonempty_string(
            item["surface_task"], f"tasks line {line_number}.surface_task"
        ),
        authorized_test_objective=objective,
        fixture_ref=_require_nonempty_string(
            item["fixture_ref"], f"tasks line {line_number}.fixture_ref"
        ),
        oracle_ref=_require_nonempty_string(
            item["oracle_ref"], f"tasks line {line_number}.oracle_ref"
        ),
        metadata=deepcopy(metadata),
    )


def _read_tasks(path: Path, *, manifest_origin: TaskOrigin) -> tuple[TaskSpec, ...]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise SchemaError(f"could not read {path}: {exc}") from exc
    tasks: list[TaskSpec] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            raise SchemaError(f"blank line is not allowed in tasks.jsonl at line {line_number}")
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SchemaError(f"invalid JSON at tasks.jsonl line {line_number}: {exc}") from exc
        tasks.append(_parse_task(raw, line_number=line_number, manifest_origin=manifest_origin))
    return tuple(tasks)


def _task_as_json(task: TaskSpec) -> dict[str, Any]:
    value = asdict(task)
    value["origin"] = task.origin.value
    return value


def _validate_task_relations(pack: TaskPack) -> None:
    task_ids: set[str] = set()
    pair_clusters: dict[str, str] = {}
    source_clusters: dict[tuple[str, str], str] = {}
    split_source_values: dict[tuple[str, str], set[str]] = {}
    task_by_id = {task.task_id: task for task in pack.tasks}
    declared_fixtures = {entry["path"] for entry in pack.manifest["fixtures"]}

    for task in pack.tasks:
        if task.task_id in task_ids:
            raise IntegrityError(f"duplicate task_id: {task.task_id}")
        task_ids.add(task.task_id)
        if task.split not in pack.manifest["splits"]:
            raise IntegrityError(f"task {task.task_id} uses undeclared split {task.split!r}")
        if task.fixture_ref not in declared_fixtures:
            raise IntegrityError(
                f"task {task.task_id} fixture_ref is not declared in manifest.fixtures"
            )
        prior_pair_cluster = pair_clusters.setdefault(task.pair_id, task.cluster_id)
        if prior_pair_cluster != task.cluster_id:
            raise IntegrityError(
                f"pair {task.pair_id} is split across independent clusters"
            )

        if task.origin is TaskOrigin.AUTHORED_SYNTHETIC:
            data_class = task.metadata.get("data_class")
            if isinstance(data_class, str) and data_class in _PUBLIC_REAL_LABELS:
                raise IntegrityError(
                    f"synthetic task {task.task_id} is mislabeled as {data_class}"
                )
            if task.metadata.get("public_real") is True:
                raise IntegrityError(
                    f"synthetic task {task.task_id} cannot set public_real=true"
                )

        for key in _INDEPENDENCE_KEYS:
            raw_value = task.metadata.get(key)
            if raw_value is None:
                continue
            value = _require_nonempty_string(raw_value, f"task {task.task_id} metadata.{key}")
            source_key = (key, value)
            prior_cluster = source_clusters.setdefault(source_key, task.cluster_id)
            if prior_cluster != task.cluster_id:
                raise IntegrityError(
                    f"{key}={value!r} appears in multiple clusters; lexical/source variants "
                    "are not independent draws"
                )
            split_source_values.setdefault(source_key, set()).add(task.split)

        lexical_of = task.metadata.get("lexical_variant_of")
        if lexical_of is not None:
            lexical_of = _require_nonempty_string(
                lexical_of, f"task {task.task_id} metadata.lexical_variant_of"
            )
            base = task_by_id.get(lexical_of)
            if base is None:
                raise IntegrityError(
                    f"task {task.task_id} refers to unknown lexical_variant_of={lexical_of!r}"
                )
            if base.cluster_id != task.cluster_id:
                raise IntegrityError(
                    f"lexical variant {task.task_id} must share cluster_id with {lexical_of}"
                )

    if pack.manifest["claim_eligible"]:
        if not pack.tasks:
            raise IntegrityError("a claim-eligible task pack cannot be empty")
        missing_independent_identity = [
            task.task_id
            for task in pack.tasks
            if not any(task.metadata.get(key) is not None for key in _INDEPENDENCE_KEYS)
        ]
        if missing_independent_identity:
            raise IntegrityError(
                "claim-eligible tasks require a frozen upstream/workflow identity: "
                f"{missing_independent_identity[:5]}"
            )
        for key in _INDEPENDENCE_KEYS:
            gate_values = {
                str(task.metadata[key])
                for task in pack.tasks
                if task.split == "gate" and key in task.metadata
            }
            formal_values = {
                str(task.metadata[key])
                for task in pack.tasks
                if task.split == "formal" and key in task.metadata
            }
            overlap = sorted(gate_values & formal_values)
            if overlap:
                raise IntegrityError(
                    f"gate/formal {key} overlap is forbidden: {overlap[:5]}"
                )


def _verify_declared_file(root: Path, entry: Mapping[str, str], label: str) -> None:
    path = _resolve_pack_file(root, entry["path"], label)
    actual = _file_sha256(path)
    if actual != entry["sha256"]:
        raise IntegrityError(
            f"{label} SHA-256 mismatch for {entry['path']}: "
            f"declared={entry['sha256']}, actual={actual}"
        )


def load_taskpack(
    root: Path,
    *,
    public_adapter_registry: Any | None = None,
    public_evidence_root: Path | None = None,
    public_evidence_manifest_sha256: str | None = None,
) -> TaskPack:
    """Load and fully verify an executable task pack.

    Loading is intentionally stronger than JSON decoding: returning a
    :class:`TaskPack` means its current on-disk bytes satisfy its provenance
    lock.  Use the candidate-manifest loaders for non-executable inventories.
    """

    root = Path(root)
    if not root.is_dir():
        raise IntegrityError(f"task-pack root does not exist: {root}")
    manifest_path = root / "manifest.json"
    tasks_path = root / "tasks.jsonl"
    if not manifest_path.is_file() or not tasks_path.is_file():
        raise IntegrityError(
            f"executable task pack requires manifest.json and tasks.jsonl under {root}"
        )
    manifest = load_json(manifest_path)
    _validate_manifest(manifest)
    origin = TaskOrigin(manifest["origin"])
    tasks = _read_tasks(tasks_path, manifest_origin=origin)
    pack = TaskPack(
        pack_id=manifest["pack_id"],
        manifest=deepcopy(manifest),
        tasks=tasks,
        root=root.resolve(),
    )
    report = verify_taskpack(
        pack,
        public_adapter_registry=public_adapter_registry,
        public_evidence_root=public_evidence_root,
        public_evidence_manifest_sha256=public_evidence_manifest_sha256,
    )
    if not report["valid"]:
        raise IntegrityError("task-pack verification failed: " + "; ".join(report["errors"]))
    return pack


def verify_taskpack(
    pack: TaskPack,
    *,
    public_adapter_registry: Any | None = None,
    public_evidence_root: Path | None = None,
    public_evidence_manifest_sha256: str | None = None,
) -> dict[str, Any]:
    """Re-verify a loaded pack against current disk contents.

    The returned report is JSON-serializable and never treats a synthetic pack
    as population-claim eligible.  Structural programmer errors are recorded as
    verification errors rather than silently repaired.
    """

    errors: list[str] = []
    checks: dict[str, bool] = {}

    def check(name: str, operation: Any) -> None:
        try:
            operation()
        except (SchemaError, IntegrityError, OSError, UnicodeError, ValueError) as exc:
            checks[name] = False
            errors.append(f"{name}: {exc}")
        else:
            checks[name] = True

    check("manifest_schema", lambda: _validate_manifest(pack.manifest))
    check(
        "pack_id_binding",
        lambda: (
            None
            if pack.pack_id == pack.manifest.get("pack_id")
            else (_ for _ in ()).throw(IntegrityError("TaskPack.pack_id differs from manifest"))
        ),
    )
    for index, entry in enumerate(pack.manifest.get("upstream", {}).get("raw_files", [])):
        check(
            f"raw_file_{index}",
            lambda entry=entry, index=index: _verify_declared_file(
                pack.root, entry, f"manifest.upstream.raw_files[{index}]"
            ),
        )
    transformation = pack.manifest.get("transformation", {})
    if isinstance(transformation, dict) and "script_path" in transformation:
        check(
            "transformation_script",
            lambda: _verify_declared_file(
                pack.root,
                {
                    "path": transformation["script_path"],
                    "sha256": transformation["script_sha256"],
                },
                "manifest.transformation.script_path",
            ),
        )
    for index, entry in enumerate(pack.manifest.get("fixtures", [])):
        check(
            f"fixture_{index}",
            lambda entry=entry, index=index: _verify_declared_file(
                pack.root, entry, f"manifest.fixtures[{index}]"
            ),
        )
    check(
        "transformed_tasks_sha256",
        lambda: (
            None
            if _file_sha256(pack.root / "tasks.jsonl") == transformation.get("tasks_sha256")
            else (_ for _ in ()).throw(IntegrityError("tasks.jsonl SHA-256 mismatch"))
        ),
    )
    check(
        "task_object_binding",
        lambda: (
            None
            if _read_tasks(
                pack.root / "tasks.jsonl",
                manifest_origin=TaskOrigin(pack.manifest["origin"]),
            )
            == pack.tasks
            else (_ for _ in ()).throw(
                IntegrityError("TaskPack.tasks differs from current tasks.jsonl")
            )
        ),
    )
    check(
        "task_count",
        lambda: (
            None
            if len(pack.tasks) == pack.manifest.get("task_count")
            else (_ for _ in ()).throw(IntegrityError("manifest.task_count mismatch"))
        ),
    )
    check(
        "cluster_count",
        lambda: (
            None
            if len({task.cluster_id for task in pack.tasks})
            == pack.manifest.get("cluster_count")
            else (_ for _ in ()).throw(IntegrityError("manifest.cluster_count mismatch"))
        ),
    )

    def check_split_counts() -> None:
        actual: dict[str, int] = {key: 0 for key in pack.manifest["splits"]}
        for task in pack.tasks:
            if task.split not in actual:
                raise IntegrityError(f"undeclared task split: {task.split}")
            actual[task.split] += 1
        if actual != pack.manifest["splits"]:
            raise IntegrityError(
                f"manifest.splits mismatch: declared={pack.manifest['splits']}, actual={actual}"
            )

    check("split_counts", check_split_counts)
    check("task_relations", lambda: _validate_task_relations(pack))

    valid = all(checks.values())
    origin = pack.manifest.get("origin")
    content_sha: str | None = None
    if valid:
        try:
            content_sha = taskpack_content_sha256(pack)
        except (SchemaError, IntegrityError, OSError, ValueError) as exc:
            valid = False
            errors.append(f"content_sha256: {exc}")
            checks["content_sha256"] = False
        else:
            checks["content_sha256"] = True
    public_readiness: dict[str, Any] | None = None
    if valid and origin == TaskOrigin.PUBLIC_BENCHMARK.value and content_sha is not None:
        # Import locally so the readiness layer can consume TaskPack-like
        # objects without introducing a module cycle.
        from .public_readiness import audit_public_readiness

        public_readiness = audit_public_readiness(
            pack,
            taskpack_sha256=content_sha,
            adapter_registry=public_adapter_registry,
            evidence_root=public_evidence_root,
            evidence_manifest_sha256=public_evidence_manifest_sha256,
        )
        # Structural provenance may remain valid while scientific launch
        # readiness is STOP.  The runner consumes population_claim_eligible,
        # which is false unless the separate readiness audit passes.
        checks["public_claim_readiness_gate_applied"] = True
    population_claim_eligible = bool(
        valid
        and pack.manifest.get("claim_eligible")
        and origin in {TaskOrigin.PUBLIC_BENCHMARK.value, TaskOrigin.REAL_WORKFLOW.value}
        and (
            origin != TaskOrigin.PUBLIC_BENCHMARK.value
            or (public_readiness is not None and public_readiness["ready"])
        )
    )
    return {
        "pack_id": pack.pack_id,
        "valid": valid,
        "claim_eligible": bool(pack.manifest.get("claim_eligible")),
        "population_claim_eligible": population_claim_eligible and valid,
        "origin": origin,
        "task_count": len(pack.tasks),
        "cluster_count": len({task.cluster_id for task in pack.tasks}),
        "content_sha256": content_sha,
        "public_readiness": public_readiness,
        "checks": checks,
        "errors": errors,
    }


def select_tasks(
    pack: TaskPack,
    *,
    split: str,
    families: frozenset[str],
    task_ids: frozenset[str] | None = None,
    public_adapter_registry: Any | None = None,
    public_evidence_root: Path | None = None,
    public_evidence_manifest_sha256: str | None = None,
    require_public_readiness: bool = False,
) -> tuple[TaskSpec, ...]:
    _require_nonempty_string(split, "split")
    if not isinstance(families, frozenset) or not families:
        raise SchemaError("families must be a nonempty frozenset")
    for family in families:
        _require_nonempty_string(family, "families item")
    if not isinstance(require_public_readiness, bool):
        raise SchemaError("require_public_readiness must be boolean")
    if (
        require_public_readiness
        and split == "formal"
        and pack.manifest.get("origin") == TaskOrigin.PUBLIC_BENCHMARK.value
    ):
        readiness = verify_taskpack(
            pack,
            public_adapter_registry=public_adapter_registry,
            public_evidence_root=public_evidence_root,
            public_evidence_manifest_sha256=public_evidence_manifest_sha256,
        )
        if readiness["population_claim_eligible"] is not True:
            public = readiness.get("public_readiness")
            codes = (
                public.get("blocker_codes", [])
                if isinstance(public, Mapping)
                else ["PUBLIC_READINESS_NOT_RECOMPUTED"]
            )
            raise IntegrityError(
                "public formal task selection requires recomputed claim readiness: "
                + ", ".join(str(code) for code in codes)
            )
    if task_ids is not None:
        if not isinstance(task_ids, frozenset) or not task_ids:
            raise SchemaError("task_ids must be None or a nonempty frozenset")
        known_ids = {task.task_id for task in pack.tasks}
        unknown = sorted(task_ids - known_ids)
        if unknown:
            raise IntegrityError(f"unknown task IDs requested: {unknown}")
    selected = tuple(
        task
        for task in pack.tasks
        if task.split == split
        and task.family in families
        and (task_ids is None or task.task_id in task_ids)
    )
    if not selected:
        raise IntegrityError("task selection is empty")
    if task_ids is not None:
        selected_ids = {task.task_id for task in selected}
        omitted = sorted(task_ids - selected_ids)
        if omitted:
            raise IntegrityError(
                f"requested task IDs do not belong to the selected split/families: {omitted}"
            )
    return selected


def taskpack_content_sha256(pack: TaskPack) -> str:
    """Hash the verified logical pack and the current declared file bytes."""

    files: list[dict[str, str]] = []
    declared: list[str] = []
    declared.extend(entry["path"] for entry in pack.manifest["upstream"]["raw_files"])
    declared.append(pack.manifest["transformation"]["script_path"])
    declared.extend(entry["path"] for entry in pack.manifest["fixtures"])
    declared.append("tasks.jsonl")
    for rel in sorted(set(declared)):
        path = _resolve_pack_file(pack.root, rel, f"content file {rel}")
        files.append({"path": rel, "sha256": _file_sha256(path)})
    logical = {
        "manifest": pack.manifest,
        "tasks": [_task_as_json(task) for task in pack.tasks],
        "files": files,
    }
    return sha256_bytes(canonical_json_bytes(logical))


def _load_upstream_registry(path: Path) -> dict[str, dict[str, Any]]:
    raw = load_json(path)
    if raw.get("schema_version") != 1 or not isinstance(raw.get("sources"), list):
        raise SchemaError("upstream manifest must have schema_version=1 and a sources list")
    registry: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(raw["sources"]):
        source = _require_object(value, f"upstream sources[{index}]")
        source_id = _require_nonempty_string(source.get("source_id"), f"source[{index}].source_id")
        if source_id in registry:
            raise IntegrityError(f"duplicate upstream source_id: {source_id}")
        registry[source_id] = source
    return registry


def _find_upstream_source(
    upstream_manifest_path: Path, *, name: str, version: str, commit: str, license_name: str
) -> dict[str, Any]:
    registry = _load_upstream_registry(upstream_manifest_path)
    matches = [
        source
        for source in registry.values()
        if source.get("version") == version
        and source.get("commit") == commit
        and source.get("license") == license_name
        and name.casefold() in str(source.get("source_id", "")).casefold()
    ]
    if len(matches) != 1:
        raise IntegrityError(
            f"candidate source does not uniquely match upstream manifest: "
            f"name={name!r}, version={version!r}, commit={commit!r}, license={license_name!r}"
        )
    return matches[0]


def _verify_upstream_files(
    source: Mapping[str, Any], declared_files: Iterable[Mapping[str, Any]]
) -> None:
    local_root = Path(_require_nonempty_string(source.get("local_root"), "source.local_root"))
    if not local_root.is_absolute():
        # The frozen upstream registry uses repository-root-relative paths.
        repo_root = Path(__file__).resolve().parents[2]
        local_root = repo_root / local_root
    frozen = {
        entry["path"]: entry["sha256"]
        for entry in source.get("task_files", [])
        if isinstance(entry, dict) and "path" in entry and "sha256" in entry
    }
    for index, entry in enumerate(declared_files):
        item = _require_object(entry, f"candidate upstream_files[{index}]")
        path = _require_nonempty_string(item.get("path"), f"upstream_files[{index}].path")
        sha = _require_sha256(item.get("sha256"), f"upstream_files[{index}].sha256")
        if frozen.get(path) != sha:
            raise IntegrityError(f"candidate raw-file lock differs from upstream manifest: {path}")
        resolved = (local_root.resolve() / path).resolve()
        try:
            resolved.relative_to(local_root.resolve())
        except ValueError as exc:
            raise IntegrityError(f"candidate upstream path escapes local_root: {path}") from exc
        if _file_sha256(resolved) != sha:
            raise IntegrityError(f"candidate upstream raw file SHA-256 mismatch: {path}")


def load_tau2_candidate_manifest(
    path: Path,
    *,
    upstream_manifest_path: Path | None = None,
) -> dict[str, Any]:
    """Load and verify the frozen tau2 candidate inventory.

    The inventory remains non-executable.  Formal execution must transform it
    into a normal ``manifest.json``/``tasks.jsonl`` task pack first.
    """

    path = Path(path)
    if not path.is_file():
        raise IntegrityError(f"tau2 candidate manifest is missing: {path}")
    raw = load_json(path)
    _require_exact_fields(
        raw,
        frozenset({"schema_version", "benchmark", "selection", "policy_profiles", "candidates"}),
        "tau2 candidate manifest",
    )
    if raw["schema_version"] != 1:
        raise SchemaError("tau2 candidate manifest schema_version must equal 1")
    benchmark = _require_object(raw["benchmark"], "tau2 benchmark")
    name = _require_nonempty_string(benchmark.get("name"), "tau2 benchmark.name")
    if name != "tau2-bench":
        raise IntegrityError(f"expected tau2-bench candidate manifest, got {name!r}")
    version = _require_nonempty_string(benchmark.get("version"), "tau2 benchmark.version")
    commit = _require_nonempty_string(benchmark.get("commit"), "tau2 benchmark.commit")
    license_obj = _require_object(benchmark.get("license"), "tau2 benchmark.license")
    license_name = _require_nonempty_string(license_obj.get("spdx"), "tau2 license.spdx")
    _require_sha256(license_obj.get("sha256"), "tau2 license.sha256")
    upstream_files = benchmark.get("upstream_files")
    if not isinstance(upstream_files, list) or not upstream_files:
        raise SchemaError("tau2 benchmark.upstream_files must be nonempty")
    candidates = raw["candidates"]
    if not isinstance(candidates, list) or not candidates:
        raise SchemaError("tau2 candidates must be nonempty")

    seen: set[tuple[str, str]] = set()
    source_clusters: dict[tuple[str, str], str] = {}
    policies = _require_object(raw["policy_profiles"], "tau2 policy_profiles")
    for index, value in enumerate(candidates):
        candidate = _require_object(value, f"tau2 candidates[{index}]")
        domain = _require_nonempty_string(candidate.get("domain"), f"candidate[{index}].domain")
        task_id = _require_nonempty_string(
            candidate.get("upstream_task_id"), f"candidate[{index}].upstream_task_id"
        )
        key = (domain, task_id)
        if key in seen:
            raise IntegrityError(f"duplicate tau2 candidate source task: {key}")
        seen.add(key)
        cluster = _require_nonempty_string(
            candidate.get("cluster_id"), f"candidate[{index}].cluster_id"
        )
        prior = source_clusters.setdefault(key, cluster)
        if prior != cluster:
            raise IntegrityError(f"tau2 source task {key} is split across clusters")
        _require_sha256(candidate.get("source_hash"), f"candidate[{index}].source_hash")
        source_path = _require_nonempty_string(
            candidate.get("source_path"), f"candidate[{index}].source_path"
        )
        policy = _require_nonempty_string(
            candidate.get("policy_requirement"), f"candidate[{index}].policy_requirement"
        )
        if policy not in policies:
            raise IntegrityError(f"candidate[{index}] references unknown policy profile {policy!r}")
        if not isinstance(candidate.get("split_membership"), list) or not candidate["split_membership"]:
            raise SchemaError(f"candidate[{index}].split_membership must be nonempty")
        if not isinstance(candidate.get("mutation_actions"), list) or not candidate["mutation_actions"]:
            raise SchemaError(f"candidate[{index}].mutation_actions must be nonempty")
        for action in candidate["mutation_actions"]:
            _require_nonempty_string(action, f"candidate[{index}].mutation_actions item")
        if not isinstance(candidate.get("needs_manual_review"), bool):
            raise SchemaError(f"candidate[{index}].needs_manual_review must be boolean")
        candidate["__source_key_for_validation__"] = [source_path, task_id]

    upstream_manifest_path = upstream_manifest_path or path.parent.parent / "upstream_manifest.json"
    source = _find_upstream_source(
        upstream_manifest_path,
        name=name,
        version=version,
        commit=commit,
        license_name=license_name,
    )
    if license_obj["sha256"] != source.get("license_sha256"):
        raise IntegrityError("tau2 license SHA-256 differs from upstream manifest")
    _verify_upstream_files(source, upstream_files)

    local_root = Path(source["local_root"])
    if not local_root.is_absolute():
        local_root = Path(__file__).resolve().parents[2] / local_root
    tasks_by_path: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        source_path, task_id = candidate.pop("__source_key_for_validation__")
        if source_path not in tasks_by_path:
            try:
                values = json.loads((local_root / source_path).read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise IntegrityError(f"could not load tau2 task source {source_path}: {exc}") from exc
            if not isinstance(values, list):
                raise SchemaError(f"tau2 task source must be a list: {source_path}")
            tasks_by_path[source_path] = {
                str(item.get("id")): item for item in values if isinstance(item, dict) and "id" in item
            }
        upstream_task = tasks_by_path[source_path].get(task_id)
        if upstream_task is None:
            raise IntegrityError(f"tau2 candidate task not found: {source_path}#{task_id}")
        actual_task_sha = sha256_bytes(canonical_json_bytes(upstream_task))
        if actual_task_sha != candidate["source_hash"]:
            raise IntegrityError(f"tau2 candidate source_hash mismatch: {source_path}#{task_id}")
    return deepcopy(raw)


def load_agentdojo_candidate_manifest(
    path: Path,
    *,
    upstream_manifest_path: Path | None = None,
) -> dict[str, Any]:
    """Load and provenance-check the frozen AgentDojo candidate inventory."""

    path = Path(path)
    if not path.is_file():
        raise IntegrityError(f"AgentDojo candidate manifest is missing: {path}")
    raw = load_json(path)
    actual_fields = frozenset(raw)
    current_fields = frozenset(
        {
            "schema_version",
            "generated_at",
            "purpose",
            "upstream",
            "selection",
            "source_hash_catalog",
            "candidates",
        }
    )
    fixture_fields = frozenset(
        {"schema_version", "upstream", "selection", "counts", "candidates"}
    )
    if actual_fields not in {current_fields, fixture_fields}:
        missing = sorted(current_fields - actual_fields)
        unknown = sorted(actual_fields - current_fields)
        raise SchemaError(
            f"AgentDojo candidate manifest fields invalid: missing={missing}, unknown={unknown}"
        )
    if raw["schema_version"] not in {1, "agentmembrane.agentdojo-candidates.v2"}:
        raise SchemaError("unsupported AgentDojo candidate manifest schema_version")
    upstream = _require_object(raw["upstream"], "AgentDojo upstream")
    name = _require_nonempty_string(upstream.get("name"), "AgentDojo upstream.name")
    if name.casefold() != "agentdojo":
        raise IntegrityError(f"expected AgentDojo candidate manifest, got {name!r}")
    version = _require_nonempty_string(
        upstream.get("version", upstream.get("package_version")),
        "AgentDojo upstream.version/package_version",
    )
    commit = _require_nonempty_string(upstream.get("commit"), "AgentDojo upstream.commit")
    license_name = _require_nonempty_string(upstream.get("license"), "AgentDojo upstream.license")
    upstream_files = upstream.get("upstream_files", upstream.get("task_files"))
    candidates = raw["candidates"]
    if not isinstance(candidates, list) or not candidates:
        raise SchemaError("AgentDojo candidates must be nonempty")
    seen_ids: set[str] = set()
    source_clusters: dict[tuple[str, str, str], str] = {}
    for index, value in enumerate(candidates):
        candidate = _require_object(value, f"AgentDojo candidates[{index}]")
        candidate_id = _require_nonempty_string(
            candidate.get("candidate_id"), f"candidate[{index}].candidate_id"
        )
        if candidate_id in seen_ids:
            raise IntegrityError(f"duplicate AgentDojo candidate_id: {candidate_id}")
        seen_ids.add(candidate_id)
        domain = _require_nonempty_string(candidate.get("domain"), f"candidate[{index}].domain")
        cluster = _require_nonempty_string(
            candidate.get("cluster_id"), f"candidate[{index}].cluster_id"
        )
        user_task = _require_object(
            candidate.get("original_user_task"), f"candidate[{index}].original_user_task"
        )
        upstream_id = _require_nonempty_string(
            user_task.get("id"), f"candidate[{index}].original_user_task.id"
        )
        source_file = _require_nonempty_string(
            user_task.get("source_file"),
            f"candidate[{index}].original_user_task.source_file",
        )
        _require_sha256(
            user_task.get("source_sha256"),
            f"candidate[{index}].original_user_task.source_sha256",
        )
        source_key = (domain, source_file, upstream_id)
        prior = source_clusters.setdefault(source_key, cluster)
        if prior != cluster:
            raise IntegrityError(
                f"AgentDojo source task {source_key} is split across independent clusters"
            )
        for nested_name in ("original_injection_task", "injection_vector"):
            nested = _require_object(
                candidate.get(nested_name), f"candidate[{index}].{nested_name}"
            )
            _require_nonempty_string(
                nested.get("id"), f"candidate[{index}].{nested_name}.id"
            )
            _require_nonempty_string(
                nested.get("source_file"),
                f"candidate[{index}].{nested_name}.source_file",
            )
            _require_sha256(
                nested.get("source_sha256"),
                f"candidate[{index}].{nested_name}.source_sha256",
            )

    selection = _require_object(raw["selection"], "AgentDojo selection")
    if "candidate_count" in selection:
        if _require_count(selection["candidate_count"], "selection.candidate_count") != len(
            candidates
        ):
            raise IntegrityError("AgentDojo selection.candidate_count mismatch")
    if "counts" in raw:
        counts = _require_object(raw["counts"], "AgentDojo counts")
        if "total" in counts and _require_count(counts["total"], "counts.total") != len(candidates):
            raise IntegrityError("AgentDojo counts.total mismatch")

    upstream_manifest_path = upstream_manifest_path or path.parent.parent / "upstream_manifest.json"
    source = _find_upstream_source(
        upstream_manifest_path,
        name=name,
        version=version,
        commit=commit,
        license_name=license_name,
    )
    candidate_license_sha = upstream.get(
        "license_sha256", upstream.get("license_file_sha256")
    )
    if candidate_license_sha is not None:
        if _require_sha256(
            candidate_license_sha, "AgentDojo license file SHA-256"
        ) != source.get("license_sha256"):
            raise IntegrityError("AgentDojo license SHA-256 differs from upstream manifest")
    local_root = Path(source["local_root"])
    if not local_root.is_absolute():
        local_root = Path(__file__).resolve().parents[2] / local_root
    license_rel = upstream.get("license_file")
    if license_rel is not None:
        license_path = (local_root.resolve() / _require_nonempty_string(
            license_rel, "AgentDojo license_file"
        )).resolve()
        try:
            license_path.relative_to(local_root.resolve())
        except ValueError as exc:
            raise IntegrityError("AgentDojo license_file escapes local root") from exc
        if _file_sha256(license_path) != source.get("license_sha256"):
            raise IntegrityError("AgentDojo license file bytes differ from upstream lock")

    if upstream_files is not None:
        if not isinstance(upstream_files, list) or not upstream_files:
            raise SchemaError("AgentDojo upstream task/raw file list must be nonempty")
        _verify_upstream_files(source, upstream_files)
    frozen_files = {
        entry["path"]: entry["sha256"]
        for entry in source["task_files"]
        if isinstance(entry, dict)
    }
    declared_candidate_files: dict[str, str] = {}
    for index, candidate in enumerate(candidates):
        for nested_name in ("original_user_task", "original_injection_task", "injection_vector"):
            nested = candidate[nested_name]
            source_file = nested["source_file"]
            source_sha = nested["source_sha256"]
            prior_sha = declared_candidate_files.setdefault(source_file, source_sha)
            if prior_sha != source_sha:
                raise IntegrityError(
                    f"AgentDojo source file has inconsistent hashes across candidates: {source_file}"
                )
            expected = frozen_files.get(source_file)
            if expected is None:
                # Injection definitions may live outside the four frozen user-task files;
                # they must nevertheless be present in the candidate upstream file lock.
                declared = {
                    entry.get("path"): entry.get("sha256") for entry in (upstream_files or [])
                }
                expected = declared.get(source_file)
            if expected is not None and expected != source_sha:
                raise IntegrityError(
                    f"candidate[{index}].{nested_name} source hash is not upstream-locked"
                )
    catalog = raw.get("source_hash_catalog")
    if catalog is not None:
        catalog = _require_object(catalog, "AgentDojo source_hash_catalog")
        catalog_hashes = {
            _require_sha256(value, f"source_hash_catalog.{key}")
            for key, value in catalog.items()
        }
        if catalog_hashes != set(declared_candidate_files.values()):
            raise IntegrityError(
                "AgentDojo source_hash_catalog does not exactly cover candidate source files"
            )
    elif upstream_files is None:
        raise IntegrityError(
            "AgentDojo candidate manifest has neither source_hash_catalog nor upstream_files"
        )
    for source_file, declared_sha in declared_candidate_files.items():
        rel = Path(source_file)
        if rel.is_absolute() or ".." in rel.parts:
            raise IntegrityError(f"AgentDojo candidate source escapes local root: {source_file}")
        source_path = (local_root.resolve() / rel).resolve()
        try:
            source_path.relative_to(local_root.resolve())
        except ValueError as exc:
            raise IntegrityError(
                f"AgentDojo candidate source escapes local root: {source_file}"
            ) from exc
        if _file_sha256(source_path) != declared_sha:
            raise IntegrityError(f"AgentDojo candidate source SHA-256 mismatch: {source_file}")
    return deepcopy(raw)


def load_candidate_manifest(
    path: Path,
    *,
    upstream_manifest_path: Path | None = None,
) -> dict[str, Any]:
    """Dispatch to the benchmark-specific candidate-manifest loader.

    There is deliberately no permissive fallback.  An absent, unknown, or
    partially generated candidate inventory prevents formal preparation.
    """

    path = Path(path)
    if not path.is_file():
        raise IntegrityError(f"candidate manifest is missing: {path}")
    raw = load_json(path)
    if "benchmark" in raw and isinstance(raw["benchmark"], dict):
        if raw["benchmark"].get("name") == "tau2-bench":
            return load_tau2_candidate_manifest(
                path, upstream_manifest_path=upstream_manifest_path
            )
    if "upstream" in raw and isinstance(raw["upstream"], dict):
        if str(raw["upstream"].get("name", "")).casefold() == "agentdojo":
            return load_agentdojo_candidate_manifest(
                path, upstream_manifest_path=upstream_manifest_path
            )
    raise SchemaError("unknown candidate-manifest benchmark; refusing permissive loading")


__all__ = [
    "TaskPack",
    "TaskSpec",
    "load_agentdojo_candidate_manifest",
    "load_candidate_manifest",
    "load_taskpack",
    "load_tau2_candidate_manifest",
    "select_tasks",
    "taskpack_content_sha256",
    "verify_taskpack",
]
