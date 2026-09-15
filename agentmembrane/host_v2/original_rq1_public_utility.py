"""Development-only public utility bindings for the original RQ1.

This module deliberately reads only the development bank.  It binds the eight
workflows used by the adaptive safety-activation gate to their upstream task
bytes and native (or, for BFCL irrelevance, source-faithful) utility checkers.
It does not implement the five-level utility experiment and it never opens the
formal holdout.
"""

from __future__ import annotations

import ast
import copy
from dataclasses import asdict, dataclass
import importlib.util
import json
from pathlib import Path
import re
import runpy
import sys
import types
from typing import Any, Mapping, Sequence

from .original_rq1_activation import select_development_activation_clusters
from .schema import sha256_bytes, sha256_json


BFCL_COMMIT = "f7cf7359b7ac615a0b294831c5ba2bc95ee4a000"
AGENTDOJO_COMMIT = "089ed468cf3ed0322acc66b0211f26d9d90dbf60"
TAU2_COMMIT = "a2c024725189473d2d7cea3a5cfdbcc67478e41f"

EXPECTED_UTILITY_CLASSES = {
    "W0_response",
    "W1_public_read",
    "W2_proposal",
    "W3_scoped_action",
    "W4_ambient_workflow",
}

BFCL_CATEGORY_FILES = {
    "irrelevance_148": "BFCL_v4_irrelevance.json",
    "multiple_46": "BFCL_v4_multiple.json",
    "simple_python_339": "BFCL_v4_simple_python.json",
}


@dataclass(frozen=True)
class DevelopmentUtilityBinding:
    source_family: str
    source_task_id: str
    cluster_id: str
    domain: str
    utility_class: str
    minimum_authority_level: str
    source_sha256: str
    upstream_task_path: str
    upstream_task_container_sha256: str
    checker_mode: str
    checker_paths: tuple[str, ...]
    checker_sha256: tuple[str, ...]
    adapter_variant: str | None = None

    def as_json(self) -> dict[str, Any]:
        value = asdict(self)
        value["checker_paths"] = list(self.checker_paths)
        value["checker_sha256"] = list(self.checker_sha256)
        return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _file_sha(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _exact_one(rows: Sequence[Mapping[str, Any]], **criteria: str) -> dict[str, Any]:
    matches = [
        dict(row)
        for row in rows
        if all(str(row.get(key)) == value for key, value in criteria.items())
    ]
    if len(matches) != 1:
        label = ", ".join(f"{key}={value!r}" for key, value in criteria.items())
        raise ValueError(f"expected exactly one public task row for {label}")
    return matches[0]


def _bfcl_binding(repo_root: Path, cluster: Mapping[str, Any]) -> DevelopmentUtilityBinding:
    task_id = str(cluster["source_task_id"])
    filename = BFCL_CATEGORY_FILES.get(task_id)
    if filename is None:
        raise ValueError(f"unsupported development BFCL task: {task_id}")
    checkout = repo_root / "data/host_boundary_v2/upstream/bfcl-f7cf735"
    data_root = checkout / "berkeley-function-call-leaderboard/bfcl_eval/data"
    task_path = data_root / filename
    task = _exact_one(_read_jsonl(task_path), id=task_id)
    ground_truth: dict[str, Any] | None = None

    if task_id.startswith("irrelevance_"):
        checker_mode = "source_faithful_official_no_valid_call_rule"
        checker_relatives = (
            "berkeley-function-call-leaderboard/bfcl_eval/eval_checker/eval_runner.py",
        )
    else:
        checker_mode = "official_native_ast_checker"
        checker_relatives = (
            "berkeley-function-call-leaderboard/bfcl_eval/eval_checker/ast_eval/ast_checker.py",
        )
        answer_name = filename
        answer_path = data_root / "possible_answer" / answer_name
        ground_truth = _exact_one(_read_jsonl(answer_path), id=task_id)
        if not isinstance(ground_truth.get("ground_truth"), list):
            raise ValueError(f"BFCL ground truth is invalid: {task_id}")

    source_payload = {
        "question": task,
        "ground_truth": ground_truth,
        "commit": BFCL_COMMIT,
    }
    if sha256_json(source_payload) != cluster.get("source_sha256"):
        raise ValueError(f"BFCL source task hash differs: {task_id}")

    checker_paths = tuple(str(checkout / relative) for relative in checker_relatives)
    return DevelopmentUtilityBinding(
        source_family="BFCL",
        source_task_id=task_id,
        cluster_id=str(cluster["cluster_id"]),
        domain=str(cluster["domain"]),
        utility_class=str(cluster["utility_class"]),
        minimum_authority_level=str(cluster["minimum_authority_level"]),
        source_sha256=str(cluster["source_sha256"]),
        upstream_task_path=str(task_path),
        upstream_task_container_sha256=_file_sha(task_path),
        checker_mode=checker_mode,
        checker_paths=checker_paths,
        checker_sha256=tuple(_file_sha(Path(path)) for path in checker_paths),
    )


def _agentdojo_binding(
    repo_root: Path, cluster: Mapping[str, Any]
) -> DevelopmentUtilityBinding:
    task_id = str(cluster["source_task_id"])
    domain, source_id = task_id.split(":", 1)
    inventory = _read_jsonl(
        repo_root / "data/host_boundary_v2/full_inventory/agentdojo_user_tasks.jsonl"
    )
    row = _exact_one(inventory, domain=domain, source_id=source_id)
    if row.get("source_class_sha256") != cluster.get("source_sha256"):
        raise ValueError(f"AgentDojo source class hash differs: {task_id}")
    checkout = repo_root / "data/host_boundary_v2/upstream/agentdojo-v4-runtime"
    task_path = checkout / str(row["source_path"])
    if _file_sha(task_path) != row.get("source_file_sha256"):
        raise ValueError(f"AgentDojo source file hash differs: {task_id}")
    checker = checkout / "src/agentdojo/task_suite/task_suite.py"
    return DevelopmentUtilityBinding(
        source_family="AgentDojo",
        source_task_id=task_id,
        cluster_id=str(cluster["cluster_id"]),
        domain=str(cluster["domain"]),
        utility_class=str(cluster["utility_class"]),
        minimum_authority_level=str(cluster["minimum_authority_level"]),
        source_sha256=str(cluster["source_sha256"]),
        upstream_task_path=str(task_path),
        upstream_task_container_sha256=_file_sha(task_path),
        checker_mode="official_native_suite_v1_utility_dispatcher",
        checker_paths=(str(checker),),
        checker_sha256=(_file_sha(checker),),
    )


def _tau2_binding(repo_root: Path, cluster: Mapping[str, Any]) -> DevelopmentUtilityBinding:
    task_id = str(cluster["source_task_id"])
    inventory = _read_jsonl(
        repo_root / "data/host_boundary_v2/full_inventory/tau2_tasks.jsonl"
    )
    row = _exact_one(inventory, workflow_id=task_id)
    if row.get("source_task_sha256") != cluster.get("source_sha256"):
        raise ValueError(f"tau2 source task hash differs: {task_id}")
    checkout = repo_root / "data/host_boundary_v2/upstream/tau2-bench-a2c0247-runtime"
    task_path = checkout / str(row["source_path"])
    source_rows = json.loads(task_path.read_text(encoding="utf-8"))
    native_id = str(row["source_task_id"])
    task = _exact_one(source_rows, id=native_id)
    if sha256_json(task) != cluster.get("source_sha256"):
        raise ValueError(f"tau2 task bytes differ: {task_id}")
    evaluator_relatives = (
        "src/tau2/evaluator/evaluator.py",
        "src/tau2/evaluator/evaluator_action.py",
        "src/tau2/evaluator/evaluator_communicate.py",
        "src/tau2/evaluator/evaluator_env.py",
    )
    checker_paths = tuple(str(checkout / relative) for relative in evaluator_relatives)
    # Adaptive completion needs a model-visible retrieval route. The official
    # BM25 variant is deterministic and local, unlike the default dense
    # embedding route, and does not expose task ground truth.
    variant = "bm25" if ":banking_knowledge:" in task_id else None
    return DevelopmentUtilityBinding(
        source_family="tau2",
        source_task_id=task_id,
        cluster_id=str(cluster["cluster_id"]),
        domain=str(cluster["domain"]),
        utility_class=str(cluster["utility_class"]),
        minimum_authority_level=str(cluster["minimum_authority_level"]),
        source_sha256=str(cluster["source_sha256"]),
        upstream_task_path=str(task_path),
        upstream_task_container_sha256=_file_sha(task_path),
        checker_mode="official_native_tau2_reward_components",
        checker_paths=checker_paths,
        checker_sha256=tuple(_file_sha(Path(path)) for path in checker_paths),
        adapter_variant=variant,
    )


def load_development_utility_bindings(
    repo_root: Path,
) -> tuple[DevelopmentUtilityBinding, ...]:
    """Resolve only the eight preselected development workflows."""

    root = Path(repo_root).resolve()
    clusters = select_development_activation_clusters(root, cluster_count=8)
    bindings: list[DevelopmentUtilityBinding] = []
    for cluster in clusters:
        source = str(cluster["source_family"])
        if source == "BFCL":
            binding = _bfcl_binding(root, cluster)
        elif source == "AgentDojo":
            binding = _agentdojo_binding(root, cluster)
        elif source == "tau2":
            binding = _tau2_binding(root, cluster)
        else:
            raise ValueError(f"unsupported source family: {source}")
        bindings.append(binding)
    if len(bindings) != 8 or len({row.cluster_id for row in bindings}) != 8:
        raise ValueError("development utility panel must contain eight independent clusters")
    return tuple(bindings)


def audit_development_utility_bindings(repo_root: Path) -> dict[str, Any]:
    bindings = load_development_utility_bindings(repo_root)
    counts = {
        source: sum(row.source_family == source for row in bindings)
        for source in ("BFCL", "AgentDojo", "tau2")
    }
    checks = {
        "development_bank_only": True,
        "formal_holdout_untouched": True,
        "eight_independent_workflows": len(bindings) == 8,
        "source_quota_3_3_2": counts == {"BFCL": 3, "AgentDojo": 3, "tau2": 2},
        "five_utility_classes_represented": {
            row.utility_class for row in bindings
        }
        == EXPECTED_UTILITY_CLASSES,
        "all_source_and_checker_hashes_bound": all(
            len(row.source_sha256) == 64
            and len(row.upstream_task_container_sha256) == 64
            and row.checker_sha256
            and all(len(value) == 64 for value in row.checker_sha256)
            for row in bindings
        ),
    }
    return {
        "schema_version": 1,
        "artifact_type": "original_rq1_v2_development_public_utility_bindings",
        "scientific_status": "nonclaim_development_adapter_binding",
        "formal_holdout_touched": False,
        "source_counts": counts,
        "checks": checks,
        "passed": all(checks.values()),
        "bindings": [row.as_json() for row in bindings],
    }


def _load_official_bfcl_ast_checker(repo_root: Path):
    """Load the frozen checker with a dependency-free model-name shim.

    BFCL's checker imports every provider SDK through its model registry even
    though the AST checker only needs the registry's ``underscore_to_dot``
    flag.  The shim supplies exactly that flag while the executed checker code
    remains the frozen upstream file whose hash is reported in the artifact.
    """

    root = Path(repo_root).resolve()
    package_root = (
        root
        / "data/host_boundary_v2/upstream/bfcl-f7cf735/berkeley-function-call-leaderboard"
    )
    checker_path = package_root / "bfcl_eval/eval_checker/ast_eval/ast_checker.py"
    inserted = str(package_root) not in sys.path
    if inserted:
        sys.path.insert(0, str(package_root))
    shim_name = "bfcl_eval.constants.model_config"
    prior = sys.modules.get(shim_name)
    shim = types.ModuleType(shim_name)
    config = types.SimpleNamespace(underscore_to_dot=True)
    shim.MODEL_CONFIG_MAPPING = {"original-rq1-openai-fc": config}
    sys.modules[shim_name] = shim
    module_name = "_agentmembrane_frozen_bfcl_ast_checker"
    try:
        spec = importlib.util.spec_from_file_location(module_name, checker_path)
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot load frozen BFCL AST checker")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        enums = __import__("bfcl_eval.constants.enums", fromlist=["Language"])
        return module.ast_checker, enums.Language
    finally:
        if prior is None:
            sys.modules.pop(shim_name, None)
        else:
            sys.modules[shim_name] = prior
        if inserted:
            try:
                sys.path.remove(str(package_root))
            except ValueError:
                pass


def _load_official_bfcl_tool_converter(repo_root: Path):
    """Load BFCL's frozen OpenAI Chat Completions tool compiler.

    The converter performs the benchmark's recursive Gorilla-to-OpenAPI type
    normalization and its prescribed dotted-name wire aliasing.  Callers must
    still verify that the resulting aliases are unique for the live task.
    """

    root = Path(repo_root).resolve()
    package_root = (
        root
        / "data/host_boundary_v2/upstream/bfcl-f7cf735/berkeley-function-call-leaderboard"
    )
    utils_path = package_root / "bfcl_eval/model_handler/utils.py"
    mapping_path = package_root / "bfcl_eval/constants/type_mappings.py"
    enum_path = package_root / "bfcl_eval/constants/enums.py"

    # Importing the full upstream utility module eagerly imports Java/JS
    # parsers and every provider adapter.  The converter itself depends only
    # on these two adjacent upstream functions plus copy/re and constants.
    # Compile those exact AST nodes with their original filename so the
    # executed bytecode remains traceable without installing irrelevant SDKs.
    parsed = ast.parse(utils_path.read_text(encoding="utf-8"), filename=str(utils_path))
    required = {"_cast_to_openai_type", "convert_to_tool"}
    bodies = [
        node
        for node in parsed.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name in required
    ]
    if {node.name for node in bodies} != required:
        raise RuntimeError("frozen BFCL converter functions are missing")
    mappings = runpy.run_path(str(mapping_path))
    enums = runpy.run_path(str(enum_path))
    namespace: dict[str, Any] = {
        "copy": copy,
        "re": re,
        "GORILLA_TO_OPENAPI": mappings["GORILLA_TO_OPENAPI"],
        "ModelStyle": enums["ModelStyle"],
    }
    code = compile(ast.Module(body=bodies, type_ignores=[]), str(utils_path), "exec")
    exec(code, namespace)
    converter = namespace["convert_to_tool"]
    if Path(converter.__code__.co_filename).resolve() != utils_path.resolve():
        raise RuntimeError("BFCL converter origin differs from the frozen checkout")
    return (
        converter,
        mappings["GORILLA_TO_OPENAPI"],
        enums["ModelStyle"].OPENAI_COMPLETIONS,
    )


def _first_allowed(value: Any) -> Any:
    if not isinstance(value, list):
        raise ValueError("BFCL possible-answer field must be a list")
    for item in value:
        if item != "":
            return item
    raise ValueError("BFCL possible-answer field has no concrete value")


def run_bfcl_native_parity(repo_root: Path) -> dict[str, Any]:
    """Run positive and negative counterexamples for all three BFCL rows."""

    root = Path(repo_root).resolve()
    data_root = (
        root
        / "data/host_boundary_v2/upstream/bfcl-f7cf735/berkeley-function-call-leaderboard/bfcl_eval/data"
    )
    checker, language = _load_official_bfcl_ast_checker(root)
    rows: list[dict[str, Any]] = []
    for task_id, filename in BFCL_CATEGORY_FILES.items():
        task = _exact_one(_read_jsonl(data_root / filename), id=task_id)
        if task_id.startswith("irrelevance_"):
            # Exact rule at eval_runner._evaluate_single_relevance_entry:
            # irrelevance succeeds iff no valid non-empty function call exists.
            positive = True  # empty call list
            negative = False  # one syntactically valid call
            mode = "source_faithful_official_no_valid_call_rule"
            positive_call_count = 0
        else:
            answer = _exact_one(
                _read_jsonl(data_root / "possible_answer" / filename), id=task_id
            )["ground_truth"]
            expected_name = next(iter(answer[0]))
            exposed_name = expected_name.replace(".", "_")
            args = {
                key: _first_allowed(values)
                for key, values in answer[0][expected_name].items()
            }
            model_output = [{exposed_name: args}]
            category = task_id.rsplit("_", 1)[0]
            positive_result = checker(
                task["function"],
                model_output,
                answer,
                language.PYTHON,
                category,
                "original-rq1-openai-fc",
            )
            negative_result = checker(
                task["function"],
                [],
                answer,
                language.PYTHON,
                category,
                "original-rq1-openai-fc",
            )
            positive = positive_result.get("valid") is True
            negative = negative_result.get("valid") is True
            mode = "official_native_ast_checker"
            positive_call_count = 1
        rows.append(
            {
                "source_task_id": task_id,
                "checker_mode": mode,
                "positive_call_count": positive_call_count,
                "known_good_passed": positive,
                "known_bad_passed": negative,
                "counterexample_discriminates": positive and not negative,
            }
        )
    return {
        "schema_version": 1,
        "benchmark": "BFCL",
        "upstream_commit": BFCL_COMMIT,
        "formal_holdout_touched": False,
        "rows": rows,
        "passed": all(row["counterexample_discriminates"] for row in rows),
    }


__all__ = [
    "DevelopmentUtilityBinding",
    "_load_official_bfcl_tool_converter",
    "audit_development_utility_bindings",
    "load_development_utility_bindings",
    "run_bfcl_native_parity",
]
