#!/usr/bin/env python3
"""Run the development-only native utility parity gate for original RQ1.

The controller executes BFCL locally and launches AgentDojo/tau2 workers in
their pinned Python environments.  Every workflow is checked with both a
known-good trace and a known-bad counterexample.  No model is called and the
formal holdout is never read.
"""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Mapping


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from agentmembrane.host_v2.original_rq1_public_utility import (
    AGENTDOJO_COMMIT,
    BFCL_COMMIT,
    TAU2_COMMIT,
    audit_development_utility_bindings,
    run_bfcl_native_parity,
)
from agentmembrane.host_v2.schema import sha256_bytes, sha256_json


V2_ROOT = REPO_ROOT / "experiments/host_boundary_v2/rq1_original_a0_a4_v2"
DEFAULT_OUTPUT = V2_ROOT / "assays/g2-public-utility-parity-v1/report.json"
AGENTDOJO_PYTHON = (
    REPO_ROOT
    / "experiments/host_boundary_v2/runtime_envs/"
    "agentdojo-0.1.35-py3123-lock-395e3d0a5921-rq1v4/bin/python"
)
TAU2_PYTHON = (
    REPO_ROOT
    / "experiments/host_boundary_v2/runtime_envs/"
    "tau2-py3123-lock-62d3a8c4807b/bin/python"
)
TAU2_KNOWLEDGE_SUPPLEMENT = (
    REPO_ROOT
    / "experiments/host_boundary_v2/runtime_envs/"
    "tau2-py3123-lock-62d3a8c4807b-knowledge-v2/lib/python3.12/site-packages"
)
AGENTDOJO_CHECKOUT = REPO_ROOT / "data/host_boundary_v2/upstream/agentdojo-v4-runtime"
TAU2_CHECKOUT = REPO_ROOT / "data/host_boundary_v2/upstream/tau2-bench-a2c0247-runtime"
BFCL_CHECKOUT = REPO_ROOT / "data/host_boundary_v2/upstream/bfcl-f7cf735"
WORKER_MARKER = "ORIGINAL_RQ1_UTILITY_WORKER_JSON="


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _file_sha(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _git_identity(path: Path) -> dict[str, Any]:
    head = subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    status = subprocess.run(
        ["git", "-C", str(path), "status", "--porcelain=v1"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    return {"path": str(path), "head": head, "tree_clean": not status, "status": status}


def _agentdojo_check(task: Any, suite: Any, actions: tuple[Any, ...], final_text: str) -> bool:
    from agentdojo.functions_runtime import FunctionsRuntime

    environment = suite.load_and_inject_default_environment({})
    environment = task.init_environment(environment)
    pre_environment = copy.deepcopy(environment)
    runtime = FunctionsRuntime(suite.tools)
    executed: list[Any] = []
    for action in actions:
        _result, error = runtime.run_function(
            environment,
            action.function,
            dict(action.args),
            raise_on_error=True,
        )
        if error is not None:
            raise RuntimeError(f"AgentDojo golden action failed: {error}")
        executed.append(action)
    content = [{"type": "text", "content": final_text}]
    result = suite._check_user_task_utility(
        task,
        content,
        pre_environment,
        environment,
        tuple(executed),
    )
    if type(result) is not bool:
        raise RuntimeError("AgentDojo native utility checker returned non-bool")
    return result


def _agentdojo_worker() -> dict[str, Any]:
    from agentdojo.task_suite.load_suites import get_suite

    selected = (
        ("banking", "user_task_11"),
        ("slack", "user_task_2"),
        ("travel", "user_task_17"),
    )
    rows: list[dict[str, Any]] = []
    for domain, task_id in selected:
        suite = get_suite("v1", domain)
        task = suite.get_user_task_by_id(task_id)
        seed_environment = suite.load_and_inject_default_environment({})
        seed_environment = task.init_environment(seed_environment)
        actions = tuple(task.ground_truth(seed_environment))
        final_text = str(getattr(task, "GROUND_TRUTH_OUTPUT", ""))
        positive = _agentdojo_check(task, suite, actions, final_text)
        negative = _agentdojo_check(task, suite, (), "")
        task_module = sys.modules[type(task).__module__]
        task_path = Path(str(task_module.__file__)).resolve()
        rows.append(
            {
                "source_task_id": f"{domain}:{task_id}",
                "native_checker": "TaskSuite._check_user_task_utility",
                "source_file": str(task_path),
                "source_file_sha256": _file_sha(task_path),
                "golden_action_count": len(actions),
                "golden_action_names": [action.function for action in actions],
                "known_good_passed": positive,
                "known_bad_passed": negative,
                "counterexample_discriminates": positive and not negative,
            }
        )
    checker_path = AGENTDOJO_CHECKOUT / "src/agentdojo/task_suite/task_suite.py"
    return {
        "schema_version": 1,
        "benchmark": "AgentDojo",
        "upstream_commit": AGENTDOJO_COMMIT,
        "python_executable": str(Path(sys.executable).resolve()),
        "python_version": ".".join(str(value) for value in sys.version_info[:3]),
        "checker_path": str(checker_path),
        "checker_sha256": _file_sha(checker_path),
        "formal_holdout_touched": False,
        "rows": rows,
        "passed": all(row["counterexample_discriminates"] for row in rows),
    }


def _tau_requestor(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _tau_known_trace(runtime: Any, environment: Any, task: Any) -> list[dict[str, Any]]:
    trace: list[dict[str, Any]] = []
    for index, action in enumerate(task.evaluation_criteria.actions or []):
        trace.append(
            runtime.dispatch(
                environment,
                call_id=f"rq1-golden-{index}",
                name=action.name,
                arguments=action.arguments,
                requestor=_tau_requestor(action.requestor),
            )
        )
    return trace


def _tau_worker() -> dict[str, Any]:
    from agentmembrane.host_v2.tau2_adapter import _ImportedTau2Runtime

    runtime = _ImportedTau2Runtime(TAU2_CHECKOUT)
    selected = (("airline", "19"), ("banking_knowledge", "task_033"))
    rows: list[dict[str, Any]] = []
    for domain, task_id in selected:
        variant = None
        if domain == "banking_knowledge":
            module = importlib.import_module("tau2.domains.banking_knowledge.environment")
            bound_task = next(task for task in module.get_tasks(None) if str(task.id) == task_id)

            class BM25Environment:
                @staticmethod
                def get_tasks(_split: Any) -> list[Any]:
                    return module.get_tasks(None)

                @staticmethod
                def get_environment(**kwargs: Any) -> Any:
                    kwargs.pop("retrieval_variant", None)
                    kwargs.pop("task", None)
                    return module.get_environment(
                        retrieval_variant="bm25",
                        task=bound_task,
                        **kwargs,
                    )

            runtime.domains[domain] = BM25Environment
            variant = "bm25"

        task, environment, _ = runtime.reset(domain, task_id)
        trace = _tau_known_trace(runtime, environment, task)
        positive_result = runtime.evaluate(
            task=task, domain=domain, native_trace=trace
        )
        negative_task, _negative_environment, _ = runtime.reset(domain, task_id)
        negative_result = runtime.evaluate(
            task=negative_task, domain=domain, native_trace=[]
        )
        criteria = task.evaluation_criteria.model_dump(mode="json")
        rows.append(
            {
                "source_task_id": f"tau2:{domain}:{task_id}",
                "native_checker": "tau2 native EvaluationType.ALL component dispatch",
                "adapter_variant": variant,
                "reward_basis": [
                    item.value if hasattr(item, "value") else str(item)
                    for item in task.evaluation_criteria.reward_basis
                ],
                "evaluation_criteria_sha256": sha256_json(criteria),
                "golden_action_count": len(trace),
                "golden_action_names": [row["name"] for row in trace],
                "known_good_passed": positive_result["utility"] is True,
                "known_bad_passed": negative_result["utility"] is True,
                "known_good_reward": positive_result["reward"],
                "known_bad_reward": negative_result["reward"],
                "checker_binding_ids": positive_result["binding_ids"],
                "counterexample_discriminates": (
                    positive_result["utility"] is True
                    and negative_result["utility"] is False
                ),
            }
        )
    checker_paths = [
        TAU2_CHECKOUT / "src/tau2/evaluator/evaluator.py",
        TAU2_CHECKOUT / "src/tau2/evaluator/evaluator_action.py",
        TAU2_CHECKOUT / "src/tau2/evaluator/evaluator_communicate.py",
        TAU2_CHECKOUT / "src/tau2/evaluator/evaluator_env.py",
    ]
    return {
        "schema_version": 1,
        "benchmark": "tau2-bench",
        "upstream_commit": TAU2_COMMIT,
        "python_executable": str(Path(sys.executable).resolve()),
        "python_version": ".".join(str(value) for value in sys.version_info[:3]),
        "dependency_versions": {
            "numpy": importlib.metadata.version("numpy"),
            "rank-bm25": importlib.metadata.version("rank-bm25"),
        },
        "knowledge_supplement_path": str(TAU2_KNOWLEDGE_SUPPLEMENT),
        "checker_files": [
            {"path": str(path), "sha256": _file_sha(path)} for path in checker_paths
        ],
        "formal_holdout_touched": False,
        "rows": rows,
        "passed": all(row["counterexample_discriminates"] for row in rows),
    }


def _run_worker(kind: str) -> dict[str, Any]:
    if kind == "agentdojo":
        python = AGENTDOJO_PYTHON
        extra_paths = [REPO_ROOT, AGENTDOJO_CHECKOUT / "src"]
    elif kind == "tau2":
        python = TAU2_PYTHON
        extra_paths = [TAU2_KNOWLEDGE_SUPPLEMENT, REPO_ROOT, TAU2_CHECKOUT / "src"]
    else:
        raise ValueError(kind)
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(str(path) for path in extra_paths)
    process = subprocess.run(
        [str(python), str(Path(__file__).resolve()), "--worker", kind],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if process.returncode != 0:
        raise RuntimeError(
            f"{kind} utility worker failed ({process.returncode})\n"
            f"stdout:\n{process.stdout[-4000:]}\nstderr:\n{process.stderr[-4000:]}"
        )
    markers = [
        line[len(WORKER_MARKER) :]
        for line in process.stdout.splitlines()
        if line.startswith(WORKER_MARKER)
    ]
    if len(markers) != 1:
        raise RuntimeError(f"{kind} utility worker did not emit one result")
    value = json.loads(markers[0])
    if not isinstance(value, dict):
        raise RuntimeError(f"{kind} utility worker result is not an object")
    return value


def run_gate() -> dict[str, Any]:
    implementation_paths = (
        Path(__file__).resolve(),
        REPO_ROOT / "agentmembrane/host_v2/original_rq1_public_utility.py",
        REPO_ROOT / "agentmembrane/host_v2/original_rq1_activation.py",
    )
    implementation_files = {
        str(path.relative_to(REPO_ROOT)): _file_sha(path)
        for path in implementation_paths
    }
    binding_audit = audit_development_utility_bindings(REPO_ROOT)
    repositories = {
        "BFCL": _git_identity(BFCL_CHECKOUT),
        "AgentDojo": _git_identity(AGENTDOJO_CHECKOUT),
        "tau2": _git_identity(TAU2_CHECKOUT),
    }
    expected_heads = {
        "BFCL": BFCL_COMMIT,
        "AgentDojo": AGENTDOJO_COMMIT,
        "tau2": TAU2_COMMIT,
    }
    bfcl = run_bfcl_native_parity(REPO_ROOT)
    agentdojo = _run_worker("agentdojo")
    tau2 = _run_worker("tau2")
    rows = [*bfcl["rows"], *agentdojo["rows"], *tau2["rows"]]
    checks = {
        "binding_audit_passed": binding_audit["passed"] is True,
        "upstream_heads_exact_and_clean": all(
            repositories[name]["head"] == expected_heads[name]
            and repositories[name]["tree_clean"] is True
            for name in expected_heads
        ),
        "exactly_eight_workflows": len(rows) == 8,
        "all_known_good_traces_pass": all(row["known_good_passed"] for row in rows),
        "all_known_bad_counterexamples_fail": all(
            not row["known_bad_passed"] for row in rows
        ),
        "all_counterexamples_discriminate": all(
            row["counterexample_discriminates"] for row in rows
        ),
        "all_three_benchmark_gates_pass": all(
            section["passed"] for section in (bfcl, agentdojo, tau2)
        ),
        "zero_model_calls": True,
        "formal_holdout_untouched": True,
    }
    return {
        "schema_version": 1,
        "artifact_type": "original_rq1_v2_development_public_utility_parity_gate",
        "created_at": _utc_now(),
        "scientific_status": "nonclaim_development_native_checker_parity",
        "interpretation_limit": (
            "Known-good trace parity establishes checker/adapter feasibility only; "
            "it is not adaptive benign completion, a five-level utility curve, G3, "
            "or an A-star result."
        ),
        "formal_holdout_touched": False,
        "model_calls": 0,
        "implementation_files": implementation_files,
        "implementation_sha256": sha256_json(implementation_files),
        "repositories": repositories,
        "binding_audit": binding_audit,
        "benchmarks": {"BFCL": bfcl, "AgentDojo": agentdojo, "tau2": tau2},
        "checks": checks,
        "passed": all(checks.values()),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", choices=("agentdojo", "tau2"))
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    if args.worker:
        result = _agentdojo_worker() if args.worker == "agentdojo" else _tau_worker()
        print(WORKER_MARKER + json.dumps(result, ensure_ascii=False, sort_keys=True))
        return 0 if result["passed"] else 1

    report = run_gate()
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({"output": str(output), "passed": report["passed"]}, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
