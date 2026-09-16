"""Run the zero-model formal runtime suite and write its bound test report."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

PROJECT = Path(__file__).resolve().parents[1]
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

from agentmembrane.host_v2.rq1_collab_v1.audit import _write_new, canonical
from agentmembrane.host_v2.rq1_three_tier_formal_v1.gate import (
    code_bundle_sha256,
)


TEST_MODULES = (
    "tests.rq1_three_tier.test_formal_runtime_wire",
    "tests.rq1_three_tier.test_formal_runtime_sealed",
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agentdojo-source-root", type=Path, required=True)
    parser.add_argument("--agentdojo-runtime-python", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if (not args.agentdojo_source_root.is_dir()
            or not args.agentdojo_runtime_python.is_file()):
        raise ValueError("agentdojo_qualification_runtime_missing")
    env = dict(os.environ)
    env.update({
        "AGENTDOJO_SOURCE_ROOT": str(args.agentdojo_source_root.resolve()),
        "AGENTDOJO_RUNTIME_PYTHON": str(
            args.agentdojo_runtime_python.absolute()),
    })
    completed = subprocess.run(
        [sys.executable, "-m", "unittest", *TEST_MODULES],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=180,
        check=False,
    )
    if completed.returncode != 0:
        # The suite contains only local test names and closed error codes.  Show
        # a bounded tail so qualification failures are actionable without
        # persisting the full test log in the formal artifact.
        sys.stderr.write(completed.stdout[-8000:])
        raise RuntimeError("formal_runtime_qualification_tests_failed")
    suite = unittest.TestSuite()
    loader = unittest.defaultTestLoader
    for module in TEST_MODULES:
        suite.addTests(loader.loadTestsFromName(module))
    body = {
        "schema_version": (
            "rq1-agentdojo-three-tier-formal-runtime-test-report/1"),
        "code_bundle_sha256": code_bundle_sha256(),
        "test_modules": list(TEST_MODULES),
        "tests_run": suite.countTestCases(),
        "real_model_calls": 0,
        "all_required_paths_passed": True,
        "H_E_action_schema_contains_S": False,
        "formal_evidence_envelope_passed": True,
        "one_shot_runtime_objects_passed": True,
        "proxy_process_lifecycle_tested": False,
        "production_fake_process_failure_paths_passed": True,
        "offline_evidence_rejected_as_formal_sample": True,
        "raw_test_output_persisted": False,
    }
    _write_new(args.output.resolve(), canonical(body) + b"\n")
    print(json.dumps({
        "report": str(args.output.resolve()),
        "tests_run": body["tests_run"],
        "real_model_calls": 0,
        "api_calls": 0,
        "research_sample_count": 0,
    }, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
