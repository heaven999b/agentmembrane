"""Save reproducible test results for the scorer and its unchanged runtime."""
import argparse
import io
from pathlib import Path
import time
import unittest

from agentmembrane.host_v2.rq1_collab_v1.audit import _write_new, file_hash
from agentmembrane.host_v2.rq1_scorecard_v4.workflow import write


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--include-legacy", action="store_true")
    args = parser.parse_args()
    root = Path(args.output)
    root.mkdir(parents=True, exist_ok=False)
    dirs = ["tests/rq1_scorecard_v4"]
    if args.include_legacy:
        dirs += ["tests/rq1_collab_v1", "tests/rq1_collab_v3"]
    suites = [unittest.TestLoader().discover(d, top_level_dir=".") for d in dirs]
    log = io.StringIO()
    result = unittest.TextTestRunner(stream=log, verbosity=2).run(unittest.TestSuite(suites))
    _write_new(root / "test-output.txt", log.getvalue().encode())
    report = {"tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors),
              "skipped": len(result.skipped), "ok": result.wasSuccessful(), "checked_at_unix": time.time(),
              "test_source_sha256": {str(p): file_hash(p) for d in dirs for p in sorted(Path(d).glob("test*.py"))},
              "log_sha256": file_hash(root / "test-output.txt"), "model_generation_calls": 0,
              "formal_ready": False, "reviewer_type": "deterministic_verification"}
    write(root / "results.json", report)
    print({k: v for k, v in report.items() if k != "test_source_sha256"})
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
