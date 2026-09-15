"""Persist reproducible integration checks. Offline engineering evidence only."""
import argparse
import io
from pathlib import Path
import time
import unittest

from agentmembrane.host_v2.rq1_collab_v1.audit import _write_new, file_hash
from agentmembrane.host_v2.rq1_scorecard_v5.workflow import write


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",required=True)
    parser.add_argument("--include-legacy",action="store_true")
    args=parser.parse_args()
    output=Path(args.output)
    output.mkdir(parents=True,exist_ok=False)
    dirs=["tests/rq1_scorecard_v5"]
    modules=["rq1_scorecard_v5"]
    if args.include_legacy:
        dirs += ["tests/rq1_collab_v1","tests/rq1_collab_v3","tests/rq1_scorecard_v4"]
        modules += ["rq1_collab_v1","rq1_collab_v3","rq1_scorecard_v4"]
    sources=[p for name in modules for p in sorted((Path("agentmembrane/host_v2")/name).glob("*.py"))]
    before={str(p):file_hash(p) for p in sources}
    suites=[unittest.TestLoader().discover(d,top_level_dir=".") for d in dirs]
    log=io.StringIO()
    result=unittest.TextTestRunner(stream=log,verbosity=2).run(unittest.TestSuite(suites))
    _write_new(output/"test-output.txt",log.getvalue().encode())
    report={"tests_run":result.testsRun,"failures":len(result.failures),"errors":len(result.errors),
            "skipped":len(result.skipped),"ok":result.wasSuccessful(),"checked_at_unix":time.time(),
            "code_sha256":before,"code_unchanged_during_tests":before=={str(p):file_hash(p) for p in sources},
            "test_source_sha256":{str(p):file_hash(p) for d in dirs for p in sorted(Path(d).glob("test*.py"))},
            "log_sha256":file_hash(output/"test-output.txt"),"new_live_model_generation_calls":0,
            "formal_ready":False,"reviewer_type":"deterministic_verification_not_scientific_validation"}
    write(output/"results.json",report)
    print({k:v for k,v in report.items() if not k.endswith("sha256")})
    return 0 if result.wasSuccessful() and report["code_unchanged_during_tests"] else 1


if __name__=="__main__":
    raise SystemExit(main())
