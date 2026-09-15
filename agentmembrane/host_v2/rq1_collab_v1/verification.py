"""Record real test execution with immutable source/test hashes and skip counts."""
from __future__ import annotations
import argparse
import io
import json
from pathlib import Path
import platform
import sys
import time
import unittest

from .audit import canonical, file_hash
from .integration import _write


class EvidenceResult(unittest.TextTestResult):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs); self.outcomes=[]
    def addSuccess(self,test):
        self.outcomes.append({"test":test.id(),"outcome":"passed"});super().addSuccess(test)
    def addError(self,test,err):
        self.outcomes.append({"test":test.id(),"outcome":"error"});super().addError(test,err)
    def addFailure(self,test,err):
        self.outcomes.append({"test":test.id(),"outcome":"failed"});super().addFailure(test,err)
    def addSkip(self,test,reason):
        self.outcomes.append({"test":test.id(),"outcome":"skipped","reason":reason});super().addSkip(test,reason)


def main(argv=None):
    parser=argparse.ArgumentParser()
    parser.add_argument("--output-dir",required=True)
    args=parser.parse_args(argv)
    out=Path(args.output_dir).absolute();out.mkdir(parents=True,exist_ok=False,mode=0o700)
    project=Path(__file__).resolve().parents[3]
    source=Path(__file__).resolve().parent;tests=project/"tests/rq1_collab_v1"
    paths=sorted(source.glob("*.py"))+sorted(tests.glob("test_*.py"))
    before={str(p.relative_to(project)):file_hash(p) for p in paths}
    _write(out/"manifest.json",{"mode":"engineering_tests","python":sys.version,"executable":sys.executable,
        "platform":platform.platform(),"argv":sys.argv,"source_and_test_hashes":before,
        "model_calls_authorized":0,"behavioral_n":0})
    stream=io.StringIO();started=time.monotonic()
    suite=unittest.defaultTestLoader.discover(str(tests))
    result=unittest.TextTestRunner(stream=stream,verbosity=2,resultclass=EvidenceResult).run(suite)
    after={str(p.relative_to(project)):file_hash(p) for p in paths}
    changed=[path for path in before if before[path]!=after[path]]
    report={"kind":"actual_engineering_test_execution","tests_run":result.testsRun,
        "passed":sum(r["outcome"]=="passed" for r in result.outcomes),"failures":len(result.failures),
        "errors":len(result.errors),"skipped":len(result.skipped),"outcomes":result.outcomes,
        "elapsed_seconds":time.monotonic()-started,"source_changed_during_run":changed,
        "pass_without_skips":result.wasSuccessful() and not result.skipped and not changed,
        "behavioral_n":0,"formal_baseline_certified":False}
    _write(out/"result.json",report)
    _write(out/"test_output.json",{"output":stream.getvalue()})
    print(json.dumps({k:v for k,v in report.items() if k!="outcomes"},indent=2))
    return 0 if report["pass_without_skips"] else 1


if __name__=="__main__": raise SystemExit(main())
