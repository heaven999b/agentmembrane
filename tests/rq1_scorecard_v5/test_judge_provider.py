"""Opt-in provider contract tests; injected transports make NO network calls."""
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1.live_pilot import (
    PROXY_BASE_ENV, PROXY_CONFIG_ENV, PROXY_CREDENTIAL_ENV_ENV,
)
from agentmembrane.host_v2.rq1_collab_v1.providers import HTTPReply
from agentmembrane.host_v2.rq1_scorecard_v5.judge_provider import JudgePool, JudgeUnavailable, validate_config


PROXY_BASE = "http://127.0.0.1:19876/v1"
PROXY_SETTINGS_ENV = {
    PROXY_BASE_ENV: PROXY_BASE,
    PROXY_CONFIG_ENV: "/synthetic/not-read.yaml",
    PROXY_CREDENTIAL_ENV_ENV: "RQ1_SYNTHETIC_PROXY_KEY",
}


def config():
    return {"schema_version":"rq1-judge-provider/5",
        "judges":[{"id":"a","profile":{"model":"gpt-5-2025-08-07","reasoning_effort":"medium","max_completion_tokens":100}},
                  {"id":"b","profile":{"model":"gpt-5-2025-08-07","reasoning_effort":"high","max_completion_tokens":100}}],
        "max_requests":12,"max_total_tokens":10000,"timeout_seconds":30}


def inventory():
    return {"base_url":PROXY_BASE,"model_ids":["gpt-5-2025-08-07"],"checked_at_unix":time.time()}


def reply(payload, **changes):
    value={"model":payload["model"],"usage":{"prompt_tokens":20,"completion_tokens":10,"total_tokens":30},
        "choices":[{"finish_reason":"stop","message":{"role":"assistant","content":'{"status":"test"}'}}]}
    value.update(changes)
    return HTTPReply(200,json.dumps(value).encode())


@patch.dict(os.environ, PROXY_SETTINGS_ENV)
class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
    def pool(self, handler=None,cfg=None,inv=None):
        self.sent=[]
        def transport(raw):
            payload=json.loads(raw);self.sent.append(payload)
            return (handler or reply)(payload)
        return JudgePool(cfg or config(),inv or inventory(),self.root/"audit",
                         transport_factory=lambda:transport)
    def test_no_request_during_construction_explicit_two_configs(self):
        p=self.pool()
        self.assertEqual(p.requests,0)
        self.assertEqual([x["id"] for x in p.entries()],["a","b"])
    def test_exact_profile_and_private_no_store_payload(self):
        p=self.pool()
        value=p.entries()[0]["complete"]({"instructions":"Return JSON.","answer_text":"public fixture"})
        self.assertEqual(value,'{"status":"test"}')
        self.assertEqual(self.sent[0]["model"],"gpt-5-2025-08-07")
        self.assertFalse(self.sent[0]["store"])
        self.assertEqual(p.summary()["reported_total_tokens"],30)
        self.assertIsNone(p.summary()["model_calls"])
        self.assertEqual(len(list((self.root/"audit").glob("*-result.json"))),1)
    def test_model_mismatch_stops_no_fallback(self):
        p=self.pool(lambda payload:reply(payload,model="different-model"))
        for _ in range(2):
            with self.assertRaises(JudgeUnavailable):
                p.entries()[0]["complete"]({"instructions":"JSON"})
        self.assertEqual(len(self.sent),1)
        self.assertTrue(p.stopped)
    def test_response_usage_unknown_stops(self):
        p=self.pool(lambda payload:reply(payload,usage={}))
        with self.assertRaisesRegex(JudgeUnavailable,"usage_unknown"):
            p.entries()[0]["complete"]({"instructions":"JSON"})
    def test_wrong_route_or_stale_inventory_refused(self):
        for inv in ({**inventory(),"checked_at_unix":0},{**inventory(),"base_url":"https://wrong.invalid/v1"},
                    {**inventory(),"model_ids":[]}):
            with self.assertRaises(ValueError):
                self.pool(inv=inv)
        self.assertFalse((self.root/"audit").exists())
    def test_exact_config_no_key_or_endpoint_override(self):
        for field in ("api_key","endpoint","automatic_retry"):
            cfg=config();cfg[field]="not-a-real-secret"
            with self.assertRaises(ValueError):
                validate_config(cfg)
        cfg=config();cfg["judges"][1]["profile"]=cfg["judges"][0]["profile"].copy()
        with self.assertRaises(ValueError):validate_config(cfg)
    def test_nonfinal_response_never_accepted(self):
        p=self.pool(lambda payload:reply(payload,choices=[{"finish_reason":"length",
            "message":{"role":"assistant","content":"partial"}}]))
        with self.assertRaises(JudgeUnavailable):
            p.entries()[0]["complete"]({"instructions":"JSON"})
    def test_request_budget_no_hidden_retry(self):
        cfg=config();cfg["max_requests"]=1
        p=self.pool(cfg=cfg)
        p.entries()[0]["complete"]({"instructions":"JSON"})
        with self.assertRaisesRegex(JudgeUnavailable,"budget_exhausted"):
            p.entries()[1]["complete"]({"instructions":"JSON"})
        self.assertEqual(len(self.sent),1)
    def test_transport_exception_does_not_serialize_secret_text(self):
        def fail(_):
            raise RuntimeError("fixture-secret-not-to-serialize")
        p=self.pool(fail)
        with self.assertRaises(JudgeUnavailable):
            p.entries()[0]["complete"]({"instructions":"JSON"})
        texts="\n".join(x.read_text() for x in (self.root/"audit").glob("*.json"))
        self.assertNotIn("fixture-secret-not-to-serialize",texts)
        self.assertIn("judge_provider_failure",texts)

    def test_rejected_secret_packet_not_in_wrapper_or_provider_logs(self):
        from agentmembrane.host_v2.rq1_scorecard_v5.workflow import _audited_judges
        from agentmembrane.host_v2.rq1_scorecard_v5.semantic import judge_field
        marker="fixture-only-credential-marker"
        class GuardedMock:
            def contains_credential(self,raw):return marker.encode() in raw
            def __call__(self,raw):raise AssertionError("no transport call permitted")
        pool=JudgePool(config(),inventory(),self.root/"audit",transport_factory=GuardedMock)
        journal=[]
        judges=_audited_judges(pool.entries(),self.root,journal)
        report=judge_field({"instructions":"JSON","answer_text":marker},judges,lambda x:x)
        self.assertEqual(len(journal),6)
        self.assertEqual(pool.requests,0)
        with self.assertRaisesRegex(JudgeUnavailable,"credential_in_scoring_report"):
            pool.assert_log_safe(report)
        for path in self.root.rglob("*.json"):
            self.assertNotIn(marker,path.read_text())


if __name__=="__main__":
    unittest.main()
