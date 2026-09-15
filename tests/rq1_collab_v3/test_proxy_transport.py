"""Fake credentials and no socket calls: real driver's repeated prepare path."""
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
from agentmembrane.host_v2.rq1_collab_v1.providers import HTTPReply, ProviderFailure
from agentmembrane.host_v2.rq1_collab_v3.proxy_transport import BoundProxyTransport, dedicated_proxy_transport
from agentmembrane.host_v2.rq1_collab_v3.driver import RoleModelDriver, role_prompts
from agentmembrane.host_v2.rq1_collab_v3.contract import make_config, PROTOCOL
from tests.rq1_collab_v1.test_provider_action_protocol import Collector


PROXY_BASE = "http://127.0.0.1:19876/v1"
KEY_ENV = "RQ1_SYNTHETIC_PROXY_KEY"
PROXY_SETTINGS_ENV = {
    PROXY_BASE_ENV: PROXY_BASE,
    PROXY_CONFIG_ENV: "/synthetic/not-read.yaml",
    PROXY_CREDENTIAL_ENV_ENV: KEY_ENV,
}


@patch.dict(os.environ, PROXY_SETTINGS_ENV)
class ProxyCredentialTests(unittest.TestCase):
    def test_actual_runtime_admits_exact_bound_transport_and_closes_evidence(self):
        from agentmembrane.host_v2.rq1_collab_v1.process_backend import ProcessNativeTask
        from agentmembrane.host_v2.rq1_collab_v1.audit import EventCollector,canonical
        from agentmembrane.host_v2.rq1_collab_v1.admission import TaskBundle
        from agentmembrane.host_v2.rq1_collab_v1.policy import compile_task_policy
        from agentmembrane.host_v2.rq1_collab_v3.contract import digest
        from agentmembrane.host_v2.rq1_collab_v3.runtime import run_episode
        root=Path(__file__).resolve().parents[2]
        python=Path(os.environ.get(
            "AGENTDOJO_RUNTIME_PYTHON",
            root/"experiments/host_boundary_v2/runtime_envs/agentdojo-0.1.35-py3123-lock-395e3d0a5921-rq1v4/bin/python",
        )).expanduser().absolute()
        source=Path(os.environ.get(
            "AGENTDOJO_SOURCE_ROOT",
            root/"data/host_boundary_v2/upstream/agentdojo",
        )).expanduser().resolve()
        native=ProcessNativeTask(str(python),str(source),"workspace","user_task_8",timeout=20)
        self.addCleanup(native.shutdown)
        record={"schema_version":"rq1-task-bundle/2","suite":"workspace","original_id":"user_task_8","source_record":native.record,
                "task_policy":compile_task_policy("workspace","user_task_8",native.prompt),
                "goal_admission":{"initial_goal_value":False},"public":{"goal":{"goal":"engineering protocol test only"}}}
        bundle=TaskBundle(canonical(record),digest(record))
        config=make_config(bundle.sha256,"bound-transport-engineering-test","H_E","low","honest",mode="live_diagnostic")
        with tempfile.TemporaryDirectory() as temp:
            collector=EventCollector(Path(temp)/"run",config["episode_id"])
            self.addCleanup(collector.abort)
            with patch("agentmembrane.host_v2.rq1_collab_v1.live_pilot.load_proxy_key",return_value="fake-dedicated-key"):
                transport=dedicated_proxy_transport(timeout_seconds=2)
            driver=RoleModelDriver(config,role_prompts(config,native.prompt,record["public"]["goal"]["goal"]),collector,transport)
            def reply(raw,**kwargs):
                payload=json.loads(raw)
                return HTTPReply(200,json.dumps({"model":payload["model"],"usage":{"prompt_tokens":10,"completion_tokens":7,"total_tokens":17},
                    "choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":None,
                    "tool_calls":[{"id":"fixture-call","type":"function","function":{"name":"submit_action","arguments":'{"type":"final","content":"engineering only"}'}}]}}]}).encode())
            with patch.object(transport,"request",side_effect=reply) as request:
                result=run_episode(config,bundle,native,driver,collector)
            self.assertEqual(result["evidence"]["terminal_reason"],"host_final")
            self.assertEqual(request.call_count,2)
            self.assertFalse(result["evidence"]["failures"])
            for path in (Path(temp)/"run").rglob("*"):
                if path.is_file():self.assertNotIn(b"fake-dedicated-key",path.read_bytes())

    def test_all_role_requests_after_environment_restoration_keep_exact_binding(self):
        for ambient in (None,"different-fake-ambient-key"):
            with self.subTest(ambient=ambient), patch.dict(os.environ,{},clear=True):
                if ambient:os.environ[KEY_ENV]=ambient
                before=dict(os.environ)
                transport=BoundProxyTransport(PROXY_BASE+"/chat/completions",KEY_ENV,
                    credential="designated-fake-key",timeout_seconds=2,hard_timeout_seconds=2)
                config=make_config("a"*64,"engineering","H_S_E","low","honest",mode="live_diagnostic")
                driver=RoleModelDriver(config,role_prompts(config,"public","public attack"),Collector(),transport)
                driver.begin_episode(deadline_monotonic=time.monotonic()+20)
                sent=[]
                def request(raw,**kwargs):
                    self.assertEqual(transport._credential,"designated-fake-key")
                    payload=json.loads(raw);sent.append(payload)
                    return HTTPReply(200,json.dumps({"model":payload["model"],"usage":{"prompt_tokens":10,"completion_tokens":7,"total_tokens":17},
                        "choices":[{"index":0,"finish_reason":"tool_calls","message":{"role":"assistant","content":None,
                        "tool_calls":[{"id":"fixture-call","type":"function","function":{"name":"submit_action","arguments":'{"type":"final","content":"done"}'}}]}}]}).encode())
                with patch.object(transport,"request",side_effect=request):
                    for actor in ("E","H","S","H"):
                        self.assertEqual(json.loads(driver.next_action(actor,{"protocol_version":PROTOCOL,"actor":actor,"history":[]}))["type"],"final")
                self.assertEqual(len(sent),4)
                self.assertEqual(dict(os.environ),before)

    def test_factory_and_judges_use_only_designated_key_not_ambient(self):
        from agentmembrane.host_v2.rq1_scorecard_v5.judge_provider import JudgePool
        with patch.dict(os.environ,{KEY_ENV:"different-fake-key"}), patch("agentmembrane.host_v2.rq1_collab_v1.live_pilot.load_proxy_key",return_value="designated-fake-key") as load:
            transport=dedicated_proxy_transport(timeout_seconds=3)
            self.assertTrue(transport.contains_credential(b"designated-fake-key"))
            self.assertFalse(transport.contains_credential(b"different-fake-key"))
            pool=object.__new__(JudgePool);pool.factory=None;pool.config={"timeout_seconds":3}
            judged=pool._prepare_transport()
            self.assertTrue(judged.contains_credential(b"designated-fake-key"))
            self.assertEqual(load.call_count,2)
            self.assertEqual(os.environ[KEY_ENV],"different-fake-key")

    def test_invalid_bound_key_is_closed_error_without_secret(self):
        for key in (None,"","bad\nfixture"):
            with self.assertRaises(ProviderFailure):
                BoundProxyTransport(PROXY_BASE+"/chat/completions",KEY_ENV,credential=key,hard_timeout_seconds=1)


if __name__=="__main__":unittest.main()
