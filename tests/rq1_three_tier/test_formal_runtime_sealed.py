"""Offline full-path qualification for the manifest-bound formal runtime.

The transport returns deterministic local HTTPReply objects. No socket, API,
credential or prior campaign is used; the native task itself runs in the
reviewed fresh worker process used by the production controller.
"""
from __future__ import annotations

import copy
from contextlib import nullcontext
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1.admission import TaskBundle
from agentmembrane.host_v2.rq1_collab_v1.audit import (
    EventCollector, canonical, file_hash, strict_loads, verify,
)
from agentmembrane.host_v2.rq1_collab_v1.policy import compile_task_policy
from agentmembrane.host_v2.rq1_collab_v1.process_backend import ProcessNativeTask
from agentmembrane.host_v2.rq1_collab_v1.providers import HTTPReply, HTTPTransport
from agentmembrane.host_v2.rq1_collab_v3.proxy_transport import (
    BoundProxyTransport,
)
from agentmembrane.host_v2.rq1_collab_v3.contract import clone, digest
from agentmembrane.host_v2.rq1_collab_v6.attack_spec import compile_attack_spec
from agentmembrane.host_v2.rq1_collab_v6.contract import PHASE_SCHEDULE
from agentmembrane.host_v2.rq1_three_tier_formal_v1 import runner
from agentmembrane.host_v2.rq1_three_tier_formal_v1.contract import (
    FORMAL_PROTOCOL, LEVEL_BINDINGS, MODEL_PROFILES,
)
from agentmembrane.host_v2.rq1_three_tier_formal_v1.driver import (
    FormalRoleModelDriver, role_prompts,
)
from agentmembrane.host_v2.rq1_three_tier_formal_v1.gate import (
    validate_evidence_admission,
)
from agentmembrane.host_v2.rq1_three_tier_formal_v1.analysis import (
    _validate_analysis_input,
)
from agentmembrane.host_v2.rq1_three_tier_formal_v1.evaluator import (
    write_formal_cell_evaluation,
)
from agentmembrane.host_v2.rq1_three_tier_formal_v1.runtime_impl import (
    FORMAL_ALLOCATION_PATH, FORMAL_EVIDENCE_PATH,
    _validate_evidence_components, evaluate_registered_native_endpoints,
    _run_offline_formal_cell_core, _run_production_formal_cell_core,
    inner_config, validate_evidence,
    validate_sealed_formal_run,
)
from agentmembrane.host_v2.rq1_three_tier_formal_v1.proxy_lifecycle import (
    CELL_LIFECYCLE_PATH, PerCellProxyLifecycle,
)


PROJECT = Path(__file__).resolve().parents[2]
SOURCE = Path(os.environ.get(
    "AGENTDOJO_SOURCE_ROOT",
    PROJECT / "data/host_boundary_v2/upstream/agentdojo",
)).expanduser().resolve()
NATIVE_PYTHON = Path(os.environ.get(
    "AGENTDOJO_RUNTIME_PYTHON",
    PROJECT / "experiments/host_boundary_v2/runtime_envs/"
    "agentdojo-0.1.35-py3123-lock-395e3d0a5921-rq1v4/bin/python",
)).expanduser().absolute()


def _write(path: Path, value: dict) -> dict:
    path.write_bytes(canonical(value) + b"\n")
    return {"path": str(path.resolve()), "sha256": file_hash(path)}


def _hashed(body: dict, field: str) -> dict:
    return {**body, field: digest(body)}


class FakeHTTP:
    def __init__(self, actions=None):
        self.calls = []
        self.actions = actions

    def __call__(self, body, *, deadline_monotonic):
        payload = json.loads(body)
        self.calls.append(payload)
        action = (copy.deepcopy(self.actions[len(self.calls) - 1])
                  if self.actions is not None else
                  {"type": "final", "content": (
                      "External phase complete." if len(self.calls) == 1
                      else "The task could not be completed without using a tool.")})
        reply = {
            "model": payload["model"],
            "choices": [{
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [{
                        "id": "call-local-%d" % len(self.calls),
                        "type": "function",
                        "function": {
                            "name": "submit_action",
                            "arguments": json.dumps(action),
                        },
                    }],
                },
            }],
            "usage": {"prompt_tokens": 20, "completion_tokens": 8,
                      "total_tokens": 28},
        }
        return HTTPReply(200, json.dumps(reply).encode("utf-8"),
                         receipt_id="local-fake-%d" % len(self.calls))


class FormalRuntimeSealedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rq1-formal-runtime-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.port = 19291
        self.native = ProcessNativeTask(
            str(NATIVE_PYTHON.absolute()), str(SOURCE.resolve()),
            "travel", "user_task_0", timeout=20,
        )
        self.addCleanup(self.native.shutdown)
        self.goal = self.native.native_goal_record("injection_task_0")
        self.attack_spec = compile_attack_spec(self.goal["goal"])
        policy = compile_task_policy(
            "travel", "user_task_0", self.native.prompt)
        record = {
            "schema_version": "rq1-task-bundle/2",
            "protocol_version": "rq1-multifactor/2",
            "suite": "travel",
            "original_id": "user_task_0",
            "source_record": clone(self.native.record),
            "task_policy": policy,
            "task_policy_sha256": digest(policy),
            "goal_admission": {"initial_goal_value": False},
            "public": {"user_request": self.native.prompt,
                       "goal": clone(self.goal)},
        }
        self.bundle = TaskBundle(canonical(record), digest(record))
        self.task_key = "travel/user_task_0"
        self.goal_cluster = ("travel/injection_task_0/"
                             + self.attack_spec["spec_sha256"])
        self.manifest, self.cell = self._manifest(record)

    def _fake_lifecycle_sources(self):
        server_source = r'''
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

COUNT = 0
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return
    def do_GET(self):
        if self.path != "/v1/models":
            self.send_error(404)
            return
        body = json.dumps({"data": [{"id": "gpt-5.6-luna"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        global COUNT
        if self.path != "/v1/chat/completions":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length))
        COUNT += 1
        action = {"type": "final", "content": (
            "External phase complete." if COUNT == 1
            else "The task could not be completed without using a tool.")}
        value = {
            "model": payload["model"],
            "choices": [{
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {"role": "assistant", "content": None,
                            "tool_calls": [{"id": "fake-call-%d" % COUNT,
                                             "type": "function",
                                             "function": {"name": "submit_action",
                                                          "arguments": json.dumps(action)}}]},
            }],
            "usage": {"prompt_tokens": 20, "completion_tokens": 8,
                      "total_tokens": 28},
        }
        body = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
'''
        runner_source = f'''
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

PORT = {self.port!r}
PARENT = Path({str(self.root)!r})
SERVER_SOURCE = {server_source!r}
CHILDREN = {{}}

def start(accounting=None):
    root = Path(tempfile.mkdtemp(prefix="fake-cell-proxy-", dir=PARENT))
    root.chmod(0o700)
    key = root / "client-key"
    key.write_text("local-test-key\\n", encoding="ascii")
    key.chmod(0o600)
    server = root / "server.py"
    server.write_text("PORT = %d\\n" % PORT + SERVER_SOURCE, encoding="utf-8")
    server.chmod(0o600)
    child = subprocess.Popen(
        [sys.executable, str(server)], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True, close_fds=True)
    CHILDREN[child.pid] = child
    (root / "pid").write_text(str(child.pid), encoding="ascii")
    for _ in range(100):
        if child.poll() is not None:
            raise RuntimeError("fake_server_exited")
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=0.05):
                break
        except OSError:
            time.sleep(0.02)
    else:
        raise RuntimeError("fake_server_timeout")
    return {{"status": "ready", "root": str(root),
             "client_key_file": str(key), "pid": child.pid}}

def stop(root):
    root = Path(root)
    pid = int((root / "pid").read_text(encoding="ascii"))
    fail_once = PARENT / "fail-stop-once"
    if fail_once.exists():
        fail_once.unlink()
        raise RuntimeError("synthetic_stop_failure")
    child = CHILDREN.pop(pid, None)
    if child is not None and child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=3)
    shutil.rmtree(root)
    return {{"status": "stopped", "root_removed": True, "pid": pid}}
'''
        runner = self.root / "fake-lifecycle-runner.py"
        runner.write_text(runner_source, encoding="utf-8")
        binary = self.root / "fake-cli-proxy-binary"
        binary.write_bytes(b"fake cli proxy binary fixture\n")
        binary.chmod(0o700)
        attestation = self.root / "fake-attestation.json"
        attestation.write_text("{}\n", encoding="utf-8")
        return {
                "lifecycle_runner": {
                    "path": str(runner.resolve()), "sha256": file_hash(runner)},
                "cli_proxy_binary": {
                    "path": str(binary.resolve()), "sha256": file_hash(binary)},
                "attestation": {
                    "path": str(attestation.resolve()),
                    "sha256": file_hash(attestation)},
            }

    def _manifest(self, record):
        h_output = {"schema_version": "fixture-H/1", "required": ["status"]}
        h_task = {
            "task_key": self.task_key,
            "bundle_sha256": self.bundle.sha256,
            "public_user_request": self.native.prompt,
            "public_goal": clone(self.goal),
            "public_user_request_sha256": digest(self.native.prompt),
            "public_goal_sha256": digest(self.goal),
            "task_policy_sha256": record["task_policy_sha256"],
            "goal_cluster_id": self.goal_cluster,
            "H_output_contract_sha256": digest(h_output),
        }
        h_contract = _hashed({"tasks": [h_task]}, "H_contract_sha256")
        assignment = {
            "task_key": self.task_key,
            "goal_id": "injection_task_0",
            "goal_source_binding": clone(self.goal),
            "attack_spec_sha256": self.attack_spec["spec_sha256"],
            "goal_cluster_id": self.goal_cluster,
        }
        goals = _hashed({"assignments": [assignment]},
                        "goal_assignment_sha256")
        source = record["source_record"]
        qid_contracts = {}
        for dimension in ("Q", "I", "D"):
            contract = _hashed({
                "schema_version": "fixture-%s-contract/1" % dimension,
                "observer_sources": [],
            }, "contract_sha256")
            path = self.root / (dimension.lower() + "-contract.json")
            source_binding = _write(path, contract)
            qid_contracts[dimension + "_contract"] = {
                "schema_version": contract["schema_version"],
                "path": source_binding["path"],
                "sha256": source_binding["sha256"],
                "contract_sha256": contract["contract_sha256"],
            }
        qid_task = {
            "task_key": self.task_key,
            "source_binding": {
                "suite": source["suite"],
                "task_id": source["task_id"],
                "initial_state_sha256": source["initial_state_sha256"],
                "prompt_sha256": source["prompt_sha256"],
                "tool_schema_sha256": source["tool_schema_sha256"],
                "assigned_goal_id": assignment["goal_id"],
                "assigned_goal_sha256": self.goal["goal_sha256"],
                "attack_spec_sha256": assignment["attack_spec_sha256"],
                "goal_cluster_id": assignment["goal_cluster_id"],
            },
            "Q": {"unit_ids_sha256": "1" * 64},
            "I": {"fact_ids_sha256": "2" * 64},
            "D": {"unit_ids_sha256": "3" * 64},
            **qid_contracts,
        }
        qid = _hashed({"tasks": [qid_task]}, "adjudication_sha256")
        formal_task_body = {
            "schema_version": "rq1-agentdojo-formal-task-binding/1",
            "task_key": self.task_key,
            "source_record": clone(source),
            "source_initial_state_sha256": source["initial_state_sha256"],
            "formal_task_source_binding_sha256": "4" * 64,
            "goal_cluster_id": self.goal_cluster,
            "H_output_contract_sha256": h_task["H_output_contract_sha256"],
            "QID_adjudicated_task_sha256": digest(qid_task),
            "formal_admitted": True,
        }
        formal_task = {**formal_task_body,
                       "formal_task_binding_sha256": digest(formal_task_body)}
        level, regime = "low", "honest"
        cell = {
            "protocol_version": FORMAL_PROTOCOL,
            "episode_id": "travel-user_task_0-H_E-low-honest-r0",
            "task_key": self.task_key,
            "formal_task_binding_sha256": formal_task[
                "formal_task_binding_sha256"],
            "goal_cluster_id": self.goal_cluster,
            "topology": "H_E",
            "level": level,
            "runtime_external_level": LEVEL_BINDINGS[level]["runtime_level"],
            "legacy_canonical_analog": LEVEL_BINDINGS[level][
                "legacy_canonical_analog"],
            "canonical_ladder_level_claimed": None,
            "regime": regime,
            "repeat": 0,
            "models": clone(MODEL_PROFILES),
            "budget": clone(inner_config.__globals__["FIXED_BUDGET"]),
            "phase_schedule": clone(PHASE_SCHEDULE),
            "execution_mode": "formal_live",
            "automatic_retry": False,
            "replacement_cell_permitted": False,
        }
        route = {
            "schema_version": "rq1-provider-route/1",
            "endpoint": f"http://127.0.0.1:{self.port}/v1/chat/completions",
            "credential_env": "FORMAL_FAKE_KEY",
            "account_label": "formal_test_route",
        }
        lifecycle_sources = self._fake_lifecycle_sources()
        route_source = {
            **_write(self.root / "route.json", route),
            "route": clone(route),
            "account_identity": (
                "operator_declared_dedicated_route_not_provider_attested"),
        }
        route_binding = _hashed({
            "schema_version": "fixture-route-runtime-binding/1",
            "route": route_source,
            **lifecycle_sources,
            "formal_lifecycle_policy": {
                "route_instance_scope": "one_fresh_dedicated_instance_per_cell",
                "workers": 1,
                "request_retry": 0,
                "max_retry_credentials": 1,
                "automatic_cell_retry": False,
                "stop_and_secret_cleanup_after_every_cell": True,
                "revalidate_route_account_binary_and_config_before_every_cell": True,
            },
        }, "route_runtime_binding_sha256")
        self.route = route
        sources = {
            "final_goal_assignment": _write(self.root / "goals.json", goals),
            "final_QID": _write(self.root / "qid.json", qid),
            "H_output_contract": _write(self.root / "h.json", h_contract),
            "route_runtime_binding": _write(
                self.root / "route-binding.json", route_binding),
        }
        manifest_body = {
            "code_bundle_sha256": "a" * 64,
            "goal_assignment_sha256": goals["goal_assignment_sha256"],
            "QID_adjudication_sha256": qid["adjudication_sha256"],
            "H_contract_sha256": h_contract["H_contract_sha256"],
            "route_runtime_binding_sha256": route_binding[
                "route_runtime_binding_sha256"],
            "source_bindings": sources,
            "tasks": [formal_task],
            "cells": [cell],
        }
        return _hashed(manifest_body, "manifest_sha256"), cell

    def _run(self):
        cfg = inner_config(self.cell, self.bundle.sha256)
        collector = EventCollector(self.root / "run", cfg["episode_id"])
        transport = BoundProxyTransport(
            self.route["endpoint"], self.route["credential_env"],
            credential="local-test-key",
            timeout_seconds=50,
            hard_timeout_seconds=PHASE_SCHEDULE[
                "model_request_hard_timeout_seconds"],
        )
        fake = FakeHTTP()
        transport.request = fake
        prompts = role_prompts(
            cfg, self.native.prompt, self.goal["goal"],
            attack_spec=self.attack_spec,
        )
        driver = FormalRoleModelDriver(cfg, prompts, collector, transport)
        with patch.dict(os.environ, {"FORMAL_FAKE_KEY": "local-test-key"}), \
             patch("agentmembrane.host_v2.rq1_three_tier_formal_v1.gate."
                   "validate_formal_manifest", side_effect=lambda value: value):
            result = _run_offline_formal_cell_core(
                manifest=self.manifest, episode_id=cfg["episode_id"],
                bundle=self.bundle, adapter=self.native,
                driver=driver, collector=collector,
            )
        return result, fake, collector, driver, transport

    def _run_production(self, name="production-run"):
        cfg = inner_config(self.cell, self.bundle.sha256)
        collector = EventCollector(self.root / name, cfg["episode_id"])
        lifecycle = PerCellProxyLifecycle(
            manifest=self.manifest, cell=self.cell, collector=collector)
        try:
            transport = lifecycle.start()
            prompts = role_prompts(
                cfg, self.native.prompt, self.goal["goal"],
                attack_spec=self.attack_spec,
            )
            driver = FormalRoleModelDriver(
                cfg, prompts, collector, transport)
            with patch(
                    "agentmembrane.host_v2.rq1_three_tier_formal_v1.gate."
                    "validate_formal_manifest", side_effect=lambda value: value):
                result = _run_production_formal_cell_core(
                    manifest=self.manifest, episode_id=cfg["episode_id"],
                    bundle=self.bundle, adapter=self.native,
                    driver=driver, collector=collector,
                    lifecycle=lifecycle,
                )
            return result, collector, lifecycle, transport
        except Exception:
            lifecycle.cleanup_after_failure()
            raise

    def _run_with_actions(self, actions, name):
        cfg = inner_config(self.cell, self.bundle.sha256)
        collector = EventCollector(self.root / name, cfg["episode_id"])
        transport = BoundProxyTransport(
            self.route["endpoint"], self.route["credential_env"],
            credential="local-test-key",
            timeout_seconds=50,
            hard_timeout_seconds=PHASE_SCHEDULE[
                "model_request_hard_timeout_seconds"],
        )
        fake = FakeHTTP(actions)
        transport.request = fake
        prompts = role_prompts(
            cfg, self.native.prompt, self.goal["goal"],
            attack_spec=self.attack_spec,
        )
        driver = FormalRoleModelDriver(cfg, prompts, collector, transport)
        with patch.dict(os.environ, {"FORMAL_FAKE_KEY": "local-test-key"}), \
             patch("agentmembrane.host_v2.rq1_three_tier_formal_v1.gate."
                   "validate_formal_manifest", side_effect=lambda value: value):
            return _run_offline_formal_cell_core(
                manifest=self.manifest, episode_id=cfg["episode_id"],
                bundle=self.bundle, adapter=self.native,
                driver=driver, collector=collector,
            )

    def test_offline_fake_transport_is_sealed_but_not_formal_sample(self):
        result, fake, collector, _, _ = self._run()
        self.assertEqual(len(fake.calls), 2)
        self.assertTrue(verify(
            collector.run_dir,
            expected_seal_hash=result["seal"]["seal_hash"],
        )["ok"])
        self.assertTrue((collector.run_dir / FORMAL_ALLOCATION_PATH).is_file())
        self.assertTrue((collector.run_dir / FORMAL_EVIDENCE_PATH).is_file())
        self.assertEqual(result["formal_evidence"]["legacy_source"], False)
        self.assertEqual(result["formal_evidence"]["bundle_sha256"],
                         self.bundle.sha256)
        self.assertEqual(result["formal_evidence"][
            "QID_adjudicated_task_sha256"],
            self.manifest["tasks"][0]["QID_adjudicated_task_sha256"])
        claim = result["allocation"]["runtime_object_claim"]
        self.assertTrue(claim["one_shot_runtime_objects"])
        self.assertFalse(claim["proxy_process_lifecycle_proven"])
        self.assertEqual(claim["object_scope"], [
            "adapter", "collector", "driver", "transport"])
        self.assertFalse(result["seal"]["metadata"]["formal_ready"])
        self.assertFalse(result["formal_evidence"]["formal_sample_eligible"])
        self.assertEqual(result["formal_evidence"]["execution_class"],
                         "offline_runtime_qualification")
        self.assertFalse((collector.run_dir / CELL_LIFECYCLE_PATH).exists())
        for delivery in result["inner_evidence"]["deliveries"]:
            permissions = delivery["payload"]["permissions"]
            self.assertFalse(permissions["can_delegate"])
            self.assertEqual(permissions["recipients"],
                             ["H"] if delivery["actor"] == "E" else [])
            self.assertNotIn("delegatable_tools", delivery["payload"])
        with patch("agentmembrane.host_v2.rq1_three_tier_formal_v1.gate."
                   "validate_formal_manifest", side_effect=lambda value: value):
            with self.assertRaisesRegex(
                    ValueError, "offline_runtime_evidence_not_formal_sample"):
                validate_evidence_admission(
                    run_root=collector.run_dir,
                    execution_seal_sha256=result["seal"]["seal_hash"],
                    manifest=self.manifest, bundle=self.bundle,
                )
        with patch("agentmembrane.host_v2.rq1_three_tier_formal_v1.gate."
                   "validate_formal_manifest", side_effect=lambda value: value):
            with self.assertRaisesRegex(
                    ValueError, "offline_runtime_evidence_not_formal_sample"):
                validate_evidence(
                    run_root=collector.run_dir,
                    expected_seal_hash=result["seal"]["seal_hash"],
                    manifest=self.manifest,
                    episode_id=self.cell["episode_id"], bundle=self.bundle,
                )
            self.assertEqual(validate_sealed_formal_run(
                collector.run_dir,
                expected_seal_hash=result["seal"]["seal_hash"],
                manifest=self.manifest,
                episode_id=self.cell["episode_id"], bundle=self.bundle,
                require_production_lifecycle=False,
            )["formal_evidence"], result["formal_evidence"])
        with self.assertRaises(TypeError):
            validate_evidence(result["formal_evidence"], manifest=self.manifest)

    def test_production_fake_process_lifecycle_is_sealed_and_admitted(self):
        result, collector, lifecycle, transport = self._run_production()
        receipt = result["production_proxy_lifecycle_receipt"]
        self.assertTrue(result["seal"]["metadata"]["formal_ready"])
        self.assertTrue(result["formal_evidence"]["formal_sample_eligible"])
        self.assertEqual(result["formal_evidence"]["execution_class"],
                         "production_per_cell_proxy")
        self.assertEqual([row["kind"] for row in receipt["events"]], [
            "proxy_process_started", "readiness_probe_passed",
            "formal_actor_run_closed", "proxy_process_stopped",
            "secret_cleanup_completed",
        ])
        self.assertEqual(receipt["model_request_count"], 2)
        self.assertIsNone(transport._credential)
        self.assertIsNone(transport._bound_credential)
        self.assertTrue(lifecycle._closed)
        self.assertFalse(lifecycle._root.exists())
        self.assertTrue((collector.run_dir / CELL_LIFECYCLE_PATH).is_file())
        with patch("agentmembrane.host_v2.rq1_three_tier_formal_v1.gate."
                   "validate_formal_manifest", side_effect=lambda value: value):
            admitted = validate_evidence_admission(
                run_root=collector.run_dir,
                execution_seal_sha256=result["seal"]["seal_hash"],
                manifest=self.manifest, bundle=self.bundle,
            )
        self.assertEqual(admitted, result["formal_evidence"])

    def test_forged_allocation_bundle_qid_and_postseal_write_fail(self):
        result, _, collector, _, _ = self._run()
        evidence = result["formal_evidence"]
        allocation = result["allocation"]
        inner = result["inner_evidence"]
        with patch("agentmembrane.host_v2.rq1_three_tier_formal_v1.gate."
                   "validate_formal_manifest", side_effect=lambda value: value):
            forged = copy.deepcopy(allocation)
            forged["QID_adjudicated_task_sha256"] = "f" * 64
            forged["allocation_sha256"] = digest({
                key: value for key, value in forged.items()
                if key != "allocation_sha256"})
            with self.assertRaisesRegex(ValueError, "allocation_binding"):
                _validate_evidence_components(
                    evidence, manifest=self.manifest, cell=self.cell,
                    allocation=forged, inner_evidence=inner,
                    bundle=self.bundle,
                )

            forged_inner = copy.deepcopy(inner)
            forged_inner["bundle_sha256"] = "e" * 64
            with self.assertRaises(ValueError):
                _validate_evidence_components(
                    evidence, manifest=self.manifest, cell=self.cell,
                    allocation=allocation, inner_evidence=forged_inner,
                    bundle=self.bundle,
                )

            formal_path = collector.run_dir / FORMAL_EVIDENCE_PATH
            formal_path.write_bytes(formal_path.read_bytes() + b" ")
            with self.assertRaisesRegex(ValueError, "seal_invalid"):
                validate_sealed_formal_run(
                    collector.run_dir,
                    expected_seal_hash=result["seal"]["seal_hash"],
                    manifest=self.manifest,
                    episode_id=self.cell["episode_id"],
                    bundle=self.bundle,
                )

    def test_driver_and_transport_are_one_shot_across_formal_attempts(self):
        result, _, collector, driver, transport = self._run()
        with patch.dict(os.environ, {"FORMAL_FAKE_KEY": "local-test-key"}), \
             patch("agentmembrane.host_v2.rq1_three_tier_formal_v1.gate."
                   "validate_formal_manifest", side_effect=lambda value: value):
            with self.assertRaisesRegex(
                    ValueError, "runtime_object_reuse_forbidden:driver"):
                _run_offline_formal_cell_core(
                    manifest=self.manifest,
                    episode_id=self.cell["episode_id"], bundle=self.bundle,
                    adapter=self.native, driver=driver, collector=collector,
                )
        self.assertTrue(verify(
            collector.run_dir,
            expected_seal_hash=result["seal"]["seal_hash"],
        )["ok"])

        second_cell = copy.deepcopy(self.cell)
        second_cell.update({
            "episode_id": self.cell["episode_id"].replace(
                "-low-honest-", "-medium-honest-"),
            "level": "medium",
            "runtime_external_level": LEVEL_BINDINGS["medium"][
                "runtime_level"],
            "legacy_canonical_analog": LEVEL_BINDINGS["medium"][
                "legacy_canonical_analog"],
        })
        manifest_body = {
            key: copy.deepcopy(value) for key, value in self.manifest.items()
            if key != "manifest_sha256"
        }
        manifest_body["cells"].append(second_cell)
        second_manifest = _hashed(manifest_body, "manifest_sha256")
        second_cfg = inner_config(second_cell, self.bundle.sha256)
        second_collector = EventCollector(
            self.root / "second-run", second_cell["episode_id"])
        self.addCleanup(second_collector.abort)
        second_adapter = ProcessNativeTask(
            str(NATIVE_PYTHON.absolute()), str(SOURCE.resolve()),
            "travel", "user_task_0", timeout=20,
        )
        self.addCleanup(second_adapter.shutdown)
        second_prompts = role_prompts(
            second_cfg, second_adapter.prompt, self.goal["goal"],
            attack_spec=self.attack_spec,
        )
        second_driver = FormalRoleModelDriver(
            second_cfg, second_prompts, second_collector, transport)
        with patch("agentmembrane.host_v2.rq1_three_tier_formal_v1.gate."
                   "validate_formal_manifest", side_effect=lambda value: value):
            with self.assertRaisesRegex(
                    ValueError, "runtime_object_reuse_forbidden:transport"):
                _run_offline_formal_cell_core(
                    manifest=second_manifest,
                    episode_id=second_cell["episode_id"], bundle=self.bundle,
                    adapter=second_adapter, driver=second_driver,
                    collector=second_collector,
                )
        self.assertFalse((second_collector.run_dir /
                          FORMAL_ALLOCATION_PATH).exists())

    def test_native_endpoint_evaluator_requires_registered_sealed_input(self):
        result, collector, _, _ = self._run_production("evaluation-run")
        evaluator = ProcessNativeTask(
            str(NATIVE_PYTHON.absolute()), str(SOURCE.resolve()),
            "travel", "user_task_0", timeout=20,
        )
        self.addCleanup(evaluator.shutdown)
        arguments = {
            "adapter": evaluator,
            "run_root": collector.run_dir,
            "expected_seal_hash": result["seal"]["seal_hash"],
            "manifest": self.manifest,
            "episode_id": self.cell["episode_id"],
            "bundle": self.bundle,
        }
        with self.assertRaisesRegex(ValueError, "registered_evaluator"):
            evaluate_registered_native_endpoints(**arguments)
        # registered_task_resource owns this marker in production.  This unit
        # test isolates the downstream sealed evaluator without rebuilding the
        # complete 46-task activation manifest.
        setattr(evaluator, "_rq1_formal_evaluator_only", True)
        with patch("agentmembrane.host_v2.rq1_three_tier_formal_v1.gate."
                   "validate_formal_manifest", side_effect=lambda value: value):
            scored = evaluate_registered_native_endpoints(**arguments)
        self.assertEqual(scored["execution_seal_sha256"],
                         result["seal"]["seal_hash"])
        self.assertEqual(scored["formal_evidence_sha256"], result[
            "formal_evidence"]["formal_evidence_sha256"])
        self.assertEqual(scored["function_call_count"], 0)
        self.assertEqual(scored["admitted"]["inner_evidence"],
                         result["inner_evidence"])

    def test_trusted_evaluator_write_read_and_rehashed_tamper_rejected(self):
        result, collector, _, _ = self._run_production("trusted-evaluation-run")
        evaluator = ProcessNativeTask(
            str(NATIVE_PYTHON.absolute()), str(SOURCE.resolve()),
            "travel", "user_task_0", timeout=20,
        )
        self.addCleanup(evaluator.shutdown)
        setattr(evaluator, "_rq1_formal_evaluator_only", True)
        resource = {"bundle": self.bundle, "adapter": evaluator}
        output = self.root / "evaluation.json"
        with patch("agentmembrane.host_v2.rq1_three_tier_formal_v1.gate."
                   "validate_formal_manifest", side_effect=lambda value: value), \
             patch("agentmembrane.host_v2.rq1_three_tier_formal_v1."
                   "evaluator.validate_formal_manifest",
                   side_effect=lambda value: value):
            written = write_formal_cell_evaluation(
                manifest=self.manifest,
                episode_id=self.cell["episode_id"],
                run_root=collector.run_dir,
                execution_seal_sha256=result["seal"]["seal_hash"],
                output=output,
                resource=resource,
            )
            loaded = strict_loads(output.read_bytes())
            admitted = _validate_analysis_input(
                loaded, manifest=self.manifest, cell=self.cell,
                task=self.manifest["tasks"][0], resource=resource,
            )
            self.assertEqual(admitted["evaluation_sha256"],
                             written["evaluation_sha256"])

            forged = copy.deepcopy(loaded)
            forged["metrics"]["Q"]["point"] = 0.5
            forged["evaluation_sha256"] = digest({
                key: value for key, value in forged.items()
                if key != "evaluation_sha256"
            })
            with self.assertRaisesRegex(
                    ValueError, "not_trusted_evaluator_output"):
                _validate_analysis_input(
                    forged, manifest=self.manifest, cell=self.cell,
                    task=self.manifest["tasks"][0], resource=resource,
                )

    def test_unbound_raw_http_transport_is_rejected_before_actor(self):
        cfg = inner_config(self.cell, self.bundle.sha256)
        collector = EventCollector(self.root / "raw-http", cfg["episode_id"])
        self.addCleanup(collector.abort)
        transport = HTTPTransport(
            self.route["endpoint"], self.route["credential_env"],
            timeout_seconds=50,
            hard_timeout_seconds=PHASE_SCHEDULE[
                "model_request_hard_timeout_seconds"],
        )
        transport.request = FakeHTTP()
        prompts = role_prompts(
            cfg, self.native.prompt, self.goal["goal"],
            attack_spec=self.attack_spec,
        )
        driver = FormalRoleModelDriver(cfg, prompts, collector, transport)
        with patch.dict(os.environ, {"FORMAL_FAKE_KEY": "local-test-key"}), \
             patch("agentmembrane.host_v2.rq1_three_tier_formal_v1.gate."
                   "validate_formal_manifest", side_effect=lambda value: value):
            with self.assertRaisesRegex(
                    ValueError, "formal_runtime_object_graph_mismatch"):
                _run_offline_formal_cell_core(
                    manifest=self.manifest,
                    episode_id=self.cell["episode_id"], bundle=self.bundle,
                    adapter=self.native, driver=driver, collector=collector,
                )
        self.assertFalse((collector.run_dir / FORMAL_ALLOCATION_PATH).exists())

    def test_model_schema_violation_is_denied_without_dropping_cell(self):
        result = self._run_with_actions([
            {"type": "final", "content": "External phase complete."},
            {"type": "send_message", "recipient": "H",
             "content": "Host attempted a forbidden self-message."},
            {"type": "final", "content": "Unable to complete the task."},
        ], "schema-violation")
        denied = [row for row in result["inner_evidence"]["decisions"]
                  if row.get("dispatch_domain")
                  == "formal_actor_protocol_guard"]
        self.assertEqual(len(denied), 1)
        self.assertEqual(denied[0]["actor"], "H")
        self.assertEqual(denied[0]["status"], "rejected")
        self.assertFalse(any(row.get("sender") == "H"
                             for row in result["inner_evidence"]["messages"]))
        self.assertFalse(result["seal"]["metadata"]["formal_ready"])
        self.assertFalse(result["formal_evidence"]["formal_sample_eligible"])

    def test_wrong_registered_goal_is_rejected_before_actor(self):
        wrong_record = self.bundle.record()
        wrong_goal = self.native.native_goal_record("injection_task_1")
        wrong_record["public"]["goal"] = wrong_goal
        wrong_bundle = TaskBundle(canonical(wrong_record), digest(wrong_record))
        collector = EventCollector(
            self.root / "wrong", self.cell["episode_id"])
        self.addCleanup(collector.abort)
        with patch("agentmembrane.host_v2.rq1_three_tier_formal_v1.gate."
                   "validate_formal_manifest", side_effect=lambda value: value):
            with self.assertRaisesRegex(ValueError, "bundle_goal_QID"):
                _run_offline_formal_cell_core(
                    manifest=self.manifest,
                    episode_id=self.cell["episode_id"],
                    bundle=wrong_bundle, adapter=self.native,
                    driver=object(), collector=collector,
                )
        self.assertFalse((collector.run_dir / FORMAL_ALLOCATION_PATH).exists())

    def test_public_runner_requires_an_activated_manifest(self):
        self.assertTrue(runner.FORMAL_CORE_RUNTIME_IMPLEMENTED)
        self.assertTrue(runner.FORMAL_RUNTIME_IMPLEMENTED)
        self.assertTrue(
            runner.FORMAL_PER_CELL_PROXY_LIFECYCLE_IMPLEMENTED)
        self.assertEqual(
            runner.FORMAL_ACTION_SCHEMAS["H"]["message_recipient_enum"], [])
        self.assertEqual(
            runner.FORMAL_ACTION_SCHEMAS["E"]["message_recipient_enum"], ["H"])
        with self.assertRaisesRegex(RuntimeError, "activated_formal_manifest"):
            runner.run_formal_cell()
        with patch("agentmembrane.host_v2.rq1_three_tier_formal_v1.gate."
                   "validate_formal_manifest", side_effect=lambda value: value):
            with self.assertRaisesRegex(
                    ValueError, "exact_registered_formal_cell_required"):
                runner.run_formal_cell(
                    manifest=self.manifest, episode_id="missing-cell",
                    run_parent=self.root / "production-attempt",
                )
        with self.assertRaises(TypeError):
            runner.run_formal_cell(
                manifest=self.manifest, episode_id=self.cell["episode_id"],
                run_parent=self.root / "production-attempt",
                driver=object(), transport=object(),
            )

    def test_public_runner_owns_full_fake_process_cell(self):
        with patch("agentmembrane.host_v2.rq1_three_tier_formal_v1.gate."
                   "validate_formal_manifest", side_effect=lambda value: value), \
             patch.object(
                 runner, "registered_execution_resource",
                 return_value=nullcontext({
                     "bundle": self.bundle, "adapter": self.native})):
            result = runner.run_formal_cell(
                manifest=self.manifest, episode_id=self.cell["episode_id"],
                run_parent=self.root / "public-production",
            )
        self.assertTrue(result["formal_evidence"]["formal_sample_eligible"])
        self.assertTrue(result["seal"]["metadata"]["formal_ready"])
        self.assertIsNotNone(result["production_proxy_lifecycle_receipt"])

    def test_stop_failure_is_not_admitted_and_cleanup_precedes_failure_seal(self):
        (self.root / "fail-stop-once").write_text("1", encoding="ascii")
        output = self.root / "failed-production"
        with patch("agentmembrane.host_v2.rq1_three_tier_formal_v1.gate."
                   "validate_formal_manifest", side_effect=lambda value: value), \
             patch.object(
                 runner, "registered_execution_resource",
                 return_value=nullcontext({
                     "bundle": self.bundle, "adapter": self.native})):
            with self.assertRaisesRegex(
                    RuntimeError, "per_cell_proxy_stop_failed"):
                runner.run_formal_cell(
                    manifest=self.manifest,
                    episode_id=self.cell["episode_id"],
                    run_parent=output,
                )
        run_dir = output / self.cell["episode_id"]
        seal = strict_loads((run_dir / "seal.json").read_bytes())
        self.assertFalse(seal["metadata"]["formal_ready"])
        cleanup = seal["metadata"]["formal_failure"]["cleanup"]
        self.assertEqual(cleanup, {
            "process_stop_confirmed": True,
            "secret_cleanup_confirmed": True,
        })
        self.assertFalse((run_dir / CELL_LIFECYCLE_PATH).exists())
        self.assertEqual(list(self.root.glob("fake-cell-proxy-*")), [])


if __name__ == "__main__":
    unittest.main()
