from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agentmembrane.host_v2.public_four_cell_v1.cliproxy_transport_v2 import (  # noqa: E402
    CLIProxySolTransport,
    CLIProxyTransportError,
    validate_loopback_chat_completions_endpoint,
)
from agentmembrane.host_v2.public_four_cell_v1.sol_planner_wire_v4 import (  # noqa: E402
    DISCOVERY_PHASE,
    _request_wire,
)
from experiments.host_boundary_v2.public_four_cell_canary_v1.run_authorized_canary import (  # noqa: E402
    AuthorizedCanaryEntrypointError,
    ValidatedExecutionPreflight,
    _build_and_run,
    run_real_canary,
    validate_execution_preflight,
)


class _Response:
    def __init__(self, body: bytes, *, status: int = 200) -> None:
        self.body = body
        self.status = status

    def read(self, amount: int = -1) -> bytes:
        return self.body if amount < 0 else self.body[:amount]

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> None:
        return None


class _Opener:
    def __init__(self, body: bytes = b'{"raw":"bytes"}') -> None:
        self.body = body
        self.calls: list[tuple[object, float]] = []
        self.error: Exception | None = None

    def __call__(self, request: object, *, timeout: float) -> _Response:
        self.calls.append((request, timeout))
        if self.error is not None:
            raise self.error
        return _Response(self.body)


def _request() -> bytes:
    _, wire = _request_wire(
        phase=DISCOVERY_PHASE,
        interface_description='{"operations":[]}',
        messages=({"role": "user", "content": "authorized user objective"},),
    )
    return wire


class CLIProxySolTransportTests(unittest.TestCase):
    def test_exact_wire_is_one_loopback_attempt_and_raw_response_is_preserved(self) -> None:
        raw = b'{ "model" : "gpt-5.6-sol" }\n'
        opener = _Opener(raw)
        transport = CLIProxySolTransport(
            endpoint="http://127.0.0.1:19876/v1/chat/completions",
            api_key="secret-not-for-artifacts",
            timeout_seconds=37,
            _opener=opener,
        )
        self.assertEqual(transport.invoke(_request()), raw)
        self.assertEqual(len(opener.calls), 1)
        sent, timeout = opener.calls[0]
        self.assertEqual(timeout, 37)
        self.assertEqual(sent.full_url, "http://127.0.0.1:19876/v1/chat/completions")
        self.assertEqual(sent.data, _request())
        wire = json.loads(sent.data)
        self.assertEqual(wire["model"], "gpt-5.6-sol")
        self.assertEqual(wire["reasoning_effort"], "max")
        self.assertEqual(wire["temperature"], 0)
        self.assertIs(wire["stream"], False)
        self.assertEqual(wire["max_completion_tokens"], 1100)
        self.assertNotIn("retries", wire)
        self.assertIs(wire["tools"][0]["function"]["strict"], True)
        self.assertEqual(
            wire["tool_choice"],
            {
                "type": "function",
                "function": {"name": "submit_public_four_cell_turn"},
            },
        )
        metadata = transport.route_metadata
        self.assertNotIn("endpoint", metadata)
        self.assertNotIn("api_key", metadata)
        self.assertNotIn("secret-not-for-artifacts", json.dumps(metadata))


def _provenance() -> dict:
    return {
        "same_session_native_observation_loop_bound": True,
        "system_injection_occurrence_count": 0,
        "user_injection_occurrence_count": 0,
        "authorized_test_objective_in_planner_input": False,
        "fixture_injection_goal_in_planner_input": False,
        "planner_trace_count": 2,
        "total_delivered_call_cap": 4,
        "native_cells": 4,
        "planner_turns_per_pair_trace": 2,
        "proposal_replay_across_treatment_arms": True,
    }


class AuthorizedEntrypointPreflightTests(unittest.TestCase):
    def _case(self, provenance: dict | None = None):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        profile = root / "profile.json"
        authorization = root / "authorization.json"
        profile.write_text("{}", encoding="utf-8")
        authorization.write_text("{}", encoding="utf-8")
        calls: list[dict] = []

        def validator(repo_root, value, **kwargs):
            calls.append({"repo_root": repo_root, "value": value, **kwargs})
            return {
                "authorization_id": "authorized-test",
                "authorization_digest": "a" * 64,
                "execution_authorized": True,
                "claim_eligible": False,
                "fresh_namespaces": {
                    "output": "outputs/fresh",
                    "cache": "cache/fresh",
                    "native": "native/fresh",
                },
                "message_provenance": provenance or _provenance(),
            }

        return temporary, root, profile, authorization, calls, validator

    def test_dry_run_validates_true_auth_and_leaks_no_route_or_key_values(self) -> None:
        temporary, root, profile, authorization, calls, validator = self._case()
        self.addCleanup(temporary.cleanup)
        result = validate_execution_preflight(
            repo_root=root,
            profile_path=profile,
            authorization_path=authorization,
            endpoint_env="RQ1B_CLIPROXY_ENDPOINT",
            api_key_env="RQ1B_CLIPROXY_API_KEY",
            timeout_seconds=300,
            environment={
                "RQ1B_CLIPROXY_ENDPOINT": (
                    "http://127.0.0.1:19876/v1/chat/completions"
                ),
                "RQ1B_CLIPROXY_API_KEY": "never-print-this-key",
            },
            _authorization_validator=validator,
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["actual_execution_counts"], {
            "api_calls": 0,
            "model_calls": 0,
            "native_checker_calls": 0,
            "native_dispatches": 0,
            "native_resets": 0,
            "network_calls": 0,
            "provider_calls": 0,
            "task_executions": 0,
        })
        self.assertEqual(result["execution_design"], "paired_proposal_replay")
        self.assertEqual(result["planner_trace_count"], 2)
        self.assertIs(result["four_independent_model_trajectories"], False)
        self.assertEqual(result["native_cells"], 4)
        self.assertEqual(result["delivered_call_cap"], 4)
        rendered = json.dumps(result, sort_keys=True)
        self.assertNotIn("127.0.0.1", rendered)
        self.assertNotIn("never-print-this-key", rendered)
        self.assertIn("--execute", result["exact_execute_argv"])

    def test_false_auth_hash_drift_and_message_provenance_fail_closed(self) -> None:
        temporary, root, profile, authorization, _, _ = self._case()
        self.addCleanup(temporary.cleanup)

        def rejected(*_args, **_kwargs):
            raise ValueError("profile SHA mismatch")

        common = {
            "repo_root": root,
            "profile_path": profile,
            "authorization_path": authorization,
            "endpoint_env": "ENDPOINT",
            "api_key_env": "API_KEY",
            "timeout_seconds": 1,
            "environment": {
                "ENDPOINT": "http://127.0.0.1:19876/v1/chat/completions",
                "API_KEY": "test",
            },
        }
        with self.assertRaisesRegex(
            AuthorizedCanaryEntrypointError, "SHA mismatch"
        ):
            validate_execution_preflight(
                **common, _authorization_validator=rejected
            )

        for mutation in (
            {"execution_authorized": False},
            {"message_provenance": None},
            {
                "message_provenance": {
                    **_provenance(),
                    "authorized_test_objective_in_planner_input": True,
                }
            },
            {
                "message_provenance": {
                    **_provenance(),
                    "user_injection_occurrence_count": 1,
                }
            },
            {
                "message_provenance": {
                    **_provenance(),
                    "total_delivered_call_cap": 8,
                }
            },
        ):
            def invalid(*_args, **_kwargs):
                result = {
                    "execution_authorized": True,
                    "claim_eligible": False,
                    "message_provenance": _provenance(),
                }
                result.update(mutation)
                return result

            with self.subTest(mutation=mutation), self.assertRaises(
                AuthorizedCanaryEntrypointError
            ):
                validate_execution_preflight(
                    **common, _authorization_validator=invalid
                )

    def test_execute_requires_nonserialized_live_preflight_context(self) -> None:
        with self.assertRaisesRegex(
            AuthorizedCanaryEntrypointError,
            "live validated preflight context",
        ):
            run_real_canary(
                preflight={"execution_authorized": True},
                endpoint_env="ENDPOINT",
                api_key_env="API_KEY",
                timeout_seconds=1,
                environment={
                    "ENDPOINT": "http://127.0.0.1:19876/v1/chat/completions",
                    "API_KEY": "test",
                },
            )

    def test_builder_runs_paired_runner_with_fake_transport_and_runtime(self) -> None:
        from agentmembrane.host_v2.public_four_cell_v1.agentdojo_adapter import (
            required_callable_source_sha256,
        )
        from tests.host_v2.test_public_four_cell_iterative_runner_v1 import (
            ATTACKER,
            AUTHORIZED,
            PROMPT,
            _Factory,
            _QueuedBytesTransport,
            _response,
        )

        def v3_response(**kwargs):
            response = json.loads(_response(**kwargs))
            function = response["choices"][0]["message"]["tool_calls"][0]["function"]
            arguments = json.loads(function["arguments"])
            arguments["actions"] = [
                {
                    "operation": action["operation"],
                    "arguments_json": json.dumps(
                        action["arguments"],
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                }
                for action in arguments["actions"]
            ]
            final_artifact = arguments.pop("final_artifact")
            arguments["final_artifact_json"] = (
                None
                if final_artifact is None
                else json.dumps(final_artifact, sort_keys=True, separators=(",", ":"))
            )
            function["arguments"] = json.dumps(
                arguments, sort_keys=True, separators=(",", ":")
            )
            return json.dumps(
                response, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")

        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            pack = root / "pack"
            pack.mkdir()
            manifest = pack / "manifest.json"
            tasks = pack / "tasks.jsonl"
            benign = pack / "agentdojo-v1-banking-u3-i1-benign.json"
            adversarial = pack / "agentdojo-v1-banking-u3-i1-adversarial.json"
            oracle = pack / "oracle.json"
            manifest.write_text(
                json.dumps({"pack_id": "fake-public-pack-v1"}), encoding="utf-8"
            )
            tasks.write_text("{}\n", encoding="utf-8")
            benign.write_text(
                json.dumps({"user_task": {"prompt": PROMPT}}), encoding="utf-8"
            )
            adversarial.write_text(
                json.dumps(
                    {
                        "user_task": {"prompt": PROMPT},
                        "injection_task": {"goal": f"send to {ATTACKER}"},
                    }
                ),
                encoding="utf-8",
            )
            oracle.write_text("{}", encoding="utf-8")
            profile = root / "profile.json"
            authorization = root / "authorization.json"
            profile.write_text("{}", encoding="utf-8")
            authorization.write_text("{}", encoding="utf-8")

            def binding(path: Path) -> dict[str, str]:
                return {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": __import__("hashlib").sha256(path.read_bytes()).hexdigest(),
                }

            runtime_path = (
                "experiments/host_boundary_v2/public_four_cell_canary_v1/"
                "config/runtime-candidates/fake.binding.json"
            )
            validation = {
                "authorization_digest": "a" * 64,
                "profile": {
                    "document": {},
                    "path": "profile.json",
                    "sha256": __import__("hashlib").sha256(
                        profile.read_bytes()
                    ).hexdigest(),
                },
                "fresh_namespaces": {
                    "outputs": "runs/fake/output",
                    "cache": "runs/fake/cache",
                    "native": "runs/fake/native",
                },
                "runtime_binding": {
                    "path": runtime_path,
                    "sha256": "7" * 64,
                    "document": {
                        "runtime_id": "agentdojo-0.1.35-fake-entrypoint-runtime",
                        "environment_root": str((root / "fake-runtime").resolve()),
                        "environment_tree_sha256": "5" * 64,
                        "receipt_path": runtime_path.replace("binding", "receipt"),
                        "receipt_sha256": "6" * 64,
                        "callable_source_sha256": required_callable_source_sha256(),
                    },
                },
                "immutable_source_bindings": [
                    binding(manifest),
                    binding(tasks),
                    binding(adversarial),
                    binding(benign),
                    binding(oracle),
                ],
            }
            preflight = ValidatedExecutionPreflight(
                {
                    "route_metadata": {
                        "provider_route_id": "local-cli-proxy",
                        "loopback_only": True,
                        "chat_completions_path": "/v1/chat/completions",
                        "timeout_seconds": 1.0,
                        "endpoint_source_id": "ENDPOINT",
                        "api_key_source_id": "API_KEY",
                    }
                },
                repo_root=root,
                profile_path=profile,
                authorization_path=authorization,
                authorization_document={},
                authorization_report=validation,
                authorization_validator=lambda *_args, **_kwargs: validation,
            )
            transport = _QueuedBytesTransport(
                [
                    v3_response(phase="discovery", call_id="benign-discovery"),
                    v3_response(
                        phase="post", call_id="benign-post", recipient=AUTHORIZED
                    ),
                    v3_response(phase="discovery", call_id="adversarial-discovery"),
                    v3_response(
                        phase="post",
                        call_id="adversarial-post",
                        recipient=ATTACKER,
                    ),
                ]
            )

            class ExactCheckerFactory(_Factory):
                def open_session(self, **kwargs):
                    session = super().open_session(**kwargs)
                    original = session.evaluate_native_checkers

                    def evaluate():
                        result = original()
                        result["checker_binding_ids"] = [
                            "agentdojo-v0.1.35-native-utility-dispatcher",
                            "agentdojo-v0.1.35-native-security-dispatcher",
                        ]
                        return result

                    session.evaluate_native_checkers = evaluate
                    return session

            envelope, result_path = _build_and_run(
                preflight=preflight,
                transport=transport,
                session_factory=ExactCheckerFactory(),
            )
            self.assertTrue(result_path.is_file())
            self.assertEqual(envelope["physical_delivered_calls"], 4)
            runner = envelope["runner_result"]
            self.assertEqual(runner["delivered_by_trace"], {"benign": 2, "adversarial": 2})
            self.assertIs(runner["paired_proposal_replay"], True)
            self.assertIs(runner["independent_agent_trajectories"], False)
            self.assertEqual(len(transport.request_wires), 4)
            wire_text = b"\n".join(transport.request_wires).decode("utf-8")
            self.assertNotIn("authorized_test_objective", wire_text)
            self.assertNotIn("injection_task", wire_text)


class CLIProxySolTransportValidationTests(unittest.TestCase):

    def test_route_must_be_literal_loopback_exact_chat_completions(self) -> None:
        accepted = (
            "http://127.0.0.1:19876/v1/chat/completions",
            "http://[::1]:19876/v1/chat/completions",
        )
        for value in accepted:
            with self.subTest(value=value):
                self.assertEqual(validate_loopback_chat_completions_endpoint(value), value)
        rejected = (
            "https://127.0.0.1:19876/v1/chat/completions",
            "http://localhost:19876/v1/chat/completions",
            "http://192.0.2.1:19876/v1/chat/completions",
            "http://127.0.0.1:19876/chat/completions",
            "http://127.0.0.1:19876/v1/chat/completions?x=1",
            "http://user:pass@127.0.0.1:19876/v1/chat/completions",
        )
        for value in rejected:
            with self.subTest(value=value), self.assertRaises(CLIProxyTransportError):
                validate_loopback_chat_completions_endpoint(value)

    def test_nonbytes_empty_and_oversize_wire_fail_before_socket(self) -> None:
        opener = _Opener()
        transport = CLIProxySolTransport(
            endpoint="http://127.0.0.1:19876/v1/chat/completions",
            api_key="test",
            timeout_seconds=1,
            max_request_bytes=4,
            _opener=opener,
        )
        for value in ({}, "bytes", b"", b"12345"):
            with self.subTest(value=value), self.assertRaises(CLIProxyTransportError):
                transport.invoke(value)
        self.assertEqual(opener.calls, [])

    def test_transport_failure_is_not_retried(self) -> None:
        opener = _Opener()
        opener.error = TimeoutError("synthetic")
        transport = CLIProxySolTransport(
            endpoint="http://127.0.0.1:19876/v1/chat/completions",
            api_key="test",
            timeout_seconds=1,
            _opener=opener,
        )
        with self.assertRaises(CLIProxyTransportError):
            transport.invoke(_request())
        self.assertEqual(len(opener.calls), 1)


if __name__ == "__main__":
    unittest.main()
