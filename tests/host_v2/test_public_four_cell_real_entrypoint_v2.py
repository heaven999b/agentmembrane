from __future__ import annotations

import base64
from io import BytesIO
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from urllib.error import HTTPError


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agentmembrane.host_v2.public_four_cell_v1.cliproxy_transport_v2 import (  # noqa: E402
    CLIProxyHTTPStatusError,
    CLIProxySolTransport,
    CLIProxyTransportError,
)
from experiments.host_boundary_v2.public_four_cell_canary_v2.run_authorized_canary import (  # noqa: E402
    AUTHORIZATION_ARTIFACT_TYPE,
    CANONICAL_LABEL,
    ENTRYPOINT_V2_PATH,
    PREDECESSOR_ATTEMPT_PATH,
    PREDECESSOR_ATTEMPT_SHA256,
    PREDECESSOR_FAILURE_PATH,
    PREDECESSOR_FAILURE_SHA256,
    PROFILE_ARTIFACT_TYPE,
    ROUTE_AUDIT_PATH,
    ROUTE_AUDIT_SHA256,
    RUN_ID,
    SOURCE_TASK_ID,
    TRANSPORT_V2_PATH,
    UPSTREAM_CAPTURE_SHA256,
    WIRE_V3_PATH,
    WIRE_V3_SHA256,
    AuthorizedCanaryEntrypointError,
    run_real_canary,
    validate_execution_preflight,
)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: dict, field: str) -> str:
    unsigned = dict(value)
    unsigned.pop(field, None)
    return hashlib.sha256(_canonical(unsigned)).hexdigest()


def _binding(root: Path, relative: Path) -> dict[str, str]:
    return {
        "path": relative.as_posix(),
        "sha256": hashlib.sha256((root / relative).read_bytes()).hexdigest(),
    }


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
    def __init__(self, result: _Response | Exception) -> None:
        self.result = result
        self.calls: list[tuple[object, float]] = []

    def __call__(self, request: object, *, timeout: float) -> _Response:
        self.calls.append((request, timeout))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _transport(opener: _Opener, *, key: str = "test-key", error_limit: int = 4096):
    return CLIProxySolTransport(
        endpoint="http://127.0.0.1:19876/v1/chat/completions",
        api_key=key,
        timeout_seconds=7,
        max_error_body_bytes=error_limit,
        _opener=opener,
    )


class CLIProxyTransportV2Tests(unittest.TestCase):
    def test_success_preserves_raw_bytes_and_one_attempt(self) -> None:
        raw = b' {"raw":true}\n'
        opener = _Opener(_Response(raw))
        transport = _transport(opener)
        self.assertEqual(transport.invoke(b'{"request":1}'), raw)
        self.assertEqual(len(opener.calls), 1)
        request, timeout = opener.calls[0]
        self.assertEqual(request.data, b'{"request":1}')
        self.assertEqual(timeout, 7)
        self.assertEqual(
            request.full_url,
            "http://127.0.0.1:19876/v1/chat/completions",
        )
        self.assertNotIn("endpoint", transport.route_metadata)
        self.assertNotIn("api_key", transport.route_metadata)

    def test_http_error_400_preserves_safe_bounded_exact_body_and_hash(self) -> None:
        body = b'{"error":{"message":"invalid request schema"}}'
        error = HTTPError(
            "http://127.0.0.1:19876/v1/chat/completions",
            400,
            "Bad Request",
            None,
            BytesIO(body),
        )
        opener = _Opener(error)
        with self.assertRaises(CLIProxyHTTPStatusError) as raised:
            _transport(opener).invoke(b"{}")
        self.assertEqual(len(opener.calls), 1)
        exc = raised.exception
        self.assertEqual(exc.http_status, 400)
        self.assertEqual(exc.error_body_bytes, body)
        self.assertEqual(exc.error_body_length, len(body))
        self.assertEqual(exc.error_body_sha256, hashlib.sha256(body).hexdigest())
        self.assertIs(exc.error_body_truncated, False)
        self.assertIs(exc.error_body_redacted, False)
        evidence = exc.to_attempt_error_evidence()
        self.assertEqual(base64.b64decode(evidence["error_body_bytes_base64"]), body)
        self.assertEqual(evidence["http_status"], 400)
        self.assertIn(evidence["error_body_sha256"], str(exc))

    def test_error_body_is_bounded_and_marks_truncation(self) -> None:
        opener = _Opener(_Response(b"abcdefghij", status=429))
        with self.assertRaises(CLIProxyHTTPStatusError) as raised:
            _transport(opener, error_limit=4).invoke(b"{}")
        exc = raised.exception
        self.assertEqual(exc.error_body_bytes, b"abcd")
        self.assertIs(exc.error_body_truncated, True)
        self.assertEqual(exc.error_body_sha256, hashlib.sha256(b"abcd").hexdigest())
        self.assertEqual(len(opener.calls), 1)

    def test_authorization_and_api_key_echoes_are_never_exposed(self) -> None:
        secret = "never-leak-this-key"
        bodies = (
            f'{{"Authorization":"Bearer {secret}"}}'.encode(),
            f'{{"api_key":"{secret}"}}'.encode(),
            f'{{"message":"{secret}"}}'.encode(),
        )
        for body in bodies:
            error = HTTPError(
                "http://127.0.0.1:19876/v1/chat/completions",
                400,
                "Bad Request",
                None,
                BytesIO(body),
            )
            with self.subTest(body=body), self.assertRaises(
                CLIProxyHTTPStatusError
            ) as raised:
                _transport(_Opener(error), key=secret).invoke(b"{}")
            rendered = json.dumps(
                raised.exception.to_attempt_error_evidence(), sort_keys=True
            ) + str(raised.exception)
            self.assertNotIn(secret, rendered)
            self.assertNotIn("Authorization", rendered)
            self.assertNotIn("api_key", rendered)
            self.assertIs(raised.exception.error_body_redacted, True)

    def test_pre_delivery_exception_has_no_retry(self) -> None:
        opener = _Opener(TimeoutError("synthetic"))
        with self.assertRaises(CLIProxyTransportError):
            _transport(opener).invoke(b"{}")
        self.assertEqual(len(opener.calls), 1)

    def test_wire_v3_publishes_http400_body_in_immutable_attempt(self) -> None:
        from agentmembrane.host_v2.public_four_cell_v1.budget import (
            build_run_chain_budget,
        )
        from agentmembrane.host_v2.public_four_cell_v1.executor import (
            ImmutablePlannerFailure,
        )
        from agentmembrane.host_v2.public_four_cell_v1.sol_planner_wire_v3 import (
            DISCOVERY_PHASE,
            WireSolAttemptStore,
            WireSolPlanner,
        )

        body = b'{"error":{"message":"schema field required"}}'
        error = HTTPError(
            "http://127.0.0.1:19876/v1/chat/completions",
            400,
            "Bad Request",
            None,
            BytesIO(body),
        )
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            budget = build_run_chain_budget(
                repo_root=root,
                chain_id="wire-v3-http400-evidence",
                cap=4,
                predecessor_attempt_paths=(),
                fresh_namespaces={
                    "output": "runs/http400/output",
                    "cache": "runs/http400/cache",
                    "native": "runs/http400/native",
                },
            )
            planner = WireSolPlanner(
                repo_root=root,
                transport=_transport(_Opener(error)),
                attempt_store=WireSolAttemptStore(
                    repo_root=root, run_dir=root / "runs/http400/cache"
                ),
                run_chain_budget=budget,
            )
            with self.assertRaises(ImmutablePlannerFailure):
                planner.plan(
                    planner_trace_id="benign",
                    phase=DISCOVERY_PHASE,
                    interface_description='{"operations":[]}',
                    messages=(
                        {"role": "user", "content": "authorized user objective"},
                    ),
                    failure_record_path=root / "runs/http400/output/failure.json",
                )
            attempts = list((root / "runs/http400/cache/attempts").glob("*/*.json"))
            self.assertEqual(len(attempts), 1)
            attempt = json.loads(attempts[0].read_text(encoding="utf-8"))
            evidence = attempt["transport_error_evidence"]
            self.assertEqual(evidence["http_status"], 400)
            self.assertEqual(base64.b64decode(evidence["error_body_bytes_base64"]), body)
            self.assertEqual(evidence["error_body_sha256"], hashlib.sha256(body).hexdigest())
            self.assertEqual(
                attempt["error_metadata"]["transport_error_evidence"], evidence
            )
            self.assertIsNone(attempt["raw_response_bytes_base64"])
            self.assertIsNone(attempt["raw_response_sha256"])
            self.assertEqual(attempt["usage"], {
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
            })


class _V2Documents:
    def __init__(self, root: Path) -> None:
        self.root = root
        for relative, payload in (
            (WIRE_V3_PATH, (REPO_ROOT / WIRE_V3_PATH).read_bytes()),
            (TRANSPORT_V2_PATH, b"frozen-transport-v2"),
            (ENTRYPOINT_V2_PATH, b"frozen-entrypoint-v2"),
            (PREDECESSOR_FAILURE_PATH, (REPO_ROOT / PREDECESSOR_FAILURE_PATH).read_bytes()),
            (PREDECESSOR_ATTEMPT_PATH, (REPO_ROOT / PREDECESSOR_ATTEMPT_PATH).read_bytes()),
            (ROUTE_AUDIT_PATH, (REPO_ROOT / ROUTE_AUDIT_PATH).read_bytes()),
        ):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        self.profile_path = (
            root
            / "experiments/host_boundary_v2/public_four_cell_canary_v2/"
            "config/real-sol-paired-canary-v2/profile.json"
        )
        self.authorization_path = self.profile_path.with_name("authorization.json")
        self.profile_path.parent.mkdir(parents=True, exist_ok=True)
        self.namespaces = {
            kind: (
                Path("experiments/host_boundary_v2/public_four_cell_canary_v2")
                / kind
                / RUN_ID
            ).as_posix()
            for kind in ("cache", "native", "outputs")
        }
        self.code = {
            "entrypoint_v2": _binding(root, ENTRYPOINT_V2_PATH),
            "planner_wire_v3": _binding(root, WIRE_V3_PATH),
            "transport_v2": _binding(root, TRANSPORT_V2_PATH),
        }
        assert self.code["planner_wire_v3"]["sha256"] == WIRE_V3_SHA256
        self.predecessor = _binding(root, PREDECESSOR_FAILURE_PATH)
        self.attempt = _binding(root, PREDECESSOR_ATTEMPT_PATH)
        self.baseline_audit = _binding(root, ROUTE_AUDIT_PATH)
        assert self.predecessor["sha256"] == PREDECESSOR_FAILURE_SHA256
        assert self.attempt["sha256"] == PREDECESSOR_ATTEMPT_SHA256
        assert self.baseline_audit["sha256"] == ROUTE_AUDIT_SHA256
        self.resolution_path = (
            Path("experiments/host_boundary_v2/public_four_cell_canary_v2")
            / "route-resolution-probe.json"
        )
        resolution_route = {
            "client_stream": False,
            "client_tool_count": 1,
            "endpoint_path": "/v1/chat/completions",
            "enforcement_status": "resolved",
            "execution_authorized": True,
            "forced_tool_choice_preserved": True,
            "image_generation_injected": False,
            "max_completion_tokens_requested": 1100,
            "max_completion_tokens_upstream_present": False,
            "max_output_tokens_upstream_present": True,
            "model_requested": "gpt-5.6-sol",
            "model_upstream_observed": "gpt-5.6-sol",
            "parallel_tool_calls_requested": False,
            "parallel_tool_calls_upstream_observed": False,
            "reasoning_effort_requested": "max",
            "reasoning_effort_upstream_observed": "max",
            "source_protocol": "openai_chat_completions",
            "strict_function_preserved": True,
            "temperature_requested": 0,
            "temperature_upstream_present": True,
            "unresolved_fields": [],
            "upstream_capture_sha256": UPSTREAM_CAPTURE_SHA256,
            "upstream_protocol": "codex_responses",
            "upstream_stream_observed": False,
            "upstream_tool_count": 1,
        }
        resolution_file = root / self.resolution_path
        resolution_file.parent.mkdir(parents=True, exist_ok=True)
        resolution_file.write_bytes(_canonical({
            "actual_execution_counts": {
                "api_calls": 0,
                "model_calls": 0,
                "native_checker_calls": 0,
                "native_dispatches": 0,
                "native_resets": 0,
                "network_calls": 0,
                "provider_calls": 0,
                "task_executions": 0,
            },
            "artifact_type": "agentmembrane_public_four_cell_route_resolution_v2",
            "route_enforcement": resolution_route,
            "schema_version": 1,
        }))
        self.route_enforcement = {
            "baseline_route_audit_binding": self.baseline_audit,
            "client_attempt_binding": self.attempt,
            "client_stream": False,
            "client_tool_count": 1,
            "endpoint_path": "/v1/chat/completions",
            "enforcement_status": "resolved",
            "execution_authorized": True,
            "forced_tool_choice_preserved": True,
            "image_generation_injected": False,
            "max_completion_tokens_requested": 1100,
            "max_completion_tokens_upstream_present": False,
            "max_output_tokens_upstream_present": True,
            "model_requested": "gpt-5.6-sol",
            "model_upstream_observed": "gpt-5.6-sol",
            "parallel_tool_calls_requested": False,
            "parallel_tool_calls_upstream_observed": False,
            "reasoning_effort_requested": "max",
            "reasoning_effort_upstream_observed": "max",
            "resolution_evidence_binding": _binding(root, self.resolution_path),
            "source_protocol": "openai_chat_completions",
            "strict_function_preserved": True,
            "temperature_requested": 0,
            "temperature_upstream_present": True,
            "unresolved_fields": [],
            "upstream_capture_sha256": UPSTREAM_CAPTURE_SHA256,
            "upstream_protocol": "codex_responses",
            "upstream_stream_observed": False,
            "upstream_tool_count": 1,
        }
        self.profile = {
            "actual_execution_counts": {
                "api_calls": 0,
                "model_calls": 0,
                "native_checker_calls": 0,
                "native_dispatches": 0,
                "native_resets": 0,
                "network_calls": 0,
                "provider_calls": 0,
                "task_executions": 0,
            },
            "artifact_type": PROFILE_ARTIFACT_TYPE,
            "canonical_label": CANONICAL_LABEL,
            "claim_eligible": False,
            "code_bindings": self.code,
            "engineering_only": True,
            "execution": {
                "delivered_call_cap": 4,
                "episodes": 4,
                "max_inflight": 1,
                "request_level_transport_retries": 0,
                "workers": 1,
            },
            "execution_authorized": False,
            "fresh_namespaces": self.namespaces,
            "model": {
                "allowed_resolved_ids": ["gpt-5.6-sol"],
                "max_completion_tokens": 1100,
                "provider_route_id": "local-cli-proxy",
                "reasoning_effort": "max",
                "request_level_transport_retries": 0,
                "requested_id": "gpt-5.6-sol",
                "stream": False,
                "temperature": 0,
            },
            "predecessor_failure_diagnostic_binding": self.predecessor,
            "profile_digest": "",
            "route_enforcement": self.route_enforcement,
            "run_id": RUN_ID,
            "schema_version": 2,
            "scientific_claim_permitted": False,
            "source_task_id": SOURCE_TASK_ID,
        }
        self.write_profile()
        self.authorization = {
            "artifact_type": AUTHORIZATION_ARTIFACT_TYPE,
            "authorization_digest": "",
            "authorization_id": "rq1b-real-sol-paired-canary-v2-002",
            "canonical_label": CANONICAL_LABEL,
            "claim_eligible": False,
            "code_bindings": self.code,
            "decision": "AUTHORIZED_ONE_SOURCE_ENGINEERING_CANARY_V2",
            "engineering_only": True,
            "execution_authorized": True,
            "fresh_namespaces": self.namespaces,
            "predecessor_failure_diagnostic_binding": self.predecessor,
            "profile_binding": _binding(
                root, self.profile_path.relative_to(root)
            ),
            "route_enforcement": self.route_enforcement,
            "run_id": RUN_ID,
            "schema_version": 2,
            "scientific_claim_permitted": False,
            "source_task_id": SOURCE_TASK_ID,
        }
        self.write_authorization()

    def write_profile(self) -> None:
        self.profile["profile_digest"] = _digest(self.profile, "profile_digest")
        self.profile_path.write_bytes(_canonical(self.profile))

    def write_authorization(self) -> None:
        self.authorization["authorization_digest"] = _digest(
            self.authorization, "authorization_digest"
        )
        self.authorization_path.write_bytes(_canonical(self.authorization))

    def preflight(self):
        return validate_execution_preflight(
            repo_root=self.root,
            profile_path=self.profile_path,
            authorization_path=self.authorization_path,
            endpoint_env="RQ1B_CLIPROXY_ENDPOINT",
            api_key_env="RQ1B_CLIPROXY_API_KEY",
            timeout_seconds=300,
            environment={
                "RQ1B_CLIPROXY_ENDPOINT": (
                    "http://127.0.0.1:19876/v1/chat/completions"
                ),
                "RQ1B_CLIPROXY_API_KEY": "never-print-this-key",
            },
        )


class AuthorizedEntrypointV2Tests(unittest.TestCase):
    def _case(self):
        temporary = tempfile.TemporaryDirectory(dir=REPO_ROOT)
        self.addCleanup(temporary.cleanup)
        documents = _V2Documents(Path(temporary.name))
        return documents

    def test_dry_run_is_zero_socket_and_binds_new_paths_and_predecessor(self) -> None:
        documents = self._case()
        report = documents.preflight()
        self.assertEqual(report["status"], "AUTHORIZED_PREFLIGHT_PASS_V2")
        self.assertEqual(report["run_id"], RUN_ID)
        self.assertEqual(report["fresh_namespaces"], documents.namespaces)
        self.assertEqual(
            report["predecessor_failure_diagnostic_binding"], documents.predecessor
        )
        self.assertEqual(report["actual_execution_counts"], {
            "api_calls": 0,
            "model_calls": 0,
            "native_checker_calls": 0,
            "native_dispatches": 0,
            "native_resets": 0,
            "network_calls": 0,
            "provider_calls": 0,
            "task_executions": 0,
        })
        rendered = json.dumps(report, sort_keys=True)
        self.assertNotIn("127.0.0.1", rendered)
        self.assertNotIn("never-print-this-key", rendered)
        self.assertIn("public_four_cell_canary_v2", report["profile_path"])
        self.assertTrue(report["exact_execute_argv"])

    def test_auth_false_v3_hash_drift_and_used_namespace_fail_closed(self) -> None:
        documents = self._case()
        documents.authorization["execution_authorized"] = False
        documents.write_authorization()
        with self.assertRaisesRegex(
            AuthorizedCanaryEntrypointError, "authorization identity/scope"
        ):
            documents.preflight()

        documents = self._case()
        (documents.root / WIRE_V3_PATH).write_bytes(b"drifted-wire-v3")
        with self.assertRaisesRegex(AuthorizedCanaryEntrypointError, "planner_wire_v3 SHA drift"):
            documents.preflight()

        documents = self._case()
        (documents.root / documents.namespaces["outputs"]).mkdir(parents=True)
        with self.assertRaisesRegex(AuthorizedCanaryEntrypointError, "already exists"):
            documents.preflight()

    def test_route_deviation_requires_explicit_resolution(self) -> None:
        documents = self._case()
        documents.profile["route_enforcement"]["temperature_upstream_present"] = False
        documents.write_profile()
        documents.authorization["profile_binding"] = _binding(
            documents.root, documents.profile_path.relative_to(documents.root)
        )
        documents.authorization["route_enforcement"] = documents.profile[
            "route_enforcement"
        ]
        documents.write_authorization()
        with self.assertRaisesRegex(
            AuthorizedCanaryEntrypointError, "remains NO_GO"
        ):
            documents.preflight()

    def test_execute_remains_disabled_after_live_preflight(self) -> None:
        preflight = self._case().preflight()
        with self.assertRaisesRegex(
            AuthorizedCanaryEntrypointError, "DISABLED_PENDING_FROZEN_WIRE_V3"
        ):
            run_real_canary(preflight=preflight)


if __name__ == "__main__":
    unittest.main()
