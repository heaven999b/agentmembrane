from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
PROBE_PATH = (
    REPO_ROOT
    / "experiments/host_boundary_v2/public_four_cell_canary_v2/"
    "responses_route_probe.py"
)


def _load_probe():
    spec = importlib.util.spec_from_file_location(
        "public_four_cell_responses_route_probe_v1_test_module", PROBE_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load route probe")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PROBE = _load_probe()


class _FakeResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self.body = body

    def read(self, amount: int = -1) -> bytes:
        return self.body if amount < 0 else self.body[:amount]

    def __enter__(self):
        return self

    def __exit__(self, *args: object) -> None:
        return None


class _Fixture:
    def __init__(self) -> None:
        self._temporary = tempfile.TemporaryDirectory(dir="/private/tmp")
        self.root = Path(self._temporary.name)
        for relative in (PROBE.SCRIPT_PATH, PROBE.TEST_PATH, PROBE.AUDIT_PATH):
            source = REPO_ROOT / relative
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
        self.profile_path = self.root / PROBE.PROFILE_PATH
        self.profile_path.parent.mkdir(parents=True, exist_ok=True)
        self.profile_path.write_bytes(
            PROBE.canonical_json_bytes(PROBE.build_profile_document(self.root)) + b"\n"
        )
        self.authorization_path = self.root / PROBE.AUTHORIZATION_PATH
        self.authorization_path.write_bytes(
            PROBE.canonical_json_bytes(PROBE.build_authorization_document(self.root))
            + b"\n"
        )
        self.log_dir = self.root / "detail-logs"
        self.log_dir.mkdir()
        self.environment = {
            PROBE.ENDPOINT_ENV: "http://127.0.0.1:19876/v1/responses",
            PROBE.API_KEY_ENV: "fixture-secret-key",
            PROBE.DETAIL_LOG_DIR_ENV: str(self.log_dir),
        }

    def close(self) -> None:
        self._temporary.cleanup()

    def opener(self, status: int, body: bytes):
        calls: list[object] = []

        def open_once(request, *, timeout: float):
            calls.append(request)
            (self.log_dir / "error-v1-responses-fixture.log").write_bytes(
                b"translated-upstream-request-fixture"
            )
            return _FakeResponse(status, body)

        return open_once, calls


class ResponsesRouteProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = _Fixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_request_is_exact_direct_responses_diagnostic_contract(self) -> None:
        request = PROBE.build_request_object()
        self.assertEqual(request["model"], "gpt-5.6-sol")
        self.assertEqual(request["reasoning"], {"effort": "max", "summary": "auto"})
        self.assertIs(request["stream"], False)
        self.assertIs(request["store"], False)
        self.assertIs(request["parallel_tool_calls"], False)
        self.assertEqual(request["max_output_tokens"], 1100)
        self.assertEqual(len(request["tools"]), 1)
        tool = request["tools"][0]
        self.assertIs(tool["strict"], True)
        self.assertEqual(request["tool_choice"], {"type": "function", "name": tool["name"]})
        arguments = tool["parameters"]["properties"]["actions"]["items"][
            "properties"
        ]["arguments"]
        self.assertEqual(arguments, {"type": "object"})
        self.assertNotIn("additionalProperties", arguments)
        self.assertNotIn("properties", arguments)

    def test_prepare_is_zero_execution_and_does_not_read_environment(self) -> None:
        result = PROBE.prepare(
            repo_root=self.fixture.root,
            profile_path=self.fixture.profile_path,
            authorization_path=self.fixture.authorization_path,
        )
        self.assertEqual(result["status"], "AUTHORIZED_DIAGNOSTIC_PREPARE_PASS")
        self.assertEqual(result["actual_execution_counts"], PROBE.ZERO_COUNTS)
        self.assertEqual(result["network_calls"], 0)
        self.assertFalse((self.fixture.root / PROBE.OUTPUT_NAMESPACE).exists())
        self.assertNotIn("fixture-secret-key", json.dumps(result))

    def test_fake_400_preserves_bounded_evidence_and_new_log_binding(self) -> None:
        body = PROBE.canonical_json_bytes(
            {
                "error": {
                    "code": "invalid_function_parameters",
                    "message": "strict nested object rejected",
                }
            }
        )
        opener, calls = self.fixture.opener(400, body)
        result = PROBE.execute_once(
            repo_root=self.fixture.root,
            profile_path=self.fixture.profile_path,
            authorization_path=self.fixture.authorization_path,
            environment=self.fixture.environment,
            opener=opener,
        )
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["status"], "EXPECTED_HTTP_400_INVALID_FUNCTION_PARAMETERS")
        self.assertEqual(result["http_status"], 400)
        self.assertEqual(result["detail_log_new_file_count"], 1)
        self.assertEqual(
            result["counts"],
            {
                "client_attempts": 1,
                "local_proxy_http_attempts": 1,
                "provider_accepted_requests": 0,
                "delivered_model_responses": 0,
                "token_bearing_calls": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
            },
        )
        request_body = json.loads(calls[0].data.decode("utf-8"))
        self.assertEqual(request_body, PROBE.build_request_object())
        persisted = json.loads((self.fixture.root / PROBE.RESULT_PATH).read_text())
        self.assertEqual(persisted, result)

    def test_fake_2xx_stops_after_one_and_fresh_namespace_blocks_rerun(self) -> None:
        body = PROBE.canonical_json_bytes(
            {
                "id": "resp_fixture",
                "usage": {"input_tokens": 5, "output_tokens": 2, "total_tokens": 7},
            }
        )
        opener, calls = self.fixture.opener(200, body)
        result = PROBE.execute_once(
            repo_root=self.fixture.root,
            profile_path=self.fixture.profile_path,
            authorization_path=self.fixture.authorization_path,
            environment=self.fixture.environment,
            opener=opener,
        )
        self.assertEqual(result["status"], "UNEXPECTED_TOKEN_BEARING_DELIVERY_STOPPED")
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["counts"]["delivered_model_responses"], 1)
        self.assertEqual(result["counts"]["token_bearing_calls"], 1)
        with self.assertRaisesRegex(PROBE.RouteProbeError, "fresh output namespace"):
            PROBE.execute_once(
                repo_root=self.fixture.root,
                profile_path=self.fixture.profile_path,
                authorization_path=self.fixture.authorization_path,
                environment=self.fixture.environment,
                opener=opener,
            )
        self.assertEqual(len(calls), 1)

    def test_fake_2xx_without_usage_is_still_unexpected_delivery(self) -> None:
        opener, calls = self.fixture.opener(204, b"{}")
        result = PROBE.execute_once(
            repo_root=self.fixture.root,
            profile_path=self.fixture.profile_path,
            authorization_path=self.fixture.authorization_path,
            environment=self.fixture.environment,
            opener=opener,
        )
        self.assertEqual(result["status"], "UNEXPECTED_2XX_DELIVERY_STOPPED")
        self.assertEqual(len(calls), 1)
        self.assertEqual(result["counts"]["delivered_model_responses"], 1)
        self.assertEqual(result["counts"]["token_bearing_calls"], 0)

    def test_secret_bearing_body_is_replaced_before_result(self) -> None:
        body = b'{"error":"Authorization: Bearer fixture-secret-key"}'
        opener, calls = self.fixture.opener(400, body)
        result = PROBE.execute_once(
            repo_root=self.fixture.root,
            profile_path=self.fixture.profile_path,
            authorization_path=self.fixture.authorization_path,
            environment=self.fixture.environment,
            opener=opener,
        )
        rendered = json.dumps(result, sort_keys=True)
        self.assertEqual(len(calls), 1)
        self.assertIs(result["body_evidence"]["redacted"], True)
        self.assertNotIn("fixture-secret-key", rendered)
        self.assertNotIn("Bearer", rendered)
        self.assertNotIn("127.0.0.1", rendered)

    def test_audit_binding_drift_fails_before_transport(self) -> None:
        (self.fixture.root / PROBE.AUDIT_PATH).write_bytes(b"drift\n")
        with self.assertRaisesRegex(PROBE.RouteProbeError, "route audit SHA drift"):
            PROBE.prepare(
                repo_root=self.fixture.root,
                profile_path=self.fixture.profile_path,
                authorization_path=self.fixture.authorization_path,
            )

    def test_non_loopback_and_wrong_route_are_rejected(self) -> None:
        for endpoint in (
            "http://example.com:19876/v1/responses",
            "http://127.0.0.1:19876/v1/chat/completions",
            "https://127.0.0.1:19876/v1/responses",
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(PROBE.RouteProbeError):
                    PROBE.validate_responses_endpoint(endpoint)

    def test_materialized_real_configs_equal_live_builders(self) -> None:
        profile = json.loads((REPO_ROOT / PROBE.PROFILE_PATH).read_text())
        authorization = json.loads((REPO_ROOT / PROBE.AUTHORIZATION_PATH).read_text())
        self.assertEqual(profile, PROBE.build_profile_document(REPO_ROOT))
        self.assertEqual(authorization, PROBE.build_authorization_document(REPO_ROOT))
        self.assertEqual(
            authorization["scope"],
            "one_direct_responses_route_diagnostic_attempt_only",
        )
        self.assertIs(authorization["execution_authorized"], True)
        self.assertIs(authorization["experiment"], False)
        self.assertIs(authorization["formal_evaluation"], False)
        self.assertIs(authorization["claim_eligible"], False)


if __name__ == "__main__":
    unittest.main()
