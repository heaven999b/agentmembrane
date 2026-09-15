from __future__ import annotations

import copy
import hashlib
import json
import unittest

from agentmembrane.host_v2.public_four_cell_v1.route_resolution_v1 import (
    EXPECTED_UPSTREAM_URL,
    RouteResolutionError,
    resolve_route,
)


def _wire(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _request(*, temperature: bool = True) -> dict[str, object]:
    value: dict[str, object] = {
        "input": [{"role": "user", "content": "route probe"}],
        "max_output_tokens": 1100,
        "model": "gpt-5.6-sol",
        "parallel_tool_calls": False,
        "reasoning": {"effort": "max", "summary": "auto"},
        "store": False,
        "stream": False,
        "tool_choice": {"type": "function", "name": "submit_turn"},
        "tools": [{
            "type": "function",
            "name": "submit_turn",
            "description": "submit",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
                "additionalProperties": False,
            },
            "strict": True,
        }],
    }
    if temperature:
        value["temperature"] = 0
    return value


def _log(request_text: str, upstream: dict[str, object], *, status: int = 400,
         response: dict[str, object] | None = None) -> bytes:
    response = response or {"error": {"code": "invalid_function_parameters"}}
    response_text = json.dumps(response, sort_keys=True, indent=2)
    upstream_text = _wire(upstream).decode("utf-8")
    return (
        "=== REQUEST INFO ===\n"
        "Version: fixture\nURL: /v1/responses\nMethod: POST\n"
        "Downstream Transport: http\nUpstream Transport: http\n"
        "Timestamp: fixture\n\n\n"
        "=== HEADERS ===\nContent-Type: application/json\n\n\n"
        f"=== REQUEST BODY ===\n{request_text}\n\n\n"
        "=== API REQUEST 1 ===\nTimestamp: fixture\n"
        f"Upstream URL: {EXPECTED_UPSTREAM_URL}\nHTTP Method: POST\n"
        "Auth: fixture\n\nHeaders:\nContent-Type: application/json\n\n"
        f"Body:\n{upstream_text}\n\n\n"
        f"=== API RESPONSE ===\nTimestamp: fixture\n{response_text}\n\n\n"
        f"=== RESPONSE ===\nStatus: {status}\nContent-Type: application/json\n\n"
        f"{response_text}\n"
    ).encode("utf-8")


def _binding(request_bytes: bytes, log_bytes: bytes) -> dict[str, object]:
    return {
        "result_path": "probe/result.json",
        "result_sha256": "a" * 64,
        "detail_log_path": "/fixture/error-v1-responses.log",
        "detail_log_sha256": hashlib.sha256(log_bytes).hexdigest(),
        "request_sha256": hashlib.sha256(request_bytes).hexdigest(),
        "http_status": 400,
        "counts": {
            "client_attempts": 1,
            "local_proxy_http_attempts": 1,
            "provider_accepted_requests": 0,
            "delivered_model_responses": 0,
            "token_bearing_calls": 0,
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
        },
    }


class RouteResolutionV1Tests(unittest.TestCase):
    def resolve(self, request: dict[str, object], upstream: dict[str, object] | None = None):
        request_bytes = _wire(request)
        log_bytes = _log(request_bytes.decode(), copy.deepcopy(upstream or request))
        return resolve_route(
            downstream_request_bytes=request_bytes,
            detail_log_bytes=log_bytes,
            probe_result_binding=_binding(request_bytes, log_bytes),
        )

    def test_exact_route_resolves_and_separates_client_from_effective(self) -> None:
        result = self.resolve(_request())
        self.assertEqual(result["resolution_status"], "resolved")
        self.assertEqual(set(result["required_controls"].values()), {True})
        self.assertEqual(result["not_proven"], [])
        self.assertEqual(result["client_requested"]["endpoint_path"], "/v1/responses")
        self.assertEqual(result["effective_upstream"]["upstream_url"], EXPECTED_UPSTREAM_URL)
        self.assertIsNot(result["client_requested"], result["effective_upstream"])
        self.assertEqual(set(result["actual_execution_counts"].values()), {0})

    def test_absent_temperature_is_explicitly_not_proven(self) -> None:
        result = self.resolve(_request(temperature=False))
        self.assertEqual(result["resolution_status"], "no_go")
        self.assertEqual(result["not_proven"], ["temperature_zero"])
        self.assertIs(result["required_controls"]["temperature_zero"], False)

    def test_effective_value_mutations_are_no_go(self) -> None:
        for field, value, control in (
            ("model", "gpt-5.6-terra", "model_exact"),
            ("reasoning", {"effort": "high", "summary": "auto"}, "reasoning_exact"),
            ("max_output_tokens", 1099, "max_output_tokens_1100"),
            ("parallel_tool_calls", True, "parallel_tool_calls_false"),
            ("stream", True, "stream_false"),
        ):
            with self.subTest(field=field):
                upstream = _request()
                upstream[field] = value
                result = self.resolve(_request(), upstream)
                self.assertEqual(result["resolution_status"], "no_go")
                self.assertIs(result["required_controls"][control], False)

    def test_image_generation_or_changed_function_is_no_go(self) -> None:
        upstream = _request()
        upstream["tools"] = [
            *upstream["tools"],
            {"type": "image_generation", "output_format": "png"},
        ]
        result = self.resolve(_request(), upstream)
        self.assertIs(result["required_controls"]["no_image_generation"], False)
        self.assertIs(
            result["required_controls"]["sole_forced_strict_function_tool"], False
        )

    def test_duplicate_json_key_is_rejected(self) -> None:
        request = _request()
        request_bytes = _wire(request)
        duplicate = request_bytes.decode().replace(
            '"model":"gpt-5.6-sol"',
            '"model":"gpt-5.6-sol","model":"gpt-5.6-sol"',
        ).encode()
        log_bytes = _log(duplicate.decode(), request)
        with self.assertRaisesRegex(RouteResolutionError, "duplicate JSON"):
            resolve_route(
                downstream_request_bytes=duplicate,
                detail_log_bytes=log_bytes,
                probe_result_binding=_binding(duplicate, log_bytes),
            )

    def test_missing_upstream_control_is_rejected(self) -> None:
        upstream = _request()
        upstream.pop("max_output_tokens")
        with self.assertRaisesRegex(RouteResolutionError, "missing a required control"):
            self.resolve(_request(), upstream)

    def test_multiple_api_requests_or_logs_are_rejected(self) -> None:
        request_bytes = _wire(_request())
        log_bytes = _log(request_bytes.decode(), _request())
        for mutated in (
            log_bytes.replace(
                b"=== API RESPONSE ===",
                b"=== API REQUEST 2 ===\nBody:\n{}\n\n=== API RESPONSE ===",
            ),
            log_bytes + log_bytes,
        ):
            with self.subTest(), self.assertRaisesRegex(
                RouteResolutionError, "exactly one ordered request"
            ):
                resolve_route(
                    downstream_request_bytes=request_bytes,
                    detail_log_bytes=mutated,
                    probe_result_binding=_binding(request_bytes, mutated),
                )

    def test_usage_and_2xx_are_rejected(self) -> None:
        request_bytes = _wire(_request())
        usage = {"usage": {"input_tokens": 1, "output_tokens": 0}}
        usage_log = _log(request_bytes.decode(), _request(), response=usage)
        with self.assertRaisesRegex(RouteResolutionError, "usage/token-bearing"):
            resolve_route(
                downstream_request_bytes=request_bytes,
                detail_log_bytes=usage_log,
                probe_result_binding=_binding(request_bytes, usage_log),
            )
        success_log = _log(request_bytes.decode(), _request(), status=200)
        with self.assertRaisesRegex(RouteResolutionError, "2xx"):
            resolve_route(
                downstream_request_bytes=request_bytes,
                detail_log_bytes=success_log,
                probe_result_binding=_binding(request_bytes, success_log),
            )

    def test_probe_binding_hash_counts_and_exact_fields_fail_closed(self) -> None:
        request_bytes = _wire(_request())
        log_bytes = _log(request_bytes.decode(), _request())
        for mutate in (
            lambda b: b.update(detail_log_sha256="0" * 64),
            lambda b: b["counts"].update(provider_accepted_requests=1),
            lambda b: b.update(extra=True),
        ):
            binding = _binding(request_bytes, log_bytes)
            mutate(binding)
            with self.subTest(), self.assertRaises(RouteResolutionError):
                resolve_route(
                    downstream_request_bytes=request_bytes,
                    detail_log_bytes=log_bytes,
                    probe_result_binding=binding,
                )

    def test_wrong_actual_upstream_url_is_rejected(self) -> None:
        request_bytes = _wire(_request())
        log_bytes = _log(request_bytes.decode(), _request()).replace(
            EXPECTED_UPSTREAM_URL.encode(), b"https://example.invalid/responses"
        )
        with self.assertRaisesRegex(RouteResolutionError, "actual upstream URL"):
            resolve_route(
                downstream_request_bytes=request_bytes,
                detail_log_bytes=log_bytes,
                probe_result_binding=_binding(request_bytes, log_bytes),
            )


if __name__ == "__main__":
    unittest.main()
