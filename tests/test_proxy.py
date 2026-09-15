from __future__ import annotations

import json
import os
import unittest
import urllib.error
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from agentmembrane import proxy_admin
from agentmembrane.host_v2.rq1_collab_v1.live_pilot import (
    PROXY_BASE_ENV,
    PROXY_CONFIG_ENV,
    PROXY_CREDENTIAL_ENV_ENV,
    _live_proxy_settings,
)
from agentmembrane.proxy import (
    LocalProxyClient,
    ProxyError,
    _parse_local_proxy_api_keys,
    classify_proxy_http_error,
    is_retryable_proxy_error,
    load_local_proxy_settings,
)


class _Response:
    def __init__(self, payload: dict[str, object]) -> None:
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


class ProxyClassificationTests(unittest.TestCase):
    def test_local_route_has_no_machine_specific_default(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ProxyError, "non_local_proxy_rejected"):
                load_local_proxy_settings()

    def test_explicit_synthetic_loopback_route_is_accepted(self) -> None:
        with patch.dict(os.environ, {
            "AGENTMEMBRANE_PROXY_BASE_URL": "http://127.0.0.1:19876/v1",
            "AGENTMEMBRANE_PROXY_API_KEY": "sk-synthetic_12345678",
        }, clear=True):
            base_url, key, model = load_local_proxy_settings()
        self.assertEqual(base_url, "http://127.0.0.1:19876/v1")
        self.assertEqual(key, "sk-synthetic_12345678")
        self.assertIsNone(model)

    def test_generic_route_rejects_url_metadata(self) -> None:
        for base_url in (
            "http://127.0.0.1:19876/v1?slot=fixture",
            "http://fixture:secret@127.0.0.1:19876/v1",
            "http://127.0.0.1:bad/v1",
        ):
            with self.subTest(base_url=base_url), patch.dict(os.environ, {
                "AGENTMEMBRANE_PROXY_BASE_URL": base_url,
                "AGENTMEMBRANE_PROXY_API_KEY": "sk-synthetic_12345678",
            }, clear=True):
                with self.assertRaisesRegex(ProxyError, "non_local_proxy_rejected"):
                    load_local_proxy_settings()

    def test_cli_proxy_config_parser_reads_only_top_level_api_keys(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "config.yaml"
            path.write_text(
                "port: 19876\n"
                "api-keys:\n"
                "  - 'sk-first_12345678'\n"
                "  - \"sk-second.12345678\"\n"
                "debug: false\n"
                "nested:\n"
                "  - sk-not-an-api-key\n",
                encoding="utf-8",
            )
            self.assertEqual(
                _parse_local_proxy_api_keys(path),
                ("sk-first_12345678", "sk-second.12345678"),
            )

    def test_cyber_policy_hidden_behind_502_is_not_transport(self) -> None:
        body = '{"error":{"code":"cyber_policy","message":"flagged"}}'
        self.assertEqual(classify_proxy_http_error(502, body), "proxy_policy_cyber")

    def test_auth_unavailable_hidden_behind_503_is_transport(self) -> None:
        body = '{"error":{"message":"auth_unavailable: no auth available"}}'
        self.assertEqual(
            classify_proxy_http_error(503, body), "proxy_auth_unavailable"
        )

    def test_unknown_http_error_preserves_status(self) -> None:
        self.assertEqual(classify_proxy_http_error(502, "bad gateway"), "proxy_http_502")

    def test_retryable_statuses_are_shared_with_infrastructure_layer(self) -> None:
        self.assertTrue(is_retryable_proxy_error(ProxyError("proxy_http_409")))
        self.assertTrue(is_retryable_proxy_error("proxy_http_429"))
        self.assertFalse(is_retryable_proxy_error("proxy_http_400"))
        self.assertFalse(is_retryable_proxy_error("proxy_policy_cyber"))


class ExplicitRouteConfigurationTests(unittest.TestCase):
    def test_legacy_diagnostic_has_no_machine_specific_default(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "explicit_live_proxy_configuration_required"):
                _live_proxy_settings()

    def test_legacy_diagnostic_accepts_complete_synthetic_contract(self) -> None:
        values = {
            PROXY_CONFIG_ENV: "/synthetic/config.yaml",
            PROXY_BASE_ENV: "http://127.0.0.1:19876/v1",
            PROXY_CREDENTIAL_ENV_ENV: "RQ1_SYNTHETIC_PROXY_KEY",
        }
        with patch.dict(os.environ, values, clear=True):
            config, base_url, credential_env = _live_proxy_settings()
        self.assertEqual(config, Path("/synthetic/config.yaml"))
        self.assertEqual(base_url, "http://127.0.0.1:19876/v1")
        self.assertEqual(credential_env, "RQ1_SYNTHETIC_PROXY_KEY")

    def test_proxy_admin_has_no_machine_specific_default(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "explicit_proxy_admin_configuration_required"):
                proxy_admin._settings()

    def test_proxy_admin_accepts_complete_synthetic_contract(self) -> None:
        values = {
            proxy_admin.BASE_URL_ENV: "http://127.0.0.1:19876/v0/management",
            proxy_admin.INSTRUCTIONS_ENV: "/synthetic/instructions.md",
        }
        with patch.dict(os.environ, values, clear=True):
            base_url, instructions = proxy_admin._settings()
        self.assertEqual(base_url, "http://127.0.0.1:19876/v0/management")
        self.assertEqual(instructions, Path("/synthetic/instructions.md"))


class LocalProxyCompletionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = LocalProxyClient(
            base_url="http://127.0.0.1:19876/v1",
            api_key="sk-test_12345678",
        )
        self.response = _Response(
            {
                "choices": [{"message": {"content": "ok"}}],
                "usage": {
                    "prompt_tokens": 2,
                    "completion_tokens": 1,
                    "total_tokens": 3,
                },
            }
        )

    def test_explicit_max_reasoning_effort_is_sent_top_level_once(self) -> None:
        with patch("agentmembrane.proxy.urllib.request.urlopen", return_value=self.response) as urlopen:
            completion = self.client.complete(
                model="gpt-5.6-sol",
                system="system",
                user="user",
                reasoning_effort="max",
                retries=0,
            )

        self.assertEqual(completion.text, "ok")
        self.assertEqual(urlopen.call_count, 1)
        request = urlopen.call_args.args[0]
        body = json.loads(request.data.decode("utf-8"))
        self.assertEqual(body["reasoning_effort"], "max")

    def test_retries_zero_does_not_amplify_failed_request(self) -> None:
        with patch(
            "agentmembrane.proxy.urllib.request.urlopen",
            side_effect=urllib.error.URLError("offline-test"),
        ) as urlopen:
            with self.assertRaisesRegex(ProxyError, "proxy_connection_failed"):
                self.client.complete(
                    model="gpt-5.6-sol",
                    system="system",
                    user="user",
                    reasoning_effort="max",
                    retries=0,
                )

        self.assertEqual(urlopen.call_count, 1)

    def test_omitted_reasoning_effort_is_absent_from_request(self) -> None:
        with patch("agentmembrane.proxy.urllib.request.urlopen", return_value=self.response) as urlopen:
            self.client.complete(
                model="gpt-5.4",
                system="system",
                user="user",
                retries=0,
            )

        request = urlopen.call_args.args[0]
        body = json.loads(request.data.decode("utf-8"))
        self.assertNotIn("reasoning_effort", body)

    def test_reasoning_effort_rejects_values_outside_api_enum(self) -> None:
        with patch("agentmembrane.proxy.urllib.request.urlopen") as urlopen:
            with self.assertRaisesRegex(ValueError, "reasoning_effort must be one of"):
                self.client.complete(
                    model="gpt-5.6-sol",
                    system="system",
                    user="user",
                    reasoning_effort="dynamic",  # type: ignore[arg-type]
                    retries=0,
                )

        urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
