from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.cli import _strict_run_preflight, build_parser, main
from agentmembrane.host_v2.profiles import ResolvedProfile


class CliTests(unittest.TestCase):
    def _run(self, argv: list[str]) -> tuple[int, dict, str, str]:
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(argv)
        lines = stdout.getvalue().splitlines()
        self.assertEqual(len(lines), 1, stdout.getvalue())
        return code, json.loads(lines[0]), stdout.getvalue(), stderr.getvalue()

    def test_structured_and_flat_commands_parse(self) -> None:
        parser = build_parser()
        self.assertTrue(
            callable(parser.parse_args(["taskpack", "verify", "--root", "pack"])._handler)
        )
        self.assertTrue(
            callable(
                parser.parse_args(
                    [
                        "profile",
                        "resolve",
                        "--profile",
                        "p.json",
                        "--gate-result",
                        "g.json",
                        "--out",
                        "r.json",
                    ]
                )._handler
            )
        )
        self.assertTrue(
            callable(
                parser.parse_args(
                    ["campaign", "aggregate", "--runs-root", "runs"]
                )._handler
            )
        )

    def test_success_is_one_json_object_and_no_diagnostic_noise(self) -> None:
        with patch("agentmembrane.host_v2.cli.load_taskpack", return_value=object()), patch(
            "agentmembrane.host_v2.cli.verify_taskpack",
            return_value={"valid": True, "errors": []},
        ):
            code, payload, _stdout, stderr = self._run(
                ["taskpack", "verify", "--root", "fixture"]
            )
        self.assertEqual(code, 0)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["command"], "taskpack.verify")
        self.assertEqual(stderr, "")

    def test_failures_still_emit_one_json_object_and_diagnostics_use_stderr(self) -> None:
        code, payload, stdout, stderr = self._run(
            ["taskpack", "verify", "--root", "/definitely/missing"]
        )
        self.assertEqual(code, 2)
        self.assertFalse(payload["ok"])
        self.assertIn("error", payload)
        self.assertNotIn("Traceback", stdout)
        self.assertTrue(stderr.strip())

    def test_formal_prepare_stops_before_runner_when_exact_gate_fails(self) -> None:
        profile = ResolvedProfile(
            raw={"run_kind": "formal", "profile_id": "rq1"},
            source_path=Path("profile.json"),
            resolved_path=Path("resolved.json"),
        )
        failed = {
            "passed": False,
            "static": {"passed": True, "checks": {}, "details": {"errors": []}},
            "frozen_gates": {
                "passed": False,
                "checks": {"exact_model_stratum": False},
                "errors": ["exact_model_stratum failed"],
            },
            "errors": ["exact_model_stratum failed"],
        }
        with patch(
            "agentmembrane.host_v2.cli.load_resolved_profile", return_value=profile
        ), patch(
            "agentmembrane.host_v2.cli._strict_run_preflight", return_value=failed
        ), patch("agentmembrane.host_v2.cli.prepare_run") as prepare:
            code, payload, _stdout, stderr = self._run(
                [
                    "prepare",
                    "--resolved-profile",
                    "resolved.json",
                    "--run-dir",
                    "run",
                ]
            )
        self.assertEqual(code, 2)
        self.assertFalse(payload["ok"])
        self.assertIn("exact_model_stratum", stderr)
        prepare.assert_not_called()

    def test_lower_cost_gate_profile_still_requires_exact_resolved_model(self) -> None:
        profile = ResolvedProfile(
            raw={
                "run_kind": "gate",
                "claim_bearing": False,
                "model": {
                    "requested_id": "lower-cost-model",
                    "provider_route_id": "provider",
                },
                "resolution": {
                    "resolved_model_id": "silent-fallback",
                    "provider_route_id": "provider",
                },
            },
            source_path=Path("profile.json"),
            resolved_path=Path("resolved.json"),
        )
        static = SimpleNamespace(passed=True, checks={}, details={"errors": []})
        with patch("agentmembrane.host_v2.cli.preflight", return_value=static):
            report = _strict_run_preflight(profile)
        self.assertFalse(report["passed"])
        self.assertFalse(
            report["model_stratum"]["checks"]["requested_equals_resolved_model"]
        )

    def test_campaign_command_serializes_dataclass_result(self) -> None:
        result = SimpleNamespace(
            campaign_id="campaign",
            profile_runs={"rq1": "/runs/rq1"},
            state="complete",
        )
        # The production result is a dataclass; use a tiny real-looking object by
        # returning a mapping here to assert the command boundary itself.
        with patch(
            "agentmembrane.host_v2.cli.run_campaign",
            return_value={
                "campaign_id": result.campaign_id,
                "profile_runs": result.profile_runs,
                "state": result.state,
            },
        ):
            code, payload, _stdout, stderr = self._run(
                [
                    "campaign",
                    "run",
                    "--campaign",
                    "campaign.json",
                    "--runs-root",
                    "runs",
                ]
            )
        self.assertEqual(code, 0)
        self.assertEqual(payload["result"]["state"], "complete")
        self.assertEqual(stderr, "")


if __name__ == "__main__":
    unittest.main()
