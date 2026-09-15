from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import build_formal_gate as gate


class FormalGateCliTests(unittest.TestCase):
    def test_private_and_output_paths_are_required(self):
        required = {
            "qualified", "goal_assignments", "models", "route", "attestation",
            "lifecycle_runner", "cli_proxy_binary", "canary",
            "canary_verification", "h_output", "route_binding_output",
            "preflight_output",
        }
        actions = {action.dest: action for action in gate.parser()._actions}
        self.assertTrue(required.issubset(actions))
        for name in required:
            self.assertTrue(actions[name].required, name)
            self.assertIsNone(actions[name].default, name)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            gate.parse_args([])

    def test_source_has_no_machine_or_account_specific_defaults(self):
        source = Path(gate.__file__).read_text(encoding="utf-8")
        for forbidden in (
            "switched_account_route_", "switched_account_proxy.py",
            "cliproxyapi/", "Path.home()", "/" + "Users/",
        ):
            self.assertNotIn(forbidden, source)

    def test_missing_input_fails_before_any_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self._inputs(Path(temporary), materialize=False)
            with self.assertRaisesRegex(
                    ValueError, "required_input_missing_or_not_regular:identity"):
                gate.build(inputs)
            self.assertFalse(inputs.h_output.exists())
            self.assertFalse(inputs.route_binding_output.exists())
            self.assertFalse(inputs.preflight_output.exists())

    def test_explicit_inputs_create_once_and_are_wired_exactly(self):
        with tempfile.TemporaryDirectory() as temporary:
            inputs = self._inputs(Path(temporary), materialize=True)
            h_contract = {
                "task_count": 1,
                "tasks": [{
                    "goal_cluster_id": "fixture-cluster",
                    "H_output_contract": {"condition_count_checked": 6},
                }],
            }
            route_binding = {"route_runtime_binding_sha256": "a" * 64}
            preflight = {"blocking_gates": ["fixture_gate_pending"]}
            with (
                mock.patch.object(gate, "build_h_output_contract",
                                  return_value=h_contract) as build_h,
                mock.patch.object(gate, "validate_h_output_contract"),
                mock.patch.object(gate, "build_route_runtime_binding",
                                  return_value=route_binding) as build_route,
                mock.patch.object(gate, "validate_route_runtime_binding"),
                mock.patch.object(gate, "preflight_status",
                                  return_value=preflight) as preflight_call,
            ):
                result = gate.build(inputs)

            self.assertEqual(json.loads(inputs.h_output.read_text()), h_contract)
            self.assertEqual(
                json.loads(inputs.route_binding_output.read_text()), route_binding)
            self.assertEqual(json.loads(inputs.preflight_output.read_text()), preflight)
            self.assertEqual(result["research_sample_count"], 0)
            self.assertEqual(result["model_calls"], 0)
            self.assertEqual(result["api_calls"], 0)
            build_h.assert_called_once_with(
                identity_path=inputs.identity.resolve(),
                pool_path=inputs.pool.resolve(),
                analysis_path=inputs.candidate_analysis.resolve(),
                qualified_path=inputs.qualified.resolve(),
                goal_assignments_path=inputs.goal_assignments.resolve(),
                models_path=inputs.models.resolve(),
            )
            build_route.assert_called_once_with(
                route_path=inputs.route.resolve(),
                attestation_path=inputs.attestation.resolve(),
                lifecycle_runner_path=inputs.lifecycle_runner.resolve(),
                cli_proxy_binary_path=inputs.cli_proxy_binary.resolve(),
                canary_path=inputs.canary.resolve(),
                canary_verification_path=inputs.canary_verification.resolve(),
            )
            call = preflight_call.call_args.kwargs
            self.assertEqual(call["candidate_identity_path"], inputs.identity.resolve())
            self.assertEqual(call["goal_balance_candidate_path"],
                             inputs.goal_balance_candidate.resolve())
            self.assertNotEqual(call["h_contract_path"], inputs.h_output)
            self.assertNotEqual(call["route_binding_path"],
                                inputs.route_binding_output)
            with self.assertRaisesRegex(ValueError, "output_already_exists:h_output"):
                gate.build(inputs)

    @staticmethod
    def _inputs(root: Path, *, materialize: bool) -> gate.GateInputs:
        input_names = (
            "identity", "pool", "candidate_analysis", "qualified",
            "goal_assignments", "goal_balance_candidate", "models", "route",
            "attestation", "lifecycle_runner", "cli_proxy_binary", "canary",
            "canary_verification",
        )
        paths = {name: root / f"{name}.json" for name in input_names}
        if materialize:
            for path in paths.values():
                path.write_text("{}\n", encoding="utf-8")
        future = {
            name: root / f"{name}.json"
            for name in (
                "governance", "final_analysis", "final_goals", "final_qid",
                "runtime_qualification", "evaluator_qualification",
            )
        }
        return gate.GateInputs(
            **paths,
            **future,
            h_output=root / "out-H.json",
            route_binding_output=root / "out-route.json",
            preflight_output=root / "out-preflight.json",
        )


if __name__ == "__main__":
    unittest.main()
