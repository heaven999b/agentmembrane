from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = (
    ROOT
    / "experiments/host_boundary_v2/public_mapping_parity_v2.2/"
    "run_tau2_parity.py"
)
SPEC = importlib.util.spec_from_file_location("run_tau2_parity", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class Tau2ParityExecutionGateTests(unittest.TestCase):
    def test_frozen_plan_fails_closed_before_any_runtime_use(self) -> None:
        result = RUNNER.audit_tau2_parity_plan(repo_root=ROOT)

        self.assertEqual(result["decision"], "NO_GO")
        self.assertEqual(result["planned_coverage"]["source_count"], 20)
        self.assertEqual(result["planned_coverage"]["case_count"], 120)
        self.assertEqual(
            set(result["planned_coverage"]["category_counts"].values()), {20}
        )
        self.assertEqual(result["executed_coverage"]["case_count"], 0)
        self.assertTrue(
            all(value == 0 for value in result["execution_counts"].values())
        )
        self.assertFalse(result["runtime_imported"])
        self.assertFalse(result["native_environment_constructed"])
        self.assertIsNone(result["security_native"])
        self.assertIsNone(result["security_projected"])
        self.assertFalse(result["host_action_derived_security_reported_as_native"])

    def test_all_materialization_and_checker_gaps_are_explicit(self) -> None:
        result = RUNNER.audit_tau2_parity_plan(repo_root=ROOT)
        blockers = {row["code"]: row for row in result["blockers"]}

        self.assertEqual(
            blockers["CASE_EXECUTION_PAYLOAD_ABSENT"]["affected_case_count"], 120
        )
        self.assertEqual(
            blockers["WRONG_MUTATION_ARGUMENT_NOT_MATERIALIZED"]["affected_case_count"],
            20,
        )
        self.assertEqual(
            blockers[
                "WRONG_ORDER_CONSTRUCTION_UNDEFINED_FOR_SINGLE_ACTION_SOURCE"
            ]["affected_case_count"],
            2,
        )
        self.assertEqual(
            blockers["OFFLINE_NATIVE_NL_ASSERTION_UNAVAILABLE"]["affected_case_count"],
            42,
        )
        self.assertEqual(
            blockers["PROJECTED_UTILITY_CHECKER_CONTRACT_UNAVAILABLE"][
                "affected_case_count"
            ],
            120,
        )

    def test_writer_requires_fresh_scoped_namespace_and_preserves_zero_counts(
        self,
    ) -> None:
        result = RUNNER.audit_tau2_parity_plan(repo_root=ROOT)
        with tempfile.TemporaryDirectory() as temporary:
            fake_root = Path(temporary)
            (fake_root / "outputs").mkdir()
            output = fake_root / "outputs" / f"{RUNNER.OUTPUT_PREFIX}unit"
            artifact_path, artifact_sha256 = RUNNER.write_fresh_diagnostic(
                repo_root=fake_root,
                output_dir=output,
                diagnostic=result,
            )
            payload = json.loads(artifact_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["decision"], "NO_GO")
            self.assertTrue(
                all(value == 0 for value in payload["execution_counts"].values())
            )
            self.assertEqual(len(artifact_sha256), 64)
            with self.assertRaises(FileExistsError):
                RUNNER.write_fresh_diagnostic(
                    repo_root=fake_root,
                    output_dir=output,
                    diagnostic=result,
                )


if __name__ == "__main__":
    unittest.main()
