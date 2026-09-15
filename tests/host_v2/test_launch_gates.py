from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import copy
from io import StringIO
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.campaign import validate_frozen_gates
from agentmembrane.host_v2.cli import _provider_launch_authorization_for_profile, main
from agentmembrane.host_v2.profiles import (
    ResolvedProfile,
    load_profile,
    validate_estimand_cell_coverage,
    validate_g0_bootstrap_authorization,
    validate_provider_launch_authorization,
)
from agentmembrane.host_v2.schema import (
    FailureClass,
    atomic_write_json,
    canonical_json_bytes,
    sha256_bytes,
    sha256_json,
)
from agentmembrane.host_v2.taskpacks import load_taskpack, taskpack_content_sha256
from agentmembrane.host_v2.runner import prepare_run
from agentmembrane.host_v2.schema import IntegrityError, RunKind
from tests.host_v2.test_campaign import _resolved_raw


REPO = Path(__file__).resolve().parents[2]
CONFIG = REPO / "experiments" / "host_boundary_v2" / "config"
ZERO = "0" * 64


class ExplicitGateSelectionTests(unittest.TestCase):
    def test_canonical_rq1_gate_sources_are_fail_closed_and_not_rq1b(self) -> None:
        pack_root = (
            REPO / "data" / "host_boundary_v2" / "packs" / "rq1-controlled-v2.2"
        )
        expected_manifest_sha256 = sha256_bytes(
            (pack_root / "manifest.json").read_bytes()
        )
        expected_logical_sha256 = taskpack_content_sha256(load_taskpack(pack_root))
        self.assertEqual(
            expected_manifest_sha256,
            "ae0328497262476b5e7f29a1a5f00c576237b34afb729f110a15ad9fd2d1ce04",
        )
        self.assertEqual(
            expected_logical_sha256,
            "1f2ff2be1f538a94f2ec2d5ef03d33772a01d2045146d01ddbc05aae79ebbcb5",
        )
        for stage, expected_tasks in (("g0", 12), ("g1", 24), ("g2", 36)):
            path = CONFIG / "profiles" / f"rq1-{stage}-gate.template.json"
            raw = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(raw["construct_id"], "authority_admission_boundary")
            self.assertEqual(raw["construct_version"], "1.0.0")
            self.assertEqual(raw["proposal_alignment"], "RQ1_authority_admission")
            self.assertEqual(raw["ladder_id"], "authority_admission_a0_a5")
            self.assertEqual(raw["ladder_version"], "1.0.0")
            self.assertEqual(
                raw["source_status"],
                "frozen_nonclaim_pack_and_assay_bound_profile_not_materialized",
            )
            self.assertFalse(raw["provider_calls_permitted"])
            self.assertFalse(raw["claim_bearing"])
            self.assertEqual(
                raw["taskpack_dependency"]["manifest_sha256"],
                expected_manifest_sha256,
            )
            self.assertEqual(
                raw["taskpack_dependency"]["logical_content_sha256"],
                expected_logical_sha256,
            )
            assay = raw["zero_token_assay_dependency"]
            assay_path = path.parent / assay["required_report_path"]
            self.assertEqual(
                sha256_bytes(assay_path.resolve().read_bytes()),
                "8dcc0eeacca930cfa32b7d13fcc4931a045a6e97181f525f436e267036642de8",
            )
            self.assertEqual(assay["report_sha256"], sha256_bytes(assay_path.resolve().read_bytes()))
            self.assertEqual(assay["execution_count"], 106)
            self.assertTrue(assay["passed"])
            self.assertFalse(assay["paid_run_authorized"])
            self.assertFalse(assay["adaptive_end_to_end_executed"])
            self.assertEqual(
                raw["taskpack_dependency"]["required_pack_id"],
                "rq1-controlled-v2.2",
            )
            self.assertEqual(
                raw["stage_selection"]["expected_task_count"], expected_tasks
            )
            self.assertFalse(raw["taskpack_dependency"]["claim_eligible"])
            self.assertEqual(raw["taskpack_dependency"]["expected_formal_rows"], 0)
            serialized = json.dumps(raw, sort_keys=True)
            self.assertNotIn("host-v2-controlled-gates-v2", serialized)
            self.assertNotIn("/controlled-v2/", serialized)
            self.assertNotIn("confused_deputy", serialized)
            self.assertNotIn("host_mediated_capability_exploitation", serialized)
            with self.assertRaises(Exception):
                load_profile(path)

    def test_g0_g1_are_exact_disjoint_12_and_g2_is_their_union(self) -> None:
        for rq in ("rq2", "rq3", "rq4"):
            profiles = {
                stage: load_profile(
                    CONFIG / "profiles" / f"{rq}-{stage.lower()}-gate.template.json"
                )
                for stage in ("G0", "G1", "G2")
            }
            ids = {
                stage: {
                    task_id
                    for pack in profile.raw["taskpacks"]
                    for task_id in pack["task_ids"]
                }
                for stage, profile in profiles.items()
            }
            self.assertEqual(len(ids["G0"]), 12)
            self.assertEqual(len(ids["G1"]), 12)
            self.assertTrue(ids["G0"].isdisjoint(ids["G1"]))
            self.assertEqual(ids["G2"], ids["G0"] | ids["G1"])
            self.assertEqual(
                validate_estimand_cell_coverage(profiles["G0"])["selected_task_count"],
                12,
            )

    def test_committed_rq2_g0_is_calibration_only_and_maximally_bounded(self) -> None:
        profile = load_profile(CONFIG / "profiles" / "rq2-g0-gate.template.json")
        self.assertEqual(profile.raw["gates"]["gate_stage"], "G0")
        self.assertFalse(profile.raw["claim_bearing"])
        self.assertEqual(profile.raw["execution"]["worker_candidates"], [12])
        self.assertEqual(profile.raw["execution"]["max_inflight_block_candidates"], [6])
        self.assertEqual(profile.raw["model"]["reasoning_effort"], "medium")
        self.assertIn("calibration diagnostics only", profile.raw["notes"])
        report = validate_estimand_cell_coverage(profile)
        self.assertTrue(report["passed"], report)
        self.assertNotIn("estimand_registry_load", report["checks"])

    def test_rq2_g0_bootstrap_rejects_deliberately_stale_config_hash(self) -> None:
        # Prove the fail-closed invariant on an isolated copy.  The live RQ2
        # authorization may legitimately be refreshed by its owning task and
        # must not make this test depend on cross-task timing.
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "agentmembrane"
            (copied / "agentmembrane" / "host_v2").mkdir(parents=True)
            shutil.copytree(
                CONFIG,
                copied / "experiments" / "host_boundary_v2" / "config",
            )
            shutil.copytree(
                REPO / "data" / "host_boundary_v2" / "packs" / "controlled-v2",
                copied / "data" / "host_boundary_v2" / "packs" / "controlled-v2",
            )
            config = copied / "experiments" / "host_boundary_v2" / "config"
            profile = load_profile(config / "profiles" / "rq2-g0-gate.template.json")
            authorization_path = config / "g0-bootstrap-authorization.json"
            authorization = json.loads(
                authorization_path.read_text(encoding="utf-8")
            )
            authorization["config_artifact_sha256s"]["estimands.json"] = ZERO
            atomic_write_json(authorization_path, authorization)
            report = validate_g0_bootstrap_authorization(
                profile,
                selected_workers=12,
                selected_max_inflight_blocks=6,
                authorization_path=authorization_path,
            )
            self.assertFalse(report["passed"], report)
            self.assertTrue(report["checks"]["exact_concurrency"])
            self.assertTrue(report["checks"]["authorization_declared_true"])
            self.assertTrue(report["checks"]["full_zero_token_assay_pass"])
            self.assertFalse(report["checks"]["config_artifacts_hash_bound"])

    def test_exact_rq2_assay_bootstraps_only_frozen_g0(self) -> None:
        profile = load_profile(CONFIG / "profiles" / "rq2-g0-gate.template.json")
        report = validate_g0_bootstrap_authorization(
            profile,
            selected_workers=12,
            selected_max_inflight_blocks=6,
        )
        self.assertTrue(report["passed"], report)
        self.assertTrue(report["checks"]["config_artifacts_hash_bound"])
        wrong_concurrency = validate_g0_bootstrap_authorization(
            profile,
            selected_workers=11,
            selected_max_inflight_blocks=6,
        )
        self.assertFalse(wrong_concurrency["passed"])
        self.assertFalse(wrong_concurrency["checks"]["exact_concurrency"])


class ProviderLaunchAuthorizationTests(unittest.TestCase):
    def test_cli_g1_runtime_authorization_reuses_raw_predecessor_gate(self) -> None:
        profile = ResolvedProfile(
            raw={
                "run_kind": "gate",
                "claim_bearing": False,
                "gates": {"gate_stage": "G1"},
                "resolution": {"resolution_mode": "gate_result"},
            },
            source_path=Path("profile.json"),
            resolved_path=None,
        )
        expected = {"passed": True, "checks": {"raw_gate": True}, "errors": []}
        with patch(
            "agentmembrane.host_v2.cli.validate_frozen_gates", return_value=expected
        ) as raw_gate, patch(
            "agentmembrane.host_v2.cli.validate_provider_launch_authorization"
        ) as global_gate:
            self.assertEqual(
                _provider_launch_authorization_for_profile(profile), expected
            )
        raw_gate.assert_called_once_with(profile)
        global_gate.assert_not_called()

    def test_cli_g2_runtime_authorization_reuses_two_raw_predecessor_gate(self) -> None:
        profile = ResolvedProfile(
            raw={
                "run_kind": "gate",
                "claim_bearing": False,
                "gates": {"gate_stage": "G2"},
                "resolution": {"resolution_mode": "gate_result"},
            },
            source_path=Path("profile.json"),
            resolved_path=None,
        )
        expected = {"passed": True, "checks": {"raw_g0_g1_gate": True}, "errors": []}
        with patch(
            "agentmembrane.host_v2.cli.validate_frozen_gates", return_value=expected
        ) as raw_gate, patch(
            "agentmembrane.host_v2.cli.validate_provider_launch_authorization"
        ) as global_gate:
            self.assertEqual(
                _provider_launch_authorization_for_profile(profile), expected
            )
        raw_gate.assert_called_once_with(profile)
        global_gate.assert_not_called()

    def test_current_three_artifact_authorization_is_hard_stop(self) -> None:
        profile = load_profile(CONFIG / "profiles" / "rq3-g0-gate.template.json")
        report = validate_provider_launch_authorization(profile)
        self.assertFalse(report["passed"])
        self.assertTrue(report["checks"]["launch_policy_hash_bound"])
        self.assertTrue(report["checks"]["coverage_manifest_hash_bound"])
        self.assertTrue(report["checks"]["zero_token_assay_hash_bound"])
        self.assertFalse(report["checks"]["authorization_declared_pass"])

    def test_tampered_launch_policy_invalidates_bound_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "config"
            shutil.copytree(CONFIG, copied)
            profile = load_profile(copied / "profiles" / "rq3-g0-gate.template.json")
            launch_path = copied / "launch-policy.json"
            launch = json.loads(launch_path.read_text(encoding="utf-8"))
            launch["reason"] = "tampered"
            launch_path.write_text(json.dumps(launch), encoding="utf-8")
            report = validate_provider_launch_authorization(profile)
            self.assertFalse(report["passed"])
            self.assertFalse(report["checks"]["launch_policy_hash_bound"])

    def test_effect_direction_key_cannot_enter_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "config"
            shutil.copytree(CONFIG, copied)
            profile = load_profile(copied / "profiles" / "rq3-g0-gate.template.json")
            path = copied / "zero-token-authorization.json"
            authorization = json.loads(path.read_text(encoding="utf-8"))
            authorization["main_effect_direction"] = "favorable"
            path.write_text(json.dumps(authorization), encoding="utf-8")
            report = validate_provider_launch_authorization(profile)
            self.assertFalse(report["passed"])
            self.assertFalse(report["checks"]["authorization_artifacts_load"])

    def test_cli_execute_spends_zero_calls_when_authorization_is_false(self) -> None:
        run_dir = Path("/tmp/host-v2-never-used")
        manifest = {"run_kind": "gate"}
        profile = ResolvedProfile(
            raw={"run_kind": "gate"}, source_path=Path("profile.json"), resolved_path=None
        )
        stdout, stderr = StringIO(), StringIO()
        with patch(
            "agentmembrane.host_v2.cli._load_run_profile",
            return_value=(manifest, profile),
        ), patch(
            "agentmembrane.host_v2.cli.validate_provider_launch_authorization",
            return_value={"passed": False, "errors": ["authorization_declared_pass failed"]},
        ), patch("agentmembrane.host_v2.cli.execute_run") as execute, redirect_stdout(
            stdout
        ), redirect_stderr(stderr):
            code = main(["execute", "--run-dir", str(run_dir)])
        self.assertEqual(code, 2)
        execute.assert_not_called()
        self.assertFalse(json.loads(stdout.getvalue())["ok"])

    def test_direct_python_prepare_bypass_stops_before_inputs_or_provider(self) -> None:
        profile = ResolvedProfile(
            raw={"run_kind": "gate", "gates": {}},
            source_path=Path("profile.json"),
            resolved_path=None,
        )
        static = SimpleNamespace(passed=True, details={"errors": []})
        with tempfile.TemporaryDirectory() as directory, patch(
            "agentmembrane.host_v2.runner.preflight", return_value=static
        ), patch("agentmembrane.host_v2.runner._load_inputs") as load_inputs:
            with self.assertRaisesRegex(IntegrityError, "provider launch authorization STOP"):
                prepare_run(
                    profile=profile,
                    run_dir=Path(directory) / "run",
                    run_kind=RunKind.GATE,
                )
        load_inputs.assert_not_called()


class V21FailClosedLaunchTests(unittest.TestCase):
    def test_v21_launch_and_authorization_flags_all_remain_false(self) -> None:
        launch = json.loads(
            (CONFIG / "launch-policy-v2.1.json").read_text(encoding="utf-8")
        )
        self.assertEqual(launch["protocol_id"], "host-boundary-v2.1")
        for field in (
            "atomic_synthetic_bringup_permitted",
            "protocol_stage_g_permitted",
            "protocol_stage_s_permitted",
            "small_real_api_smoke_permitted",
            "variance_pilot_permitted",
            "blinded_verifier_audit_permitted",
            "formal_paid_gate_permitted",
            "formal_run_permitted",
            "public_formal_run_permitted",
            "large_scale_execution_permitted",
            "claim_bearing_output_permitted",
        ):
            self.assertFalse(launch[field], field)
        self.assertFalse(launch["manual_override_allowed"])
        self.assertFalse(launch["effect_direction_is_authorization_input"])
        self.assertIn("assay_passed", launch["reason"])
        self.assertNotIn("not_bound_or_passed", launch["reason"])
        self.assertEqual(
            launch["next_stage_after_offline_gate_a"],
            "complete_public_readiness_repairs_before_any_provider_calibration_proposal",
        )
        for taskpack in launch["formal_taskpacks"]:
            self.assertEqual(taskpack["formal_rows"], 0)
            self.assertFalse(taskpack["claim_eligible"])

        authorization = json.loads(
            (CONFIG / "zero-token-authorization-v2.1.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(authorization["protocol_id"], "host-boundary-v2.1")
        self.assertEqual(
            authorization["assay_report_path"],
            "../../../outputs/host_v2.1_atomic_committed_profile_gate_20260830/"
            "host-v2.1-atomic-controlled-committed-source-v1/report.json",
        )
        self.assertEqual(
            authorization["assay_report_sha256"],
            "3e24b729786945b5161b922b554704469b863132ee70cad8eff30f478c5e6761",
        )
        self.assertFalse(authorization["passed"])
        self.assertTrue(
            all(value is False for value in authorization["authorized_stages"].values())
        )

    def test_v21_formal_templates_cannot_pass_provider_authorization(self) -> None:
        paths = sorted(
            (CONFIG / "profiles" / "v2.1").glob("*-formal.template.json")
        )
        self.assertEqual(len(paths), 4)
        for path in paths:
            with self.subTest(profile=path.name):
                profile = load_profile(path)
                self.assertEqual(profile.raw["execution_stage"], "formal")
                self.assertFalse(profile.raw["claim_bearing"])
                self.assertFalse(profile.raw["h_ladder_covered"])
                self.assertFalse(profile.raw["scientific_sample_gate_satisfied"])
                report = validate_provider_launch_authorization(profile)
                self.assertFalse(report["passed"], report)
                self.assertTrue(report["errors"])


class RawGateRecomputationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.run_dir = self.root / "raw-run"
        self.run_dir.mkdir()
        schedule = [
            {"episode_id": "1" * 64},
            {"episode_id": "2" * 64},
        ]
        atomic_write_json(self.run_dir / "schedule.json", schedule)
        atomic_write_json(self.run_dir / "cache-identity.json", {"identity": "frozen"})
        records = [
            self._record("1" * 64, role="adversarial", success=True),
            self._record("2" * 64, role="benign", success=True),
        ]
        (self.run_dir / "records.jsonl").write_bytes(
            b"".join(canonical_json_bytes(row) + b"\n" for row in records)
        )
        self.manifest = {
            "run_identity_sha256": "3" * 64,
            "schedule_sha256": sha256_json(schedule),
            "taskpack_hashes": {"pack": ZERO},
            "requested_model_id": "exact-model",
            "resolved_model_id": "exact-model",
            "provider_route_id": "provider-a",
            "selected_workers": 2,
            "selected_max_inflight_blocks": 1,
        }
        atomic_write_json(self.run_dir / "run-manifest.json", self.manifest)
        failures = {item.value: 0 for item in FailureClass}
        failures[FailureClass.NONE.value] = 2
        self.gate = {
            "schema_version": 3,
            "profile_id": "rq1",
            "candidate_results": [
                {
                    "workers": 2,
                    "max_inflight_blocks": 1,
                    "run_dir": str(self.run_dir),
                    "run_identity_sha256": "3" * 64,
                    "run_manifest_sha256": sha256_bytes(
                        (self.run_dir / "run-manifest.json").read_bytes()
                    ),
                    "resolved_profile_sha256": ZERO,
                    "schedule_sha256": sha256_json(schedule),
                    "taskpack_hashes": {"pack": ZERO},
                    "task_ids": ["task-adversarial", "task-benign"],
                    "families": ["delegation"],
                    "requested_model_id": "exact-model",
                    "resolved_model_id": "exact-model",
                    "provider_route_id": "provider-a",
                    "cache_manifest_sha256": sha256_bytes(
                        (self.run_dir / "cache-identity.json").read_bytes()
                    ),
                    "records_sha256": sha256_bytes(
                        (self.run_dir / "records.jsonl").read_bytes()
                    ),
                    "records_count": 2,
                    "objective_activation_count": 1,
                    "failure_class_counts": failures,
                    "positive_control_success_by_family": {
                        "delegation": {"successes": 1, "attempted": 1}
                    },
                    "benign_success_by_family": {
                        "delegation": {"successes": 1, "attempted": 1}
                    },
                    "passed": True,
                }
            ],
            "selected_workers": 2,
            "selected_max_inflight_blocks": 1,
            "selection_rule": "highest candidate satisfying all frozen gates",
            "passed": True,
            "created_at": "2026-08-30T00:00:00Z",
        }
        atomic_write_json(self.root / "gate.json", self.gate)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _record(episode_id: str, *, role: str, success: bool) -> dict:
        oracle = (
            {"attack_success": success, "benign_success": False}
            if role == "adversarial"
            else {"attack_success": False, "benign_success": success}
        )
        return {
            "schema_version": 2,
            "episode_id": episode_id,
            "schedule_ordinal": 1 if role == "adversarial" else 2,
            "wave_id": "wave-1",
            "block_id": "block-1",
            "profile_id": "gate-run",
            "replicate_id": "r1",
            "taskpack_id": "pack",
            "task_id": f"task-{role}",
            "cluster_id": "cluster",
            "family": "delegation",
            "domain_id": "domain",
            "pair_id": "pair",
            "pair_role": role,
            "condition_id": "A5-C0",
            "planner_role": "objective_aware_white_box_attacker" if role == "adversarial" else "ordinary_task_agent",
            "attempt_keys": [],
            "planner_status": "ok",
            "failure_class": "none",
            "actions_requested": [{"op": "attempt", "args": {}}] if role == "adversarial" else [],
            "action_log": [],
            "event_log": [],
            "initial_snapshot_sha256": ZERO,
            "final_snapshot_sha256": ZERO,
            "final_artifact": None,
            "oracle_result": oracle,
            "started_at": "2026-08-30T00:00:00Z",
            "finished_at": "2026-08-30T00:00:01Z",
            "execution_session_id": "session",
            "worker_id": "worker",
        }

    def _profile(self) -> ResolvedProfile:
        raw = _resolved_raw()
        raw["resolution"]["gate_result_sha256"] = sha256_bytes(
            (self.root / "gate.json").read_bytes()
        )
        return ResolvedProfile(raw=raw, source_path=self.root / "profile.json", resolved_path=None)

    def test_two_row_self_reported_v3_gate_is_rejected(self) -> None:
        report = validate_frozen_gates(self._profile())
        self.assertFalse(report["passed"], report)
        detail = report["raw_candidate_recomputation"]["2x1"]
        self.assertFalse(detail["passed"])

    def test_raw_record_tamper_invalidates_unchanged_gate_json(self) -> None:
        path = self.run_dir / "records.jsonl"
        path.write_bytes(path.read_bytes() + b"\n")
        report = validate_frozen_gates(self._profile())
        self.assertFalse(report["passed"])
        detail = report["raw_candidate_recomputation"]["2x1"]
        self.assertTrue(detail["errors"])

    def test_tampered_gate_aggregate_is_not_trusted(self) -> None:
        damaged = copy.deepcopy(self.gate)
        damaged["candidate_results"][0]["objective_activation_count"] = 0
        atomic_write_json(self.root / "gate.json", damaged)
        report = validate_frozen_gates(self._profile())
        self.assertFalse(report["passed"])
        detail = report["raw_candidate_recomputation"]["2x1"]
        self.assertFalse(detail["passed"])

    def test_v4_schema_requires_exactly_one_g0_and_one_g1(self) -> None:
        base = copy.deepcopy(self.gate["candidate_results"][0])
        artifact = {
            "schema_version": 4,
            "profile_id": "g2",
            "predecessor_runs": [
                {"gate_stage": "G0", **copy.deepcopy(base)},
                {"gate_stage": "G1", **copy.deepcopy(base)},
            ],
            "selected_workers": 48,
            "selected_max_inflight_blocks": 8,
            "selection_rule": "highest candidate satisfying all frozen gates",
            "passed": True,
            "created_at": "2026-08-30T00:00:00Z",
        }
        from agentmembrane.host_v2.schema import SchemaError, validate_json

        validate_json(artifact, schema_name="gate_result")
        artifact["predecessor_runs"][1]["gate_stage"] = "G0"
        with self.assertRaises(SchemaError):
            validate_json(artifact, schema_name="gate_result")


if __name__ == "__main__":
    unittest.main()
