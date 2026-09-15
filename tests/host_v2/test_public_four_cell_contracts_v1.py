from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
GATE_PATH = REPO_ROOT / "experiments/host_boundary_v2/public_four_cell_v1/offline_gate.py"


def _load_gate():
    spec = importlib.util.spec_from_file_location("public_four_cell_v1_offline_gate", GATE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load offline gate")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


GATE = _load_gate()
CONTRACTS = GATE._load_overlay_module(REPO_ROOT, "contracts")


class PublicFourCellContractsV1Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.prompt, self.manifest = GATE._manifest_fixture(CONTRACTS)

    def test_canonical_label_and_exact_ordered_schedule(self) -> None:
        self.assertEqual(CONTRACTS.CANONICAL_LABEL, "Host-mediated RQ1b / legacy HB-RQ2")
        self.assertEqual(
            [cell.cell_id for cell in CONTRACTS.FOUR_CELLS],
            [
                "benign-vulnerable",
                "benign-protected",
                "adversarial-vulnerable",
                "adversarial-protected",
            ],
        )
        self.assertEqual(len(set(CONTRACTS.FOUR_CELLS)), 4)
        self.assertEqual(CONTRACTS.DEFAULT_CONSTRUCT_STATUS, "unadjudicated")

    def test_authorization_manifest_is_exact_and_prompt_derived(self) -> None:
        result = CONTRACTS.validate_authorization_manifest(self.manifest)
        self.assertEqual(result.authorized_operation, "send_money")
        self.assertEqual(result.authorized_argument, "recipient")
        self.assertEqual(
            self.prompt[result.substring_start : result.substring_end], result.authorized_value
        )
        self.assertEqual(
            result.user_prompt_sha256, hashlib.sha256(self.prompt.encode("utf-8")).hexdigest()
        )

    def test_authorization_manifest_rejects_oracle_or_extra_field(self) -> None:
        invalid = copy.deepcopy(self.manifest)
        invalid["injection_goal"] = "hidden attacker answer"
        with self.assertRaises(CONTRACTS.ContractError):
            CONTRACTS.validate_authorization_manifest(invalid)

    def test_authorization_manifest_rejects_wrong_binding_and_derivation(self) -> None:
        for field, value in (
            ("source_task_id", "agentdojo-v1-banking-u0-i5"),
            ("authorized_operation", "read_file"),
            ("authorized_argument", "account"),
            ("derivation_method", "oracle_lookup"),
        ):
            invalid = copy.deepcopy(self.manifest)
            invalid[field] = value
            with self.subTest(field=field), self.assertRaises(CONTRACTS.ContractError):
                CONTRACTS.validate_authorization_manifest(invalid)

    def test_four_zero_token_witnesses_are_exact(self) -> None:
        audit = GATE._audit_zero_token_witnesses(CONTRACTS, self.manifest)
        self.assertTrue(audit["passed"])
        self.assertTrue(audit["vulnerable_adversarial_reach_witnessed"])
        self.assertTrue(audit["protected_adversarial_pre_dispatch_block_witnessed"])
        self.assertTrue(audit["dual_arm_benign_witnessed"])
        self.assertTrue(all(row["native_dispatch_observed"] is False for row in audit["rows"]))
        self.assertTrue(all(row["execution_authorized"] is False for row in audit["rows"]))

    def test_pre_dispatch_witness_rejects_execution_claim_or_observation(self) -> None:
        manifest_sha = hashlib.sha256(GATE._canonical_json_bytes(self.manifest)).hexdigest()
        baseline = GATE._decision_fixture(CONTRACTS, CONTRACTS.FOUR_CELLS[0], manifest_sha)
        for field in ("execution_authorized", "claim_eligible", "native_dispatch_observed"):
            invalid = copy.deepcopy(baseline)
            invalid[field] = True
            with self.subTest(field=field), self.assertRaises(CONTRACTS.ContractError):
                CONTRACTS.validate_pre_dispatch_decision(invalid)

    def test_pre_dispatch_witness_rejects_unknown_enum_and_bad_hash(self) -> None:
        manifest_sha = hashlib.sha256(GATE._canonical_json_bytes(self.manifest)).hexdigest()
        baseline = GATE._decision_fixture(CONTRACTS, CONTRACTS.FOUR_CELLS[0], manifest_sha)
        for field, value in (("pair_role", "redteam"), ("request_sha256", "ABC")):
            invalid = copy.deepcopy(baseline)
            invalid[field] = value
            with self.subTest(field=field), self.assertRaises(CONTRACTS.ContractError):
                CONTRACTS.validate_pre_dispatch_decision(invalid)

    def test_hcer_contract_has_six_components_and_missing_is_null(self) -> None:
        self.assertEqual(len(CONTRACTS.HCER_COMPONENTS), 6)
        self.assertEqual(len(set(CONTRACTS.HCER_COMPONENTS)), 6)
        report = GATE.run_offline_gate(REPO_ROOT)
        self.assertEqual(report["hcer_audit"]["components"], {
            name: None for name in CONTRACTS.HCER_COMPONENTS
        })
        self.assertIsNone(report["hcer_audit"]["hcer"])
        self.assertFalse(report["hcer_audit"]["claim_eligible"])
        self.assertFalse(report["hcer_audit"]["injection_success_used_as_hcer_evidence"])

    def test_native_alias_and_refusal_denial_are_separate(self) -> None:
        report = GATE.run_offline_gate(REPO_ROOT)
        alias = report["native_alias_audit"]
        self.assertEqual(alias["semantics"], "injection_objective_achieved")
        self.assertIs(alias["adversarial"]["native_security"], alias["adversarial"]["injection_success"])
        self.assertIsNone(alias["benign"]["native_security"])
        outcome = report["outcome_separation"]
        self.assertNotEqual(outcome["terminal_refusal"], outcome["membrane_denial"])
        self.assertTrue(outcome["fields_are_independent"])

    def test_immutable_fields_and_execution_counts_are_frozen(self) -> None:
        report = GATE.run_offline_gate(REPO_ROOT)
        self.assertEqual(
            report["immutable_audit"]["required_binding_fields"],
            list(CONTRACTS.IMMUTABLE_BINDING_FIELDS),
        )
        self.assertFalse(report["immutable_audit"]["namespace_reused"])
        self.assertEqual(
            report["immutable_audit"]["initial_state_sha256"],
            report["immutable_audit"]["cleanup_state_sha256"],
        )
        self.assertTrue(all(value == 0 for value in report["execution_counts"].values()))
        self.assertFalse(report["execution_authorized"])
        self.assertFalse(report["claim_eligible"])

    def test_dependency_audit_rejects_parent_shared_import_and_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            overlay = root / GATE.OVERLAY_RELATIVE
            overlay.mkdir(parents=True)
            (overlay / "bad.py").write_text(
                "from ..planner import PlannerTurn\n"
                "REF = 'agentmembrane.host_v2.public_host_bridge:Adapter'\n",
                encoding="utf-8",
            )
            report = GATE.audit_overlay_dependencies(root)
        self.assertFalse(report["passed"])
        reasons = {row["reason"] for row in report["violations"]}
        self.assertIn("parent_import:planner", reasons)
        self.assertIn("forbidden_import:planner", reasons)
        self.assertIn("forbidden_binding:public_host_bridge", reasons)

    def test_dependency_audit_accepts_stdlib_and_overlay_local_imports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            overlay = root / GATE.OVERLAY_RELATIVE
            overlay.mkdir(parents=True)
            (overlay / "good.py").write_text(
                "from pathlib import Path\nfrom .contracts import FOUR_CELLS\n",
                encoding="utf-8",
            )
            report = GATE.audit_overlay_dependencies(root)
        self.assertTrue(report["passed"], report["violations"])

    def test_full_gate_never_authorizes_and_requires_fresh_double_prepare(self) -> None:
        report = GATE.run_offline_gate(REPO_ROOT)
        self.assertFalse(report["execution_authorized"])
        self.assertFalse(report["scientific_or_population_claim_permitted"])
        self.assertTrue(report["fresh_integrated_snapshot_required"])
        self.assertTrue(report["double_prepare_required"])
        self.assertEqual(report["observed_prepare_passes"], 0)
        if not report["passed"]:
            self.assertEqual(report["status"], "FAIL_CLOSED")

    def test_two_prepare_snapshot_drift_blocks(self) -> None:
        first = {"contracts.py": "a" * 64, "profile.json": "b" * 64}
        self.assertTrue(GATE.audit_two_prepare_snapshots(first, dict(first))["passed"])
        drifted = dict(first)
        drifted["profile.json"] = "c" * 64
        report = GATE.audit_two_prepare_snapshots(first, drifted)
        self.assertFalse(report["passed"])
        self.assertEqual(report["drifted_bindings"], ["profile.json"])
        self.assertFalse(report["execution_authorized"])

    def test_native_alias_requires_exact_adversarial_and_benign_null(self) -> None:
        records = GATE._load_overlay_module(REPO_ROOT, "records")
        semantics = CONTRACTS.INJECTION_SUCCESS_SEMANTICS
        adversarial = {
            "native_utility": True,
            "native_security": True,
            "injection_success": True,
            "injection_success_semantics": semantics,
        }
        self.assertTrue(
            records.validate_native_verdict_alias(
                adversarial, pair_role="adversarial"
            ).injection_success
        )
        invalid = dict(adversarial, injection_success=False)
        with self.assertRaises(records.RecordError):
            records.validate_native_verdict_alias(invalid, pair_role="adversarial")
        benign = dict(adversarial, native_security=None, injection_success=None)
        result = records.validate_native_verdict_alias(benign, pair_role="benign")
        self.assertIsNone(result.native_security)
        invalid_benign = dict(benign, native_security=False, injection_success=False)
        with self.assertRaises(records.RecordError):
            records.validate_native_verdict_alias(invalid_benign, pair_role="benign")

    @staticmethod
    def _write_attempt(root: Path, *, request_key: str, index: int, delivered: bool) -> tuple[str, dict]:
        key = f"{request_key}:{index}"
        attempt = {
            "attempt_key": key,
            "request_key": request_key,
            "attempt_index": index,
            "planner_status": "failed" if not delivered else "complete",
            "failure_class": "proxy_connection_failed" if not delivered else "none",
            "error": "boom" if not delivered else None,
            "error_metadata": {},
            "usage": {
                "input_tokens": 0 if not delivered else 3,
                "output_tokens": 0 if not delivered else 2,
                "total_tokens": 0 if not delivered else 5,
            },
            "raw_response": None if not delivered else "{\"actions\":[]}",
            "resolved_model_id": None if not delivered else "gpt-5.6-sol",
        }
        path = root / "attempts" / request_key / f"{index}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(attempt, sort_keys=True), encoding="utf-8")
        return path.relative_to(root).as_posix(), attempt

    def test_budget_arithmetic_corruption_and_immutable_replay(self) -> None:
        budget_module = GATE._load_overlay_module(REPO_ROOT, "budget")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first_path, _ = self._write_attempt(
                root, request_key="1" * 64, index=1, delivered=False
            )
            second_path, _ = self._write_attempt(
                root, request_key="2" * 64, index=1, delivered=True
            )
            namespaces = {"output": "out-001", "cache": "cache-001", "native": "native-001"}
            budget = budget_module.build_run_chain_budget(
                repo_root=root,
                chain_id="chain-a",
                cap=24,
                predecessor_attempt_paths=[first_path, second_path],
                fresh_namespaces=namespaces,
            )
            self.assertEqual((budget.consumed, budget.remaining), (2, 22))
            self.assertEqual(budget.counters.delivered_model_responses, 1)
            self.assertEqual(budget.counters.total_tokens, 5)
            manifest_path = root / "run-chain.json"
            budget_module.materialize_run_chain_budget(
                manifest_path,
                repo_root=root,
                chain_id="chain-a",
                cap=24,
                predecessor_attempt_paths=[first_path, second_path],
                fresh_namespaces=namespaces,
            )
            with self.assertRaises(budget_module.RunChainBudgetError):
                budget_module.materialize_run_chain_budget(
                    manifest_path,
                    repo_root=root,
                    chain_id="chain-b",
                    cap=24,
                    predecessor_attempt_paths=[first_path, second_path],
                    fresh_namespaces=namespaces,
                )
            attempt_path = root / first_path
            corrupted = json.loads(attempt_path.read_text(encoding="utf-8"))
            corrupted["attempt_index"] = 9
            attempt_path.write_text(json.dumps(corrupted), encoding="utf-8")
            with self.assertRaises(budget_module.RunChainBudgetError):
                budget_module.validate_run_chain_budget(
                    repo_root=root, manifest_path=manifest_path
                )

    def test_namespace_manifest_race_has_single_winner(self) -> None:
        budget_module = GATE._load_overlay_module(REPO_ROOT, "budget")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "race-manifest.json"
            namespaces = {"output": "out-race", "cache": "cache-race", "native": "native-race"}

            def publish(chain_id: str) -> str:
                try:
                    budget_module.materialize_run_chain_budget(
                        target,
                        repo_root=root,
                        chain_id=chain_id,
                        cap=24,
                        predecessor_attempt_paths=[],
                        fresh_namespaces=namespaces,
                    )
                    return "won"
                except budget_module.RunChainBudgetError:
                    return "rejected"

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(publish, ("race-a", "race-b")))
            self.assertEqual(sorted(results), ["rejected", "won"])
            self.assertTrue(target.is_file())

    def _executor_fixture(self, root: Path, *, malformed: bool = False):
        executor = GATE._load_overlay_module(REPO_ROOT, "executor")
        relative, attempt = self._write_attempt(
            root, request_key="3" * 64, index=1, delivered=False
        )
        if malformed:
            attempt.pop("usage")
            (root / relative).write_text(json.dumps(attempt), encoding="utf-8")
        key = attempt["attempt_key"]
        cache = SimpleNamespace(run_dir=root, load_attempt=lambda requested: attempt if requested == key else None)
        turn = SimpleNamespace(
            request_key=attempt["request_key"],
            actions=(),
            final_artifact=None,
            strategy=None,
            status="failed",
            explicit_abstention=False,
            failure_class=attempt["failure_class"],
            terminal_error=attempt["error"],
            attempt_keys=(key,),
        )
        return executor, cache, turn

    def test_failed_turn_and_malformed_ledger_never_load_text_or_checker(self) -> None:
        for malformed in (False, True):
            with self.subTest(malformed=malformed), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                executor, cache, turn = self._executor_fixture(root, malformed=malformed)
                calls = {"text": 0}

                def load_text() -> str:
                    calls["text"] += 1
                    return "must not be called"

                error = executor.ExecutorContractError
                with self.assertRaises(error):
                    executor.resolve_planner_turn(
                        repo_root=root,
                        cache=cache,
                        turn=turn,
                        source_task_id=CONTRACTS.SOURCE_TASK_ID,
                        cell_id="adversarial-vulnerable",
                        run_chain_manifest_sha256="d" * 64,
                        failure_record_path=root / "failure.json",
                        checker_binding_ids=("state-checker",),
                        checker_capabilities=(),
                        terminal_text_mode=executor.CONFIRMED_ASSISTANT_TEXT_MODE,
                        terminal_text_loader=load_text,
                    )
                self.assertEqual(calls["text"], 0)
                if not malformed:
                    record = json.loads((root / "failure.json").read_text(encoding="utf-8"))
                    self.assertEqual(record["native_checker_invocation_count"], 0)
                    self.assertFalse(record["terminal_text_extraction_attempted"])

    def test_valid_text_resolution_still_does_not_invoke_checker(self) -> None:
        executor = GATE._load_overlay_module(REPO_ROOT, "executor")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            turn = SimpleNamespace(
                request_key="4" * 64,
                actions=(),
                final_artifact=None,
                strategy=None,
                status="complete",
                explicit_abstention=False,
                failure_class="none",
                terminal_error=None,
                attempt_keys=(),
            )
            capability = executor.CheckerTextCapability(
                source_task_id=CONTRACTS.SOURCE_TASK_ID,
                checker_binding_id="state-checker",
                reads_terminal_text=False,
                raw_response_envelope_compatible=False,
            )
            calls = {"text": 0, "checker": 0}

            def load_text() -> str:
                calls["text"] += 1
                return "ledger-confirmed assistant text"

            resolution = executor.resolve_planner_turn(
                repo_root=root,
                cache=SimpleNamespace(run_dir=root, load_attempt=lambda _: None),
                turn=turn,
                source_task_id=CONTRACTS.SOURCE_TASK_ID,
                cell_id="benign-vulnerable",
                run_chain_manifest_sha256="d" * 64,
                failure_record_path=root / "unused.json",
                checker_binding_ids=("state-checker",),
                checker_capabilities=(capability,),
                terminal_text_mode=executor.CONFIRMED_ASSISTANT_TEXT_MODE,
                terminal_text_loader=load_text,
            )
            self.assertEqual(resolution.terminal_text, "ledger-confirmed assistant text")
            self.assertEqual(calls, {"text": 1, "checker": 0})

    def test_undeclared_text_mode_rejected_before_text_load(self) -> None:
        executor = GATE._load_overlay_module(REPO_ROOT, "executor")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            turn = SimpleNamespace(
                request_key="5" * 64, actions=(), final_artifact=None, strategy=None,
                status="complete", explicit_abstention=False, failure_class="none",
                terminal_error=None, attempt_keys=(),
            )
            capability = executor.CheckerTextCapability(
                source_task_id=CONTRACTS.SOURCE_TASK_ID,
                checker_binding_id="text-checker",
                reads_terminal_text=True,
                raw_response_envelope_compatible=False,
            )
            calls = {"text": 0}

            def load_text() -> str:
                calls["text"] += 1
                return "must not be called"

            with self.assertRaises(executor.ExecutorContractError):
                executor.resolve_planner_turn(
                    repo_root=root,
                    cache=SimpleNamespace(run_dir=root, load_attempt=lambda _: None),
                    turn=turn,
                    source_task_id=CONTRACTS.SOURCE_TASK_ID,
                    cell_id="benign-protected",
                    run_chain_manifest_sha256="d" * 64,
                    failure_record_path=root / "unused.json",
                    checker_binding_ids=("text-checker",),
                    checker_capabilities=(capability,),
                    terminal_text_mode="undeclared_text_mode",
                    terminal_text_loader=load_text,
                )
            self.assertEqual(calls["text"], 0)


if __name__ == "__main__":
    unittest.main()
