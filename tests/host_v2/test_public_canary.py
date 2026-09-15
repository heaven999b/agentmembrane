from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.cache import CacheIdentity
from agentmembrane.host_v2.host import ActionRequest
from agentmembrane.host_v2.planner import PlannerTurn
from agentmembrane.host_v2.public_canary import (
    MODEL_ID,
    PROVIDER_ROUTE_ID,
    SIX_CATEGORIES,
    ExactSolMaxLocalProxyClient,
    build_derived_pack_documents,
    ledger_confirmed_assistant_text,
    materialize_derived_pack,
    validate_narrow_authorization,
)
from agentmembrane.host_v2.schema import FailureClass, IntegrityError, sha256_bytes


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ID = "agentdojo-v1-banking-u0-i5"


class _Ledger:
    def __init__(self, attempt: dict[str, object]) -> None:
        self.identity = CacheIdentity(
            implementation_sha256="1" * 64,
            protocol_sha256="2" * 64,
            resolved_model_id=MODEL_ID,
            provider_route_id=PROVIDER_ROUTE_ID,
        )
        self.attempt = attempt

    def load_attempt(self, key: str) -> dict[str, object] | None:
        return self.attempt if self.attempt.get("attempt_key") == key else None


def _terminal_ledger() -> tuple[_Ledger, PlannerTurn, str]:
    episode_id = "e" * 64
    request_key = "a" * 64
    key = f"{request_key}:1"
    response = json.dumps(
        {
            "actions": [],
            "final_artifact": {"status": "done"},
            "strategy": "complete",
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    parsed = json.loads(response)
    request = {
        "episode_id": episode_id,
        "turn_number": 2,
        "requested_model_id": MODEL_ID,
        "resolved_model_id": MODEL_ID,
        "provider_route_id": PROVIDER_ROUTE_ID,
        "model_settings": {
            "temperature": 0,
            "max_completion_tokens": 1100,
            "reasoning_effort": "max",
        },
        "retry_policy": {"request_level_transport_retries": 0},
    }
    attempt = {
        "attempt_key": key,
        "request_key": request_key,
        "attempt_index": 1,
        "request": request,
        "episode_id": episode_id,
        "turn_number": 2,
        "requested_model_id": MODEL_ID,
        "resolved_model_id": MODEL_ID,
        "provider_route_id": PROVIDER_ROUTE_ID,
        "planner_status": "ok",
        "failure_class": "none",
        "raw_response": response,
        "parsed_response": parsed,
        "actions": [],
        "final_artifact": {"status": "done"},
    }
    turn = PlannerTurn(
        request_key=request_key,
        actions=(),
        final_artifact={"status": "done"},
        strategy="complete",
        status="complete",
        explicit_abstention=False,
        failure_class=FailureClass.NONE,
        terminal_error=None,
        attempt_keys=(key,),
    )
    return _Ledger(attempt), turn, response


class PublicCanaryPackTests(unittest.TestCase):
    def test_builder_is_deterministic_and_does_not_copy_goal(self) -> None:
        arguments = {
            "conformance_slice_plan_path": (
                "experiments/host_boundary_v2/public_mapping_parity_v2.3/packs/"
                "host-v2-agentdojo-v0.1.35-v1/u0_i5_conformance_slice_plan.json"
            ),
            "static_source_scan_path": (
                "experiments/host_boundary_v2/public_mapping_parity_v2.3/"
                "static_agentdojo_20_source_order_scan.json"
            ),
        }
        first = build_derived_pack_documents(REPO_ROOT, SOURCE_ID, **arguments)
        second = build_derived_pack_documents(REPO_ROOT, SOURCE_ID, **arguments)
        self.assertEqual(first, second)
        source_lines = (
            REPO_ROOT / "data/host_boundary_v2/packs/agentdojo-v0.1.35-v1/tasks.jsonl"
        ).read_text(encoding="utf-8").splitlines()
        goal = json.loads(source_lines[13])["authorized_test_objective"].encode()
        self.assertTrue(all(goal not in payload for payload in first.values()))
        tasks = [json.loads(line) for line in first["tasks.jsonl"].splitlines()]
        self.assertEqual({row["pair_role"] for row in tasks}, {"benign"})
        self.assertEqual(
            {row["metadata"]["source_pair_role"] for row in tasks},
            {"benign", "adversarial"},
        )
        self.assertTrue(all(row["authorized_test_objective"] is None for row in tasks))

    def test_materialized_pack_passes_generic_and_canary_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            report = materialize_derived_pack(
                REPO_ROOT,
                Path(temporary) / "pack",
                SOURCE_ID,
                conformance_slice_plan_path=(
                    "experiments/host_boundary_v2/public_mapping_parity_v2.3/packs/"
                    "host-v2-agentdojo-v0.1.35-v1/u0_i5_conformance_slice_plan.json"
                ),
                static_source_scan_path=(
                    "experiments/host_boundary_v2/public_mapping_parity_v2.3/"
                    "static_agentdojo_20_source_order_scan.json"
                ),
            )
            self.assertEqual(report.selected_source_task_id, SOURCE_ID)
            self.assertEqual(len(report.pack.tasks), 2)


class PublicCanaryLedgerTests(unittest.TestCase):
    def test_exact_client_injects_max_and_enforces_hard_cap(self) -> None:
        client = ExactSolMaxLocalProxyClient(
            base_url="http://127.0.0.1:19876/v1",
            api_key="sk-test-value",
        )
        response = {
            "choices": [{"message": {"content": '{"actions":[],"final_artifact":{"done":true},"strategy":"done"}'}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
        }
        with patch.object(
            ExactSolMaxLocalProxyClient.__mro__[1],
            "_request",
            return_value=response,
        ) as request:
            completion = client.complete(
                model=MODEL_ID,
                system="system",
                user="user",
                max_completion_tokens=1100,
                retries=0,
            )
        self.assertEqual(completion.model, MODEL_ID)
        self.assertEqual(client.calls_made, 3)
        self.assertEqual(request.call_args.kwargs["payload"]["reasoning_effort"], "max")

    def test_only_delivered_terminal_raw_response_is_returned(self) -> None:
        cache, turn, response = _terminal_ledger()
        actual = ledger_confirmed_assistant_text(
            cache=cache,  # type: ignore[arg-type]
            turn=turn,
            expected_episode_id="e" * 64,
            expected_turn_number=2,
        )
        self.assertEqual(actual, response)

    def test_nonexact_model_settings_fail_closed(self) -> None:
        cache, turn, _ = _terminal_ledger()
        cache.attempt["request"]["model_settings"]["reasoning_effort"] = "high"  # type: ignore[index]
        with self.assertRaises(IntegrityError):
            ledger_confirmed_assistant_text(
                cache=cache,  # type: ignore[arg-type]
                turn=turn,
                expected_episode_id="e" * 64,
                expected_turn_number=2,
            )

    def test_nonempty_action_uses_canonical_actionrequest_comparison(self) -> None:
        cache, turn, _ = _terminal_ledger()
        response = json.dumps(
            {
                "actions": [{"op": "read_file", "args": {"file_path": "bill.txt"}}],
                "final_artifact": None,
                "strategy": "read the requested bill",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        parsed = json.loads(response)
        action = ActionRequest(op="read_file", args={"file_path": "bill.txt"})
        cache.attempt["raw_response"] = response
        cache.attempt["parsed_response"] = parsed
        cache.attempt["actions"] = parsed["actions"]
        cache.attempt["final_artifact"] = None
        action_turn = PlannerTurn(
            request_key=turn.request_key,
            actions=(action,),
            final_artifact=None,
            strategy="read the requested bill",
            status="ok",
            explicit_abstention=False,
            failure_class=FailureClass.NONE,
            terminal_error=None,
            attempt_keys=turn.attempt_keys,
        )
        actual = ledger_confirmed_assistant_text(
            cache=cache,  # type: ignore[arg-type]
            turn=action_turn,
            expected_episode_id="e" * 64,
            expected_turn_number=2,
        )
        self.assertEqual(actual, response)

    def test_tool_observation_or_artifact_cannot_replace_missing_text(self) -> None:
        cache, turn, _ = _terminal_ledger()
        cache.attempt["raw_response"] = None
        cache.attempt["tool_observation"] = "not assistant text"
        with self.assertRaises(IntegrityError):
            ledger_confirmed_assistant_text(
                cache=cache,  # type: ignore[arg-type]
                turn=turn,
                expected_episode_id="e" * 64,
                expected_turn_number=2,
            )


class PublicCanaryAuthorizationTests(unittest.TestCase):
    def _write(self, path: Path, value: object) -> str:
        payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        return sha256_bytes(payload)

    def _parity(self, *, pass_count: int = 6) -> dict[str, object]:
        return {
            "artifact_type": "agentmembrane_agentdojo_source_grounded_conformance_slice_result",
            "benchmark": "AgentDojo",
            "claim_bearing": False,
            "decision": "PASS" if pass_count == 6 else "NO_GO",
            "scope": {
                "scope": "engineering_canary_source_slice",
                "source_task_id": SOURCE_ID,
                "categories": list(SIX_CATEGORIES),
                "full_120_completed": False,
                "not_full_parity": True,
            },
            "aggregate": {
                "passed": pass_count == 6,
                "pass_count": pass_count,
                "case_count": 6,
            },
            "fresh_namespace_validation": {
                "passed": True,
                "fresh_case_namespace_count": 6,
            },
            "cleanup_validation": {
                "passed": True,
                "cleanup_pass_count": 6,
                "required_cleanup_count": 6,
            },
            "execution_counts": {
                "parity_comparison_count": 6,
                "native_checker_invocation_count": 6,
                "projected_checker_invocation_count": 6,
                "cleanup_count": 6,
                "api_call_count": 0,
                "model_call_count": 0,
                "provider_call_count": 0,
                "network_call_count": 0,
                "external_call_count": 0,
            },
        }

    def _runtime_triplet(self, root: Path) -> list[dict[str, str]]:
        runtime_id = "agentdojo-test-recovered-runtime"
        environment_root = "/private/tmp/agentmembrane-rq2-agentdojo-runtime-test/environment-v2"
        environment_tree = "3" * 64
        upstream = {"checkout_head": "4" * 40, "lock_sha256": "5" * 64}
        receipt = {
            "artifact_type": "agentmembrane_native_runtime_provisioning_receipt",
            "runtime_id": runtime_id,
            "environment": {"root": environment_root, "tree_sha256": environment_tree},
            "upstream": upstream,
            "interpreter": {"version": "3.12.3"},
            "bootstrap": {"version": "0.8.17"},
            "execution_counts": {
                "api_calls": 0,
                "model_calls": 0,
                "native_checker_executions": 0,
                "parity_executions": 0,
                "provider_calls": 0,
                "task_executions": 0,
            },
        }
        receipt_sha = self._write(root / "evidence/receipt.json", receipt)
        live = {
            "artifact_type": "agentmembrane_agentdojo_recovered_runtime_live_validator",
            "runtime_id": runtime_id,
            "environment_root": environment_root,
            "environment_tree_sha256": environment_tree,
            "receipt_sha256": receipt_sha,
            "upstream": upstream,
            "interpreter": {"version": "3.12.3"},
            "uv": {"version": "0.8.17"},
            "hygiene": {
                "pyc_count": 0,
                "pycache_dir_count": 0,
                "dataless_file_count": 0,
                "compressed_file_count": 0,
            },
            "execution_counts": {
                "api_calls": 0,
                "dispatches": 0,
                "model_calls": 0,
                "native_checker_calls": 0,
                "parity_cases": 0,
                "provider_calls": 0,
                "resets": 0,
                "runtime_probe_network_attempts": 0,
                "task_executions": 0,
            },
            "validation": {
                "generic_live_validator_passed": True,
                "tree_independently_recomputed": True,
                "old_runtime_id_rejected": True,
            },
        }
        live_sha = self._write(root / "evidence/live.json", live)
        preflight = {
            "artifact_type": "agentmembrane_agentdojo_recovered_adapter_import_only_preflight",
            "runtime_id": runtime_id,
            "environment_root": environment_root,
            "environment_tree_sha256": environment_tree,
            "receipt_sha256": receipt_sha,
            "live_validator_sha256": live_sha,
            "scope": "adapter_import_only",
            "checks": {
                "adapter_class_importable": True,
                "environment_tree_unchanged": True,
                "network_denied_and_unused": True,
                "receipt_live_validated": True,
            },
            "adapter": {"network_attempts": 0},
            "execution_counts": {
                "api_calls": 0,
                "dispatches": 0,
                "model_calls": 0,
                "native_checker_calls": 0,
                "parity_cases": 0,
                "provider_calls": 0,
                "resets": 0,
                "runtime_probe_network_attempts": 0,
                "task_executions": 0,
            },
        }
        preflight_sha = self._write(root / "evidence/preflight.json", preflight)
        return [
            {"name": "fresh_runtime_receipt", "path": "evidence/receipt.json", "sha256": receipt_sha},
            {"name": "fresh_runtime_live_validator", "path": "evidence/live.json", "sha256": live_sha},
            {"name": "fresh_runtime_adapter_preflight", "path": "evidence/preflight.json", "sha256": preflight_sha},
        ]

    def _authorization(
        self, parity_sha: str, dummy_sha: str, runtime_rows: list[dict[str, str]]
    ) -> dict[str, object]:
        return {
            "selected_source_task_id": SOURCE_ID,
            "slice_parity_artifact_name": "v2_3_selected_source_slice",
            "fresh_runtime_artifact_names": {
                "receipt": "fresh_runtime_receipt",
                "live_validator": "fresh_runtime_live_validator",
                "adapter_import_preflight": "fresh_runtime_adapter_preflight",
            },
            "required_artifacts": [
                {
                    "name": "v2_3_selected_source_slice",
                    "path": "evidence/parity.json",
                    "sha256": parity_sha,
                },
                {
                    "name": "bridge_and_nonleakage_tests",
                    "path": "evidence/tests.json",
                    "sha256": dummy_sha,
                },
                *runtime_rows,
            ],
            "immutable_canary_contract": {
                "api_call_cap": 12,
                "claim_bearing": False,
                "episodes": 2,
                "engineering_only": True,
                "full_120_parity_required_for_this_canary": False,
                "full_120_parity_required_for_expansion_or_claims": True,
                "max_turns_per_episode": 6,
                "model": MODEL_ID,
                "nonestimating": True,
                "reasoning_effort": "max",
                "prior_failed_api_attempts": 2,
                "remaining_api_call_budget": 10,
                "request_level_transport_retries": 0,
            },
        }

    def test_exact_slice_pass_authorizes_only_the_narrow_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parity_sha = self._write(root / "evidence/parity.json", self._parity())
            dummy_sha = self._write(root / "evidence/tests.json", {"passed": True})
            authorization = self._authorization(
                parity_sha, dummy_sha, self._runtime_triplet(root)
            )
            self._write(root / "authorization.json", authorization)
            status = validate_narrow_authorization(root, root / "authorization.json")
            self.assertTrue(status["authorized"])
            self.assertEqual(status["scope"], "selected_source_six_category_slice_only")

    def test_five_of_six_never_authorizes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parity_sha = self._write(
                root / "evidence/parity.json", self._parity(pass_count=5)
            )
            dummy_sha = self._write(root / "evidence/tests.json", {"passed": True})
            self._write(
                root / "authorization.json",
                self._authorization(parity_sha, dummy_sha, self._runtime_triplet(root)),
            )
            status = validate_narrow_authorization(root, root / "authorization.json")
            self.assertFalse(status["authorized"])
            self.assertFalse(status["checks"]["selected_source_six_category_slice_pass"])

    def test_unfrozen_or_missing_required_artifact_stops(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parity_sha = self._write(root / "evidence/parity.json", self._parity())
            authorization = self._authorization(
                parity_sha, "0" * 64, self._runtime_triplet(root)
            )
            self._write(root / "authorization.json", authorization)
            status = validate_narrow_authorization(root, root / "authorization.json")
            self.assertFalse(status["authorized"])
            self.assertFalse(status["checks"]["bridge_and_nonleakage_tests"])

    def test_runtime_triplet_must_be_mutually_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            parity_sha = self._write(root / "evidence/parity.json", self._parity())
            dummy_sha = self._write(root / "evidence/tests.json", {"passed": True})
            runtime_rows = self._runtime_triplet(root)
            runtime_rows[2]["sha256"] = "0" * 64
            authorization = self._authorization(parity_sha, dummy_sha, runtime_rows)
            self._write(root / "authorization.json", authorization)
            status = validate_narrow_authorization(root, root / "authorization.json")
            self.assertFalse(status["authorized"])
            self.assertFalse(status["checks"]["fresh_runtime_triplet"])


if __name__ == "__main__":
    unittest.main()
