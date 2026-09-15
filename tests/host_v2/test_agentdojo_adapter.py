from __future__ import annotations

from dataclasses import dataclass, replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from agentmembrane.host_v2.agentdojo_adapter import (
    AGENTDOJO_COMMIT,
    AGENTDOJO_VERSION_OR_COMMIT,
    AgentDojoAdapter,
    AgentDojoRuntimeError,
)
from agentmembrane.host_v2.public_adapters import (
    PublicAdapterRegistry,
    describe_adapter_type,
    normalize_runtime_preflight,
)
from agentmembrane.host_v2.public_evidence import TRUSTED_MECHANISM_IDS
from agentmembrane.host_v2.projected_checker import (
    MECHANISM_IDS,
    PROJECTED_CHECKER_CONTRACT_VERSION,
    ProjectedCheckerSnapshot,
)
from agentmembrane.host_v2.schema import canonical_json_bytes, sha256_bytes


class _FakeEnvironment:
    def __init__(self, value: int = 0) -> None:
        self.value = value

    def model_copy(self, *, deep: bool):
        assert deep is True
        return _FakeEnvironment(self.value)

    def model_dump(self, *, mode: str):
        assert mode == "json"
        return {"value": self.value}


class _FakeUserTask:
    ID = "user_task_0"

    @staticmethod
    def init_environment(environment):
        return environment


class _FakeInjectionTask:
    ID = "injection_task_5"
    GOAL = "fixture injection goal"


@dataclass
class _FakeFunctionCall:
    function: str
    args: dict
    id: str | None = None


class _FakeRuntime:
    def __init__(self, tools) -> None:
        self.tools = tools

    def run_function(self, environment, function, args, *, raise_on_error):
        assert raise_on_error is True
        if function != "set_value":
            raise LookupError(function)
        environment.value = args["value"]
        return {"stored": environment.value}, None


class _FakeSuite:
    tools = ("set_value",)

    def load_and_inject_default_environment(self, injections):
        assert isinstance(injections, dict)
        return _FakeEnvironment()

    def get_user_task_by_id(self, task_id):
        if task_id != "user_task_0":
            raise KeyError(task_id)
        return _FakeUserTask()

    def get_injection_task_by_id(self, task_id):
        if task_id != "injection_task_5":
            raise KeyError(task_id)
        return _FakeInjectionTask()

    def _check_user_task_utility(
        self, task, model_output, pre_environment, post_environment, calls
    ):
        return (
            task.ID == "user_task_0"
            and model_output == [{"type": "text", "content": "done"}]
            and pre_environment.value == 0
            and post_environment.value == 7
            and calls[0].function == "set_value"
        )

    def _check_injection_task_security(
        self, task, model_output, pre_environment, post_environment, calls
    ):
        return (
            task.ID == "injection_task_5"
            and pre_environment.value == 0
            and post_environment.value == 7
            and calls[0].args == {"value": 7}
        )


class _PlumbingOnlyAdapter(AgentDojoAdapter):
    """Synthetic plumbing fixture; never public/native parity evidence."""

    def preflight(self):
        return {"executable": True, "blockers": []}

    def _get_native_runtime(self):
        suite = _FakeSuite()
        return {
            "get_suite": lambda version, domain: suite,
            "TaskSuite": _FakeSuite,
            "FunctionsRuntime": _FakeRuntime,
            "FunctionCall": _FakeFunctionCall,
        }


def _projected_provenance(
    source_kind: str, field_path: str, *, discriminator: str
) -> list[dict[str, str]]:
    return [
        {
            "source_id": f"agentdojo:synthetic:{discriminator}",
            "source_kind": source_kind,
            "source_sha256": sha256_bytes(discriminator.encode("utf-8")),
            "field_path": field_path,
        }
    ]


def _synthetic_projected_input() -> dict:
    """Full independent checker input; it contains no native outcome field."""

    host_event_id = "agentdojo:synthetic:event:host-action"
    terminal_event_id = "agentdojo:synthetic:event:terminal"
    events = []
    for index, (event_id, event_type, action) in enumerate(
        (
            (host_event_id, "host_action", "synthetic_store"),
            (terminal_event_id, "terminal_output", "emit_terminal"),
        )
    ):
        events.append(
            {
                "event_id": event_id,
                "sequence_index": index,
                "event_type": event_type,
                "actor_id": "synthetic-external-agent",
                "action": action,
                "payload_sha256": sha256_bytes(
                    f"synthetic-payload:{index}".encode("utf-8")
                ),
                "authorization": {
                    "decision_id": f"synthetic-authorization:{index}",
                    "principal_id": "synthetic-external-agent",
                    "action": action,
                    "outcome": "authorized",
                    "credential_id": None,
                    "provenance": _projected_provenance(
                        "authorization_log",
                        f"$.authorization[{index}]",
                        discriminator=f"authorization-{index}",
                    ),
                },
                "provenance": _projected_provenance(
                    "adapter_trace",
                    f"$.events[{index}]",
                    discriminator=f"event-{index}",
                ),
            }
        )

    mechanism_evidence = []
    for index, mechanism_id in enumerate(MECHANISM_IDS):
        eligibility = "eligible"
        witnesses = [host_event_id] if index == 0 else []
        exclusion_code = None
        exclusion_rationale = None
        if index == 1:
            eligibility = "excluded"
            exclusion_code = "SYNTHETIC_NOT_PRESENT"
            exclusion_rationale = (
                "The synthetic contract fixture contains no eligible source boundary."
            )
        mechanism_evidence.append(
            {
                "mechanism_id": mechanism_id,
                "eligibility": eligibility,
                "witness_event_ids": witnesses,
                "exclusion_code": exclusion_code,
                "exclusion_rationale": exclusion_rationale,
                "provenance": _projected_provenance(
                    "mechanism_mapping",
                    f"$.mechanism_evidence[{index}]",
                    discriminator=f"mechanism-{index}",
                ),
            }
        )

    before = sha256_bytes(b"synthetic-state-before")
    after = sha256_bytes(b"synthetic-state-after")
    return {
        "source_task_id": "agentdojo-synthetic-contract-fixture-0",
        "trace_id": "agentdojo:synthetic:trace:0",
        "trusted_events": events,
        "pre_state_sha256": before,
        "post_state_sha256": after,
        "state_delta": {
            "delta_id": "agentdojo:synthetic:delta:0",
            "delta_kind": "updated",
            "before_sha256": before,
            "after_sha256": after,
            "changed_paths": ["$.synthetic_value"],
            "witness_event_ids": [host_event_id],
            "provenance": _projected_provenance(
                "state_snapshot", "$.state_delta", discriminator="state-delta"
            ),
        },
        "terminal": {
            "output_sha256": sha256_bytes(b"synthetic terminal output"),
            "reason": "completed",
            "witness_event_ids": [terminal_event_id],
            "provenance": _projected_provenance(
                "terminal_capture", "$.terminal", discriminator="terminal"
            ),
        },
        "mechanism_evidence": mechanism_evidence,
    }


class AgentDojoPreflightTests(unittest.TestCase):
    def test_correct_pin_and_locks_are_detected_but_missing_dependencies_fail_closed(self):
        adapter = AgentDojoAdapter()
        first = adapter.preflight()
        second = adapter.preflight()

        self.assertEqual(first, second)
        canonical_json_bytes(first)
        self.assertEqual(first["upstream_version_or_commit"], AGENTDOJO_VERSION_OR_COMMIT)
        self.assertEqual(first["upstream_head"], AGENTDOJO_COMMIT)
        self.assertTrue(first["checks"]["git_head_exact"])
        self.assertTrue(first["checks"]["git_tree_clean"])
        self.assertTrue(first["checks"]["source_locks_exact"])
        self.assertTrue(first["checks"]["pack_locks_exact"])
        self.assertFalse(first["checks"]["dependencies_available"])
        self.assertFalse(first["checks"]["native_checker_importable"])
        self.assertFalse(first["executable"])
        codes = {row["code"] for row in first["blockers"]}
        self.assertIn("AGENTDOJO_DEPENDENCY_MISSING:deepdiff", codes)
        self.assertEqual(len(first["implementation_sha256"]), 64)
        self.assertEqual(len(first["checker_bindings"]), 2)
        normalized = normalize_runtime_preflight(
            first, descriptor=describe_adapter_type(type(adapter))
        )
        self.assertFalse(normalized.executable)

    def test_shared_normalizer_accepts_mocked_executable_preflight(self):
        adapter = AgentDojoAdapter()
        dependencies = [
            {
                "module": module,
                "available": True,
                "version": adapter.DEPENDENCY_VERSIONS[module],
            }
            for module, _ in adapter.REQUIRED_MODULES
        ]
        suite = _FakeSuite()
        native = {
            "get_suite": lambda version, domain: suite,
            "TaskSuite": _FakeSuite,
            "FunctionsRuntime": _FakeRuntime,
            "FunctionCall": _FakeFunctionCall,
        }
        with (
            mock.patch.object(adapter, "_dependency_status", return_value=dependencies),
            mock.patch.object(adapter, "_import_native_runtime", return_value=native),
        ):
            report = adapter.preflight()
        normalized = normalize_runtime_preflight(
            report, descriptor=describe_adapter_type(type(adapter))
        )
        self.assertTrue(report["executable"])
        self.assertTrue(normalized.executable)

    def test_wrong_head_is_a_stable_blocker(self):
        adapter = AgentDojoAdapter()
        wrong_git = {
            "head": "0" * 40,
            "status_entries": [],
            "head_available": True,
            "tree_clean": True,
        }
        with mock.patch.object(adapter, "_git_identity", return_value=wrong_git):
            report = adapter.preflight()
        self.assertFalse(report["checks"]["git_head_exact"])
        self.assertIn(
            "AGENTDOJO_HEAD_MISMATCH",
            {row["code"] for row in report["blockers"]},
        )

    def test_wrong_source_hash_is_a_stable_blocker(self):
        adapter = AgentDojoAdapter()
        altered = tuple(
            (path, "0" * 64 if path == "pyproject.toml" else digest)
            for path, digest in adapter.SOURCE_LOCKS
        )
        with mock.patch.object(AgentDojoAdapter, "SOURCE_LOCKS", altered):
            report = adapter.preflight()
        self.assertFalse(report["checks"]["source_locks_exact"])
        self.assertIn(
            "AGENTDOJO_SOURCE_LOCK_MISMATCH",
            {row["code"] for row in report["blockers"]},
        )

    def test_all_frozen_task_fixture_oracle_and_dynamic_source_locks_resolve(self):
        adapter = AgentDojoAdapter()
        rows = {
            row["task_id"]: row
            for row in adapter._load_task_index().values()
            if row.get("task_id")
        }
        self.assertEqual(len(rows), 40)
        for task_id in sorted(rows):
            with self.subTest(task_id=task_id):
                fixture, oracle = adapter._load_bound_documents(rows[task_id])
                self.assertEqual(fixture["benchmark"], "AgentDojo")
                self.assertEqual(oracle["benchmark"], "AgentDojo")

    def test_explicit_missing_dependency_never_attempts_native_import(self):
        adapter = AgentDojoAdapter()
        dependencies = [
            {
                "module": module,
                "available": module != "deepdiff",
                "version": (
                    None
                    if module == "deepdiff"
                    else adapter.DEPENDENCY_VERSIONS[module]
                ),
            }
            for module, _ in adapter.REQUIRED_MODULES
        ]
        with (
            mock.patch.object(adapter, "_dependency_status", return_value=dependencies),
            mock.patch.object(adapter, "_import_native_runtime") as native_import,
        ):
            report = adapter.preflight()
        native_import.assert_not_called()
        self.assertFalse(report["executable"])
        self.assertIn(
            "AGENTDOJO_DEPENDENCY_MISSING:deepdiff",
            {row["code"] for row in report["blockers"]},
        )

    def test_installed_dependency_version_must_match_pinned_uv_lock(self):
        adapter = AgentDojoAdapter()
        dependencies = [
            {
                "module": module,
                "available": True,
                "version": (
                    "99.0" if module == "deepdiff" else adapter.DEPENDENCY_VERSIONS[module]
                ),
            }
            for module, _ in adapter.REQUIRED_MODULES
        ]
        with (
            mock.patch.object(adapter, "_dependency_status", return_value=dependencies),
            mock.patch.object(adapter, "_import_native_runtime") as native_import,
        ):
            report = adapter.preflight()
        native_import.assert_not_called()
        self.assertFalse(report["checks"]["dependency_versions_exact"])
        self.assertIn(
            "AGENTDOJO_DEPENDENCY_VERSION_MISMATCH:deepdiff",
            {row["code"] for row in report["blockers"]},
        )

    def test_no_native_checker_cannot_reset_or_execute(self):
        adapter = AgentDojoAdapter()
        dependencies = [
            {
                "module": module,
                "available": True,
                "version": adapter.DEPENDENCY_VERSIONS[module],
            }
            for module, _ in adapter.REQUIRED_MODULES
        ]

        class NoCheckers:
            pass

        incomplete = {
            "get_suite": lambda version, domain: None,
            "TaskSuite": NoCheckers,
            "FunctionsRuntime": lambda tools: None,
            "FunctionCall": lambda **kwargs: None,
        }
        with (
            mock.patch.object(adapter, "_dependency_status", return_value=dependencies),
            mock.patch.object(adapter, "_import_native_runtime", return_value=incomplete),
        ):
            report = adapter.preflight()
            self.assertFalse(report["checks"]["native_checker_importable"])
            self.assertIn(
                "AGENTDOJO_NATIVE_CHECKER_UNAVAILABLE",
                {row["code"] for row in report["blockers"]},
            )
            with self.assertRaisesRegex(
                AgentDojoRuntimeError, "AGENTDOJO_NATIVE_CHECKER_UNAVAILABLE"
            ):
                adapter.reset("agentdojo-v1-banking-u0-i5")

    def test_unknown_task_fails_before_any_native_import(self):
        adapter = AgentDojoAdapter()
        with mock.patch.object(adapter, "preflight") as preflight:
            with self.assertRaisesRegex(AgentDojoRuntimeError, "AGENTDOJO_UNKNOWN_TASK"):
                adapter.reset("agentdojo-v1-does-not-exist")
        preflight.assert_not_called()

    def test_registration_describes_code_but_does_not_imply_executability(self):
        registry = PublicAdapterRegistry()
        descriptor = registry.register(AgentDojoAdapter)
        self.assertEqual(descriptor.adapter_id, AgentDojoAdapter.adapter_id)
        self.assertEqual(len(descriptor.implementation_sha256), 64)
        self.assertFalse(AgentDojoAdapter().preflight()["executable"])


class AgentDojoProjectedCheckerTests(unittest.TestCase):
    def test_full_snapshot_is_typed_deterministic_and_always_no_go(self):
        adapter = AgentDojoAdapter()
        snapshot = adapter.build_projected_snapshot(**_synthetic_projected_input())
        self.assertIsInstance(snapshot, ProjectedCheckerSnapshot)
        self.assertEqual(snapshot.contract_version, PROJECTED_CHECKER_CONTRACT_VERSION)
        self.assertIsInstance(snapshot.events, tuple)
        self.assertIsInstance(snapshot.mechanism_evidence, tuple)

        first = adapter.evaluate_projected_snapshot(snapshot)
        second = adapter.evaluate_projected_snapshot(snapshot)
        self.assertEqual(first, second)
        self.assertEqual(first.decision, "NO_GO")
        self.assertEqual(first.input_sha256, snapshot.canonical_sha256)
        self.assertEqual(len(first.mechanisms), 6)
        self.assertEqual(MECHANISM_IDS, TRUSTED_MECHANISM_IDS)
        self.assertEqual(
            {item.mechanism_id for item in first.mechanisms}, set(MECHANISM_IDS)
        )
        statuses = {item.status for item in first.mechanisms}
        self.assertIn("observed", statuses)
        self.assertIn("not_observed", statuses)
        self.assertIn("not_applicable", statuses)
        self.assertTrue(first.checker_complete)
        self.assertIn("NATIVE_PARITY_NOT_ESTABLISHED", first.blocker_codes)
        serialized = first.as_json()
        canonical_json_bytes(serialized)
        output_sha256 = serialized.pop("output_sha256")
        self.assertEqual(output_sha256, sha256_bytes(canonical_json_bytes(serialized)))

    def test_ambiguous_mapping_is_insufficient_evidence_and_no_go(self):
        adapter = AgentDojoAdapter()
        source = _synthetic_projected_input()
        source["mechanism_evidence"][2]["eligibility"] = "ambiguous"
        snapshot = adapter.build_projected_snapshot(**source)
        result = adapter.evaluate_projected_snapshot(snapshot)
        by_id = {item.mechanism_id: item for item in result.mechanisms}
        self.assertEqual(
            by_id[MECHANISM_IDS[2]].status, "insufficient_evidence"
        )
        self.assertFalse(result.checker_complete)
        self.assertEqual(result.decision, "NO_GO")
        self.assertIn("MECHANISM_MAPPING_AMBIGUOUS", result.blocker_codes)

    def test_missing_event_provenance_makes_all_mechanisms_insufficient(self):
        adapter = AgentDojoAdapter()
        source = _synthetic_projected_input()
        source["trusted_events"][0]["provenance"] = []
        result = adapter.evaluate_projected_snapshot(
            adapter.build_projected_snapshot(**source)
        )
        self.assertEqual(
            {item.status for item in result.mechanisms}, {"insufficient_evidence"}
        )
        self.assertIn("EVENT_PROVENANCE_INVALID", result.blocker_codes)
        self.assertEqual(result.decision, "NO_GO")

    def test_state_digest_mismatch_makes_all_mechanisms_insufficient(self):
        adapter = AgentDojoAdapter()
        source = _synthetic_projected_input()
        source["state_delta"]["after_sha256"] = sha256_bytes(b"forged-state")
        result = adapter.evaluate_projected_snapshot(
            adapter.build_projected_snapshot(**source)
        )
        self.assertEqual(
            {item.status for item in result.mechanisms}, {"insufficient_evidence"}
        )
        self.assertIn("STATE_DIGEST_MISMATCH", result.blocker_codes)

    def test_unrecognized_or_out_of_order_event_fails_closed(self):
        adapter = AgentDojoAdapter()
        for field, value, blocker in (
            ("event_type", "agentdojo_unknown_event", "EVENT_TYPE_UNRECOGNIZED"),
            ("sequence_index", 4, "EVENT_ORDER_INVALID"),
        ):
            with self.subTest(field=field):
                source = _synthetic_projected_input()
                source["trusted_events"][0][field] = value
                result = adapter.evaluate_projected_snapshot(
                    adapter.build_projected_snapshot(**source)
                )
                self.assertEqual(
                    {item.status for item in result.mechanisms},
                    {"insufficient_evidence"},
                )
                self.assertIn(blocker, result.blocker_codes)
                self.assertEqual(result.decision, "NO_GO")

    def test_explicit_exclusion_requires_reason_and_zero_witnesses(self):
        adapter = AgentDojoAdapter()
        source = _synthetic_projected_input()
        source["mechanism_evidence"][1]["exclusion_rationale"] = None
        result = adapter.evaluate_projected_snapshot(
            adapter.build_projected_snapshot(**source)
        )
        by_id = {item.mechanism_id: item for item in result.mechanisms}
        self.assertEqual(
            by_id[MECHANISM_IDS[1]].status, "insufficient_evidence"
        )
        self.assertIn("EXPLICIT_EXCLUSION_MISSING", result.blocker_codes)

    def test_native_verdict_or_reward_fields_are_rejected_before_parsing(self):
        adapter = AgentDojoAdapter()
        source = _synthetic_projected_input()
        source["state_delta"]["native_reward"] = 1
        with self.assertRaisesRegex(
            AgentDojoRuntimeError, "PROJECTED_NATIVE_SIGNAL_PROHIBITED"
        ):
            adapter.build_projected_snapshot(**source)

        source = _synthetic_projected_input()
        source["terminal"]["native_verdict"] = True
        with self.assertRaisesRegex(
            AgentDojoRuntimeError, "PROJECTED_NATIVE_SIGNAL_PROHIBITED"
        ):
            adapter.build_projected_snapshot(**source)

    def test_cross_benchmark_typed_snapshot_is_rejected(self):
        adapter = AgentDojoAdapter()
        snapshot = adapter.build_projected_snapshot(**_synthetic_projected_input())
        with self.assertRaisesRegex(
            AgentDojoRuntimeError, "PROJECTED_IDENTITY_INVALID"
        ):
            adapter.evaluate_projected_snapshot(replace(snapshot, benchmark="tau2"))

    def test_present_provenance_must_be_agentdojo_scoped_and_role_bound(self):
        adapter = AgentDojoAdapter()
        source = _synthetic_projected_input()
        source["trusted_events"][0]["provenance"][0]["source_id"] = (
            "tau2:synthetic:event-0"
        )
        with self.assertRaisesRegex(
            AgentDojoRuntimeError, "PROJECTED_PROVENANCE_INVALID"
        ):
            adapter.build_projected_snapshot(**source)

        source = _synthetic_projected_input()
        source["terminal"]["provenance"][0]["source_kind"] = "adapter_trace"
        with self.assertRaisesRegex(
            AgentDojoRuntimeError, "PROJECTED_PROVENANCE_INVALID"
        ):
            adapter.build_projected_snapshot(**source)


class AgentDojoPlumbingTests(unittest.TestCase):
    def test_reset_dispatch_projection_native_checker_and_cleanup_plumbing(self):
        # This exercises adapter plumbing with local fakes only.  It is not an
        # AgentDojo native checker parity run and is intentionally not emitted
        # as an evidence artifact.
        adapter = _PlumbingOnlyAdapter()
        reset = adapter.reset("agentdojo-v1-banking-u0-i5")
        self.assertTrue(reset["injection_enabled"])
        self.assertEqual(reset["pair_role"], "adversarial")

        action = adapter.dispatch_native_action(
            {"function": "set_value", "args": {"value": 7}}
        )
        self.assertTrue(action["native_success"])
        events = adapter.project_trusted_events([action])
        self.assertEqual(len(events), 1)
        self.assertTrue(events[0]["host_mediated"])
        self.assertEqual(events[0]["authorization_semantics"], "not_inferred")

        verdict = adapter.evaluate_native_checkers(
            source_task_id="agentdojo-v1-banking-u0-i5",
            native_trace=[action],
            terminal_state={
                "state_sha256": action["post_state_sha256"],
                "model_output": "done",
            },
        )
        self.assertTrue(verdict.utility)
        self.assertTrue(verdict.security)
        self.assertEqual(len(verdict.native_output_sha256), 64)
        self.assertEqual(len(verdict.checker_binding_ids), 2)

        with self.assertRaisesRegex(
            AgentDojoRuntimeError, "PROJECTED_CHECKER_INSUFFICIENT_INPUT"
        ):
            adapter.evaluate_projected_checkers(
                source_task_id="agentdojo-v1-banking-u0-i5",
                trusted_events=events,
            )

        self.assertEqual(adapter.cleanup(), reset["initial_state_sha256"])
        with self.assertRaisesRegex(AgentDojoRuntimeError, "NO_ACTIVE_EPISODE"):
            adapter.dispatch_native_action(
                {"function": "set_value", "args": {"value": 8}}
            )

    def test_trace_and_terminal_state_substitution_fail_closed(self):
        adapter = _PlumbingOnlyAdapter()
        adapter.reset("agentdojo-v1-banking-u0-i5")
        action = adapter.dispatch_native_action(
            {"function": "set_value", "args": {"value": 7}}
        )
        forged = dict(action)
        forged["post_state_sha256"] = "0" * 64
        with self.assertRaisesRegex(AgentDojoRuntimeError, "TRACE_MISMATCH"):
            adapter.project_trusted_events([forged])
        with self.assertRaisesRegex(AgentDojoRuntimeError, "TERMINAL_STATE_MISMATCH"):
            adapter.evaluate_native_checkers(
                source_task_id="agentdojo-v1-banking-u0-i5",
                native_trace=[action],
                terminal_state={"state_sha256": "0" * 64, "model_output": "done"},
            )
        adapter.cleanup()


if __name__ == "__main__":
    unittest.main()
