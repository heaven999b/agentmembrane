from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.public_adapters import (
    PublicAdapterRegistry,
    describe_adapter_type,
    normalize_runtime_preflight,
)
from agentmembrane.host_v2.projected_checker import MECHANISM_IDS
from agentmembrane.host_v2.schema import (
    IntegrityError,
    SchemaError,
    canonical_json_bytes,
    sha256_bytes,
)
from agentmembrane.host_v2.tau2_adapter import (
    TAU2_ATTACK_SEMANTICS,
    TAU2_COMMIT,
    TAU2_PIN,
    Tau2V101Adapter,
)


SOURCE_TASK_ID = "airline:7"
INITIAL_STATE = {"agent_db_sha256": "initial", "user_db_sha256": None}


def _fixture_sha(label: str) -> str:
    return sha256_bytes(label.encode("utf-8"))


def _field_provenance(
    source_kind: str, field_path: str, source_suffix: str
) -> dict[str, str]:
    return {
        "source_id": f"tau2:synthetic:{source_suffix}",
        "source_kind": source_kind,
        "source_sha256": _fixture_sha(f"source:{source_suffix}"),
        "field_path": field_path,
    }


def _projected_fixture() -> dict:
    event_types = (
        "credential_use",
        "authorization_decision",
        "state_observation",
        "tool_result",
        "follow_on_action",
        "cross_boundary_handoff",
    )
    events = []
    for index, event_type in enumerate(event_types):
        event_id = f"tau2:event:{index}"
        action = f"synthetic_action_{index}"
        events.append(
            {
                "event_id": event_id,
                "sequence_index": index,
                "event_type": event_type,
                "actor_id": "synthetic-assistant",
                "action": action,
                "payload_sha256": _fixture_sha(f"payload:{index}"),
                "authorization": {
                    "decision_id": f"tau2:authorization:{index}",
                    "principal_id": "synthetic-assistant",
                    "action": action,
                    "outcome": "authorized",
                    "credential_id": f"synthetic-credential-{index}",
                    "provenance": [
                        _field_provenance(
                            "authorization_log",
                            f"$.events[{index}].authorization",
                            f"authorization:{index}",
                        )
                    ],
                },
                "provenance": [
                    _field_provenance(
                        "host_event_log",
                        f"$.events[{index}]",
                        f"event:{index}",
                    )
                ],
            }
        )

    pre_state_sha256 = _fixture_sha("pre-state")
    post_state_sha256 = _fixture_sha("post-state")
    mechanisms = []
    for index, mechanism_id in enumerate(MECHANISM_IDS):
        mechanisms.append(
            {
                "mechanism_id": mechanism_id,
                "eligibility": "eligible",
                "witness_event_ids": [events[index]["event_id"]],
                "exclusion_code": None,
                "exclusion_rationale": None,
                "provenance": [
                    _field_provenance(
                        "mechanism_mapping",
                        f"$.mechanism_evidence[{index}]",
                        f"mechanism:{index}",
                    )
                ],
            }
        )
    return {
        "source_task_id": "synthetic:tau2:projected-case-001",
        "trace_id": "tau2:synthetic:trace-001",
        "trusted_events": events,
        "pre_state_sha256": pre_state_sha256,
        "post_state_sha256": post_state_sha256,
        "state_delta": {
            "delta_id": "tau2:synthetic:delta-001",
            "delta_kind": "updated",
            "before_sha256": pre_state_sha256,
            "after_sha256": post_state_sha256,
            "changed_paths": ["$.agent_db.synthetic_record"],
            "witness_event_ids": [events[2]["event_id"]],
            "provenance": [
                _field_provenance(
                    "state_snapshot", "$.state_delta", "state-delta"
                )
            ],
        },
        "terminal": {
            "output_sha256": _fixture_sha("terminal-output"),
            "reason": "completed",
            "witness_event_ids": [events[-1]["event_id"]],
            "provenance": [
                _field_provenance(
                    "terminal_capture", "$.terminal", "terminal"
                )
            ],
        },
        "mechanism_evidence": mechanisms,
    }


class _FakeTask:
    pass


class _FakeTau2Runtime:
    """Unit-only runtime double; never evidence of public checker parity."""

    def __init__(
        self,
        checkout: Path,
        *,
        utility: bool = True,
        cleanup_state: dict | None = None,
    ) -> None:
        self.checkout = checkout
        self.utility = utility
        self.cleanup_state = cleanup_state or dict(INITIAL_STATE)
        self.task = _FakeTask()
        self.dispatch_count = 0
        self.evaluate_count = 0

    def reset(self, domain: str, native_task_id: str):
        if (domain, native_task_id) != ("airline", "7"):
            raise AssertionError("unexpected fake source task")
        environment = {"state": dict(INITIAL_STATE)}
        return self.task, environment, dict(INITIAL_STATE)

    @staticmethod
    def terminal_state(environment):
        return dict(environment["state"])

    def dispatch(
        self,
        environment,
        *,
        call_id,
        name,
        arguments,
        requestor,
    ):
        self.dispatch_count += 1
        environment["state"] = {
            "agent_db_sha256": "mutated",
            "user_db_sha256": None,
        }
        return {
            "kind": "native_action",
            "call_id": call_id,
            "name": name,
            "arguments": dict(arguments),
            "requestor": requestor,
            "response_content": json.dumps({"ok": True}, sort_keys=True),
            "error": False,
        }

    def evaluate(self, *, task, domain, native_trace):
        if task is not self.task or domain != "airline" or not native_trace:
            raise AssertionError("fake native evaluator received wrong episode")
        self.evaluate_count += 1
        # An injected security value is deliberately ignored by the adapter.
        return {
            "utility": self.utility,
            "security": True,
            "reward": 1.0 if self.utility else 0.0,
            "reward_basis": ["DB"],
            "components": {"environment": {"reward": int(self.utility)}},
            "binding_ids": [
                "tau2-v1.0.1-environment-utility",
                "tau2-v1.0.1-action-utility",
                "tau2-v1.0.1-communicate-utility",
            ],
        }

    def cleanup(self, domain, task):
        if domain != "airline" or task is not self.task:
            raise AssertionError("fake cleanup received wrong episode")
        return dict(self.cleanup_state)


def _compatible_adapter(*, runtime: _FakeTau2Runtime | None = None):
    holder = {}

    def load(checkout):
        selected = runtime or _FakeTau2Runtime(checkout)
        holder["runtime"] = selected
        return selected

    adapter = Tau2V101Adapter(
        python_version=(3, 12, 9),
        python_executable="/fixture/python3.12",
        module_finder=lambda _module: True,
        version_lookup=lambda _distribution: "fixture-installed",
        git_probe=lambda _checkout: (TAU2_COMMIT, True),
        runtime_loader=load,
    )
    return adapter, holder


class Tau2PreflightTests(unittest.TestCase):
    def test_exact_pin_head_source_and_checker_locks_are_json_stable(self) -> None:
        adapter = Tau2V101Adapter()
        first = adapter.preflight()
        second = adapter.preflight()

        self.assertEqual(canonical_json_bytes(first), canonical_json_bytes(second))
        self.assertEqual(
            set(first),
            {
                "schema_version",
                "artifact_type",
                "adapter_id",
                "benchmark",
                "upstream_version_or_commit",
                "contract_version",
                "implementation_sha256",
                "upstream_checkout_path",
                "upstream_head",
                "python_executable",
                "python_version",
                "required_python",
                "dependencies",
                "checker_bindings",
                "checks",
                "blockers",
                "executable",
            },
        )
        self.assertEqual(first["schema_version"], 1)
        self.assertEqual(
            first["artifact_type"],
            "agentmembrane_public_adapter_runtime_preflight",
        )
        self.assertEqual(first["upstream_version_or_commit"], TAU2_PIN)
        self.assertEqual(first["upstream_head"], TAU2_COMMIT)
        self.assertTrue(first["checks"]["upstream_head_matches"])
        self.assertTrue(first["checks"]["source_locks_match"])
        self.assertTrue(first["checks"]["pack_locks_match"])
        self.assertTrue(first["checks"]["task_inventory_valid"])
        self.assertEqual(len(first["checker_bindings"]), 3)
        self.assertTrue(
            all(len(item["source_sha256"]) == 64 for item in first["checker_bindings"])
        )
        self.assertEqual(adapter.attack_semantics, TAU2_ATTACK_SEMANTICS)
        self.assertIs(adapter.native_security_checker_available, False)
        descriptor = describe_adapter_type(Tau2V101Adapter)
        expected_implementation = sha256_bytes(
            Path(descriptor.implementation_path).read_bytes()
        )
        self.assertEqual(first["implementation_sha256"], expected_implementation)
        self.assertEqual(descriptor.implementation_sha256, expected_implementation)
        normalized = normalize_runtime_preflight(first, descriptor=descriptor)
        self.assertEqual(normalized.adapter_id, adapter.adapter_id)
        self.assertEqual(normalized.executable, first["executable"])

    def test_shared_normalizer_accepts_mocked_executable_preflight(self) -> None:
        adapter, _holder = _compatible_adapter()
        report = adapter.preflight()
        self.assertTrue(report["executable"])
        descriptor = describe_adapter_type(Tau2V101Adapter)
        normalized = normalize_runtime_preflight(report, descriptor=descriptor)
        self.assertTrue(normalized.executable)

        registry = PublicAdapterRegistry()
        registry.register(Tau2V101Adapter)
        registry.bind_runtime(adapter)
        bound = registry.runtime_preflight(adapter.adapter_id)
        self.assertIsNotNone(bound)
        self.assertTrue(bound.executable)

    def test_python_and_dependencies_fail_closed_without_importing_runtime(self) -> None:
        called = []
        adapter = Tau2V101Adapter(
            python_version=(3, 11, 9),
            module_finder=lambda _module: False,
            git_probe=lambda _checkout: (TAU2_COMMIT, True),
            runtime_loader=lambda path: called.append(path),
        )
        report = adapter.preflight()
        codes = [item["code"] for item in report["blockers"]]
        self.assertFalse(report["executable"])
        self.assertIn("TAU2_PYTHON_UNSUPPORTED", codes)
        self.assertIn("TAU2_DEPENDENCIES_MISSING", codes)
        self.assertTrue(all(row["version"] is None for row in report["dependencies"]))
        with self.assertRaisesRegex(IntegrityError, "preflight is not executable"):
            adapter.reset(SOURCE_TASK_ID)
        self.assertEqual(called, [])

    def test_wrong_head_and_changed_source_are_explicit_blockers(self) -> None:
        wrong_head = Tau2V101Adapter(
            python_version=(3, 12, 1),
            module_finder=lambda _module: True,
            version_lookup=lambda _distribution: "fixture",
            git_probe=lambda _checkout: ("0" * 40, True),
        ).preflight()
        self.assertFalse(wrong_head["checks"]["upstream_head_matches"])
        self.assertIn(
            "TAU2_HEAD_MISMATCH",
            [item["code"] for item in wrong_head["blockers"]],
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            checkout = Path(temp_dir)
            (checkout / "pyproject.toml").write_text("changed", encoding="utf-8")
            changed = Tau2V101Adapter(
                checkout_path=checkout,
                python_version=(3, 12, 1),
                module_finder=lambda _module: True,
                version_lookup=lambda _distribution: "fixture",
                git_probe=lambda _checkout: (TAU2_COMMIT, True),
            ).preflight()
        self.assertFalse(changed["checks"]["source_locks_match"])
        self.assertFalse(changed["checks"]["checker_bindings_locked"])
        self.assertIn(
            "TAU2_SOURCE_LOCK_MISMATCH",
            [item["code"] for item in changed["blockers"]],
        )


class Tau2ProjectedCheckerContractTests(unittest.TestCase):
    def test_all_six_mechanisms_are_independent_and_output_is_canonical(self) -> None:
        adapter = Tau2V101Adapter()
        fixture = _projected_fixture()
        first_snapshot = adapter.build_projected_snapshot(**fixture)
        second_snapshot = adapter.build_projected_snapshot(**deepcopy(fixture))

        self.assertEqual(
            canonical_json_bytes(first_snapshot.as_json()),
            canonical_json_bytes(second_snapshot.as_json()),
        )
        first = adapter.evaluate_projected_snapshot(first_snapshot)
        second = adapter.evaluate_projected_snapshot(second_snapshot)
        self.assertEqual(
            canonical_json_bytes(first.as_json()),
            canonical_json_bytes(second.as_json()),
        )
        self.assertEqual(
            tuple(item.mechanism_id for item in first.mechanisms), MECHANISM_IDS
        )
        self.assertEqual(
            [item.status for item in first.mechanisms], ["observed"] * 6
        )
        self.assertEqual(
            [item.witness_ids for item in first.mechanisms],
            [(f"tau2:event:{index}",) for index in range(6)],
        )
        self.assertTrue(first.checker_complete)
        self.assertEqual(first.decision, "NO_GO")
        self.assertIn("NATIVE_PARITY_NOT_ESTABLISHED", first.blocker_codes)
        self.assertEqual(len(first.input_sha256), 64)
        self.assertEqual(len(first.checker_implementation_sha256), 64)
        payload = first.as_json()
        output_sha256 = payload.pop("output_sha256")
        self.assertEqual(output_sha256, sha256_bytes(canonical_json_bytes(payload)))
        serialized = canonical_json_bytes(first.as_json()).decode("utf-8")
        for prohibited in ('"reward"', '"utility"', '"security"', '"verdict"'):
            self.assertNotIn(prohibited, serialized)

    def test_explicit_exclusion_and_eligible_nonobservation_are_distinct(self) -> None:
        adapter = Tau2V101Adapter()
        fixture = _projected_fixture()
        excluded = fixture["mechanism_evidence"][4]
        excluded.update(
            {
                "eligibility": "excluded",
                "witness_event_ids": [],
                "exclusion_code": "TAU2_TASK_HAS_NO_PERSISTENCE_SURFACE",
                "exclusion_rationale": (
                    "The frozen synthetic task exposes no persistence or follow-on "
                    "surface."
                ),
            }
        )
        not_observed = fixture["mechanism_evidence"][5]
        not_observed["witness_event_ids"] = []

        result = adapter.evaluate_projected_snapshot(
            adapter.build_projected_snapshot(**fixture)
        )
        statuses = {item.mechanism_id: item.status for item in result.mechanisms}
        self.assertEqual(
            statuses["multi_step_capability_chaining"], "not_applicable"
        )
        self.assertEqual(
            statuses["proposal_to_action_conversion"], "not_observed"
        )
        self.assertTrue(result.checker_complete)
        self.assertEqual(result.decision, "NO_GO")

    def test_ambiguous_mapping_is_insufficient_and_no_go(self) -> None:
        adapter = Tau2V101Adapter()
        fixture = _projected_fixture()
        fixture["mechanism_evidence"][1]["eligibility"] = "ambiguous"

        result = adapter.evaluate_projected_snapshot(
            adapter.build_projected_snapshot(**fixture)
        )
        by_mechanism = {item.mechanism_id: item for item in result.mechanisms}
        self.assertEqual(
            by_mechanism["confused_deputy"].status, "insufficient_evidence"
        )
        self.assertFalse(result.checker_complete)
        self.assertEqual(result.decision, "NO_GO")
        self.assertIn("MECHANISM_MAPPING_AMBIGUOUS", result.blocker_codes)

    def test_global_trust_order_and_digest_defects_make_every_result_insufficient(
        self,
    ) -> None:
        adapter = Tau2V101Adapter()
        fixtures = []

        missing_provenance = _projected_fixture()
        missing_provenance["trusted_events"][0]["provenance"] = []
        fixtures.append((missing_provenance, "EVENT_PROVENANCE_INVALID"))

        unrecognized_event = _projected_fixture()
        unrecognized_event["trusted_events"][0]["event_type"] = "tau2_unknown_event"
        fixtures.append((unrecognized_event, "EVENT_TYPE_UNRECOGNIZED"))

        unordered = _projected_fixture()
        unordered["trusted_events"][0]["sequence_index"] = 4
        fixtures.append((unordered, "EVENT_ORDER_INVALID"))

        mismatched_digest = _projected_fixture()
        mismatched_digest["state_delta"]["after_sha256"] = _fixture_sha("forged")
        fixtures.append((mismatched_digest, "STATE_DIGEST_MISMATCH"))

        for fixture, blocker in fixtures:
            with self.subTest(blocker=blocker):
                result = adapter.evaluate_projected_snapshot(
                    adapter.build_projected_snapshot(**fixture)
                )
                self.assertEqual(
                    [item.status for item in result.mechanisms],
                    ["insufficient_evidence"] * 6,
                )
                self.assertFalse(result.checker_complete)
                self.assertEqual(result.decision, "NO_GO")
                self.assertIn(blocker, result.blocker_codes)

    def test_missing_explicit_exclusion_is_insufficient(self) -> None:
        adapter = Tau2V101Adapter()
        fixture = _projected_fixture()
        evidence = fixture["mechanism_evidence"][0]
        evidence["eligibility"] = "excluded"
        evidence["witness_event_ids"] = []

        result = adapter.evaluate_projected_snapshot(
            adapter.build_projected_snapshot(**fixture)
        )
        self.assertEqual(result.mechanisms[0].status, "insufficient_evidence")
        self.assertIn("EXPLICIT_EXCLUSION_MISSING", result.blocker_codes)
        self.assertFalse(result.checker_complete)
        self.assertEqual(result.decision, "NO_GO")

    def test_native_verdict_and_reward_channels_are_rejected_before_projection(
        self,
    ) -> None:
        adapter = Tau2V101Adapter()
        for field, value in (
            ("native_reward", 1.0),
            ("native_verdict", True),
            ("utility", True),
            ("security", False),
        ):
            fixture = _projected_fixture()
            fixture["trusted_events"][0][field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    IntegrityError, "must not contain native verdict/reward field"
                ):
                    adapter.build_projected_snapshot(**fixture)

    def test_tau2_provenance_namespace_and_benchmark_are_bound(self) -> None:
        from dataclasses import replace

        adapter = Tau2V101Adapter()
        fixture = _projected_fixture()
        fixture["terminal"]["provenance"][0]["source_id"] = "other:terminal"
        with self.assertRaisesRegex(IntegrityError, "tau2: namespace"):
            adapter.build_projected_snapshot(**fixture)

        snapshot = adapter.build_projected_snapshot(**_projected_fixture())
        with self.assertRaisesRegex(IntegrityError, "benchmark mismatch"):
            adapter.evaluate_projected_snapshot(
                replace(snapshot, benchmark="not-tau2")
            )


class Tau2EpisodeContractTests(unittest.TestCase):
    def test_unknown_source_task_fails_before_lazy_runtime_load(self) -> None:
        adapter, holder = _compatible_adapter()
        self.assertTrue(adapter.preflight()["executable"])
        with self.assertRaisesRegex(IntegrityError, "unknown tau2 source_task_id"):
            adapter.reset("airline:does-not-exist")
        self.assertEqual(holder, {})

    def test_native_utility_and_derived_security_are_strictly_separated(self) -> None:
        adapter, holder = _compatible_adapter()
        reset = adapter.reset(SOURCE_TASK_ID)
        self.assertEqual(reset["native_task_id"], "7")
        action = adapter.dispatch_native_action(
            {
                "name": "cancel_reservation",
                "arguments": {"reservation_id": "XEHM4B"},
            }
        )
        communication = adapter.append_native_assistant_message("done")
        trace = [action, communication]
        terminal = adapter.terminal_state()
        captured = adapter.capture_terminal_state(
            reset_state=reset, native_trace=trace
        )
        self.assertEqual(captured, terminal)

        verdict = adapter.evaluate_native_checkers(
            source_task_id=SOURCE_TASK_ID,
            native_trace=trace,
            terminal_state=terminal,
        )
        self.assertIs(verdict.utility, True)
        self.assertIsNone(verdict.security)
        self.assertEqual(
            verdict.checker_binding_ids,
            (
                "tau2-v1.0.1-environment-utility",
                "tau2-v1.0.1-action-utility",
                "tau2-v1.0.1-communicate-utility",
            ),
        )
        self.assertEqual(len(verdict.native_output_sha256), 64)
        self.assertEqual(holder["runtime"].evaluate_count, 1)

        events = adapter.project_trusted_events(trace)
        self.assertEqual(len(events), 2)
        self.assertTrue(
            all(
                event["security_classification"]
                == "not_provided_by_tau2_native"
                for event in events
            )
        )
        self.assertTrue(
            all(event["attack_semantics"] == TAU2_ATTACK_SEMANTICS for event in events)
        )
        self.assertTrue(all("unauthorized" not in event for event in events))
        with self.assertRaisesRegex(IntegrityError, "legacy projected-checker input"):
            adapter.evaluate_projected_checkers(
                source_task_id=SOURCE_TASK_ID,
                trusted_events=events,
            )

        cleanup_sha = adapter.cleanup()
        self.assertEqual(len(cleanup_sha), 64)
        adapter.reset(SOURCE_TASK_ID)
        adapter.cleanup()

    def test_trace_terminal_and_task_mismatch_fail_closed(self) -> None:
        adapter, _holder = _compatible_adapter()
        adapter.reset(SOURCE_TASK_ID)
        action = adapter.dispatch_native_action(
            {"name": "write", "arguments": {"value": 1}}
        )
        terminal = adapter.terminal_state()
        with self.assertRaisesRegex(IntegrityError, "source_task_id differs"):
            adapter.evaluate_native_checkers(
                source_task_id="retail:0",
                native_trace=[action],
                terminal_state=terminal,
            )
        with self.assertRaisesRegex(IntegrityError, "trace differs"):
            adapter.evaluate_native_checkers(
                source_task_id=SOURCE_TASK_ID,
                native_trace=[],
                terminal_state=terminal,
            )
        with self.assertRaisesRegex(IntegrityError, "terminal state differs"):
            adapter.evaluate_native_checkers(
                source_task_id=SOURCE_TASK_ID,
                native_trace=[action],
                terminal_state={"agent_db_sha256": "forged", "user_db_sha256": None},
            )
        adapter.cleanup()

    def test_action_schema_and_overlapping_reset_fail_closed(self) -> None:
        adapter, _holder = _compatible_adapter()
        adapter.reset(SOURCE_TASK_ID)
        with self.assertRaisesRegex(IntegrityError, "active episode"):
            adapter.reset(SOURCE_TASK_ID)
        with self.assertRaisesRegex(SchemaError, "unknown fields"):
            adapter.dispatch_native_action(
                {"name": "write", "arguments": {}, "untrusted": True}
            )
        with self.assertRaisesRegex(SchemaError, "requestor is invalid"):
            adapter.dispatch_native_action(
                {"name": "write", "arguments": {}, "requestor": "system"}
            )
        adapter.cleanup()

    def test_cleanup_mismatch_preserves_closed_episode_state(self) -> None:
        runtime = _FakeTau2Runtime(
            Path("."),
            cleanup_state={"agent_db_sha256": "not-initial", "user_db_sha256": None},
        )
        adapter, _holder = _compatible_adapter(runtime=runtime)
        adapter.reset(SOURCE_TASK_ID)
        with self.assertRaisesRegex(IntegrityError, "cleanup reset differs"):
            adapter.cleanup()
        with self.assertRaisesRegex(IntegrityError, "active episode"):
            adapter.reset(SOURCE_TASK_ID)


if __name__ == "__main__":
    unittest.main()
