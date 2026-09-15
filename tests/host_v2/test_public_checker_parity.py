from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

from agentmembrane.host_v2.public_adapters import (
    ADAPTER_CONTRACT_VERSION,
    RUNTIME_PREFLIGHT_ARTIFACT_TYPE,
    AdapterRuntimePreflight,
    NativeCheckerVerdict,
    ProjectedCheckerVerdict,
    PublicAdapterRegistry,
    PublicBenchmarkAdapter,
    describe_adapter_type,
    normalize_runtime_preflight,
)
from agentmembrane.host_v2.public_checker_parity import (
    CHECKER_PARITY_ARTIFACT_TYPE,
    CHECKER_PARITY_DIAGNOSTIC_ARTIFACT_TYPE,
    REQUIRED_CHECKER_PARITY_CATEGORIES,
    CheckerParityCase,
    run_checker_parity,
    validate_namespace_reservation,
)
from agentmembrane.host_v2.schema import IntegrityError, canonical_json_bytes, sha256_bytes


FAKE_TASKPACK_SHA256 = "a" * 64
FIXTURE_SOURCE_SHA256 = "b" * 64


class _LegacyFixtureAdapter(PublicBenchmarkAdapter):
    adapter_id = "fixture-only-adapter"
    benchmark = "fixture-only-not-public-benchmark"
    upstream_version_or_commit = "fixture@fixture-head"

    def reset(self, source_task_id):
        return {"source_task_id": source_task_id}

    def dispatch_native_action(self, action):
        return dict(action)

    def project_trusted_events(self, native_trace):
        return tuple(native_trace)

    def evaluate_native_checkers(self, *, source_task_id, native_trace, terminal_state):
        raise AssertionError("legacy fixture native checker must not execute")

    def cleanup(self):
        return sha256_bytes(b"fixture-clean")


class _ExecutableFixtureAdapter(_LegacyFixtureAdapter):
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.cleanup_count = 0

    def preflight(self):
        descriptor = describe_adapter_type(type(self))
        return {
            "schema_version": 1,
            "artifact_type": RUNTIME_PREFLIGHT_ARTIFACT_TYPE,
            "adapter_id": descriptor.adapter_id,
            "benchmark": descriptor.benchmark,
            "upstream_version_or_commit": descriptor.upstream_version_or_commit,
            "contract_version": ADAPTER_CONTRACT_VERSION,
            "implementation_sha256": descriptor.implementation_sha256,
            "upstream_checkout_path": "/fixture/pinned-source",
            "upstream_head": "fixture-head",
            "python_executable": "/fixture/python",
            "python_version": "3.fixture",
            "required_python": ">=3.fixture",
            "dependencies": [
                {"module": "fixture_native", "available": True, "version": "1.fixture"}
            ],
            "checker_bindings": [
                {
                    "binding_id": "fixture-native-checker",
                    "callable_ref": "fixture.native:evaluate",
                    "source_path": "fixture/native.py",
                    "source_sha256": FIXTURE_SOURCE_SHA256,
                }
            ],
            "checks": {
                "exact_upstream_head": True,
                "native_checker_importable": True,
                "source_lock_verified": True,
            },
            "blockers": [],
            "executable": True,
        }

    def reset(self, source_task_id):
        self.calls.append(f"reset:{source_task_id}")
        return {"source_task_id": source_task_id, "clean": True}

    def dispatch_native_action(self, action):
        self.calls.append("dispatch")
        return dict(action)

    def evaluate_native_checkers(self, *, source_task_id, native_trace, terminal_state):
        self.calls.append("native")
        value = dict(native_trace[-1])
        verdict = {"utility": value["utility"], "security": value["security"]}
        return NativeCheckerVerdict(
            utility=value["utility"],
            security=value["security"],
            checker_binding_ids=("fixture-native-checker",),
            native_output_sha256=sha256_bytes(canonical_json_bytes(verdict)),
        )

    def project_trusted_events(self, native_trace):
        self.calls.append("project")
        return tuple(
            {
                "trusted_utility": item["utility"],
                "trusted_security": item["security"],
            }
            for item in native_trace
        )

    def evaluate_projected_checkers(self, *, source_task_id, trusted_events):
        self.calls.append("projected-checker")
        value = dict(trusted_events[-1])
        verdict = {
            "utility": value["trusted_utility"],
            "security": value["trusted_security"],
        }
        return ProjectedCheckerVerdict(
            utility=value["trusted_utility"],
            security=value["trusted_security"],
            projected_output_sha256=sha256_bytes(canonical_json_bytes(verdict)),
        )

    def cleanup(self):
        self.calls.append("cleanup")
        self.cleanup_count += 1
        return sha256_bytes(b"fixture-clean")


class _NativeFailureFixtureAdapter(_ExecutableFixtureAdapter):
    def evaluate_native_checkers(self, *, source_task_id, native_trace, terminal_state):
        self.calls.append("native")
        raise RuntimeError("fixture native checker failed")


class _CleanupFailureFixtureAdapter(_ExecutableFixtureAdapter):
    def cleanup(self):
        self.calls.append("cleanup")
        self.cleanup_count += 1
        raise RuntimeError("fixture cleanup failed")


class _MismatchFixtureAdapter(_ExecutableFixtureAdapter):
    def evaluate_projected_checkers(self, *, source_task_id, trusted_events):
        self.calls.append("projected-checker")
        value = dict(trusted_events[-1])
        return ProjectedCheckerVerdict(
            utility=not value["trusted_utility"],
            security=value["trusted_security"],
            projected_output_sha256=sha256_bytes(b"fixture-mismatch"),
        )


def _cases(count: int = 20) -> list[CheckerParityCase]:
    categories = sorted(REQUIRED_CHECKER_PARITY_CATEGORIES)
    return [
        CheckerParityCase(
            trace_id=f"fixture-trace-{index:02d}",
            task_id=f"fixture-formal-{index:02d}",
            source_task_id=f"fixture-source-{index:02d}",
            case_category=categories[index % len(categories)],
            actions=(
                {
                    "utility": index % 2 == 0,
                    "security": index % 3 == 0,
                    "mutation": categories[index % len(categories)],
                },
            ),
        )
        for index in range(count)
    ]


def _run(adapter, root: Path, namespace: str, cases=None):
    selected = _cases() if cases is None else cases
    return run_checker_parity(
        adapter,
        selected,
        output_root=root,
        namespace=namespace,
        parity_id="fixture-parity-only-v1",
        pack_id="fixture-pack-only",
        taskpack_content_sha256=FAKE_TASKPACK_SHA256,
        formal_task_ids=[case.task_id for case in selected],
        generated_at="2026-08-30T00:00:00Z",
        attack_semantics="native_upstream_security_checker",
    )


class RuntimePreflightContractTests(unittest.TestCase):
    def test_legacy_registration_is_not_runtime_executability(self) -> None:
        registry = PublicAdapterRegistry()
        descriptor = registry.register(_LegacyFixtureAdapter)
        self.assertIsNone(registry.runtime_preflight(descriptor.adapter_id))
        adapter = _LegacyFixtureAdapter()
        registry.bind_runtime(adapter)
        preflight = registry.runtime_preflight(descriptor.adapter_id)
        self.assertIsInstance(preflight, AdapterRuntimePreflight)
        self.assertFalse(preflight.executable)
        self.assertEqual(
            [item.code for item in preflight.blockers],
            ["RUNTIME_PREFLIGHT_NOT_IMPLEMENTED"],
        )

    def test_executable_flag_must_be_derived_not_declared(self) -> None:
        adapter = _ExecutableFixtureAdapter()
        descriptor = describe_adapter_type(type(adapter))
        raw = adapter.preflight()
        raw["checks"]["native_checker_importable"] = False
        with self.assertRaisesRegex(IntegrityError, "not derived"):
            normalize_runtime_preflight(raw, descriptor=descriptor)

    def test_runtime_binding_rejects_unregistered_instance(self) -> None:
        with self.assertRaisesRegex(IntegrityError, "before code registration"):
            PublicAdapterRegistry().bind_runtime(_ExecutableFixtureAdapter())


class CheckerParityDriverTests(unittest.TestCase):
    def test_nonexecutable_preflight_writes_only_structured_no_go(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = _run(_LegacyFixtureAdapter(), Path(temporary), "legacy-no-go")
            self.assertEqual(result.decision, "NO_GO")
            self.assertEqual(
                result.artifact["artifact_type"],
                CHECKER_PARITY_DIAGNOSTIC_ARTIFACT_TYPE,
            )
            self.assertIn(
                "RUNTIME_PREFLIGHT_NOT_IMPLEMENTED",
                result.artifact["blocker_codes"],
            )
            namespace = Path(result.namespace_path)
            self.assertTrue((namespace / "diagnostic.json").is_file())
            self.assertFalse((namespace / "report.json").exists())

    def test_fixture_pass_requires_independent_invocations_and_cleanup(self) -> None:
        adapter = _ExecutableFixtureAdapter()
        with tempfile.TemporaryDirectory() as temporary:
            result = _run(adapter, Path(temporary), "fixture-pass")
            self.assertEqual(result.decision, "PASS")
            self.assertEqual(result.artifact["artifact_type"], CHECKER_PARITY_ARTIFACT_TYPE)
            self.assertEqual(result.artifact["summary"]["trace_count"], 20)
            self.assertEqual(
                result.artifact["summary"]["distinct_source_task_count"], 20
            )
            self.assertEqual(adapter.cleanup_count, 20)
            for offset in range(0, len(adapter.calls), 6):
                self.assertEqual(
                    adapter.calls[offset + 2 : offset + 6],
                    ["native", "project", "projected-checker", "cleanup"],
                )
            self.assertTrue(Path(result.artifact_path).is_file())
            self.assertTrue(result.artifact["summary"]["cleanup_complete"])

    def test_pass_reservation_reference_is_byte_bound_and_missing_fails(self) -> None:
        adapter = _ExecutableFixtureAdapter()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = _run(adapter, root, "reservation-bound")
            reservation = validate_namespace_reservation(
                result.artifact, evidence_root=root
            )
            self.assertEqual(
                reservation["reservation_id"],
                "fixture-parity-only-v1:reservation-bound",
            )
            reference = result.artifact["namespace_reservation"]
            path = root / reference["path"]
            original = path.read_bytes()
            path.write_bytes(b"{}")
            with self.assertRaisesRegex(IntegrityError, "SHA-256 mismatch"):
                validate_namespace_reservation(result.artifact, evidence_root=root)
            path.write_bytes(original)
            path.unlink()
            with self.assertRaisesRegex(IntegrityError, "missing"):
                validate_namespace_reservation(result.artifact, evidence_root=root)

    def test_short_or_category_incomplete_set_is_diagnostic_not_pass(self) -> None:
        cases = _cases(19)
        with tempfile.TemporaryDirectory() as temporary:
            result = _run(
                _ExecutableFixtureAdapter(), Path(temporary), "short-no-go", cases
            )
            self.assertEqual(result.decision, "NO_GO")
            self.assertIn("PARITY_INPUT_INVALID", result.artifact["blocker_codes"])
            self.assertFalse((Path(result.namespace_path) / "report.json").exists())

    def test_native_failure_attempts_cleanup_and_never_writes_pass(self) -> None:
        adapter = _NativeFailureFixtureAdapter()
        with tempfile.TemporaryDirectory() as temporary:
            result = _run(adapter, Path(temporary), "native-failure")
            self.assertEqual(result.decision, "NO_GO")
            self.assertIn("NATIVE_PARITY_CASE_FAILED", result.artifact["blocker_codes"])
            self.assertEqual(adapter.cleanup_count, 1)
            self.assertFalse((Path(result.namespace_path) / "report.json").exists())

    def test_cleanup_failure_invalidates_matching_case(self) -> None:
        adapter = _CleanupFailureFixtureAdapter()
        with tempfile.TemporaryDirectory() as temporary:
            result = _run(adapter, Path(temporary), "cleanup-failure")
            self.assertEqual(result.decision, "NO_GO")
            self.assertIn("NATIVE_CLEANUP_FAILED", result.artifact["blocker_codes"])
            self.assertFalse((Path(result.namespace_path) / "report.json").exists())

    def test_one_mismatch_prevents_a_pass_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = _run(
                _MismatchFixtureAdapter(), Path(temporary), "mismatch-no-go"
            )
            self.assertEqual(result.decision, "NO_GO")
            self.assertIn(
                "NATIVE_CHECKER_PARITY_MISMATCH", result.artifact["blocker_codes"]
            )
            self.assertFalse((Path(result.namespace_path) / "report.json").exists())

    def test_namespace_reuse_fails_before_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = _run(_LegacyFixtureAdapter(), root, "never-reuse")
            before = Path(first.artifact_path).read_bytes()
            with self.assertRaisesRegex(IntegrityError, "not fresh"):
                _run(_LegacyFixtureAdapter(), root, "never-reuse")
            self.assertEqual(Path(first.artifact_path).read_bytes(), before)

    def test_forged_preflight_hash_is_not_copied_from_adapter_mapping(self) -> None:
        adapter = _ExecutableFixtureAdapter()
        forged = deepcopy(adapter.preflight())
        forged["implementation_sha256"] = "f" * 64
        adapter.preflight = lambda: forged  # type: ignore[method-assign]
        with tempfile.TemporaryDirectory() as temporary:
            result = _run(adapter, Path(temporary), "forged-preflight")
            self.assertEqual(result.decision, "NO_GO")
            self.assertIn("RUNTIME_PREFLIGHT_INVALID", result.artifact["blocker_codes"])


if __name__ == "__main__":
    unittest.main()
