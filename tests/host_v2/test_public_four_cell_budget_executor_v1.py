from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from agentmembrane.host_v2.public_four_cell_v1.budget import (
    AttemptCounters,
    RunChainBudgetError,
    build_run_chain_budget,
    claim_fresh_namespaces,
    materialize_run_chain_budget,
    validate_run_chain_budget,
)
from agentmembrane.host_v2.public_four_cell_v1.executor import (
    CheckerTextCapability,
    CONFIRMED_ASSISTANT_TEXT_MODE,
    ExecutorContractError,
    ImmutablePlannerFailure,
    RunChainBudgetGuard,
    RAW_RESPONSE_ENVELOPE_MODE,
    TEXT_CAPABILITY_CONTRACT,
    resolve_planner_turn,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_TASK_ID = "agentdojo-v1-banking-u3-i1"
REQUEST_KEY = "a" * 64
ATTEMPT_KEY = f"{REQUEST_KEY}:1"


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class _Turn:
    request_key: str
    actions: tuple[object, ...]
    final_artifact: dict[str, object] | None
    strategy: str | None
    status: str
    explicit_abstention: bool
    failure_class: str
    terminal_error: str | None
    attempt_keys: tuple[str, ...]


def _attempt(
    *,
    status: str,
    failure_class: str,
    raw_response: str | None,
    input_tokens: int = 0,
    output_tokens: int = 0,
    error: str | None = None,
) -> dict[str, object]:
    return {
        "schema_version": 2,
        "request_key": REQUEST_KEY,
        "attempt_key": ATTEMPT_KEY,
        "attempt_index": 1,
        "planner_status": status,
        "failure_class": failure_class,
        "resolved_model_id": "gpt-5.6-sol" if raw_response is not None else None,
        "raw_response": raw_response,
        "error": error,
        "error_metadata": {"code": "test_failure"} if error else {},
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
            "latency_ms": 0,
        },
    }


def _write_attempt(root: Path, relative: str, value: dict[str, object]) -> str:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_canonical_json_bytes(value))
    return relative


def _fresh_namespaces(prefix: str) -> dict[str, str]:
    return {
        "output": f"runs/{prefix}/output",
        "cache": f"runs/{prefix}/cache",
        "native": f"runs/{prefix}/native",
    }


class _Cache:
    def __init__(self, run_dir: Path, value: dict[str, object]) -> None:
        self.run_dir = run_dir
        self.value = value

    def load_attempt(self, key: str) -> dict[str, object] | None:
        return copy.deepcopy(self.value) if key == ATTEMPT_KEY else None


def _failed_turn(failure_class: str = "transport_failure") -> _Turn:
    return _Turn(
        request_key=REQUEST_KEY,
        actions=(),
        final_artifact=None,
        strategy=None,
        status="failed",
        explicit_abstention=False,
        failure_class=failure_class,
        terminal_error="exact failure",
        attempt_keys=(ATTEMPT_KEY,),
    )


def _delivered_turn() -> _Turn:
    return _Turn(
        request_key=REQUEST_KEY,
        actions=(),
        final_artifact={"done": True},
        strategy="done",
        status="complete",
        explicit_abstention=False,
        failure_class="none",
        terminal_error=None,
        attempt_keys=(ATTEMPT_KEY,),
    )


class RunChainBudgetTests(unittest.TestCase):
    def test_manifest_derives_orthogonal_counts_and_arbitrary_namespace(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            paths = [
                _write_attempt(
                    root,
                    "attempts/transport.json",
                    _attempt(
                        status="failed",
                        failure_class="transport_failure",
                        raw_response=None,
                        error="down",
                    ),
                ),
                _write_attempt(
                    root,
                    "attempts/delivered.json",
                    {
                        **_attempt(
                            status="ok",
                            failure_class="none",
                            raw_response='{"actions":[]}',
                            input_tokens=7,
                            output_tokens=3,
                        ),
                        "request_key": "b" * 64,
                        "attempt_key": f"{'b' * 64}:1",
                    },
                ),
            ]
            manifest_path = root / "manifests/arbitrary-name.json"
            budget = materialize_run_chain_budget(
                manifest_path,
                repo_root=root,
                chain_id="chain-without-numeric-suffix",
                cap=24,
                predecessor_attempt_paths=paths,
                fresh_namespaces=_fresh_namespaces("zebra"),
            )
            self.assertEqual(budget.consumed, 2)
            self.assertEqual(budget.remaining, 22)
            self.assertEqual(
                budget.counters,
                AttemptCounters(
                    client_attempts=2,
                    provider_accepted_requests=1,
                    delivered_model_responses=1,
                    token_bearing_calls=1,
                    input_tokens=7,
                    output_tokens=3,
                    total_tokens=10,
                ),
            )
            stored = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertIs(stored["execution_authorized"], False)
            self.assertNotIn("prior_attempts", stored)
            self.assertNotIn("execution_namespace_suffix", stored)
            self.assertEqual(
                validate_run_chain_budget(
                    repo_root=root, manifest_path=manifest_path
                ).manifest_payload_sha256,
                budget.manifest_payload_sha256,
            )

    def test_failed_http_attempt_consumes_without_delivery_or_tokens(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            path = _write_attempt(
                root,
                "attempts/http400.json",
                _attempt(
                    status="failed",
                    failure_class="other_failure",
                    raw_response=None,
                    error="proxy_http_400",
                ),
            )
            budget = build_run_chain_budget(
                repo_root=root,
                chain_id="http-failure-chain",
                cap=5,
                predecessor_attempt_paths=[path],
                fresh_namespaces=_fresh_namespaces("http-failure"),
            )
            self.assertEqual(budget.consumed, 1)
            self.assertEqual(budget.counters.provider_accepted_requests, 0)
            self.assertEqual(budget.counters.delivered_model_responses, 0)
            self.assertEqual(budget.counters.token_bearing_calls, 0)

    def test_manifest_rejects_predecessor_mutation(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            relative = _write_attempt(
                root,
                "attempts/one.json",
                _attempt(
                    status="failed",
                    failure_class="transport_failure",
                    raw_response=None,
                    error="down",
                ),
            )
            manifest = root / "manifest.json"
            materialize_run_chain_budget(
                manifest,
                repo_root=root,
                chain_id="mutation-chain",
                cap=4,
                predecessor_attempt_paths=[relative],
                fresh_namespaces=_fresh_namespaces("mutation"),
            )
            mutated = _attempt(
                status="failed",
                failure_class="other_failure",
                raw_response=None,
                error="changed",
            )
            (root / relative).write_bytes(_canonical_json_bytes(mutated))
            with self.assertRaisesRegex(
                RunChainBudgetError, "deterministic reconstruction"
            ):
                validate_run_chain_budget(repo_root=root, manifest_path=manifest)

    def test_existing_or_nested_namespace_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            (root / "already").mkdir()
            with self.assertRaisesRegex(RunChainBudgetError, "already exists"):
                build_run_chain_budget(
                    repo_root=root,
                    chain_id="reused-namespace",
                    cap=2,
                    predecessor_attempt_paths=[],
                    fresh_namespaces={
                        "output": "already",
                        "cache": "fresh-cache",
                        "native": "fresh-native",
                    },
                )
            with self.assertRaisesRegex(RunChainBudgetError, "must not contain"):
                build_run_chain_budget(
                    repo_root=root,
                    chain_id="nested-namespace",
                    cap=2,
                    predecessor_attempt_paths=[],
                    fresh_namespaces={
                        "output": "new",
                        "cache": "new/cache",
                        "native": "native",
                    },
                )

    def test_immutable_manifest_rejects_unequal_replay(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            path = root / "manifest.json"
            materialize_run_chain_budget(
                path,
                repo_root=root,
                chain_id="first-chain",
                cap=2,
                predecessor_attempt_paths=[],
                fresh_namespaces=_fresh_namespaces("first"),
            )
            with self.assertRaisesRegex(
                RunChainBudgetError, "immutable artifact collision"
            ):
                materialize_run_chain_budget(
                    path,
                    repo_root=root,
                    chain_id="second-chain",
                    cap=3,
                    predecessor_attempt_paths=[],
                    fresh_namespaces=_fresh_namespaces("second"),
                )

    def test_manifest_rejects_corrupt_cap_counters_index_hash_and_replay(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            relative = _write_attempt(
                root,
                "attempts/one.json",
                _attempt(
                    status="failed",
                    failure_class="transport_failure",
                    raw_response=None,
                    error="down",
                ),
            )
            path = root / "manifest.json"
            materialize_run_chain_budget(
                path,
                repo_root=root,
                chain_id="corruption-chain",
                cap=4,
                predecessor_attempt_paths=[relative],
                fresh_namespaces=_fresh_namespaces("corruption"),
            )
            original = json.loads(path.read_text(encoding="utf-8"))

            def corrupt_cap(value: dict[str, object]) -> None:
                value["cap"] = 5

            def corrupt_counters(value: dict[str, object]) -> None:
                value["counters"]["client_attempts"] = 0  # type: ignore[index]

            def corrupt_index(value: dict[str, object]) -> None:
                value["predecessor_attempts"][0]["attempt_key"] = (  # type: ignore[index]
                    f"{'f' * 64}:9"
                )

            def corrupt_hash(value: dict[str, object]) -> None:
                value["predecessor_attempts"][0]["sha256"] = "0" * 64  # type: ignore[index]

            def replay_row(value: dict[str, object]) -> None:
                value["predecessor_attempts"].append(  # type: ignore[union-attr]
                    copy.deepcopy(value["predecessor_attempts"][0])  # type: ignore[index]
                )

            def omit_row(value: dict[str, object]) -> None:
                value["predecessor_attempts"] = []

            for label, mutate in (
                ("cap", corrupt_cap),
                ("counters", corrupt_counters),
                ("index", corrupt_index),
                ("hash", corrupt_hash),
                ("omission", omit_row),
                ("replay", replay_row),
            ):
                with self.subTest(label=label):
                    candidate = copy.deepcopy(original)
                    mutate(candidate)
                    path.write_bytes(_canonical_json_bytes(candidate))
                    with self.assertRaises(RunChainBudgetError):
                        validate_run_chain_budget(repo_root=root, manifest_path=path)

    def test_atomic_namespace_race_has_exactly_one_winner(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            budget = build_run_chain_budget(
                repo_root=root,
                chain_id="namespace-race-chain",
                cap=4,
                predecessor_attempt_paths=[],
                fresh_namespaces=_fresh_namespaces("race-target"),
            )

            def claim() -> bool:
                try:
                    claim_fresh_namespaces(repo_root=root, budget=budget)
                    return True
                except RunChainBudgetError:
                    return False

            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(lambda _: claim(), range(2)))
            self.assertEqual(outcomes.count(True), 1)
            self.assertEqual(outcomes.count(False), 1)
            for relative in budget.fresh_namespaces.values():
                marker = root / relative / ".namespace-claim.json"
                self.assertTrue(marker.is_file())
                claim_record = json.loads(marker.read_text(encoding="utf-8"))
                self.assertIs(claim_record["execution_authorized"], False)


class ExecutorOrderingTests(unittest.TestCase):
    def _failure_fixture(
        self, root: Path, *, delivered_bytes: bool = False
    ) -> tuple[_Cache, _Turn]:
        attempt = _attempt(
            status="failed",
            failure_class=("parse_failure" if delivered_bytes else "transport_failure"),
            raw_response=("not-json" if delivered_bytes else None),
            error="exact failure",
        )
        run_dir = root / "cache"
        attempt_path = run_dir / "attempts" / REQUEST_KEY / "1.json"
        attempt_path.parent.mkdir(parents=True)
        attempt_path.write_bytes(_canonical_json_bytes(attempt))
        return (
            _Cache(run_dir, attempt),
            _failed_turn(
                "parse_failure" if delivered_bytes else "transport_failure"
            ),
        )

    def test_failed_turn_is_recorded_before_terminal_text_loader(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            cache, turn = self._failure_fixture(root)
            loader_calls = 0

            def forbidden_loader() -> str:
                nonlocal loader_calls
                loader_calls += 1
                raise AssertionError("terminal text must not be requested")

            failure_path = root / "failures/failure.json"
            with self.assertRaises(ImmutablePlannerFailure) as raised:
                resolve_planner_turn(
                    repo_root=root,
                    cache=cache,
                    turn=turn,
                    source_task_id=SOURCE_TASK_ID,
                    cell_id="adversarial-vulnerable",
                    run_chain_manifest_sha256="c" * 64,
                    failure_record_path=failure_path,
                    checker_binding_ids=("utility",),
                    checker_capabilities=(),
                    terminal_text_mode=RAW_RESPONSE_ENVELOPE_MODE,
                    terminal_text_loader=forbidden_loader,
                )
            self.assertEqual(loader_calls, 0)
            record = json.loads(failure_path.read_text(encoding="utf-8"))
            self.assertIs(record["terminal_text_extraction_attempted"], False)
            self.assertEqual(record["native_checker_invocation_count"], 0)
            self.assertEqual(record["native_dispatch_observed"], False)
            self.assertEqual(
                raised.exception.record_sha256, _sha256_bytes(failure_path.read_bytes())
            )

    def test_delivered_parse_failure_bytes_are_not_terminal_text(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            cache, turn = self._failure_fixture(root, delivered_bytes=True)
            calls: list[str] = []
            failure_path = root / "failures/parse.json"
            with self.assertRaises(ImmutablePlannerFailure):
                resolve_planner_turn(
                    repo_root=root,
                    cache=cache,
                    turn=turn,
                    source_task_id=SOURCE_TASK_ID,
                    cell_id="benign-vulnerable",
                    run_chain_manifest_sha256="c" * 64,
                    failure_record_path=failure_path,
                    checker_binding_ids=("utility",),
                    checker_capabilities=(),
                    terminal_text_mode=RAW_RESPONSE_ENVELOPE_MODE,
                    terminal_text_loader=lambda: calls.append("called") or "not-json",
                )
            self.assertEqual(calls, [])
            record = json.loads(failure_path.read_text(encoding="utf-8"))
            self.assertIs(record["delivered_failure_bytes_present"], True)

    def test_failure_record_is_immutable(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            cache, turn = self._failure_fixture(root)
            path = root / "failure.json"
            arguments = dict(
                repo_root=root,
                cache=cache,
                turn=turn,
                source_task_id=SOURCE_TASK_ID,
                cell_id="adversarial-protected",
                run_chain_manifest_sha256="c" * 64,
                failure_record_path=path,
                checker_binding_ids=("utility",),
                checker_capabilities=(),
                terminal_text_mode=RAW_RESPONSE_ENVELOPE_MODE,
                terminal_text_loader=lambda: "forbidden",
            )
            with self.assertRaises(ImmutablePlannerFailure):
                resolve_planner_turn(**arguments)
            before = path.read_bytes()
            # Exact replay is idempotent, not a rewrite.
            with self.assertRaises(ImmutablePlannerFailure):
                resolve_planner_turn(**arguments)
            self.assertEqual(path.read_bytes(), before)
            with self.assertRaisesRegex(
                ExecutorContractError, "immutable artifact collision"
            ):
                resolve_planner_turn(
                    **{**arguments, "cell_id": "benign-protected"}
                )

    def test_missing_or_malformed_ledger_still_yields_failure_artifact(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            calls: list[str] = []
            missing_turn = _Turn(
                **{
                    **_failed_turn().__dict__,
                    "attempt_keys": (),
                }
            )
            cases = (
                ("missing", _Cache(root / "missing-cache", {}), missing_turn),
                (
                    "malformed",
                    _Cache(root / "malformed-cache", {"attempt_key": ATTEMPT_KEY}),
                    _failed_turn(),
                ),
            )
            malformed_path = (
                root / "malformed-cache" / "attempts" / REQUEST_KEY / "1.json"
            )
            malformed_path.parent.mkdir(parents=True)
            malformed_path.write_text("{}", encoding="utf-8")
            for label, cache, turn in cases:
                with self.subTest(label=label):
                    record_path = root / f"failure-{label}.json"
                    with self.assertRaises(ImmutablePlannerFailure):
                        resolve_planner_turn(
                            repo_root=root,
                            cache=cache,
                            turn=turn,
                            source_task_id=SOURCE_TASK_ID,
                            cell_id="adversarial-protected",
                            run_chain_manifest_sha256="c" * 64,
                            failure_record_path=record_path,
                            checker_binding_ids=("state_checker",),
                            checker_capabilities=(),
                            terminal_text_mode=RAW_RESPONSE_ENVELOPE_MODE,
                            terminal_text_loader=(
                                lambda: calls.append("called") or "forbidden"
                            ),
                        )
                    record = json.loads(record_path.read_text(encoding="utf-8"))
                    self.assertIn(record["ledger_status"], {"missing", "malformed"})
                    self.assertIs(record["terminal_text_extraction_attempted"], False)
            self.assertEqual(calls, [])


class CheckerCapabilityTests(unittest.TestCase):
    def test_text_sensitive_checker_without_proof_stops_before_loader(self) -> None:
        calls: list[str] = []
        capability = CheckerTextCapability(
            source_task_id=SOURCE_TASK_ID,
            checker_binding_id="output_checker",
            reads_terminal_text=True,
            raw_response_envelope_compatible=False,
        )
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            with self.assertRaisesRegex(ExecutorContractError, "lacks raw-response"):
                resolve_planner_turn(
                    repo_root=Path(temporary),
                    cache=_Cache(Path(temporary) / "unused", {}),
                    turn=_delivered_turn(),
                    source_task_id=SOURCE_TASK_ID,
                    cell_id="benign-vulnerable",
                    run_chain_manifest_sha256="c" * 64,
                    failure_record_path=Path(temporary) / "unused.json",
                    checker_binding_ids=("output_checker",),
                    checker_capabilities=(capability,),
                    terminal_text_mode=CONFIRMED_ASSISTANT_TEXT_MODE,
                    terminal_text_loader=lambda: calls.append("called") or "text",
                )
        self.assertEqual(calls, [])

    def test_proven_text_checker_requires_live_hash_bound_evidence(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            evidence = root / "evidence/text-parity.json"
            evidence.parent.mkdir(parents=True)
            evidence.write_text("{}", encoding="utf-8")
            capability = CheckerTextCapability(
                source_task_id=SOURCE_TASK_ID,
                checker_binding_id="output_checker",
                reads_terminal_text=True,
                raw_response_envelope_compatible=True,
                compatibility_contract=TEXT_CAPABILITY_CONTRACT,
                evidence_path="evidence/text-parity.json",
                evidence_sha256=_sha256_bytes(evidence.read_bytes()),
            )
            resolved = resolve_planner_turn(
                repo_root=root,
                cache=_Cache(root / "unused", {}),
                turn=_delivered_turn(),
                source_task_id=SOURCE_TASK_ID,
                cell_id="benign-protected",
                run_chain_manifest_sha256="c" * 64,
                failure_record_path=root / "unused.json",
                checker_binding_ids=("output_checker",),
                checker_capabilities=(capability,),
                terminal_text_mode=CONFIRMED_ASSISTANT_TEXT_MODE,
                terminal_text_loader=lambda: "ledger raw response envelope",
            )
            self.assertEqual(resolved.terminal_text, "ledger raw response envelope")
            evidence.write_text('{"mutated":true}', encoding="utf-8")
            calls: list[str] = []
            with self.assertRaisesRegex(ExecutorContractError, "SHA mismatch"):
                resolve_planner_turn(
                    repo_root=root,
                    cache=_Cache(root / "unused", {}),
                    turn=_delivered_turn(),
                    source_task_id=SOURCE_TASK_ID,
                    cell_id="benign-protected",
                    run_chain_manifest_sha256="c" * 64,
                    failure_record_path=root / "unused.json",
                    checker_binding_ids=("output_checker",),
                    checker_capabilities=(capability,),
                    terminal_text_mode=CONFIRMED_ASSISTANT_TEXT_MODE,
                    terminal_text_loader=lambda: calls.append("called") or "text",
                )
            self.assertEqual(calls, [])

    def test_state_only_checker_allows_ledger_text_without_fake_proof(self) -> None:
        capability = CheckerTextCapability(
            source_task_id=SOURCE_TASK_ID,
            checker_binding_id="state_checker",
            reads_terminal_text=False,
            raw_response_envelope_compatible=False,
        )
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            resolved = resolve_planner_turn(
                repo_root=Path(temporary),
                cache=_Cache(Path(temporary) / "unused", {}),
                turn=_delivered_turn(),
                source_task_id=SOURCE_TASK_ID,
                cell_id="adversarial-vulnerable",
                run_chain_manifest_sha256="c" * 64,
                failure_record_path=Path(temporary) / "unused.json",
                checker_binding_ids=("state_checker",),
                checker_capabilities=(capability,),
                terminal_text_mode=RAW_RESPONSE_ENVELOPE_MODE,
                terminal_text_loader=lambda: "ledger text",
            )
        self.assertEqual(resolved.terminal_text, "ledger text")

    def test_text_sensitive_checker_rejects_envelope_or_undeclared_mode(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            root = Path(temporary)
            evidence = root / "text-equivalence.json"
            evidence.write_text("{}", encoding="utf-8")
            text_capability = CheckerTextCapability(
                source_task_id=SOURCE_TASK_ID,
                checker_binding_id="output_checker",
                reads_terminal_text=True,
                raw_response_envelope_compatible=True,
                compatibility_contract=TEXT_CAPABILITY_CONTRACT,
                evidence_path="text-equivalence.json",
                evidence_sha256=_sha256_bytes(evidence.read_bytes()),
            )
            state_capability = CheckerTextCapability(
                source_task_id=SOURCE_TASK_ID,
                checker_binding_id="state_checker",
                reads_terminal_text=False,
                raw_response_envelope_compatible=False,
            )
            calls: list[str] = []
            with self.assertRaisesRegex(
                ExecutorContractError, "requires confirmed_assistant_text"
            ):
                resolve_planner_turn(
                    repo_root=root,
                    cache=_Cache(root / "unused", {}),
                    turn=_delivered_turn(),
                    source_task_id=SOURCE_TASK_ID,
                    cell_id="adversarial-vulnerable",
                    run_chain_manifest_sha256="c" * 64,
                    failure_record_path=root / "unused.json",
                    checker_binding_ids=("output_checker",),
                    checker_capabilities=(text_capability,),
                    terminal_text_mode=RAW_RESPONSE_ENVELOPE_MODE,
                    terminal_text_loader=lambda: calls.append("called") or "{}",
                )
            with self.assertRaisesRegex(
                ExecutorContractError, "missing or undeclared"
            ):
                resolve_planner_turn(
                    repo_root=root,
                    cache=_Cache(root / "unused", {}),
                    turn=_delivered_turn(),
                    source_task_id=SOURCE_TASK_ID,
                    cell_id="adversarial-vulnerable",
                    run_chain_manifest_sha256="c" * 64,
                    failure_record_path=root / "unused.json",
                    checker_binding_ids=("state_checker",),
                    checker_capabilities=(state_capability,),
                    terminal_text_mode="json",
                    terminal_text_loader=lambda: calls.append("called") or "{}",
                )
            self.assertEqual(calls, [])


class BudgetGuardTests(unittest.TestCase):
    def test_guard_charges_before_outcome_and_preserves_separate_counts(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            budget = build_run_chain_budget(
                repo_root=Path(temporary),
                chain_id="guard-chain",
                cap=2,
                predecessor_attempt_paths=[],
                fresh_namespaces=_fresh_namespaces("guard"),
            )
            guard = RunChainBudgetGuard(budget)
            first = guard.reserve_client_attempt()
            self.assertEqual(guard.snapshot().consumed, 1)
            guard.classify_reserved_attempt(
                first,
                provider_accepted=False,
                delivered_model_response=False,
            )
            second = guard.reserve_client_attempt()
            guard.classify_reserved_attempt(
                second,
                provider_accepted=True,
                delivered_model_response=True,
                input_tokens=11,
                output_tokens=2,
            )
            snapshot = guard.snapshot()
            self.assertEqual(snapshot.consumed, 2)
            self.assertEqual(snapshot.remaining, 0)
            self.assertEqual(snapshot.counters.provider_accepted_requests, 1)
            self.assertEqual(snapshot.counters.delivered_model_responses, 1)
            self.assertEqual(snapshot.counters.token_bearing_calls, 1)
            with self.assertRaisesRegex(ExecutorContractError, "cap exhausted"):
                guard.reserve_client_attempt()

    def test_guard_rejects_tokens_without_delivery(self) -> None:
        with tempfile.TemporaryDirectory(dir=REPO_ROOT) as temporary:
            budget = build_run_chain_budget(
                repo_root=Path(temporary),
                chain_id="guard-mutation",
                cap=2,
                predecessor_attempt_paths=[],
                fresh_namespaces=_fresh_namespaces("guard-mutation"),
            )
            guard = RunChainBudgetGuard(budget)
            ordinal = guard.reserve_client_attempt()
            with self.assertRaisesRegex(ExecutorContractError, "token-bearing"):
                guard.classify_reserved_attempt(
                    ordinal,
                    provider_accepted=True,
                    delivered_model_response=False,
                    input_tokens=1,
                )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
