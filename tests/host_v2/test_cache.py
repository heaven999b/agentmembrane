from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import threading
import unittest

from agentmembrane.host_v2.cache import (
    CacheIdentity,
    RunCache,
    RunLock,
    RunStateStore,
    attempt_key,
    episode_id,
)
from agentmembrane.host_v2.schema import IntegrityError, RunState


def _identity(*, implementation: str = "1", model: str = "gpt-test") -> CacheIdentity:
    return CacheIdentity(
        implementation_sha256=implementation * 64,
        protocol_sha256="2" * 64,
        resolved_model_id=model,
        provider_route_id="local-cli-proxy",
    )


def _request() -> dict:
    return {
        "requested_model_id": "requested-test",
        "settings": {"temperature": 0, "max_completion_tokens": 1400},
        "prompt": "exact prompt bytes as UTF-8 text",
        "turn_number": 1,
        "prior_feedback_sha256": "3" * 64,
        "retry_policy": {"request_level_transport_retries": 2},
    }


def _attempt(
    cache: RunCache,
    request: dict,
    index: int,
    failure_class: str,
    *,
    raw_response: str | None = None,
) -> tuple[str, dict]:
    request_key = cache.request_key(request)
    key = attempt_key(request_key, index)
    has_delivered_bytes = raw_response is not None
    return key, {
        "schema_version": 2,
        "request_key": request_key,
        "attempt_key": key,
        "attempt_index": index,
        "episode_id": "4" * 64,
        "turn_number": request["turn_number"],
        "implementation_sha256": cache.identity.implementation_sha256,
        "protocol_sha256": cache.identity.protocol_sha256,
        "requested_model_id": "requested-test",
        "resolved_model_id": cache.identity.resolved_model_id,
        "provider_route_id": cache.identity.provider_route_id,
        "request": request,
        "raw_response": raw_response,
        "parsed_response": {},
        "actions": [],
        "final_artifact": None,
        "planner_status": "failed" if failure_class != "none" else "ok",
        "failure_class": failure_class,
        "error": None if has_delivered_bytes else "provider transport unavailable",
        "error_metadata": {} if has_delivered_bytes else {"type": "TransportError"},
        "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0, "latency_ms": 0},
        "started_at": "2026-08-28T00:00:00Z",
        "finished_at": "2026-08-28T00:00:01Z",
    }


def _episode(identifier: str, *, attempt_keys: list[str] | None = None) -> dict:
    return {
        "schema_version": 2,
        "episode_id": identifier,
        "attempt_keys": list(attempt_keys or []),
        "actions_requested": [],
        "action_log": [],
        "event_log": [],
        "oracle_result": {"evidence": []},
    }


class CacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.temporary.name) / "run"
        self.cache = RunCache(self.run_dir, _identity())

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_request_key_binds_identity_model_settings_prompt_and_feedback(self) -> None:
        base = _request()
        base_key = self.cache.request_key(base)
        variants = []
        for field, value in (
            ("prompt", "changed"),
            ("turn_number", 3),
            ("prior_feedback_sha256", "5" * 64),
        ):
            changed = dict(base)
            changed[field] = value
            variants.append(changed)
        settings_changed = dict(base)
        settings_changed["settings"] = {"temperature": 0, "max_completion_tokens": 999}
        variants.append(settings_changed)
        self.assertTrue(all(self.cache.request_key(value) != base_key for value in variants))
        other_implementation = RunCache(self.run_dir / "other-a", _identity(implementation="6"))
        other_model = RunCache(self.run_dir / "other-b", _identity(model="other-model"))
        self.assertNotEqual(other_implementation.request_key(base), base_key)
        self.assertNotEqual(other_model.request_key(base), base_key)

    def test_attempts_are_immutable_and_transport_is_the_only_retry(self) -> None:
        request = _request()
        first_key, first = _attempt(self.cache, request, 1, "transport_failure")
        self.cache.store_attempt(first_key, first)
        self.assertEqual(self.cache.next_attempt_index(
            self.cache.request_key(request), request_level_transport_retries=2
        ), 2)
        second_key, second = _attempt(self.cache, request, 2, "parse_failure", raw_response="bad")
        self.cache.store_attempt(second_key, second)
        self.assertIsNone(self.cache.next_attempt_index(
            self.cache.request_key(request), request_level_transport_retries=2
        ))
        third_key, third = _attempt(self.cache, request, 3, "transport_failure")
        with self.assertRaises(IntegrityError):
            self.cache.store_attempt(third_key, third)
        changed = dict(second)
        changed["raw_response"] = "replacement"
        with self.assertRaises(IntegrityError):
            self.cache.store_attempt(second_key, changed)
        self.assertEqual(self.cache.load_attempt(second_key)["raw_response"], "bad")

    def test_retry_budget_is_frozen_and_does_not_redraw_success(self) -> None:
        request = _request()
        key, value = _attempt(self.cache, request, 1, "none", raw_response="{}")
        self.cache.store_attempt(key, value)
        with self.assertRaises(IntegrityError):
            self.cache.next_attempt_index(
                self.cache.request_key(request), request_level_transport_retries=99
            )
        self.assertIsNone(
            self.cache.next_attempt_index(
                self.cache.request_key(request), request_level_transport_retries=2
            )
        )

    def test_concurrent_attempt_publication_is_atomic(self) -> None:
        request = _request()
        key, base = _attempt(self.cache, request, 1, "parse_failure")

        def publish(index: int) -> str:
            value = dict(base)
            value["raw_response"] = f"candidate-{index}"
            try:
                self.cache.store_attempt(key, value)
                return "published"
            except IntegrityError:
                return "collision"

        with ThreadPoolExecutor(max_workers=16) as executor:
            results = list(executor.map(publish, range(32)))
        self.assertGreaterEqual(results.count("published"), 1)
        stored = self.cache.load_attempt(key)
        self.assertIn(stored["raw_response"], {f"candidate-{index}" for index in range(32)})
        self.cache.store_episode("4" * 64, _episode("4" * 64, attempt_keys=[key]))
        self.assertTrue(self.cache.verify()["valid"])

    def test_episode_and_manifest_are_create_once(self) -> None:
        row = {"ordinal": 1, "task_id": "task", "condition_id": "condition"}
        identifier = episode_id(row, protocol_sha256=self.cache.identity.protocol_sha256)
        value = _episode(identifier)
        self.cache.store_episode(identifier, value)
        self.cache.store_episode(identifier, value)  # exact idempotent replay is harmless
        with self.assertRaises(IntegrityError):
            self.cache.store_episode(identifier, {**value, "attempt_keys": ["changed"]})
        self.assertEqual(self.cache.completed_episode_ids(), frozenset({identifier}))

        manifest = {"schema_version": 2, "run_id": "run-a"}
        self.cache.store_run_manifest(manifest)
        self.cache.store_run_manifest(manifest)
        with self.assertRaises(IntegrityError):
            self.cache.store_run_manifest({"schema_version": 2, "run_id": "run-b"})

    def test_run_lock_and_state_machine(self) -> None:
        scheduled_ids = ["8" * 64, "9" * 64]
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "schedule.json").write_text(
            json.dumps([{"episode_id": value} for value in scheduled_ids]), encoding="utf-8"
        )
        episodes = self.run_dir / "episodes"
        episodes.mkdir(exist_ok=True)
        for value in scheduled_ids:
            (episodes / f"{value}.json").write_text(
                json.dumps({"episode_id": value}), encoding="utf-8"
            )
        state = RunStateStore(self.run_dir)
        state.initialize(run_id="run-a", expected_episodes=2)
        with RunLock(self.run_dir) as lock:
            with self.assertRaises(IntegrityError):
                RunLock(self.run_dir).acquire()
            running = state.transition(
                RunState.RUNNING, lock=lock, active_execution_session_id="session-a"
            )
            self.assertEqual(running["revision"], 1)
            with self.assertRaises(IntegrityError):
                state.transition(RunState.COMPLETE, lock=lock, completed_episodes=1)
            completed = state.transition(
                RunState.COMPLETE, lock=lock, completed_episodes=2, last_completed_ordinal=2
            )
            self.assertEqual(completed["state"], RunState.COMPLETE.value)
            audited = state.transition(RunState.AUDITED_VALID, lock=lock)
            self.assertEqual(audited["revision"], 3)
        with self.assertRaises(IntegrityError):
            state.transition(RunState.AUDITED_INVALID, lock=RunLock(self.run_dir))

    def test_retry_budget_cannot_be_bypassed_by_direct_store(self) -> None:
        request = _request()
        request["retry_policy"] = {"request_level_transport_retries": 1}
        first_key, first = _attempt(self.cache, request, 1, "transport_failure")
        self.cache.store_attempt(first_key, first)
        second_key, second = _attempt(self.cache, request, 2, "transport_failure")
        self.cache.store_attempt(second_key, second)
        third_key, third = _attempt(self.cache, request, 3, "transport_failure")
        with self.assertRaises(IntegrityError):
            self.cache.store_attempt(third_key, third)

    def test_reservation_allows_only_one_concurrent_provider_attempt(self) -> None:
        request = _request()
        request_key = self.cache.request_key(request)
        barrier = threading.Barrier(16)

        def reserve_and_publish(_: int) -> int | None:
            barrier.wait()
            try:
                index = self.cache.next_attempt_index(
                    request_key, request_level_transport_retries=2
                )
            except IntegrityError:
                return None
            if index is None:
                return None
            key, value = _attempt(
                self.cache, request, index, "parse_failure", raw_response="invalid-json"
            )
            self.cache.store_attempt(key, value)
            return index

        with ThreadPoolExecutor(max_workers=16) as executor:
            results = list(executor.map(reserve_and_publish, range(16)))
        self.assertEqual([value for value in results if value is not None], [1])
        self.assertEqual(self.cache._attempt_indices(request_key), [1])

    def test_unresolved_durable_reservation_fails_closed_without_redraw(self) -> None:
        request = _request()
        request_key = self.cache.request_key(request)
        directory = self.cache.attempts_dir / request_key
        directory.mkdir(parents=True)
        (directory / ".reservation").write_text(
            json.dumps(
                {
                    "schema_version": 2,
                    "request_key": request_key,
                    "attempt_index": 1,
                    "cache_identity": self.cache.identity.to_dict(),
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(IntegrityError, "unresolved durable"):
            self.cache.next_attempt_index(
                request_key, request_level_transport_retries=2
            )
        report = self.cache.verify()
        self.assertFalse(report["valid"])
        self.assertTrue(any("durable attempt reservation" in error for error in report["errors"]))

    def test_numeric_attempt_order_and_complete_episode_reference(self) -> None:
        request = _request()
        request["retry_policy"] = {"request_level_transport_retries": 10}
        keys: list[str] = []
        for index in range(1, 12):
            key, value = _attempt(self.cache, request, index, "transport_failure")
            self.cache.store_attempt(key, value)
            keys.append(key)
        self.cache.store_episode("4" * 64, _episode("4" * 64, attempt_keys=keys))
        report = self.cache.verify()
        self.assertTrue(report["valid"], report["errors"])
        self.assertEqual(report["attempt_count"], 11)
        reversed_episode = _episode("4" * 64, attempt_keys=list(reversed(keys)))
        with self.assertRaises(IntegrityError):
            self.cache.store_episode("4" * 64, reversed_episode)

    def test_episode_rejects_missing_evidence_action_and_reverse_refs(self) -> None:
        base = _episode("6" * 64)
        base.update(
            {
                "actions_requested": [{"op": "write"}],
                "action_log": [
                    {
                        "turn_number": 1,
                        "action_index": 1,
                        "request": {"op": "write"},
                        "events": [{"event_id": "event-2", "parent_event_ids": ["event-1"]}],
                    }
                ],
                "event_log": [
                    {"event_id": "event-1"},
                    {"event_id": "event-2", "parent_event_ids": ["event-1"]},
                ],
                "oracle_result": {"evidence": [{"event_id": "event-2"}]},
            }
        )
        self.cache.store_episode("6" * 64, base)
        bad_evidence = {**base, "episode_id": "7" * 64, "oracle_result": {"evidence": [{"event_id": "missing"}]}}
        with self.assertRaises(IntegrityError):
            self.cache.store_episode("7" * 64, bad_evidence)
        bad_reverse = {
            **base,
            "episode_id": "a" * 64,
            "event_log": list(reversed(base["event_log"])),
        }
        with self.assertRaises(IntegrityError):
            self.cache.store_episode("a" * 64, bad_reverse)

    def test_model_fallback_requires_a_separate_run_directory(self) -> None:
        with self.assertRaises(IntegrityError):
            RunCache(self.run_dir, _identity(model="fallback-model"))

    def test_complete_rejects_count_only_or_unexpected_episode(self) -> None:
        identifier = "b" * 64
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "schedule.json").write_text(
            json.dumps([{"episode_id": identifier}]), encoding="utf-8"
        )
        state = RunStateStore(self.run_dir)
        state.initialize(run_id="run-b", expected_episodes=1)
        with RunLock(self.run_dir) as lock:
            state.transition(
                RunState.RUNNING, lock=lock, active_execution_session_id="session-b"
            )
            with self.assertRaises(IntegrityError):
                state.transition(
                    RunState.COMPLETE,
                    lock=lock,
                    completed_episodes=1,
                    last_completed_ordinal=1,
                )
            (self.run_dir / "episodes" / f"{identifier}.json").write_text(
                json.dumps({"episode_id": identifier}), encoding="utf-8"
            )
            unexpected = "c" * 64
            (self.run_dir / "episodes" / f"{unexpected}.json").write_text(
                json.dumps({"episode_id": unexpected}), encoding="utf-8"
            )
            with self.assertRaises(IntegrityError):
                state.transition(
                    RunState.COMPLETE,
                    lock=lock,
                    completed_episodes=1,
                    last_completed_ordinal=1,
                )

    def test_state_load_rejects_unknown_fields_and_boolean_counters(self) -> None:
        state = RunStateStore(self.run_dir)
        state.initialize(run_id="run-strict", expected_episodes=1)
        value = json.loads(state.path.read_text(encoding="utf-8"))
        value["unknown"] = True
        state.path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(IntegrityError):
            state.load()
        value.pop("unknown")
        value["completed_episodes"] = True
        state.path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(IntegrityError):
            state.load()

    def test_delivered_attempt_requires_exact_resolved_model(self) -> None:
        request = _request()
        key, value = _attempt(
            self.cache, request, 1, "parse_failure", raw_response="invalid-json"
        )
        value["resolved_model_id"] = None
        with self.assertRaises(IntegrityError):
            self.cache.store_attempt(key, value)


if __name__ == "__main__":
    unittest.main()
