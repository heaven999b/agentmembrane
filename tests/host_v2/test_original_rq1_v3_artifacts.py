from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from agentmembrane.host_v2 import original_rq1_v3_artifacts as artifacts
from agentmembrane.host_v2.original_rq1_v3_artifacts import (
    EP_TEST_IDS,
    REQUIRED_FREEZE_ROLES,
    RQ1V3ArtifactLedger,
    adaptive_request_sha256,
    build_freeze_lock,
    file_sha256,
    json_sha256,
    publish_immutable_json,
    provider_idempotency_key,
    validate_gates,
    validate_integrity,
)
from agentmembrane.host_v2.original_rq1_v3_banks import adaptive_block_id
from agentmembrane.host_v2.schema import IntegrityError


ZERO = "0" * 64
ONE = "1" * 64
TWO = "2" * 64
THREE = "3" * 64


class RunFixture:
    def __init__(self, root: Path, *, track: str = "adaptive_end_to_end") -> None:
        self.root = root
        self.track = track
        self.run_id = f"unit-{track}"
        self.profile = {
            "profile_id": "offline-null" if track.startswith("fixed") else "offline-adaptive",
            "requested_model_id": "none" if track.startswith("fixed") else "test-model",
            "provider_route_id": "none" if track.startswith("fixed") else "test-route",
            "allowed_resolved_model_ids": (
                ["none"] if track.startswith("fixed") else ["test-model"]
            ),
        }
        self.cache_identity = {
            "implementation_sha256": ONE,
            "protocol_sha256": TWO,
            "resolved_model_id": self.profile["requested_model_id"],
            "provider_route_id": self.profile["provider_route_id"],
        }
        if track == "adaptive_end_to_end":
            self.replicates = ["r1", "r2", "r3"]
            self.schedule = self._adaptive_schedule()
        else:
            self.replicates = []
            self.schedule = [
                {
                    "track": track,
                    "bank_id": "development-fixed-trace",
                    "trace_id": "trace-1",
                    "episode_id": json_sha256({"track": track, "trace_id": "trace-1"}),
                }
            ]

        publish_immutable_json(root / "schedule.json", self.schedule)
        publish_immutable_json(root / "resolved-profile.json", self.profile)
        publish_immutable_json(root / "cache-identity.json", self.cache_identity)
        locked = root / "locked"
        locked.mkdir(parents=True)
        entries: list[dict[str, str]] = []
        for role in sorted(REQUIRED_FREEZE_ROLES - {"schedule", "model_profile"}):
            path = locked / f"{role}.json"
            value = (
                {"request_level_transport_retries": 1}
                if role == "retry_policy"
                else {"role": role, "fixture": True}
            )
            publish_immutable_json(path, value)
            entries.append(
                {
                    "role": role,
                    "path": path.relative_to(root).as_posix(),
                    "sha256": file_sha256(path),
                }
            )
        entries.extend(
            [
                {
                    "role": "schedule",
                    "path": "schedule.json",
                    "sha256": file_sha256(root / "schedule.json"),
                },
                {
                    "role": "model_profile",
                    "path": "resolved-profile.json",
                    "sha256": file_sha256(root / "resolved-profile.json"),
                },
            ]
        )
        proposal_hash = next(item["sha256"] for item in entries if item["role"] == "proposal")
        with mock.patch.object(artifacts, "PROPOSAL_SHA256", proposal_hash):
            self.freeze = build_freeze_lock(
                run_id=self.run_id,
                entries=entries,
                sealed_at="2026-09-06T00:00:00Z",
            )
            by_role = {item["role"]: item["sha256"] for item in entries}
            self.manifest = {
                "schema_version": 3,
                "run_id": self.run_id,
                "scientific_stage": "development",
                "track": track,
                "proposal_sha256": proposal_hash,
                "protocol_sha256": by_role["protocol"],
                "machine_spec_sha256": by_role["machine_spec"],
                "implementation_manifest_sha256": by_role["implementation_manifest"],
                "bank_id": "development",
                "bank_sha256": by_role["bank"],
                "formal_unsealed_at_manifest_creation": False,
                "schedule_sha256": file_sha256(root / "schedule.json"),
                "profile_sha256": file_sha256(root / "resolved-profile.json"),
                "statistics_contract_sha256": by_role["statistics_contract"],
                "retry_policy_sha256": by_role["retry_policy"],
                "freeze_lock_sha256": json_sha256(self.freeze),
                "cache_identity_sha256": file_sha256(root / "cache-identity.json"),
                "expected_episode_count": len(self.schedule),
                "expected_replication_ids": self.replicates,
                "created_at": "2026-09-06T00:00:01Z",
            }
            self.ledger = RQ1V3ArtifactLedger(root)
            self.ledger.initialize(
                manifest=self.manifest,
                freeze_lock=self.freeze,
                schedule=self.schedule,
                resolved_profile=self.profile,
                cache_identity=self.cache_identity,
            )

    def _adaptive_schedule(self) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        ordinal = 0
        for role in ("honest", "adversarial"):
            for level in artifacts.LEVELS:
                for arm in artifacts.ARMS:
                    for replicate_index, replicate in enumerate(("r1", "r2", "r3"), 1):
                        ordinal += 1
                        route_id = "route-1" if role == "adversarial" else None
                        hazard_id = "H-TOOL" if role == "adversarial" else None
                        task_contract_id = "task-1"
                        base = {
                            "track": "adaptive_end_to_end",
                            "bank_id": "development",
                            "lineage_group_id": "lineage-1",
                            "cluster_id": "cluster-1",
                            "authority_level": level,
                            "arm": arm,
                            "pair_role": role,
                            "replicate_id": replicate,
                            "schedule_seed": 7001,
                            "generation_seed": 7100 + replicate_index,
                            "task_contract_id": task_contract_id,
                            "hazard_id": hazard_id,
                            "route_id": route_id,
                            "weight": 1.0,
                            "block_id": adaptive_block_id(
                                lineage_group_id="lineage-1",
                                cluster_id="cluster-1",
                                task_contract_id=task_contract_id,
                                pair_role=role,
                                hazard_id=hazard_id,
                                route_id=route_id,
                            ),
                        }
                        rows.append({**base, "episode_id": json_sha256(base)})
        return rows

    def attempt_kwargs(
        self,
        row: dict[str, object],
        *,
        attempt_index: int = 1,
        turn_number: int = 1,
    ) -> dict[str, object]:
        payload = {
            "model": "test-model",
            "messages": [],
            "fixture": True,
            "turn_number": turn_number,
        }
        payload_path, payload_sha = self.ledger.publish_attempt_evidence(
            "model-visible-request", artifacts.canonical_json_bytes(payload)
        )
        schedule_binding = json_sha256(row)
        request_sha = adaptive_request_sha256(
            episode_id=row["episode_id"],
            turn_number=turn_number,
            replicate_id=row["replicate_id"],
            schedule_seed=row["schedule_seed"],
            generation_seed=row["generation_seed"],
            schedule_binding_sha256=schedule_binding,
            model_visible_payload_sha256=payload_sha,
            profile_sha256=self.manifest["profile_sha256"],
        )
        return {
            "episode_id": row["episode_id"],
            "turn_number": turn_number,
            "replicate_id": row["replicate_id"],
            "pair_role": row["pair_role"],
            "schedule_binding_sha256": schedule_binding,
            "schedule_seed": row["schedule_seed"],
            "generation_seed": row["generation_seed"],
            "request_sha256": request_sha,
            "model_visible_payload_sha256": payload_sha,
            "model_visible_payload_path": payload_path,
            "requested_model_id": "test-model",
            "provider_route_id": "test-route",
            "attempt_index": attempt_index,
        }

    def commit_terminal(
        self,
        row: dict[str, object],
        *,
        outcome_class: str = "valid_turn",
        turn_number: int = 1,
    ) -> list[str]:
        keys: list[str] = []
        attempt_count = 2 if outcome_class == "transport_failure" else 1
        for attempt_index in range(1, attempt_count + 1):
            key = self.ledger.reserve_attempt(
                **self.attempt_kwargs(
                    row,
                    attempt_index=attempt_index,
                    turn_number=turn_number,
                )
            )
            keys.append(key)
            if outcome_class == "transport_failure":
                path, digest = self.ledger.publish_attempt_evidence(
                    "non-delivery-proof",
                    f"pre-send failure {attempt_index}".encode("utf-8"),
                )
                self.ledger.commit_attempt(
                    key,
                    delivery_state="not_delivered",
                    outcome_class=outcome_class,
                    resolved_model_id=None,
                    non_delivery_proof_sha256=digest,
                    non_delivery_proof_path=path,
                )
            elif outcome_class == "delivery_unknown":
                path, digest = self.ledger.publish_attempt_evidence(
                    "delivery-ambiguity", b"ambiguous delivery"
                )
                self.ledger.commit_attempt(
                    key,
                    delivery_state="unknown",
                    outcome_class=outcome_class,
                    resolved_model_id=None,
                    error_evidence_sha256=digest,
                    error_evidence_path=path,
                )
            else:
                path, digest = self.ledger.publish_attempt_evidence(
                    "provider-response", b'{"fixture":true}'
                )
                resolved_model_id = (
                    "unexpected-model"
                    if outcome_class == "resolved_model_drift"
                    else "test-model"
                )
                self.ledger.commit_attempt(
                    key,
                    delivery_state="delivered",
                    outcome_class=outcome_class,
                    resolved_model_id=resolved_model_id,
                    raw_response_sha256=digest,
                    raw_response_path=path,
                )
        return keys

    def commit_all_valid_episodes(self) -> None:
        for row in self.schedule:
            keys = self.commit_terminal(row)
            self.ledger.commit_episode(self.empty_episode(row, attempt_keys=keys))

    def evidence(self, *, all_injections: bool = True) -> dict[str, object]:
        return {
            "gates": {
                gate: {requirement: True for requirement in requirements}
                for gate, requirements in artifacts.GATE_REQUIREMENTS.items()
            },
            "failure_injections": {
                test_id: all_injections for test_id in EP_TEST_IDS
            },
        }

    def empty_episode(self, row: dict[str, object], *, attempt_keys: list[str] | None = None):
        attempt_keys = attempt_keys or []
        return {
            "schema_version": 3,
            "episode_id": row["episode_id"],
            "schedule_binding_sha256": json_sha256(row),
            "track": self.track,
            "attempt_keys": attempt_keys,
            "target_model_call_count": len(attempt_keys),
            "user_simulator_call_count": 0,
            "terminal_reason": "fixed_trace_complete" if not attempt_keys else "provider_terminal",
            "trusted_event_ledger": [],
            "oracle_version": "oracle-v3",
            "oracle_evidence": [],
            "checker_version": "checker-v3",
            "checker_evidence": [],
            "exposure": False,
            "hazard_vector": {
                "H-MEM": False,
                "H-TOOL": False,
                "H-XAG": False,
                "H-CAP": False,
                "H-CTRL": False,
            },
            "union_outcome": False,
            "system_task_utility": 1,
            "nuisance_classification": {},
            "artifact_references": [],
        }


class OriginalRQ1V3ArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        proposal_hash = json_sha256({"role": "proposal", "fixture": True})
        proposal_patch = mock.patch.object(artifacts, "PROPOSAL_SHA256", proposal_hash)
        proposal_patch.start()
        self.addCleanup(proposal_patch.stop)

    def test_ep10_unresolved_reservation_becomes_delivery_unknown_without_resend(self) -> None:
        fixture = RunFixture(self.root)
        fixture.ledger.start("session-1")
        row = fixture.schedule[0]
        key = fixture.ledger.reserve_attempt(**fixture.attempt_kwargs(row))
        fixture.ledger.suspend("injected crash after reservation")
        plan = fixture.ledger.resume(session_id="session-2", crash_evidence_sha256=THREE)
        self.assertEqual(plan.recovered_delivery_unknown_attempts, (key,))
        self.assertEqual(plan.retryable_non_delivery_attempts, ())
        self.assertIn(row["episode_id"], plan.reconstruct_episode_ids)
        attempt = fixture.ledger.load_attempt(key)
        self.assertEqual(attempt["delivery_state"], "unknown")
        self.assertEqual(attempt["outcome_class"], "delivery_unknown")
        with self.assertRaisesRegex(IntegrityError, "already has an immutable terminal"):
            fixture.ledger.reserve_attempt(**fixture.attempt_kwargs(row))

    def test_ep11_terminal_before_episode_is_reconstructed_without_provider_call(self) -> None:
        fixture = RunFixture(self.root)
        fixture.ledger.start("session-1")
        row = fixture.schedule[0]
        key = fixture.ledger.reserve_attempt(**fixture.attempt_kwargs(row))
        response_path, response_sha = fixture.ledger.publish_attempt_evidence(
            "provider-response", b"valid response"
        )
        fixture.ledger.commit_attempt(
            key,
            delivery_state="delivered",
            outcome_class="valid_turn",
            resolved_model_id="test-model",
            raw_response_sha256=response_sha,
            raw_response_path=response_path,
        )
        fixture.ledger.suspend("injected crash after terminal")
        plan = fixture.ledger.resume(session_id="session-2", crash_evidence_sha256=ZERO)
        self.assertEqual(plan.recovered_delivery_unknown_attempts, ())
        self.assertEqual(plan.reconstruct_episode_ids[0], row["episode_id"])

    def test_resume_exposes_only_mechanically_proven_retry_continuation(self) -> None:
        fixture = RunFixture(self.root)
        fixture.ledger.start("session-1")
        row = fixture.schedule[0]
        first = fixture.ledger.reserve_attempt(**fixture.attempt_kwargs(row))
        proof_path, proof_sha = fixture.ledger.publish_attempt_evidence(
            "non-delivery-proof", b"socket closed before request write"
        )
        fixture.ledger.commit_attempt(
            first,
            delivery_state="not_delivered",
            outcome_class="transport_failure",
            resolved_model_id=None,
            non_delivery_proof_sha256=proof_sha,
            non_delivery_proof_path=proof_path,
        )
        first_idempotency = fixture.ledger.load_reservation(first)["idempotency_key"]
        fixture.ledger.suspend("retryable interruption")
        plan = fixture.ledger.resume(
            session_id="session-2", crash_evidence_sha256=ZERO
        )
        self.assertEqual(plan.retryable_non_delivery_attempts, (first,))
        self.assertEqual(plan.next_episode_id, row["episode_id"])
        second = fixture.ledger.reserve_attempt(
            **fixture.attempt_kwargs(row, attempt_index=2)
        )
        self.assertEqual(
            fixture.ledger.load_reservation(second)["idempotency_key"],
            first_idempotency,
        )

    def test_delivery_unknown_episode_must_remain_conservative_nuisance(self) -> None:
        fixture = RunFixture(self.root)
        fixture.ledger.start("session-1")
        row = next(row for row in fixture.schedule if row["pair_role"] == "adversarial")
        key = fixture.ledger.reserve_attempt(**fixture.attempt_kwargs(row))
        ambiguity_path, ambiguity_sha = fixture.ledger.publish_attempt_evidence(
            "delivery-ambiguity", b"timeout after send"
        )
        fixture.ledger.commit_attempt(
            key,
            delivery_state="unknown",
            outcome_class="delivery_unknown",
            resolved_model_id=None,
            error_evidence_sha256=ambiguity_sha,
            error_evidence_path=ambiguity_path,
        )
        episode = fixture.empty_episode(row, attempt_keys=[key])
        episode["system_task_utility"] = 0
        with self.assertRaisesRegex(IntegrityError, "retain nuisance status"):
            fixture.ledger.commit_episode(episode)
        episode["nuisance_classification"] = {
            "non_evaluable": True,
            "utility_noncompletion": True,
            "terminal_outcome_classes": ["delivery_unknown"],
            "infrastructure_failure": True,
            "delivery_unknown": True,
            "conservative_possible_hazard": True,
        }
        fixture.ledger.commit_episode(episode)

    def test_ep12_immutable_collision_blocks_manifest_reservation_and_episode_overwrite(self) -> None:
        fixture = RunFixture(self.root, track="fixed_trace_host_replay")
        with self.assertRaisesRegex(IntegrityError, "immutable collision"):
            publish_immutable_json(self.root / "manifest.json", {"different": True})
        fixture.ledger.start("fixed-session")
        row = fixture.schedule[0]
        episode = fixture.empty_episode(row)
        fixture.ledger.commit_episode(episode)
        changed = dict(episode)
        changed["system_task_utility"] = 0
        with self.assertRaisesRegex(IntegrityError, "immutable collision"):
            fixture.ledger.commit_episode(changed)
        with self.assertRaisesRegex(IntegrityError, "must not contain provider attempts"):
            fixture.ledger.reserve_attempt(
                episode_id=row["episode_id"],
                turn_number=1,
                replicate_id="r1",
                pair_role="honest",
                schedule_binding_sha256=json_sha256(row),
                schedule_seed=7001,
                generation_seed=None,
                request_sha256=ONE,
                model_visible_payload_sha256=TWO,
                model_visible_payload_path="not-used-for-fixed-track",
                requested_model_id="test-model",
                provider_route_id="test-route",
            )

    def test_ep17_locked_byte_drift_rejects_resume(self) -> None:
        fixture = RunFixture(self.root)
        fixture.ledger.start("session-1")
        fixture.ledger.suspend("injected interruption")
        path = self.root / "locked" / "host_runtime.json"
        path.write_text('{"tampered":true}', encoding="utf-8")
        with self.assertRaisesRegex(IntegrityError, "locked input drift"):
            fixture.ledger.resume(session_id="session-2", crash_evidence_sha256=THREE)

    def test_ep18_complete_requires_exact_schedule_and_self_fingerprints(self) -> None:
        fixture = RunFixture(self.root, track="fixed_trace_host_replay")
        fixture.ledger.start("session-1")
        with self.assertRaisesRegex(IntegrityError, "episode coverage differs"):
            fixture.ledger.complete()
        row = fixture.schedule[0]
        fixture.ledger.commit_episode(fixture.empty_episode(row))
        completed = fixture.ledger.complete()
        self.assertEqual(completed["state"], "COMPLETE")
        episode_path = self.root / "episodes" / f"{row['episode_id']}.json"
        value = json.loads(episode_path.read_text(encoding="utf-8"))
        value["terminal_reason"] = "tampered"
        episode_path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(IntegrityError, "fingerprint mismatch"):
            fixture.ledger.completed_episode_ids()

    def test_retry_requires_proven_non_delivery_and_frozen_budget(self) -> None:
        fixture = RunFixture(self.root)
        fixture.ledger.start("session-1")
        row = fixture.schedule[0]
        first = fixture.ledger.reserve_attempt(**fixture.attempt_kwargs(row))
        with self.assertRaisesRegex(IntegrityError, "non-delivery proof"):
            fixture.ledger.commit_attempt(
                first,
                delivery_state="not_delivered",
                outcome_class="transport_failure",
                resolved_model_id=None,
            )
        fixture.ledger.commit_attempt(
            first,
            delivery_state="not_delivered",
            outcome_class="transport_failure",
            resolved_model_id=None,
            non_delivery_proof_sha256=(
                proof := fixture.ledger.publish_attempt_evidence(
                    "non-delivery-proof", b"socket failed before write"
                )
            )[1],
            non_delivery_proof_path=proof[0],
        )
        second = fixture.ledger.reserve_attempt(
            **fixture.attempt_kwargs(row, attempt_index=2)
        )
        self.assertEqual(fixture.ledger.load_reservation(first)["idempotency_key"], fixture.ledger.load_reservation(second)["idempotency_key"])
        with self.assertRaisesRegex(IntegrityError, "retry budget"):
            fixture.ledger.reserve_attempt(
                **fixture.attempt_kwargs(row, attempt_index=3)
            )

    def test_adaptive_episode_with_zero_attempts_is_rejected(self) -> None:
        fixture = RunFixture(self.root)
        fixture.ledger.start("session-1")
        with self.assertRaisesRegex(IntegrityError, "at least one provider attempt"):
            fixture.ledger.commit_episode(fixture.empty_episode(fixture.schedule[0]))

    def test_every_failure_is_utility_noncompletion_and_conservative_safety_nuisance(
        self,
    ) -> None:
        outcomes = (
            "explicit_refusal",
            "content_filter",
            "parse_failure",
            "schema_failure",
            "provider_policy_failure",
            "transport_failure",
            "resolved_model_drift",
            "delivery_unknown",
        )
        for outcome_class in outcomes:
            with self.subTest(outcome_class=outcome_class):
                run_root = self.root / outcome_class
                fixture = RunFixture(run_root)
                fixture.ledger.start("session-1")
                row = next(
                    row
                    for row in fixture.schedule
                    if row["pair_role"] == "adversarial"
                )
                keys = fixture.commit_terminal(row, outcome_class=outcome_class)
                episode = fixture.empty_episode(row, attempt_keys=keys)
                episode["nuisance_classification"] = {
                    "non_evaluable": True,
                    "utility_noncompletion": True,
                    "terminal_outcome_classes": [outcome_class],
                    "infrastructure_failure": outcome_class != "explicit_refusal",
                    "delivery_unknown": outcome_class == "delivery_unknown",
                    "conservative_possible_hazard": True,
                }
                with self.assertRaisesRegex(IntegrityError, "utility non-completion"):
                    fixture.ledger.commit_episode(episode)
                episode["system_task_utility"] = 0
                episode["nuisance_classification"]["conservative_possible_hazard"] = False
                with self.assertRaisesRegex(IntegrityError, "possible hazard"):
                    fixture.ledger.commit_episode(episode)
                episode["nuisance_classification"]["conservative_possible_hazard"] = True
                fixture.ledger.commit_episode(episode)

    def test_reservation_context_and_idempotency_are_row_bound(self) -> None:
        fixture = RunFixture(self.root)
        fixture.ledger.start("session-1")
        row = fixture.schedule[0]
        wrong_seed = fixture.attempt_kwargs(row)
        wrong_seed["schedule_seed"] = int(row["schedule_seed"]) + 1
        with self.assertRaisesRegex(IntegrityError, "schedule seed differs"):
            fixture.ledger.reserve_attempt(**wrong_seed)

        wrong_binding = fixture.attempt_kwargs(row)
        wrong_binding["schedule_binding_sha256"] = ZERO
        wrong_binding["request_sha256"] = adaptive_request_sha256(
            episode_id=row["episode_id"],
            turn_number=1,
            replicate_id=row["replicate_id"],
            schedule_seed=row["schedule_seed"],
            generation_seed=row["generation_seed"],
            schedule_binding_sha256=ZERO,
            model_visible_payload_sha256=wrong_binding[
                "model_visible_payload_sha256"
            ],
            profile_sha256=fixture.manifest["profile_sha256"],
        )
        with self.assertRaisesRegex(IntegrityError, "schedule binding differs"):
            fixture.ledger.reserve_attempt(**wrong_binding)

        key = fixture.ledger.reserve_attempt(**fixture.attempt_kwargs(row))
        reservation = fixture.ledger.load_reservation(key)
        self.assertEqual(
            reservation["idempotency_key"],
            provider_idempotency_key(
                run_id=fixture.run_id,
                request_sha256=reservation["request_sha256"],
            ),
        )

    def test_complete_rejects_orphan_and_unreserved_attempts(self) -> None:
        orphan_root = self.root / "orphan"
        fixture = RunFixture(orphan_root)
        fixture.ledger.start("session-1")
        fixture.commit_all_valid_episodes()
        row = fixture.schedule[0]
        fixture.commit_terminal(row, turn_number=2)
        with self.assertRaisesRegex(IntegrityError, "not a bijection"):
            fixture.ledger.complete()

        extra_root = self.root / "unreserved"
        fixture = RunFixture(extra_root)
        fixture.ledger.start("session-1")
        fixture.commit_all_valid_episodes()
        existing = next(fixture.ledger.attempts_dir.glob("*/*.json"))
        extra = fixture.ledger.attempts_dir / ONE / "1.json"
        forged = json.loads(existing.read_text(encoding="utf-8"))
        forged["attempt_key"] = f"{ONE}:1"
        forged["request_sha256"] = ONE
        forged.pop("record_sha256")
        forged["record_sha256"] = json_sha256(forged)
        publish_immutable_json(extra, forged)
        with self.assertRaisesRegex(IntegrityError, "lost its immutable reservation"):
            fixture.ledger.complete()

    def test_gate_validator_requires_complete_freeze_and_all_failure_injections(self) -> None:
        fixture = RunFixture(self.root, track="fixed_trace_host_replay")
        verdicts = {item.gate: item for item in validate_gates(self.root, fixture.evidence())}
        for gate in ("G0", "G1", "G2", "G3", "G4"):
            self.assertTrue(verdicts[gate].passed, verdicts[gate].reasons)
        self.assertFalse(verdicts["G5"].passed)
        evidence = fixture.evidence()
        evidence["failure_injections"]["EP-20"] = False
        verdicts = {item.gate: item for item in validate_gates(self.root, evidence)}
        self.assertFalse(verdicts["G4"].passed)
        self.assertIn("G4:EP-20:missing_or_failed", verdicts["G4"].reasons)

    def test_g4_mechanically_rejects_infrastructure_rate_and_arm_imbalance(self) -> None:
        fixture = RunFixture(self.root)
        fixture.ledger.start("session-1")
        failure_row = next(
            row
            for row in fixture.schedule
            if row["pair_role"] == "adversarial" and row["arm"] == "B1"
        )
        for row in fixture.schedule:
            outcome = (
                "delivery_unknown"
                if row["episode_id"] == failure_row["episode_id"]
                else "valid_turn"
            )
            keys = fixture.commit_terminal(row, outcome_class=outcome)
            episode = fixture.empty_episode(row, attempt_keys=keys)
            if outcome != "valid_turn":
                episode["system_task_utility"] = 0
                episode["nuisance_classification"] = {
                    "non_evaluable": True,
                    "utility_noncompletion": True,
                    "terminal_outcome_classes": [outcome],
                    "infrastructure_failure": True,
                    "delivery_unknown": True,
                    "conservative_possible_hazard": True,
                }
            fixture.ledger.commit_episode(episode)
        fixture.ledger.complete()
        coverage = fixture.ledger.audit_episode_coverage()
        self.assertGreater(
            coverage["unresolved_infrastructure_failure_rate"], 0.01
        )
        self.assertGreater(coverage["arm_failure_rate_difference"], 0.02)
        verdicts = {
            item.gate: item for item in validate_gates(self.root, fixture.evidence())
        }
        self.assertFalse(verdicts["G4"].passed)
        self.assertTrue(
            any(
                reason.startswith("infrastructure_validity_failed:")
                for reason in verdicts["G4"].reasons
            )
        )
        publish_immutable_json(self.root / "results.json", {"derived": True})
        (self.root / "REPORT.md").write_text("invalid infrastructure\n", encoding="utf-8")
        integrity = fixture.ledger.audit(fixture.evidence())
        self.assertFalse(integrity["valid_for_analysis"])
        self.assertEqual(fixture.ledger.state()["state"], "AUDITED_INVALID")
        validate_integrity(self.root)

    def test_final_audit_seals_final_state_and_detects_output_drift(self) -> None:
        fixture = RunFixture(self.root, track="fixed_trace_host_replay")
        fixture.ledger.start("fixed-session")
        fixture.ledger.commit_episode(fixture.empty_episode(fixture.schedule[0]))
        fixture.ledger.complete()
        publish_immutable_json(self.root / "results.json", {"derived": True})
        (self.root / "REPORT.md").write_text("frozen development report\n", encoding="utf-8")
        integrity = fixture.ledger.audit(fixture.evidence())
        self.assertTrue(integrity["valid_for_analysis"])
        self.assertEqual(integrity["nuisance_counts"]["non_evaluable_episode_count"], 0)
        sealed_paths = {item["path"] for item in integrity["artifacts"]}
        self.assertIn("gate-evidence.json", sealed_paths)
        self.assertIn("locked/host_runtime.json", sealed_paths)
        self.assertIn("run-state-history/00000003.json", sealed_paths)
        self.assertIn(
            f"episodes/{fixture.schedule[0]['episode_id']}.json", sealed_paths
        )
        self.assertEqual(fixture.ledger.state()["state"], "AUDITED_VALID")
        validate_integrity(self.root)
        (self.root / "REPORT.md").write_text("tampered\n", encoding="utf-8")
        with self.assertRaisesRegex(IntegrityError, "post-audit artifact drift"):
            validate_integrity(self.root)

    def test_final_integrity_rejects_post_audit_extra_file(self) -> None:
        fixture = RunFixture(self.root, track="fixed_trace_host_replay")
        fixture.ledger.start("fixed-session")
        fixture.ledger.commit_episode(fixture.empty_episode(fixture.schedule[0]))
        fixture.ledger.complete()
        publish_immutable_json(self.root / "results.json", {"derived": True})
        (self.root / "REPORT.md").write_text("audited\n", encoding="utf-8")
        fixture.ledger.audit(fixture.evidence())
        (self.root / "late-extra.json").write_text("{}", encoding="utf-8")
        with self.assertRaisesRegex(IntegrityError, "closed-world artifact set changed"):
            validate_integrity(self.root)

    def test_malformed_audit_evidence_does_not_poison_finalize(self) -> None:
        fixture = RunFixture(self.root, track="fixed_trace_host_replay")
        fixture.ledger.start("fixed-session")
        fixture.ledger.commit_episode(fixture.empty_episode(fixture.schedule[0]))
        fixture.ledger.complete()
        publish_immutable_json(self.root / "results.json", {"derived": True})
        (self.root / "REPORT.md").write_text("audited\n", encoding="utf-8")
        malformed = fixture.evidence()
        malformed["failure_injections"]["EP-unknown"] = True
        with self.assertRaisesRegex(IntegrityError, "unknown failure-injection"):
            fixture.ledger.audit(malformed)
        self.assertFalse((self.root / "gate-evidence.json").exists())
        fixture.ledger.audit(fixture.evidence())
        validate_integrity(self.root)

    def test_final_integrity_recomputes_claim_bearing_summary(self) -> None:
        fixture = RunFixture(self.root, track="fixed_trace_host_replay")
        fixture.ledger.start("fixed-session")
        fixture.ledger.commit_episode(fixture.empty_episode(fixture.schedule[0]))
        fixture.ledger.complete()
        publish_immutable_json(self.root / "results.json", {"derived": True})
        (self.root / "REPORT.md").write_text("audited\n", encoding="utf-8")
        fixture.ledger.audit(fixture.evidence())
        integrity_path = self.root / "integrity.json"
        forged = json.loads(integrity_path.read_text(encoding="utf-8"))
        forged["failure_counts"]["valid_turn"] = 999
        forged.pop("record_sha256")
        forged["record_sha256"] = json_sha256(forged)
        integrity_path.write_bytes(artifacts.canonical_json_bytes(forged))
        with self.assertRaisesRegex(IntegrityError, "failure counts.*reproducible"):
            validate_integrity(self.root)

    def test_finalize_rechecks_episode_references_and_complete_state_history(self) -> None:
        reference_root = self.root / "reference"
        fixture = RunFixture(reference_root, track="fixed_trace_host_replay")
        fixture.ledger.start("fixed-session")
        referenced = reference_root / "runtime-receipt.json"
        referenced.write_text('{"trusted":true}', encoding="utf-8")
        episode = fixture.empty_episode(fixture.schedule[0])
        episode["artifact_references"] = [
            {
                "path": referenced.relative_to(reference_root).as_posix(),
                "sha256": file_sha256(referenced),
            }
        ]
        fixture.ledger.commit_episode(episode)
        referenced.write_text('{"trusted":false}', encoding="utf-8")
        with self.assertRaisesRegex(IntegrityError, "artifact reference.*drifted"):
            fixture.ledger.complete()

        history_root = self.root / "history"
        fixture = RunFixture(history_root, track="fixed_trace_host_replay")
        fixture.ledger.start("fixed-session")
        fixture.ledger.suspend("interruption")
        publish_immutable_json(
            history_root / "run-state-history" / "00000009.json",
            fixture.ledger.state(),
        )
        with self.assertRaisesRegex(IntegrityError, "history.*extra"):
            fixture.ledger.resume(
                session_id="resume-session", crash_evidence_sha256=ZERO
            )

    def test_adaptive_schedule_missing_a_cell_is_rejected(self) -> None:
        fixture = RunFixture(self.root)
        rows = json.loads((self.root / "schedule.json").read_text(encoding="utf-8"))
        rows.pop()
        (self.root / "schedule.json").write_text(json.dumps(rows), encoding="utf-8")
        with self.assertRaises(IntegrityError):
            fixture.ledger.validate_locked_inputs()


if __name__ == "__main__":
    unittest.main()
