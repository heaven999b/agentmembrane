from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from agentmembrane.host_v2 import original_rq1_v3_artifacts as artifacts
from agentmembrane.host_v2.original_rq1_v3_artifacts import (
    REQUIRED_FREEZE_ROLES,
    RQ1V3ArtifactLedger,
    build_freeze_lock,
    build_manifest,
    file_sha256,
    publish_immutable_json,
    validate_schedule,
)
from agentmembrane.host_v2.original_rq1_v3_banks import (
    CandidateRecord,
    RouteApplicability,
    build_matched_schedule,
    split_candidate_frame,
)
from agentmembrane.host_v2.original_rq1_v3_protocol import (
    DeliveryState,
    EpisodeRole,
    NativeEpisodeDriver,
    NativeProtocolProfile,
    OutcomeClass,
    ProviderReply,
    RequestContext,
)
from agentmembrane.host_v2.schema import sha256_bytes, sha256_json


def _hash(value: str) -> str:
    return sha256_json(value)


def _route(index: int, *, hazard_id: str, route_id: str, onset: str) -> RouteApplicability:
    return RouteApplicability(
        hazard_id=hazard_id,
        route_id=route_id,
        applicability="applicable",
        reason_code="task_native",
        required_legitimate_operation="call_tool",
        required_visible_operations=("call_tool",),
        first_reachable_level=onset,
        reachability_status="reachable_witnessed",
        reachability_witness_sha256=_hash(f"witness-{route_id}-{index}"),
        attack_template_lineage_id=f"attack-{route_id}-{index}",
        fixed_terminal_event="backend_effect",
        effect_target_sha256=_hash(f"target-{route_id}-{index}"),
        adjudication_version="cross-module-fixture-v1",
    )


def _candidate(index: int) -> CandidateRecord:
    return CandidateRecord(
        candidate_id=f"candidate-{index}",
        cluster_id=f"cluster-{index}",
        source_dataset="fixture@1",
        source_task_id=f"task-{index}",
        source_payload_sha256=_hash(f"payload-{index}"),
        source_template_id=f"template-{index}",
        source_template_sha256=_hash(f"template-{index}"),
        parameter_family_id=f"parameters-{index}",
        normalized_task_contract_sha256=_hash(f"task-contract-{index}"),
        authorized_effect_target_sha256=_hash(f"authorized-{index}"),
        checker_contract_sha256=_hash(f"checker-{index}"),
        initial_state_sha256=_hash(f"state-{index}"),
        domain="fixture-domain",
        utility_eligible=True,
        utility_stratum="fixture-stratum",
        route_applicability=(
            _route(index, hazard_id="H-TOOL", route_id="sensitive-call", onset="A3"),
            _route(index, hazard_id="H-MEM", route_id="persistent-write", onset="A4"),
        ),
        historical_exposure_component_id=f"exposure-{index}",
        prior_model_exposure=False,
        prior_human_tuning_exposure=False,
        eligibility_status="eligible",
        exclusion_reasons=(),
    )


def _formal_schedule() -> tuple[dict[str, Any], ...]:
    candidates = tuple(_candidate(index) for index in range(4))
    split = split_candidate_frame(
        candidates,
        formal_counts_by_stratum={"fixture-stratum": 1},
        development_counts_by_stratum=None,
        utility_target_masses={"fixture-stratum": 1.0},
        safety_target_masses={
            "H-MEM:persistent-write": 0.5,
            "H-TOOL:sensitive-call": 0.5,
        },
        selection_seed=8101,
    )
    return tuple(
        row.to_dict()
        for row in build_matched_schedule(
            split,
            candidates,
            bank_id="formal_holdout",
            model_seeds=(8201, 8202, 8203),
            schedule_randomization_seed=8301,
            prompt_bundle_sha256=_hash("prompt-bundle"),
            surface_contract_sha256=_hash("surface-contract"),
        )
    )


def _development_schedule() -> tuple[dict[str, Any], ...]:
    candidates = tuple(_candidate(index) for index in range(4))
    split = split_candidate_frame(
        candidates,
        formal_counts_by_stratum={"fixture-stratum": 1},
        development_counts_by_stratum=None,
        utility_target_masses={"fixture-stratum": 1.0},
        safety_target_masses={
            "H-MEM:persistent-write": 0.5,
            "H-TOOL:sensitive-call": 0.5,
        },
        selection_seed=8101,
    )
    return tuple(
        row.to_dict()
        for row in build_matched_schedule(
            split,
            candidates,
            bank_id="development",
            replicate_generation_seeds={"r1": None, "r2": None, "r3": None},
            schedule_randomization_seed=8301,
            prompt_bundle_sha256=_hash("prompt-bundle"),
            surface_contract_sha256=_hash("surface-contract"),
        )
    )


def test_bank_schedule_is_directly_accepted_without_route_collapse(tmp_path: Path) -> None:
    schedule = _formal_schedule()
    publish_immutable_json(tmp_path / "schedule.json", list(schedule))
    manifest = {
        "track": "adaptive_end_to_end",
        "scientific_stage": "formal",
        "bank_id": "formal-v3",
        "schedule_sha256": file_sha256(tmp_path / "schedule.json"),
        "expected_episode_count": len(schedule),
        "expected_replication_ids": ["seed-8201", "seed-8202", "seed-8203"],
    }
    report = validate_schedule(tmp_path, manifest)
    assert report["row_count"] == len(schedule) == 90
    assert len(report["episode_ids"]) == len(set(report["episode_ids"]))
    adversarial = [row for row in schedule if row["pair_role"] == "adversarial"]
    assert {row["route_id"] for row in adversarial} == {
        "persistent-write",
        "sensitive-call",
    }
    assert len({row["block_id"] for row in adversarial}) == 2


def test_development_bank_rows_keep_explicit_null_seed_and_weight(tmp_path: Path) -> None:
    schedule = _development_schedule()
    publish_immutable_json(tmp_path / "schedule.json", list(schedule))
    manifest = {
        "track": "adaptive_end_to_end",
        "scientific_stage": "development",
        "schedule_sha256": file_sha256(tmp_path / "schedule.json"),
        "expected_episode_count": len(schedule),
        "expected_replication_ids": ["r1", "r2", "r3"],
    }
    assert validate_schedule(tmp_path, manifest)["row_count"] == len(schedule)
    assert {row["generation_seed"] for row in schedule} == {None}
    assert {row["weight"] for row in schedule} == {None}


def _initialize_ledger(
    run_dir: Path,
    schedule: tuple[dict[str, Any], ...],
    profile: NativeProtocolProfile,
    monkeypatch: Any,
) -> RQ1V3ArtifactLedger:
    profile_value = profile.to_dict()
    cache_identity = {
        "implementation_sha256": _hash("implementation"),
        "protocol_sha256": _hash("protocol"),
        "resolved_model_id": profile.requested_model_id,
        "provider_route_id": profile.provider_route_id,
    }
    publish_immutable_json(run_dir / "schedule.json", list(schedule))
    publish_immutable_json(run_dir / "resolved-profile.json", profile_value)
    publish_immutable_json(run_dir / "cache-identity.json", cache_identity)
    locked = run_dir / "locked"
    locked.mkdir()
    entries: list[dict[str, str]] = []
    for role in sorted(REQUIRED_FREEZE_ROLES - {"schedule", "model_profile"}):
        path = locked / f"{role}.json"
        value = (
            {"request_level_transport_retries": profile.transport_retry_budget}
            if role == "retry_policy"
            else {"role": role, "fixture": True}
        )
        publish_immutable_json(path, value)
        entries.append(
            {
                "role": role,
                "path": path.relative_to(run_dir).as_posix(),
                "sha256": file_sha256(path),
            }
        )
    entries.extend(
        [
            {
                "role": "schedule",
                "path": "schedule.json",
                "sha256": file_sha256(run_dir / "schedule.json"),
            },
            {
                "role": "model_profile",
                "path": "resolved-profile.json",
                "sha256": file_sha256(run_dir / "resolved-profile.json"),
            },
        ]
    )
    proposal_hash = next(row["sha256"] for row in entries if row["role"] == "proposal")
    monkeypatch.setattr(artifacts, "PROPOSAL_SHA256", proposal_hash)
    freeze = build_freeze_lock(
        run_id="cross-module-development",
        entries=entries,
        sealed_at="2026-09-06T00:00:00Z",
    )
    by_role = {row["role"]: row["sha256"] for row in entries}
    expected_replication_ids = tuple(
        sorted({str(row["replicate_id"]) for row in schedule})
    )
    manifest = build_manifest(
        run_id="cross-module-development",
        scientific_stage="development",
        track="adaptive_end_to_end",
        protocol_sha256=by_role["protocol"],
        machine_spec_sha256=by_role["machine_spec"],
        implementation_manifest_sha256=by_role["implementation_manifest"],
        bank_id="development",
        bank_sha256=by_role["bank"],
        schedule=schedule,
        resolved_profile=profile_value,
        cache_identity=cache_identity,
        statistics_contract_sha256=by_role["statistics_contract"],
        retry_policy_sha256=by_role["retry_policy"],
        freeze_lock=freeze,
        expected_replication_ids=expected_replication_ids,
        created_at="2026-09-06T00:00:01Z",
        proposal_sha256=proposal_hash,
    )
    ledger = RQ1V3ArtifactLedger(run_dir)
    ledger.initialize(
        manifest=manifest,
        freeze_lock=freeze,
        schedule=schedule,
        resolved_profile=profile_value,
        cache_identity=cache_identity,
    )
    ledger.start("cross-module-session")
    return ledger


class _InspectingProvider:
    def __init__(
        self,
        ledger: RQ1V3ArtifactLedger,
        outcomes: list[ProviderReply | BaseException],
    ) -> None:
        self.ledger = ledger
        self.outcomes = outcomes
        self.call_count = 0

    def complete(
        self, payload: Mapping[str, Any], *, idempotency_key: str
    ) -> ProviderReply:
        self.call_count += 1
        assert len(self.ledger.unresolved_attempt_keys()) == 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def test_provider_dispatch_is_reserved_then_losslessly_committed_and_timeout_is_not_retried(
    tmp_path: Path, monkeypatch: Any
) -> None:
    schedule = _development_schedule()
    profile = NativeProtocolProfile(
        requested_model_id="model-exact",
        allowed_resolved_model_ids=("model-exact",),
        provider_route_id="provider-route",
        provider_api_version="2026-01-01",
        reasoning_effort="low",
        generation_seed_support="unsupported",
        transport_retry_budget=1,
    )
    ledger = _initialize_ledger(tmp_path, schedule, profile, monkeypatch)
    raw = (
        b'{  "model" : "model-exact", "choices" : '
        b'[{"finish_reason":"stop","message":{"content":"done"}}] }\n'
    )
    response = {
        "model": "model-exact",
        "choices": [{"finish_reason": "stop", "message": {"content": "done"}}],
    }
    first_provider = _InspectingProvider(
        ledger,
        [
            ProviderReply(
                response=response,
                raw_response_bytes=raw,
                provider_request_id="provider-request-1",
                generation_seed_receipt=None,
            )
        ],
    )
    first_context = RequestContext(
        episode_id=schedule[0]["episode_id"],
        turn_number=1,
        replicate_id=schedule[0]["replicate_id"],
        schedule_seed=schedule[0]["schedule_seed"],
        generation_seed=schedule[0]["generation_seed"],
        schedule_binding_sha256=sha256_json(schedule[0]),
    )
    first = NativeEpisodeDriver(
        profile=profile, provider=first_provider, artifact_ledger=ledger
    ).run_turn(
        episode_role=EpisodeRole(schedule[0]["pair_role"]),
        context=first_context,
        messages=[{"role": "user", "content": "Complete the task."}],
        tools=(),
    )
    terminal = ledger.load_attempt(first.attempts[0].attempt_key)
    assert terminal is not None
    assert terminal["raw_response_sha256"] == sha256_bytes(raw)
    assert (tmp_path / terminal["raw_response_path"]).read_bytes() == raw
    assert ledger.unresolved_attempt_keys() == ()

    second_provider = _InspectingProvider(ledger, [TimeoutError("timeout after send")])
    second_context = RequestContext(
        episode_id=schedule[1]["episode_id"],
        turn_number=1,
        replicate_id=schedule[1]["replicate_id"],
        schedule_seed=schedule[1]["schedule_seed"],
        generation_seed=schedule[1]["generation_seed"],
        schedule_binding_sha256=sha256_json(schedule[1]),
    )
    second = NativeEpisodeDriver(
        profile=profile, provider=second_provider, artifact_ledger=ledger
    ).run_turn(
        episode_role=EpisodeRole(schedule[1]["pair_role"]),
        context=second_context,
        messages=[{"role": "user", "content": "Complete the task."}],
        tools=(),
    )
    assert second_provider.call_count == 1
    assert second.outcome_class is OutcomeClass.DELIVERY_UNKNOWN
    assert second.attempts[0].delivery_state is DeliveryState.UNKNOWN
    timeout_terminal = ledger.load_attempt(second.attempts[0].attempt_key)
    assert timeout_terminal is not None
    assert timeout_terminal["outcome_class"] == "delivery_unknown"
    assert ledger.unresolved_attempt_keys() == ()
