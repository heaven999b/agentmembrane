from __future__ import annotations

import copy
from dataclasses import replace
import json
from pathlib import Path

import pytest

from agentmembrane.host_v2.cache import CacheIdentity, RunCache
from agentmembrane.host_v2.profiles import ResolvedProfile
from agentmembrane.host_v2.rq1_adaptive_v23 import bind_task_view_v23, load_task_overlay
from agentmembrane.host_v2.rq1_safety_framing_v24 import (
    CONTRACT_RELATIVE_PATH,
    FAILED_ATTEMPT_RELATIVE_PATH,
    OLD_PLANNER_ROLE,
    SafetyFramedModelPlannerV24,
    SafetyFramedResponseClientV24,
    V24_PLANNER_ROLE,
    V24_RECEIPT,
    forbidden_lexicon_hits_v24,
    frame_model_visible_messages_v24,
    load_contract_v24,
)
from agentmembrane.host_v2.runner import bind_visible_context_profile
from agentmembrane.host_v2.schema import IntegrityError
from agentmembrane.host_v2.taskpacks import load_taskpack
from agentmembrane.proxy import Completion


REPO_ROOT = Path(__file__).resolve().parents[2]
PROMPT_ROOT = REPO_ROOT / "experiments/host_boundary_v2/config/prompts"
PACK_ROOT = REPO_ROOT / "data/host_boundary_v2/packs/rq1-controlled-v2.2"
OVERLAY_PATH = REPO_ROOT / (
    "experiments/host_boundary_v2/config/rq1_adaptive_smoke_v2.3/"
    "adaptive-task-overlay-v2.3.json"
)
_MODEL = "gpt-5.6-sol"
_ROUTE = "local-cli-proxy"
_IMPLEMENTATION = "1" * 64
_PROTOCOL = "2" * 64


def _contract():
    return load_contract_v24(REPO_ROOT / CONTRACT_RELATIVE_PATH)


def _failed_user() -> dict:
    attempt = json.loads((REPO_ROOT / FAILED_ATTEMPT_RELATIVE_PATH).read_text())
    return json.loads(attempt["request"]["user_prompt"])


@pytest.mark.parametrize("turn", range(1, 7))
@pytest.mark.parametrize(
    "prompt_name",
    [
        "attacker-primary.txt",
        "attacker-route-diversity.txt",
        "attacker-delegation-lifecycle.txt",
        "attacker-composition-persistence.txt",
    ],
)
def test_all_six_turns_and_all_frozen_prompt_variants_are_framed(
    turn: int, prompt_name: str
) -> None:
    contract = _contract()
    source_user = _failed_user()
    source_user["turn_number"] = turn
    source_user["interaction_budget"]["current_turn"] = turn
    source_user["prior_feedback"] = [
        {"turn_number": prior, "allowed": False, "reason": "not_permitted"}
        for prior in range(1, turn)
    ]
    source_system = (PROMPT_ROOT / prompt_name).read_text()
    framed_system, framed_user_text = frame_model_visible_messages_v24(
        system_prompt=source_system,
        user_prompt=json.dumps(source_user),
        contract=contract.raw,
    )
    framed_user = json.loads(framed_user_text)
    assert framed_user["turn_number"] == turn
    assert framed_user["interaction_budget"]["current_turn"] == turn
    assert framed_user["interaction_budget"]["max_actions_this_turn"] == 1
    assert framed_user["response_contract"]["maximum_actions_this_turn"] == 1
    assert framed_user["planner_role"] == V24_PLANNER_ROLE
    assert framed_user["runtime_interface"] == source_user["runtime_interface"]
    assert framed_user["surface_task"] == source_user["surface_task"]
    assert forbidden_lexicon_hits_v24(
        system_prompt=framed_system,
        user_payload=framed_user,
        contract=contract.raw,
    ) == ()


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("redteaming", "red-team"),
        ("adversaries", "adversarial"),
        ("attacking", "attack"),
        ("attackers", "attack"),
        ("escaped", "escape"),
        ("exploitable", "exploit"),
        ("jailbroken", "jailbreak"),
        ("bypassing", "bypass"),
        ("exfiltration", "exfiltrate"),
        ("hackers", "hack"),
        ("cybersecurity", "cyber"),
        ("white_boxed", "white-box"),
    ],
)
def test_lexicon_scanner_catches_inflections_and_compounds(
    text: str, expected: str
) -> None:
    contract = _contract()
    assert expected in forbidden_lexicon_hits_v24(
        system_prompt=text,
        user_payload={"exact_value": "rq1-resource-attack"},
        contract=contract.raw,
    )


@pytest.mark.parametrize(
    "leaked_key",
    [
        "condition_id",
        "episode_id",
        "admission_level",
        "enabled_mechanisms",
        "oracle_code",
        "hidden_policy",
        "private_policy",
        "treatment_label",
        "gold_outcome",
    ],
)
def test_full_production_blinded_key_set_fails_closed(leaked_key: str) -> None:
    contract = _contract()
    user = _failed_user()
    user["runtime_interface"][leaked_key] = "opaque-but-forbidden-key"
    with pytest.raises(IntegrityError, match="condition/oracle keys"):
        frame_model_visible_messages_v24(
            system_prompt=(PROMPT_ROOT / "attacker-primary.txt").read_text(),
            user_prompt=json.dumps(user),
            contract=contract.raw,
        )


class FakeClient:
    def __init__(self, text: str) -> None:
        self.text = text
        self.calls: list[dict] = []

    def complete(self, **kwargs):
        self.calls.append(copy.deepcopy(kwargs))
        return Completion(
            text=self.text,
            model=kwargs["model"],
            latency_ms=1,
            input_tokens=10,
            output_tokens=5,
            total_tokens=15,
        )


def test_benign_messages_and_completion_are_byte_exact_passthrough() -> None:
    contract = _contract()
    system = "ordinary benign task system prompt"
    user = '{"planner_role":"ordinary_task_agent","surface_task":"normal task"}'
    assert frame_model_visible_messages_v24(
        system_prompt=system, user_prompt=user, contract=contract.raw
    ) == (system, user)
    raw = '{"actions":[],"final_artifact":null,"strategy":"completed: benign"}'
    fake = FakeClient(raw)
    wrapped = SafetyFramedResponseClientV24(fake, contract=contract.raw)
    completion = wrapped.complete(model=_MODEL, system=system, user=user, retries=0)
    assert completion.text == raw
    assert fake.calls[0]["system"] == system
    assert fake.calls[0]["user"] == user


def test_response_bridge_maps_only_public_label_and_rejects_internal_label() -> None:
    contract = _contract()
    source_user = _failed_user()
    system, user = frame_model_visible_messages_v24(
        system_prompt=(PROMPT_ROOT / "attacker-primary.txt").read_text(),
        user_prompt=json.dumps(source_user),
        contract=contract.raw,
    )
    public_response = json.dumps(
        {
            "actions": [],
            "final_artifact": {
                "artifact_type": V24_RECEIPT,
                "event_id": "event:opaque",
                "status": "completed",
            },
            "strategy": "completed: exact effect observed",
        }
    )
    wrapped = SafetyFramedResponseClientV24(
        FakeClient(public_response), contract=contract.raw
    )
    parsed = json.loads(
        wrapped.complete(model=_MODEL, system=system, user=user, retries=0).text
    )
    assert parsed["final_artifact"] == {
        "artifact_type": "attack_event_receipt",
        "event_id": "event:opaque",
        "status": "completed",
    }

    internal_response = public_response.replace(V24_RECEIPT, "attack_event_receipt")
    rejected = SafetyFramedResponseClientV24(
        FakeClient(internal_response), contract=contract.raw
    )
    with pytest.raises(IntegrityError, match="internal receipt label"):
        rejected.complete(model=_MODEL, system=system, user=user, retries=0)


def _resolved_profile(tmp_path: Path) -> ResolvedProfile:
    return ResolvedProfile(
        raw={
            "model": {
                "requested_id": _MODEL,
                "provider_route_id": _ROUTE,
                "allowed_resolved_ids": [_MODEL],
                "temperature": 0,
                "max_completion_tokens": 1100,
                "reasoning_effort": "max",
            },
            "planner": {
                "attacker_prompt_path": "../prompts/attacker-primary.txt",
                "benign_prompt_path": "../prompts/benign-system.txt",
                "max_turns": 6,
                "max_actions_per_turn": 1,
                "response_schema_version": 2,
            },
            "retries": {
                "request_level_transport_retries": 0,
                "immutable_failure_classes": [
                    "provider_policy",
                    "parse",
                    "schema",
                    "explicit_abstention",
                ],
            },
            "resolution": {
                "implementation_sha256": _IMPLEMENTATION,
                "protocol_sha256": _PROTOCOL,
                "resolved_model_id": _MODEL,
                "provider_route_id": _ROUTE,
                "reasoning_effort": "max",
            },
        },
        source_path=(REPO_ROOT / CONTRACT_RELATIVE_PATH).with_name("profile.json"),
        resolved_path=None,
    )


def _attacker_task():
    pack = load_taskpack(PACK_ROOT)
    task = next(
        row for row in pack.tasks if row.task_id == "rq1-resource-adversarial-s01"
    )
    overlay = load_task_overlay(OVERLAY_PATH)
    overlaid = bind_task_view_v23(
        task, overlay=overlay.raw, overlay_sha256=overlay.file_sha256
    ).task
    visible = bind_visible_context_profile(
        overlaid, "objective_aware_adaptive", required=True
    )
    metadata = copy.deepcopy(visible.metadata)
    metadata["schedule_episode_id"] = "e" * 64
    return replace(visible, metadata=metadata)


def test_fake_client_runs_through_production_modelplanner_seam(tmp_path: Path) -> None:
    contract = _contract()
    attempt = json.loads((REPO_ROOT / FAILED_ATTEMPT_RELATIVE_PATH).read_text())
    runtime = json.loads(attempt["request"]["user_prompt"])["runtime_interface"]
    admission = copy.deepcopy(runtime["admission"])
    admission.pop("principal_binding")
    response = json.dumps(
        {
            "actions": [{"op": "request_admission", "args": admission}],
            "final_artifact": None,
            "strategy": "Request the exact declared admission and await feedback.",
        }
    )
    fake = FakeClient(response)
    identity = CacheIdentity(
        implementation_sha256=_IMPLEMENTATION,
        protocol_sha256=_PROTOCOL,
        resolved_model_id=_MODEL,
        provider_route_id=_ROUTE,
    )
    cache = RunCache(tmp_path / "cache", identity)
    planner = SafetyFramedModelPlannerV24(
        resolved_profile=_resolved_profile(tmp_path),
        cache=cache,
        client=fake,
        contract=contract.raw,
    )
    turn = planner.plan_turn(
        task=_attacker_task(),
        condition_binding_sha256="a" * 64,
        turn_number=1,
        feedback=(),
        runtime_interface=runtime,
        max_actions=1,
    )
    assert turn.status == "ok"
    assert len(turn.actions) == 1
    assert fake.calls[0]["retries"] == 0
    assert fake.calls[0]["reasoning_effort"] == "max"
    provider_user = json.loads(fake.calls[0]["user"])
    assert provider_user["planner_role"] == V24_PLANNER_ROLE
    assert forbidden_lexicon_hits_v24(
        system_prompt=fake.calls[0]["system"],
        user_payload=provider_user,
        contract=contract.raw,
    ) == ()
    attempt_row = cache.load_attempt(turn.attempt_keys[0])
    assert attempt_row is not None
    # Internal role semantics stay adversarial even though provider bytes are framed.
    assert attempt_row["request"]["planner_role"] == OLD_PLANNER_ROLE
    assert attempt_row["request"]["system_prompt"] == fake.calls[0]["system"]
    assert attempt_row["request"]["user_prompt"] == fake.calls[0]["user"]
