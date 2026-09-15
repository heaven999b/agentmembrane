from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from agentmembrane.host_v2.rq1_public_agentdojo_multi_v3 import executor as EXEC
from agentmembrane.host_v2.rq1_public_agentdojo_multi_v3.selector import (
    engineering_smoke_schedule,
)
from agentmembrane.proxy import Completion


REPO_ROOT = Path(__file__).resolve().parents[2]
GATE_RECEIPT = {
    "schema_version": 1,
    "artifact_type": "synthetic_test_integration_gate",
    "gate_id": "synthetic-test-gate",
    "gate_sha256": "9" * 64,
}
RUNTIME_BINDING = {
    "runtime_id": "synthetic-test-runtime",
    "python_launcher": "test-only/python",
    "source_and_pack_locks_exact": True,
}


def _completion(value: dict, *, tokens: tuple[int, int, int] = (2, 3, 5)) -> Completion:
    return Completion(
        text=json.dumps(value, sort_keys=True, separators=(",", ":")),
        model="gpt-5.6-sol",
        latency_ms=1,
        input_tokens=tokens[0],
        output_tokens=tokens[1],
        total_tokens=tokens[2],
    )


def _final(text: str = "done") -> Completion:
    return _completion({"type": "final", "text": text})


def _raw_completion(text: str) -> Completion:
    return Completion(
        text=text,
        model="gpt-5.6-sol",
        latency_ms=1,
        input_tokens=2,
        output_tokens=3,
        total_tokens=5,
    )


def _action() -> Completion:
    return _completion(
        {
            "type": "tool_action",
            "name": "read_public_item",
            "arguments": {"item": "visible"},
        }
    )


class _Dispatch:
    def __init__(self, *, allowed: bool, observation=None) -> None:
        self.allowed = allowed
        self.observation = observation

    def as_json(self):
        return {
            "schema_version": 1,
            "allowed": self.allowed,
            "reason": "fake_allowed" if self.allowed else "fake_predispatch_denial",
            "observation": copy.deepcopy(self.observation),
            "native_trace_row": {"fake": True} if self.allowed else None,
            "pre_state_sha256": "1" * 64,
            "post_state_sha256": "2" * 64 if self.allowed else "1" * 64,
            "native_dispatch_count_before": 0,
            "native_dispatch_count_after": 1 if self.allowed else 0,
            "denied_pre_dispatch": not self.allowed,
            "protected_preview_completed_effect": not self.allowed,
        }


class FakeFrozenSession:
    created: list["FakeFrozenSession"] = []

    def __init__(self, *, source_task_id, pair_role, arm) -> None:
        self.source_task_id = source_task_id
        self.pair_role = pair_role
        self.arm = arm
        self.reset_calls = 0
        self.dispatch_calls: list[dict] = []
        self.native_dispatch_count = 0
        self.evaluate_calls = 0
        self.cleaned = False
        type(self).created.append(self)

    def reset(self):
        self.reset_calls += 1
        return {"source_task_id": self.source_task_id}

    def read(self):
        return {
            "messages": [{"role": "user", "content": "ordinary task"}],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "read_public_item",
                        "description": "Read one visible item.",
                        "parameters": {
                            "type": "object",
                            "properties": {"item": {"type": "string"}},
                            "required": ["item"],
                        },
                    },
                }
            ],
        }

    def dispatch(self, action):
        assert set(action) == {"function", "args", "id"}
        assert action["function"] == "read_public_item"
        assert action["args"] == {"item": "visible"}
        assert action["id"].startswith("cell-")
        self.dispatch_calls.append(copy.deepcopy(action))
        denied = self.arm == "protected"
        if not denied:
            self.native_dispatch_count += 1
        return _Dispatch(
            allowed=not denied,
            observation={"value": "visible"} if not denied else None,
        )

    def evaluate_final(self, *, final_assistant_text, terminal_reason):
        self.evaluate_calls += 1
        return {
            "schema_version": 1,
            "utility": final_assistant_text == "done",
            "security": bool(self.native_dispatch_count),
            "terminal_reason_observed": terminal_reason,
        }

    def cleanup(self):
        self.cleaned = True
        return "a" * 64


@pytest.fixture(autouse=True)
def _offline_provenance(monkeypatch: pytest.MonkeyPatch):
    FakeFrozenSession.created.clear()

    def validate_gate(value):
        if value != GATE_RECEIPT:
            raise ValueError("synthetic gate mismatch")
        return copy.deepcopy(GATE_RECEIPT)

    monkeypatch.setattr(EXEC, "validate_integration_gate", validate_gate)
    monkeypatch.setattr(
        EXEC,
        "_runtime_binding",
        lambda repo_root, require_active_process: copy.deepcopy(RUNTIME_BINDING),
    )


def _documents(namespace: str):
    profile = EXEC.build_profile_document(REPO_ROOT, gate_receipt=GATE_RECEIPT)
    authorization = EXEC.build_authorization_document(
        profile=profile, namespace=namespace
    )
    return profile, authorization


def _factory(default_steps=None, overrides=None):
    steps = default_steps or [_final()]
    rows = {
        cell.cell_id: list((overrides or {}).get(cell.cell_id, steps))
        for cell in engineering_smoke_schedule()
    }
    return EXEC.OfflineScriptedClientFactory(rows)


def _canary_cells():
    return tuple(
        cell
        for cell in engineering_smoke_schedule()
        if cell.execution_ordinal in EXEC.CANARY_ORDINALS
    )


def _continuation_cells():
    return tuple(
        cell
        for cell in engineering_smoke_schedule()
        if cell.execution_ordinal not in EXEC.CANARY_ORDINALS
    )


def test_all_48_cells_use_fresh_sessions_clients_and_reconcile_usage(
    tmp_path: Path,
) -> None:
    namespace = "multi-v3-all-48"
    profile, authorization = _documents(namespace)
    factory = _factory()
    canary = EXEC.execute_canary_test_only_v3(
        repo_root=REPO_ROOT,
        output_root=tmp_path,
        namespace=namespace,
        gate_receipt=GATE_RECEIPT,
        profile=profile,
        authorization=authorization,
        client_factory=factory,
        session_factory=FakeFrozenSession,
    )
    assert canary["cell_count"] == 4
    assert canary["continuation_started"] is False
    assert [row["execution_ordinal"] for row in canary["cells"]] == [
        1,
        13,
        25,
        37,
    ]
    assert [cell.domain for cell in _canary_cells()] == [
        "banking",
        "slack",
        "travel",
        "workspace",
    ]
    assert len(factory.created) == 4
    assert (tmp_path / namespace / "cells/cell-37.json").is_file()
    assert not (tmp_path / namespace / "cells/cell-02.json").exists()
    assert not (tmp_path / namespace / "cells/cell-05.json").exists()
    assert not (tmp_path / namespace / "report.json").exists()
    report = EXEC.execute_continuation_test_only_v3(
        repo_root=REPO_ROOT,
        namespace_path=tmp_path / namespace,
        gate_receipt=GATE_RECEIPT,
        profile=profile,
        authorization=authorization,
        client_factory=factory,
        session_factory=FakeFrozenSession,
    )
    assert report["cell_count"] == 48
    assert report["all_assigned_cells_have_records"] is True
    assert report["evidence_eligible"] is True
    assert report["evidence_eligibility"]["failure_reasons"] == []
    assert len(report["cells"]) == 48
    assert [row["execution_ordinal"] for row in report["cells"]] == list(range(1, 49))
    assert len(factory.created) == 48
    assert len({id(client) for _, client in factory.created}) == 48
    assert len(FakeFrozenSession.created) == 48
    assert len({id(session) for session in FakeFrozenSession.created}) == 48
    assert all(
        session.reset_calls == 1 and session.cleaned
        for session in FakeFrozenSession.created
    )
    usage = report["call_and_usage_accounting"]
    assert usage == {
        "provider_call_reservations": 48,
        "provider_terminal_records": 48,
        "returned_completion_count": 48,
        "provider_error_count": 0,
        "indeterminate_consumed_call_count": 0,
        "known_input_tokens": 96,
        "known_output_tokens": 144,
        "known_total_tokens": 240,
        "usage_unknown_call_count": 0,
        "global_call_hard_cap": 288,
        "within_global_call_hard_cap": True,
        "reconciled": True,
    }
    assert report["continuation_depended_on_observed_outcome"] is False
    assert report["safety_classification_performed"] is False
    assert len(list((tmp_path / namespace / "cells").glob("cell-*.json"))) == 48


def test_provider_failure_is_persisted_and_later_cells_continue(tmp_path: Path) -> None:
    namespace = "multi-v3-provider-failure"
    cells = engineering_smoke_schedule()
    profile, authorization = _documents(namespace)
    factory = _factory(
        overrides={_canary_cells()[1].cell_id: [RuntimeError("offline failure")]}
    )
    canary = EXEC.execute_canary_test_only_v3(
        repo_root=REPO_ROOT,
        output_root=tmp_path,
        namespace=namespace,
        gate_receipt=GATE_RECEIPT,
        profile=profile,
        authorization=authorization,
        client_factory=factory,
        session_factory=FakeFrozenSession,
    )
    assert [row["status"] for row in canary["cells"]] == [
        "completed",
        "provider_failure",
        "completed",
        "completed",
    ]
    assert canary["operational_gate_passed"] is False
    assert len(factory.created) == 4
    assert not (tmp_path / namespace / "cells/cell-05.json").exists()
    with pytest.raises(EXEC.MultiSourceGlobalFatal, match="operationally passing"):
        EXEC.execute_continuation_test_only_v3(
            repo_root=REPO_ROOT,
            namespace_path=tmp_path / namespace,
            gate_receipt=GATE_RECEIPT,
            profile=profile,
            authorization=authorization,
            client_factory=factory,
            session_factory=FakeFrozenSession,
        )
    assert (tmp_path / namespace / "cells/cell-37.json").is_file()
    assert not (tmp_path / namespace / "cells/cell-05.json").exists()
    failed = json.loads((tmp_path / namespace / "cells/cell-13.json").read_text())
    assert failed["native_checker_observed"] is None
    assert failed["metrics_contract"]["provider_failure_counted_as_safety"] is False
    assert canary["call_and_usage_accounting"]["provider_error_count"] == 1
    assert canary["call_and_usage_accounting"]["usage_unknown_call_count"] == 1


def test_continuation_provider_failure_is_persisted_and_later_cells_continue(
    tmp_path: Path,
) -> None:
    namespace = "multi-v3-continuation-failure"
    cells = engineering_smoke_schedule()
    profile, authorization = _documents(namespace)
    factory = _factory(overrides={cells[4].cell_id: [RuntimeError("offline failure")]})
    canary = EXEC.execute_canary_test_only_v3(
        repo_root=REPO_ROOT,
        output_root=tmp_path,
        namespace=namespace,
        gate_receipt=GATE_RECEIPT,
        profile=profile,
        authorization=authorization,
        client_factory=factory,
        session_factory=FakeFrozenSession,
    )
    assert canary["operational_gate_passed"] is True
    report = EXEC.execute_continuation_test_only_v3(
        repo_root=REPO_ROOT,
        namespace_path=tmp_path / namespace,
        gate_receipt=GATE_RECEIPT,
        profile=profile,
        authorization=authorization,
        client_factory=factory,
        session_factory=FakeFrozenSession,
    )
    assert report["cells"][4]["status"] == "provider_failure"
    assert report["cells"][5]["status"] == "completed"
    assert report["cells"][47]["status"] == "completed"
    assert report["evidence_eligible"] is False
    assert (
        report["evidence_eligibility"]["failed_or_unknown_cells_counted_as_safe"]
        is False
    )
    assert (
        "one_or_more_cells_not_completed"
        in report["evidence_eligibility"]["failure_reasons"]
    )
    assert "provider_usage_unknown" in report["evidence_eligibility"]["failure_reasons"]


def test_canary_parse_failure_completes_four_cells_but_blocks_continuation(
    tmp_path: Path,
) -> None:
    namespace = "multi-v3-canary-parse-no-go"
    cells = engineering_smoke_schedule()
    profile, authorization = _documents(namespace)
    malformed = Completion(
        text="not-json",
        model="gpt-5.6-sol",
        latency_ms=1,
        input_tokens=2,
        output_tokens=1,
        total_tokens=3,
    )
    factory = _factory(overrides={_canary_cells()[1].cell_id: [malformed]})
    canary = EXEC.execute_canary_test_only_v3(
        repo_root=REPO_ROOT,
        output_root=tmp_path,
        namespace=namespace,
        gate_receipt=GATE_RECEIPT,
        profile=profile,
        authorization=authorization,
        client_factory=factory,
        session_factory=FakeFrozenSession,
    )
    assert [row["status"] for row in canary["cells"]] == [
        "completed",
        "parse_failure",
        "completed",
        "completed",
    ]
    assert canary["operational_gate_passed"] is False
    assert len(factory.created) == 4
    assert not (tmp_path / namespace / "cells/cell-05.json").exists()
    with pytest.raises(EXEC.MultiSourceGlobalFatal, match="operationally passing"):
        EXEC.execute_continuation_test_only_v3(
            repo_root=REPO_ROOT,
            namespace_path=tmp_path / namespace,
            gate_receipt=GATE_RECEIPT,
            profile=profile,
            authorization=authorization,
            client_factory=factory,
            session_factory=FakeFrozenSession,
        )


def test_single_trailing_brace_repair_is_valid_durable_success(
    tmp_path: Path,
) -> None:
    namespace = "multi-v3-repair-success"
    profile, authorization = _documents(namespace)
    repaired = _raw_completion('{"type":"final","text":"done"}}')
    canary = EXEC.execute_canary_test_only_v3(
        repo_root=REPO_ROOT,
        output_root=tmp_path,
        namespace=namespace,
        gate_receipt=GATE_RECEIPT,
        profile=profile,
        authorization=authorization,
        client_factory=_factory(default_steps=[repaired]),
        session_factory=FakeFrozenSession,
    )
    assert canary["operational_gate_passed"] is True
    for ordinal in EXEC.CANARY_ORDINALS:
        cell = json.loads(
            (tmp_path / namespace / f"cells/cell-{ordinal:02d}.json").read_text()
        )
        request = cell["provider_request_records"][0]
        assert request["raw_parse_status"] == ("parsed_single_trailing_brace_repair")
        assert request["status"] == "parsed_final"
        assert request["response_type"] == "final"
        assert len(request["response_sha256"]) == 64


def test_repair_failure_statuses_match_durable_parse_and_contract_failures(
    tmp_path: Path,
) -> None:
    namespace = "multi-v3-repair-failure-statuses"
    profile, authorization = _documents(namespace)
    canary_cells = _canary_cells()
    repair_parse_failure = _raw_completion('{"type":"final","text":"still-invalid"}}}')
    repair_contract_failure = _raw_completion(
        '[{"type":"final","text":"not-an-object"}]}'
    )
    canary = EXEC.execute_canary_test_only_v3(
        repo_root=REPO_ROOT,
        output_root=tmp_path,
        namespace=namespace,
        gate_receipt=GATE_RECEIPT,
        profile=profile,
        authorization=authorization,
        client_factory=_factory(
            overrides={
                canary_cells[0].cell_id: [repair_parse_failure],
                canary_cells[1].cell_id: [repair_contract_failure],
            }
        ),
        session_factory=FakeFrozenSession,
    )
    assert [row["status"] for row in canary["cells"]] == [
        "parse_failure",
        "schema_failure",
        "completed",
        "completed",
    ]
    parse_cell = json.loads((tmp_path / namespace / "cells/cell-01.json").read_text())
    contract_cell = json.loads(
        (tmp_path / namespace / "cells/cell-13.json").read_text()
    )
    assert parse_cell["provider_request_records"][0]["raw_parse_status"] == (
        "json_parse_failed_after_single_trailing_brace_repair"
    )
    assert contract_cell["provider_request_records"][0]["raw_parse_status"] == (
        "union_contract_failed_after_single_trailing_brace_repair"
    )


@pytest.mark.parametrize(
    ("tamper_kind", "error_pattern"),
    [
        ("swap_success_failure", "parse status is inconsistent"),
        ("repair_success_missing_response_sha", "parsed completion status"),
        ("repair_failure_pretends_success", "failed parse status"),
        ("unknown_parse_status", "completion evidence differs"),
    ],
)
def test_repair_provenance_tamper_is_rejected_before_continuation(
    tmp_path: Path,
    tamper_kind: str,
    error_pattern: str,
) -> None:
    namespace = f"multi-v3-repair-tamper-{tamper_kind}"
    profile, authorization = _documents(namespace)
    canary_cells = _canary_cells()
    factory = _factory(
        overrides={
            canary_cells[0].cell_id: [
                _raw_completion('{"type":"final","text":"done"}}')
            ],
            canary_cells[1].cell_id: [
                _raw_completion('{"type":"final","text":"invalid"}}}')
            ],
        }
    )
    EXEC.execute_canary_test_only_v3(
        repo_root=REPO_ROOT,
        output_root=tmp_path,
        namespace=namespace,
        gate_receipt=GATE_RECEIPT,
        profile=profile,
        authorization=authorization,
        client_factory=factory,
        session_factory=FakeFrozenSession,
    )
    success_path = tmp_path / namespace / "cells/cell-01.json"
    failure_path = tmp_path / namespace / "cells/cell-13.json"
    success_cell = json.loads(success_path.read_text())
    failure_cell = json.loads(failure_path.read_text())
    success = success_cell["provider_request_records"][0]
    failure = failure_cell["provider_request_records"][0]
    if tamper_kind == "swap_success_failure":
        success["raw_parse_status"], failure["raw_parse_status"] = (
            failure["raw_parse_status"],
            success["raw_parse_status"],
        )
    elif tamper_kind == "repair_success_missing_response_sha":
        success.pop("response_sha256")
    elif tamper_kind == "repair_failure_pretends_success":
        failure.update(
            {
                "status": "parsed_final",
                "failure_class": None,
                "error_type": None,
                "response_type": "final",
                "response_sha256": "a" * 64,
            }
        )
    else:
        success["raw_parse_status"] = "parsed_unknown_repair"
    for path, cell in ((success_path, success_cell), (failure_path, failure_cell)):
        path.write_text(
            json.dumps(cell, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    with pytest.raises(EXEC.MultiSourceGlobalFatal, match=error_pattern):
        EXEC.execute_continuation_test_only_v3(
            repo_root=REPO_ROOT,
            namespace_path=tmp_path / namespace,
            gate_receipt=GATE_RECEIPT,
            profile=profile,
            authorization=authorization,
            client_factory=factory,
            session_factory=FakeFrozenSession,
        )
    assert not (tmp_path / namespace / "cells/cell-02.json").exists()


def test_canary_integrity_failure_is_durable_no_go_and_does_not_skip_cell_four(
    tmp_path: Path,
) -> None:
    namespace = "multi-v3-canary-integrity-no-go"
    cells = engineering_smoke_schedule()
    profile, authorization = _documents(namespace)
    normal_factory = _factory()
    requested: list[str] = []

    def factory(cell):
        requested.append(cell.cell_id)
        if cell.cell_id == _canary_cells()[1].cell_id:
            raise EXEC.MultiSourceExecutorError("synthetic cell binding failure")
        return normal_factory(cell)

    canary = EXEC.execute_canary_test_only_v3(
        repo_root=REPO_ROOT,
        output_root=tmp_path,
        namespace=namespace,
        gate_receipt=GATE_RECEIPT,
        profile=profile,
        authorization=authorization,
        client_factory=factory,
        session_factory=FakeFrozenSession,
    )

    assert requested == [cell.cell_id for cell in _canary_cells()]
    assert [row["status"] for row in canary["cells"]] == [
        "completed",
        "integrity_failure",
        "completed",
        "completed",
    ]
    assert canary["operational_gate_passed"] is False
    assert (
        "integrity_failure"
        in canary["operational_gate_contract"]["disallowed_failure_statuses"]
    )
    with pytest.raises(EXEC.MultiSourceGlobalFatal, match="operationally passing"):
        EXEC.execute_continuation_test_only_v3(
            repo_root=REPO_ROOT,
            namespace_path=tmp_path / namespace,
            gate_receipt=GATE_RECEIPT,
            profile=profile,
            authorization=authorization,
            client_factory=normal_factory,
            session_factory=FakeFrozenSession,
        )
    assert not (tmp_path / namespace / "cells/cell-05.json").exists()


def test_continuation_schema_and_native_failures_are_durable_and_do_not_stop_later_cells(
    tmp_path: Path,
) -> None:
    namespace = "multi-v3-continuation-native-errors"
    cells = engineering_smoke_schedule()
    profile, authorization = _documents(namespace)
    factory = _factory(
        overrides={cells[4].cell_id: [_action()], cells[5].cell_id: [_action()]}
    )

    class ErrorSession(FakeFrozenSession):
        def dispatch(self, action):
            coordinate = (self.source_task_id, self.pair_role, self.arm)
            schema_coordinate = (
                cells[4].source_task_id,
                cells[4].pair_role,
                cells[4].host_arm,
            )
            native_coordinate = (
                cells[5].source_task_id,
                cells[5].pair_role,
                cells[5].host_arm,
            )
            if coordinate == schema_coordinate:
                from agentmembrane.host_v2.schema import SchemaError

                raise SchemaError("synthetic native action schema failure")
            if coordinate == native_coordinate:
                raise RuntimeError("synthetic native dispatch failure")
            return super().dispatch(action)

    canary = EXEC.execute_canary_test_only_v3(
        repo_root=REPO_ROOT,
        output_root=tmp_path,
        namespace=namespace,
        gate_receipt=GATE_RECEIPT,
        profile=profile,
        authorization=authorization,
        client_factory=factory,
        session_factory=ErrorSession,
    )
    assert canary["operational_gate_passed"] is True
    report = EXEC.execute_continuation_test_only_v3(
        repo_root=REPO_ROOT,
        namespace_path=tmp_path / namespace,
        gate_receipt=GATE_RECEIPT,
        profile=profile,
        authorization=authorization,
        client_factory=factory,
        session_factory=ErrorSession,
    )
    assert report["cells"][4]["status"] == "schema_failure"
    assert report["cells"][5]["status"] == "native_failure"
    assert report["cells"][6]["status"] == "completed"
    assert report["cells"][47]["status"] == "completed"
    assert report["evidence_eligible"] is False
    assert report["evidence_eligibility"]["failure_reasons"] == [
        "one_or_more_cells_not_completed"
    ]
    failed_coordinates = {
        (cells[4].source_task_id, cells[4].pair_role, cells[4].host_arm),
        (cells[5].source_task_id, cells[5].pair_role, cells[5].host_arm),
    }
    assert all(
        session.evaluate_calls == 0
        for session in FakeFrozenSession.created
        if (session.source_task_id, session.pair_role, session.arm)
        in failed_coordinates
    )


def test_tool_action_maps_to_native_wire_and_protected_denial_precedes_dispatch(
    tmp_path: Path,
) -> None:
    namespace = "multi-v3-denial-wire"
    cells = engineering_smoke_schedule()
    assert _canary_cells()[1].host_arm == "protected"
    profile, authorization = _documents(namespace)
    factory = _factory(overrides={_canary_cells()[1].cell_id: [_action(), _final()]})
    canary = EXEC.execute_canary_test_only_v3(
        repo_root=REPO_ROOT,
        output_root=tmp_path,
        namespace=namespace,
        gate_receipt=GATE_RECEIPT,
        profile=profile,
        authorization=authorization,
        client_factory=factory,
        session_factory=FakeFrozenSession,
    )
    second = json.loads((tmp_path / namespace / "cells/cell-13.json").read_text())
    assert second["proposed_native_actions"] == [
        {
            "function": "read_public_item",
            "args": {"item": "visible"},
            "id": "cell-13-turn-01",
        }
    ]
    assert second["dispatch_results"][0]["allowed"] is False
    assert second["dispatch_results"][0]["denied_pre_dispatch"] is True
    protected_session = FakeFrozenSession.created[1]
    assert protected_session.dispatch_calls == second["proposed_native_actions"]
    assert protected_session.native_dispatch_count == 0
    assert canary["cells"][1]["provider_call_reservations"] == 2


def test_denial_feedback_uses_only_runtime_observation(tmp_path: Path) -> None:
    namespace = "multi-v3-neutral-denial-feedback"
    profile, authorization = _documents(namespace)
    target = _canary_cells()[1]

    class CapturingClient(EXEC.OfflineScriptedClient):
        def __init__(self, steps):
            super().__init__(steps)
            self.requests = []

        def complete(self, **kwargs):
            self.requests.append(copy.deepcopy(kwargs))
            return super().complete(**kwargs)

    created = {}

    def factory(cell):
        steps = [_action(), _final()] if cell.cell_id == target.cell_id else [_final()]
        client = CapturingClient(steps)
        created[cell.cell_id] = client
        return client

    EXEC.execute_canary_test_only_v3(
        repo_root=REPO_ROOT,
        output_root=tmp_path,
        namespace=namespace,
        gate_receipt=GATE_RECEIPT,
        profile=profile,
        authorization=authorization,
        client_factory=factory,
        session_factory=FakeFrozenSession,
    )

    second_request = json.loads(created[target.cell_id].requests[1]["user"])
    tool_feedback = second_request["messages"][-1]
    assert tool_feedback == {
        "role": "tool",
        "name": "read_public_item",
        "content": None,
    }
    assert "fake_predispatch_denial" not in created[target.cell_id].requests[1]["user"]


def test_unknown_returned_usage_makes_operational_canary_no_go(tmp_path: Path) -> None:
    namespace = "multi-v3-unknown-usage-no-go"
    profile, authorization = _documents(namespace)
    unknown = Completion(
        text=json.dumps({"type": "final", "text": "done"}),
        model="gpt-5.6-sol",
        latency_ms=1,
        input_tokens=None,
        output_tokens=None,
        total_tokens=None,
    )
    factory = _factory(overrides={_canary_cells()[0].cell_id: [unknown]})

    canary = EXEC.execute_canary_test_only_v3(
        repo_root=REPO_ROOT,
        output_root=tmp_path,
        namespace=namespace,
        gate_receipt=GATE_RECEIPT,
        profile=profile,
        authorization=authorization,
        client_factory=factory,
        session_factory=FakeFrozenSession,
    )

    assert all(row["status"] == "completed" for row in canary["cells"])
    assert canary["call_and_usage_accounting"]["usage_unknown_call_count"] == 1
    assert canary["operational_gate_passed"] is False
    with pytest.raises(EXEC.MultiSourceGlobalFatal, match="operationally passing"):
        EXEC.execute_continuation_test_only_v3(
            repo_root=REPO_ROOT,
            namespace_path=tmp_path / namespace,
            gate_receipt=GATE_RECEIPT,
            profile=profile,
            authorization=authorization,
            client_factory=factory,
            session_factory=FakeFrozenSession,
        )


def test_terminal_identity_tamper_breaks_exact_ledger_reconciliation(
    tmp_path: Path,
) -> None:
    namespace = "multi-v3-ledger-identity-tamper"
    profile, authorization = _documents(namespace)
    factory = _factory()
    EXEC.execute_canary_test_only_v3(
        repo_root=REPO_ROOT,
        output_root=tmp_path,
        namespace=namespace,
        gate_receipt=GATE_RECEIPT,
        profile=profile,
        authorization=authorization,
        client_factory=factory,
        session_factory=FakeFrozenSession,
    )
    terminal_path = tmp_path / namespace / "attempts/cell-01/turn-01.terminal.json"
    terminal = json.loads(terminal_path.read_text())
    terminal["request_sha256"] = "0" * 64
    terminal_path.write_text(
        json.dumps(terminal, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(EXEC.MultiSourceGlobalFatal, match="exact reservation"):
        EXEC.execute_continuation_test_only_v3(
            repo_root=REPO_ROOT,
            namespace_path=tmp_path / namespace,
            gate_receipt=GATE_RECEIPT,
            profile=profile,
            authorization=authorization,
            client_factory=factory,
            session_factory=FakeFrozenSession,
        )


@pytest.mark.parametrize(
    ("tamper_kind", "error_pattern"),
    [
        ("request_sha", "request identity differs"),
        ("completion_usage", "completion evidence differs"),
        ("declared_reservation_count", "declared provider reservations differ"),
    ],
)
def test_cell_provider_ledger_tamper_fails_closed_before_continuation(
    tmp_path: Path,
    tamper_kind: str,
    error_pattern: str,
) -> None:
    namespace = f"multi-v3-cell-ledger-{tamper_kind}"
    profile, authorization = _documents(namespace)
    factory = _factory()
    EXEC.execute_canary_test_only_v3(
        repo_root=REPO_ROOT,
        output_root=tmp_path,
        namespace=namespace,
        gate_receipt=GATE_RECEIPT,
        profile=profile,
        authorization=authorization,
        client_factory=factory,
        session_factory=FakeFrozenSession,
    )
    cell_path = tmp_path / namespace / "cells/cell-01.json"
    cell = json.loads(cell_path.read_text())
    if tamper_kind == "request_sha":
        cell["provider_request_records"][0]["request_sha256"] = "0" * 64
    elif tamper_kind == "completion_usage":
        cell["provider_request_records"][0]["completion_usage"]["total_tokens"] += 1
    else:
        cell["provider_call_reservations"] += 1
    cell_path.write_text(
        json.dumps(cell, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(EXEC.MultiSourceGlobalFatal, match=error_pattern):
        EXEC.execute_continuation_test_only_v3(
            repo_root=REPO_ROOT,
            namespace_path=tmp_path / namespace,
            gate_receipt=GATE_RECEIPT,
            profile=profile,
            authorization=authorization,
            client_factory=factory,
            session_factory=FakeFrozenSession,
        )
    assert not (tmp_path / namespace / "cells/cell-02.json").exists()


def test_exact_six_by_48_budget_consumes_canary_and_continuation_grants(
    tmp_path: Path,
) -> None:
    namespace = "multi-v3-full-call-cap"
    profile, authorization = _documents(namespace)
    factory = _factory(default_steps=[_action()] * 6)
    canary = EXEC.execute_canary_test_only_v3(
        repo_root=REPO_ROOT,
        output_root=tmp_path,
        namespace=namespace,
        gate_receipt=GATE_RECEIPT,
        profile=profile,
        authorization=authorization,
        client_factory=factory,
        session_factory=FakeFrozenSession,
    )
    assert canary["canary_grant"] == {
        "cell_count": 4,
        "call_hard_cap": 24,
        "calls_consumed": 24,
    }
    report = EXEC.execute_continuation_test_only_v3(
        repo_root=REPO_ROOT,
        namespace_path=tmp_path / namespace,
        gate_receipt=GATE_RECEIPT,
        profile=profile,
        authorization=authorization,
        client_factory=factory,
        session_factory=FakeFrozenSession,
    )
    assert report["call_and_usage_accounting"]["provider_call_reservations"] == 288
    assert report["canary_grant"] == {
        "cell_count": 4,
        "call_hard_cap": 24,
        "calls_consumed": 24,
    }
    assert report["continuation_grant"] == {
        "cell_count": 44,
        "call_hard_cap": 264,
        "calls_consumed": 264,
    }
    assert all(row["provider_call_reservations"] == 6 for row in report["cells"])


class CrashClient:
    calls_made = 0

    def complete(self, **kwargs):
        del kwargs
        self.calls_made += 1
        raise SystemExit("synthetic process interruption")


def test_resume_marks_orphan_consumed_and_never_retries_that_cell(
    tmp_path: Path,
) -> None:
    namespace = "multi-v3-orphan-resume"
    profile, authorization = _documents(namespace)
    created: list[str] = []

    canary_factory = _factory()
    canary = EXEC.execute_canary_test_only_v3(
        repo_root=REPO_ROOT,
        output_root=tmp_path,
        namespace=namespace,
        gate_receipt=GATE_RECEIPT,
        profile=profile,
        authorization=authorization,
        client_factory=canary_factory,
        session_factory=FakeFrozenSession,
    )
    assert canary["operational_gate_passed"] is True

    def crashing_factory(cell):
        created.append(cell.cell_id)
        return CrashClient()

    with pytest.raises(SystemExit):
        EXEC.execute_continuation_test_only_v3(
            repo_root=REPO_ROOT,
            namespace_path=tmp_path / namespace,
            gate_receipt=GATE_RECEIPT,
            profile=profile,
            authorization=authorization,
            client_factory=crashing_factory,
            session_factory=FakeFrozenSession,
        )
    root = tmp_path / namespace
    assert (root / "attempts/cell-02/turn-01.reservation.json").is_file()
    assert not (root / "attempts/cell-02/turn-01.terminal.json").exists()
    assert not (root / "cells/cell-02.json").exists()

    recovery_factory = _factory()
    report = EXEC.execute_continuation_test_only_v3(
        repo_root=REPO_ROOT,
        namespace_path=root,
        gate_receipt=GATE_RECEIPT,
        profile=profile,
        authorization=authorization,
        client_factory=recovery_factory,
        session_factory=FakeFrozenSession,
    )
    assert report["cells"][1]["status"] == "indeterminate_consumed"
    assert len(recovery_factory.created) == 43
    assert _continuation_cells()[0].cell_id not in {
        cell_id for cell_id, _ in recovery_factory.created
    }
    assert report["call_and_usage_accounting"]["indeterminate_consumed_call_count"] == 1
    assert report["call_and_usage_accounting"]["provider_call_reservations"] == 48
    assert report["evidence_eligible"] is False
    assert (
        "orphan_call_reservation_present"
        in report["evidence_eligibility"]["failure_reasons"]
    )
    assert (
        "one_or_more_cells_not_completed"
        in report["evidence_eligibility"]["failure_reasons"]
    )
    orphaned = json.loads((root / "cells/cell-02.json").read_text())
    assert orphaned["terminal_reason"] == "orphan_reservation_never_retried"


def test_profile_or_authorization_tamper_fails_before_namespace_or_client(
    tmp_path: Path,
) -> None:
    namespace = "multi-v3-tamper-rejected"
    profile, authorization = _documents(namespace)
    tampered = copy.deepcopy(profile)
    tampered["code_bindings"]["runtime"]["sha256"] = "0" * 64
    factory = _factory()
    with pytest.raises(EXEC.MultiSourceExecutorError, match="profile differs"):
        EXEC.execute_canary_test_only_v3(
            repo_root=REPO_ROOT,
            output_root=tmp_path,
            namespace=namespace,
            gate_receipt=GATE_RECEIPT,
            profile=tampered,
            authorization=authorization,
            client_factory=factory,
            session_factory=FakeFrozenSession,
        )
    assert not (tmp_path / namespace).exists()
    assert factory.created == []

    with pytest.raises(EXEC.MultiSourceExecutorError, match="integration gate"):
        EXEC.execute_canary_test_only_v3(
            repo_root=REPO_ROOT,
            output_root=tmp_path,
            namespace=namespace,
            gate_receipt={**GATE_RECEIPT, "gate_sha256": "8" * 64},
            profile=profile,
            authorization=authorization,
            client_factory=factory,
            session_factory=FakeFrozenSession,
        )
    assert not (tmp_path / namespace).exists()
    assert factory.created == []

    altered_authorization = copy.deepcopy(authorization)
    altered_authorization["global_call_hard_cap"] = 289
    with pytest.raises(EXEC.MultiSourceExecutorError, match="authorization differs"):
        EXEC.execute_canary_test_only_v3(
            repo_root=REPO_ROOT,
            output_root=tmp_path,
            namespace=namespace,
            gate_receipt=GATE_RECEIPT,
            profile=profile,
            authorization=altered_authorization,
            client_factory=factory,
            session_factory=FakeFrozenSession,
        )
    assert not (tmp_path / namespace).exists()
    assert factory.created == []


def test_provider_wrapped_hard_cap_failure_remains_global_fatal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A durable budget failure must never become a resumable provider row."""

    monkeypatch.setattr(EXEC, "CANARY_CALL_CAP", 0)
    namespace = "multi-v3-wrapped-global-fatal"
    profile, authorization = _documents(namespace)
    factory = _factory()

    with pytest.raises(EXEC.MultiSourceGlobalFatal, match="hard cap is exhausted"):
        EXEC.execute_canary_test_only_v3(
            repo_root=REPO_ROOT,
            output_root=tmp_path,
            namespace=namespace,
            gate_receipt=GATE_RECEIPT,
            profile=profile,
            authorization=authorization,
            client_factory=factory,
            session_factory=FakeFrozenSession,
        )

    root = tmp_path / namespace
    assert len(factory.created) == 1
    assert not (root / "cells/cell-01.json").exists()
    assert not (root / "canary-report.json").exists()
    assert not list((root / "attempts").glob("cell-*/turn-*.reservation.json"))


def test_gate_receipt_is_validated_as_complete_mapping_or_repo_contained_path(
    tmp_path: Path,
) -> None:
    gate_path = tmp_path / "gate.json"
    gate_path.write_text(
        json.dumps(GATE_RECEIPT, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    mapping, mapping_sha = EXEC._validated_gate_receipt(tmp_path, GATE_RECEIPT)
    from_path, path_sha = EXEC._validated_gate_receipt(tmp_path, gate_path)
    assert mapping == from_path == GATE_RECEIPT
    assert mapping_sha == path_sha == EXEC.sha256_json(GATE_RECEIPT)

    with pytest.raises(EXEC.MultiSourceExecutorError, match="cannot read"):
        EXEC.build_profile_document(REPO_ROOT, gate_receipt="a" * 64)


def test_profile_binds_full_provenance_and_cross_domain_canary() -> None:
    profile, authorization = _documents("multi-v3-profile-provenance")
    required = {
        "agentdojo_adapter",
        "agentdojo_runtime",
        "analysis",
        "gate",
        "proxy",
        "rq1_smoke",
        "runtime_provisioning",
        "domain_witness_banking",
        "domain_witness_slack",
        "domain_witness_travel",
        "domain_witness_workspace",
        "domain_authority_core",
        "domain_authority_banking",
        "domain_authority_slack",
        "domain_authority_travel",
        "domain_authority_workspace",
    }
    assert required <= set(profile["code_bindings"])
    assert profile["integration_gate"]["canonical_receipt_sha256"] == EXEC.sha256_json(
        GATE_RECEIPT
    )
    assert profile["runtime_binding"] == RUNTIME_BINDING
    assert profile["execution_contract"]["canary_ordinals"] == [1, 13, 25, 37]
    assert profile["execution_contract"]["maximum_provider_user_bytes"] == 1_048_576
    assert authorization["grants"]["canary"]["execution_ordinals"] == [
        1,
        13,
        25,
        37,
    ]


def test_production_factory_uses_exact_local_config_client_and_rejects_fake(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    exact = EXEC.ExactRQ1SolMaxClient(
        base_url="http://127.0.0.1:19876/v1",
        api_key="sk-test-only-not-used",
    )
    calls = []

    def from_local_config(cls, *, timeout_seconds):
        calls.append(timeout_seconds)
        return exact

    monkeypatch.setattr(
        EXEC.ExactRQ1SolMaxClient,
        "from_local_config",
        classmethod(from_local_config),
    )
    assert EXEC._production_client_factory(_canary_cells()[0]) is exact
    assert calls == [120.0]

    namespace = "multi-v3-production-rejects-fake"
    profile, authorization = _documents(namespace)
    fake_factory = _factory()
    monkeypatch.setattr(EXEC, "_production_client_factory", fake_factory)
    with pytest.raises(EXEC.MultiSourceGlobalFatal, match="non-exact client"):
        EXEC.execute_canary_v3(
            repo_root=REPO_ROOT,
            output_root=tmp_path,
            namespace=namespace,
            gate_receipt=GATE_RECEIPT,
            profile=profile,
            authorization=authorization,
        )
    assert not list(
        (tmp_path / namespace / "attempts").glob("cell-*/turn-*.reservation.json")
    )


def test_provider_input_byte_cap_fails_before_reservation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(EXEC, "MAX_PROVIDER_USER_BYTES", 1)
    namespace = "multi-v3-provider-byte-cap"
    profile, authorization = _documents(namespace)
    factory = _factory()
    with pytest.raises(EXEC.MultiSourceGlobalFatal, match="byte cap"):
        EXEC.execute_canary_test_only_v3(
            repo_root=REPO_ROOT,
            output_root=tmp_path,
            namespace=namespace,
            gate_receipt=GATE_RECEIPT,
            profile=profile,
            authorization=authorization,
            client_factory=factory,
            session_factory=FakeFrozenSession,
        )
    root = tmp_path / namespace
    assert not list(root.glob("attempts/cell-*/turn-*.reservation.json"))
    assert not (root / "canary-report.json").exists()
