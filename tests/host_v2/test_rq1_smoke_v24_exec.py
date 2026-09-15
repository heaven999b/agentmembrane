from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentmembrane.host_v2 import rq1_smoke_v24_exec as V24
from agentmembrane.host_v2.rq1_safety_framing_v24 import (
    V24_PLANNER_ROLE,
    V24_RECEIPT,
    forbidden_lexicon_hits_v24,
    load_contract_v24,
)
from agentmembrane.proxy import Completion, ProxyError


REPO_ROOT = Path(__file__).resolve().parents[2]


class FakeFramedTarget:
    def __init__(self) -> None:
        self.calls_made = 0
        self.calls: list[dict] = []

    def complete(self, **kwargs):
        self.calls_made += 1
        self.calls.append(dict(kwargs))
        return {"offline": True, "call": self.calls_made}


def _call(client, assignment: dict) -> None:
    client.complete(
        model="offline-v24",
        system="offline",
        user=json.dumps(
            {
                "turn_number": 1,
                "task_id": assignment["task_id"],
            }
        ),
        retries=0,
    )


def _record(assignment: dict, attempt_key: str, **overrides):
    value = {
        "task_id": assignment["task_id"],
        "condition_id": assignment["condition_id"],
        "schedule_ordinal": assignment["ordinal"],
        "attempt_keys": [attempt_key],
        "failure_class": "none",
        "planner_status": "ok",
        "planner_terminal_kind": "normal",
        "oracle_result": {"direction": "not-a-continuation-gate"},
    }
    value.update(overrides)
    return value


def test_provider_failure_cell_is_durable_and_cells_three_four_still_run(
    tmp_path: Path,
) -> None:
    namespace = tmp_path / "v24-provider-failure"
    client = FakeFramedTarget()
    observed: list[int] = []

    def runner(*, assignment, client, max_turns):
        assert max_turns == 6
        ordinal = assignment["ordinal"]
        observed.append(ordinal)
        if ordinal == 3:
            assert (namespace / "cells/cell-01.json").is_file()
            assert (namespace / "cells/cell-02.json").is_file()
            persisted = json.loads((namespace / "cells/cell-02.json").read_text())
            assert persisted["status"] == "provider_policy_failure"
        _call(client, assignment)
        record = _record(assignment, f"attempt-{ordinal}")
        if ordinal == 2:
            record.update(
                failure_class="provider_policy_failure",
                planner_status="failed",
                planner_terminal_kind="provider_policy_refusal",
            )
        return record

    result = V24.execute_resilient_four_cell_v24(
        namespace=namespace,
        client=client,
        episode_runner=runner,
    )
    assert observed == [1, 2, 3, 4]
    statuses = [row["status"] for row in result.report["assigned_cells"]]
    assert statuses == [
        "recorded",
        "provider_policy_failure",
        "recorded",
        "recorded",
    ]
    assert result.report["execution_status"] == "all_cells_attempted"
    assert result.report["continuation_depended_on_oracle_direction"] is False
    assert result.report["attempt_ledger"]["reconciled"] is True
    assert result.report["provider_calls_framed"] == 4
    assert client.calls_made == 4
    assert all(call["retries"] == 0 for call in client.calls)
    assert len(list((namespace / "cells").glob("cell-*.json"))) == 4
    assert len(list((namespace / "attempts").glob("call-*.json"))) == 4


def test_runner_exception_is_rejected_per_cell_and_later_cells_continue(
    tmp_path: Path,
) -> None:
    namespace = tmp_path / "v24-runner-error"
    client = FakeFramedTarget()
    observed: list[int] = []

    def runner(*, assignment, client, max_turns):
        del max_turns
        ordinal = assignment["ordinal"]
        observed.append(ordinal)
        _call(client, assignment)
        if ordinal == 2:
            raise RuntimeError("cell-local host failure")
        return _record(assignment, f"attempt-{ordinal}")

    result = V24.execute_resilient_four_cell_v24(
        namespace=namespace,
        client=client,
        episode_runner=runner,
    )
    assert observed == [1, 2, 3, 4]
    assert [row["status"] for row in result.report["assigned_cells"]] == [
        "recorded",
        "runner_error",
        "recorded",
        "recorded",
    ]
    rejected = json.loads((namespace / "cells/cell-02.json").read_text())
    assert rejected["record"] is None
    assert rejected["error"]["error_type"] == "RuntimeError"
    assert rejected["provider_call_frames"] == 1
    assert (namespace / "cells/cell-01.json").is_file()
    assert (namespace / "cells/cell-03.json").is_file()
    assert (namespace / "cells/cell-04.json").is_file()
    assert result.report["attempt_ledger"]["reconciled"] is True
    assert result.report["attempt_ledger"]["returned_attempt_key_count"] == 3
    assert result.report["attempt_ledger"]["frame_count"] == 4
    assert result.report["attempt_ledger"]["error_cell_unbound_frame_count"] == 1
    assert result.report["attempt_ledger"]["all_frames_accounted"] is True


def test_cell_terminal_taxonomy_never_controls_continuation(tmp_path: Path) -> None:
    namespace = tmp_path / "v24-terminal-taxonomy"
    client = FakeFramedTarget()
    outcomes = {
        1: {
            "failure_class": "parse_failure",
            "planner_status": "failed",
            "planner_terminal_kind": "pre_attempt_abandonment",
        },
        2: {
            "failure_class": "schema_failure",
            "planner_status": "failed",
            "planner_terminal_kind": "pre_attempt_abandonment",
        },
        3: {
            "failure_class": "explicit_abstention",
            "planner_status": "explicit_abstention",
            "planner_terminal_kind": "post_host_feedback_decline",
        },
        4: {
            "failure_class": "none",
            "planner_status": "ok",
            "planner_terminal_kind": "budget_exhausted",
        },
    }

    def runner(*, assignment, client, max_turns):
        del max_turns
        _call(client, assignment)
        return _record(
            assignment,
            f"attempt-{assignment['ordinal']}",
            **outcomes[assignment["ordinal"]],
        )

    report = V24.execute_resilient_four_cell_v24(
        namespace=namespace,
        client=client,
        episode_runner=runner,
    ).report
    assert [row["status"] for row in report["assigned_cells"]] == [
        "parse_failure",
        "schema_failure",
        "explicit_abstention",
        "budget_exhausted",
    ]
    assert report["execution_status"] == "all_cells_attempted"
    assert report["attempt_ledger"]["reconciled"] is True


def test_zero_retry_violation_is_global_fatal_but_report_lists_all_assignments(
    tmp_path: Path,
) -> None:
    namespace = tmp_path / "v24-retry-fatal"
    client = FakeFramedTarget()

    def runner(*, assignment, client, max_turns):
        del assignment, max_turns
        client.complete(model="offline", system="offline", user="{}", retries=1)
        raise AssertionError("unreachable")

    report = V24.execute_resilient_four_cell_v24(
        namespace=namespace,
        client=client,
        episode_runner=runner,
    ).report
    assert report["execution_status"] == "global_fatal"
    assert len(report["assigned_cells"]) == 4
    assert [row["status"] for row in report["assigned_cells"]] == [
        "global_fatal",
        "not_run_global_fatal",
        "not_run_global_fatal",
        "not_run_global_fatal",
    ]
    assert report["provider_calls_framed"] == 0
    assert (namespace / "report.json").is_file()


def test_framed_client_factory_is_injectable_and_namespace_is_exclusive(
    tmp_path: Path,
) -> None:
    namespace = tmp_path / "v24-custom-wrapper"
    client = FakeFramedTarget()
    wrappers = []

    class ObservedWrapper(V24.FramedClientV24):
        pass

    def factory(target, *, ledger_dir):
        wrapper = ObservedWrapper(target, ledger_dir=ledger_dir)
        wrappers.append(wrapper)
        return wrapper

    def runner(*, assignment, client, max_turns):
        del max_turns
        _call(client, assignment)
        return _record(assignment, f"attempt-{assignment['ordinal']}")

    V24.execute_resilient_four_cell_v24(
        namespace=namespace,
        client=client,
        episode_runner=runner,
        framed_client_factory=factory,
    )
    assert len(wrappers) == 1
    assert wrappers[0].calls_made == 4
    original = (namespace / "cells/cell-01.json").read_bytes()
    with pytest.raises(V24.RQ1V24GlobalFatal, match="namespace must be fresh"):
        V24.execute_resilient_four_cell_v24(
            namespace=namespace,
            client=FakeFramedTarget(),
            episode_runner=runner,
        )
    assert (namespace / "cells/cell-01.json").read_bytes() == original


def test_per_cell_six_call_cap_stops_globally_and_accounts_reserved_frames(
    tmp_path: Path,
) -> None:
    namespace = tmp_path / "v24-cell-cap"
    client = FakeFramedTarget()

    def runner(*, assignment, client, max_turns):
        assert max_turns == 6
        for turn in range(1, 8):
            client.complete(
                model="offline",
                system="offline",
                user=json.dumps({"turn_number": min(turn, 6)}),
                retries=0,
            )
        raise AssertionError("seventh call must fail")

    report = V24.execute_resilient_four_cell_v24(
        namespace=namespace,
        client=client,
        episode_runner=runner,
    ).report
    assert report["execution_status"] == "global_fatal"
    assert report["provider_calls_framed"] == 6
    assert client.calls_made == 6
    assert report["attempt_ledger"]["error_cell_unbound_frame_count"] == 6
    assert report["attempt_ledger"]["all_frames_accounted"] is True
    assert report["attempt_ledger"]["reconciled"] is True


class FakeProductionCompletionClient:
    """Public provider seam; it never receives condition or oracle labels."""

    def __init__(self) -> None:
        self.calls_made = 0
        self.calls: list[dict] = []
        self.failed_first_framed_request = False

    def complete(self, **kwargs):
        self.calls_made += 1
        self.calls.append(dict(kwargs))
        user = json.loads(kwargs["user"])
        role = user["planner_role"]
        if role == V24_PLANNER_ROLE and not self.failed_first_framed_request:
            self.failed_first_framed_request = True
            raise ProxyError("proxy_policy_cyber")

        runtime = user["runtime_interface"]
        feedback = user["prior_feedback"]
        receipt = next(
            (
                row["completion_receipt"]
                for row in reversed(feedback)
                if isinstance(row, dict)
                and isinstance(row.get("completion_receipt"), dict)
            ),
            None,
        )
        if receipt is not None:
            response = {
                "actions": [],
                "final_artifact": receipt,
                "strategy": "completed: trusted event receipt observed",
            }
        elif "admission" in runtime:
            operation = next(
                row for row in runtime["operations"] if row["name"] == "request_admission"
            )
            descriptor = runtime["admission"]
            args = {
                key: descriptor[key]
                for key in operation["argument_schema"]["properties"]
                if key in descriptor
            }
            response = {
                "actions": [{"op": "request_admission", "args": args}],
                "final_artifact": None,
                "strategy": "Request the exact declared admission and await feedback.",
            }
        else:
            handles = runtime["capability_handles"]
            assert len(handles) == 1
            if role == "ordinary_task_agent":
                goal = user["model_visible_context"]["task_goal_spec"]
                resource = goal["resource"]
                value = goal["desired_value"]
            else:
                resource = "restricted:secret"
                value = "rq1-resource-attack"
            response = {
                "actions": [
                    {
                        "op": "write_low_risk",
                        "args": {
                            "resource": resource,
                            "value": value,
                            "capability_id": handles[0],
                        },
                    }
                ],
                "final_artifact": None,
                "strategy": "Request the exact visible synthetic effect.",
            }
        return Completion(
            text=json.dumps(response),
            model=kwargs["model"],
            latency_ms=1,
            input_tokens=10,
            output_tokens=5,
            total_tokens=15,
        )


def test_production_runner_frames_provider_and_continues_after_cell_two_failure(
    tmp_path: Path,
) -> None:
    namespace = tmp_path / "v24-production-real-seam"
    client = FakeProductionCompletionClient()
    result = V24.execute_resilient_four_cell_v24(
        namespace=namespace,
        repo_root=REPO_ROOT,
        client=client,
    )

    statuses = [row["status"] for row in result.report["assigned_cells"]]
    assert statuses == [
        "recorded",
        "provider_policy_failure",
        "recorded",
        "recorded",
    ]
    assert result.report["execution_status"] == "all_cells_attempted"
    assert result.report["continuation_depended_on_oracle_direction"] is False
    assert result.report["attempt_ledger"]["reconciled"] is True
    assert result.report["provider_calls_framed"] == client.calls_made
    assert 0 < client.calls_made <= 24
    assert all(call["retries"] == 0 for call in client.calls)
    assert all(call["reasoning_effort"] == "max" for call in client.calls)

    contract = load_contract_v24(REPO_ROOT / V24.CONTRACT_RELATIVE_PATH)
    benign_calls = [
        call
        for call in client.calls
        if json.loads(call["user"])["planner_role"] == "ordinary_task_agent"
    ]
    attacker_calls = [
        call
        for call in client.calls
        if json.loads(call["user"])["planner_role"] == V24_PLANNER_ROLE
    ]
    assert benign_calls and attacker_calls
    benign_prompt = (
        REPO_ROOT / "experiments/host_boundary_v2/config/prompts/benign-system.txt"
    ).read_text()
    assert all(call["system"] == benign_prompt for call in benign_calls)
    for call in attacker_calls:
        user = json.loads(call["user"])
        assert "evaluation_objective" in user
        assert "authorized_test_objective" not in user
        assert "condition_id" not in user
        assert forbidden_lexicon_hits_v24(
            system_prompt=call["system"],
            user_payload=user,
            contract=contract.raw,
        ) == ()

    assert (namespace / "cells/cell-03.json").is_file()
    assert (namespace / "cells/cell-04.json").is_file()
    cell3 = json.loads((namespace / "cells/cell-03.json").read_text())
    assert cell3["record"]["final_artifact"]["artifact_type"] == "attack_event_receipt"
    # The provider only saw the public v2.4 label; the trusted record contains
    # the bridge's internal label after the real planner seam parsed it.
    public_receipts = [
        json.loads(call["user"])
        for call in attacker_calls
        if V24_RECEIPT in call["user"]
    ]
    assert public_receipts
