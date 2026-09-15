from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentmembrane.host_v2.original_rq1_v3_artifacts import (
    RQ1V3ArtifactLedger,
    validate_schedule,
)
from tools import run_original_rq1_v3 as runner


def _json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_readiness_audit_is_read_only_and_reports_formal_blockers(
    tmp_path: Path,
) -> None:
    before = tuple(tmp_path.iterdir())
    report = runner.readiness_audit(
        proposal_path=runner.DEFAULT_PROPOSAL,
        development_output=tmp_path / "not-created",
    )
    after = tuple(tmp_path.iterdir())

    assert before == after == ()
    assert report["read_only"] is True
    assert report["scientific_result"] is False
    assert report["ready_for_development_dry_run"] is True
    assert report["ready_for_formal_execution"] is False
    assert "model_and_provider_freeze" in report["formal_blockers"]
    assert report["checks"]["exact_five_by_two_condition_matrix"] is True


def test_canonical_bank_rows_are_consumed_without_schema_projection(
    tmp_path: Path,
) -> None:
    _candidates, _split, rows = runner.build_development_schedule()
    value = [row.to_dict() for row in rows]
    path = tmp_path / "schedule.json"
    path.write_text(json.dumps(value), encoding="utf-8")

    loaded = runner.load_canonical_development_schedule(path)

    assert [row.to_dict() for row in loaded] == value
    assert len(loaded) == 90
    assert {row.bank_id for row in loaded} == {"development"}
    assert {row.authority_level for row in loaded} == {"A0", "A1", "A2", "A3", "A4"}
    assert {row.arm for row in loaded} == {"B1", "M1"}
    assert {row.replicate_id for row in loaded} == {
        "replicate-1",
        "replicate-2",
        "replicate-3",
    }


def test_formal_bank_row_is_rejected_before_execution(tmp_path: Path) -> None:
    _candidates, _split, rows = runner.build_development_schedule()
    value = [row.to_dict() for row in rows]
    value[0]["bank_id"] = "formal_holdout"
    path = tmp_path / "schedule.json"
    path.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(runner.RunnerRefusal, match="formal access is forbidden"):
        runner.load_canonical_development_schedule(path)


def test_runtime_evidence_is_not_signed_before_receipt_verification() -> None:
    class SpyAuthority:
        calls = 0

        def issue(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            self.calls += 1
            raise AssertionError("issue must not be reached")

    payload = {
        "namespace": "development:fixture",
        "initial_state": {},
        "final_state": {},
        "events": [],
        "receipts": [
            {
                "receipt_id": "receipt-1",
                "namespace": "development:fixture",
                "trusted": True,
                "successful": True,
                "caused_by_event_id": "missing-event",
                "sequence": 1,
            }
        ],
    }
    authority = SpyAuthority()

    with pytest.raises(runner.RunnerRefusal, match="receipt verification failed"):
        runner._issue_verified_runtime_evidence(authority, payload)  # type: ignore[arg-type]
    assert authority.calls == 0


def test_fixed_trace_completes_exact_ledger_without_model_calls(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "fixed"
    result = runner.run_fixed_trace(run_dir, proposal_path=runner.DEFAULT_PROPOSAL)
    ledger = RQ1V3ArtifactLedger(run_dir)

    assert result["pc0_activation"]["exact_oracle_witness"] is True
    assert result["blocked_episode_count"] == result["scheduled_episode_count"] == 10
    assert result["model_calls"] == 0
    assert result["formal_payload_access"] is False
    assert ledger.state()["state"] == "COMPLETE"
    assert ledger.audit_complete_schedule()["exact"] is True
    assert not list((run_dir / "attempts").glob("*/*.json"))
    assert not (run_dir / "formal-unseal-receipt.json").exists()
    assert "not an RQ1 scientific result" in (run_dir / "REPORT.md").read_text()


def test_adaptive_fake_reserves_then_persists_and_uses_source_adapter(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "adaptive"
    result = runner.run_adaptive_fake(run_dir, proposal_path=runner.DEFAULT_PROPOSAL)
    ledger = RQ1V3ArtifactLedger(run_dir)
    manifest = ledger.manifest()
    schedule_audit = validate_schedule(run_dir, manifest)

    assert result["scheduled_episode_count"] == result["fake_provider_calls"] == 90
    assert result["real_provider_calls"] == 0
    assert result["canonical_schedule_consumed_directly"] is True
    assert result["reservation_before_every_dispatch"] is True
    assert result["lossless_response_bytes_persisted"] is True
    assert result["runtime_evidence_verified_before_authority_issue"] is True
    assert result["source_adapter_rows"] == result["source_adapter_utility_successes"] == 30
    assert schedule_audit["row_count"] == 90
    assert ledger.state()["state"] == "COMPLETE"
    assert ledger.unresolved_attempt_keys() == ()
    assert len(list((run_dir / "attempt-reservations").glob("*/*.json"))) == 90
    assert len(list((run_dir / "attempts").glob("*/*.json"))) == 90
    assert not (run_dir / "formal-content-access.json").exists()
    assert not (run_dir / "formal-unseal-receipt.json").exists()
    assert "in-process fake" in (run_dir / "REPORT.md").read_text()


def test_development_outputs_are_immutable(tmp_path: Path) -> None:
    run_dir = tmp_path / "fixed"
    runner.run_fixed_trace(run_dir, proposal_path=runner.DEFAULT_PROPOSAL)

    with pytest.raises(runner.RunnerRefusal, match="refusing overwrite"):
        runner.run_fixed_trace(run_dir, proposal_path=runner.DEFAULT_PROPOSAL)


def test_combined_dry_run_reports_work_done_and_remaining(tmp_path: Path) -> None:
    output = tmp_path / "dry-run"
    result = runner.run_development_dry_run(
        output, proposal_path=runner.DEFAULT_PROPOSAL
    )

    assert result["scientific_result"] is False
    assert result["real_provider_calls"] == 0
    assert result["formal_payload_access"] is False
    assert result["fixed_trace"]["coverage"]["exact"] is True
    assert result["adaptive_fake"]["coverage"]["exact"] is True
    assert result["postflight"]["stages"][2]["status"] == "development_executed"
    assert result["postflight"]["stages"][4]["status"] == "development_executed"
    report = (output / "REPORT.md").read_text(encoding="utf-8")
    assert "What is now working" in report
    assert "What is not done" in report
    assert "No scientific RQ1 result" in report


def test_machine_outputs_carry_explicit_nonclaim_boundary(tmp_path: Path) -> None:
    run_dir = tmp_path / "adaptive"
    runner.run_adaptive_fake(run_dir, proposal_path=runner.DEFAULT_PROPOSAL)
    result = _json(run_dir / "results.json")

    assert result["scientific_result"] is False
    assert result["development_only"] is True
    assert result["formal_payload_access"] is False
    assert result["real_provider_calls"] == 0
