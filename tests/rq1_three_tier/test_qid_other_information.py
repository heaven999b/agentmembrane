"""Private information subset controls; no model or proxy calls."""
import json
import os
from pathlib import Path

from agentmembrane.host_v2.rq1_collab_v1.native import NativeTask
from agentmembrane.host_v2.rq1_measurement_v1.qid_other_information import score_e_private_subset


ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(os.environ.get(
    "AGENTDOJO_SOURCE_ROOT",
    str(ROOT / "data/host_boundary_v2/upstream/agentdojo"),
))
DRAFTS = ROOT / "experiments/host_boundary_v2/rq1_three_tier_large_scale/qid_contract_drafts_other_001/drafts.json"


def _case(suite, task_id, tool, args):
    task = NativeTask(str(SOURCE), suite, task_id)
    before = task.snapshot()
    result = task.call(tool, args)
    assert result["error"] is None
    call = {"call_id": "case:1", "tool": tool, "arguments": args,
            "result": result["result"], "status": "committed",
            "record_origin": "trusted_native_adapter",
            "evidence_quality": result["evidence_quality"]}
    delivery = {"actor": "E", "status": "model_response_observed", "event_id": "delivery:1",
                "payload": {"actor": "E", "history": [{"status": "tool_result", "call_id": "case:1",
                                                      "result": result["result"]}]}}
    key = f"{suite}/{task_id}"
    return key, before, task.record, call, delivery


def test_exact_subset_denominators_and_native_receipts():
    cases = [
        ("banking", "user_task_3", "get_user_info", {}, 5, 4),
        ("slack", "user_task_5", "read_inbox", {"user": "Bob"}, 4, 3),
        ("travel", "user_task_3", "get_user_information", {}, 6, 6),
    ]
    for suite, task_id, tool, args, denominator, received in cases:
        key, before, record, call, delivery = _case(suite, task_id, tool, args)
        score = score_e_private_subset(key, before, record, [call], [delivery])
        assert score["registered_subset_denominator"] == denominator
        assert score["confirmed_exposed"] == received
        assert score["I_full"] is None and score["subset_rate_upper"] == 1.0
        assert all("value" not in row for row in score["confirmed_receipts"])


def test_all_22_registered_subsets_are_stable_but_full_i_is_unknown():
    rows = json.loads(DRAFTS.read_text())["tasks"]
    assert len(rows) == 22
    total = 0
    for row in rows:
        suite, task_id = row["task_key"].split("/")
        task = NativeTask(str(SOURCE), suite, task_id)
        score = score_e_private_subset(row["task_key"], task.snapshot(), task.record, [], [])
        expected = {"banking": 5, "slack": 4, "travel": 6}[suite]
        assert score["registered_subset_denominator"] == expected
        assert score["I_full"] is None and score["subset_rate_upper"] == 1.0
        total += expected
    assert total == 120


def test_denominator_preserved_but_no_zero_leakage_claim_for_unobserved_receipt():
    key, before, record, call, delivery = _case("travel", "user_task_3", "get_user_information", {})
    queued = {**delivery, "status": "queued"}
    score = score_e_private_subset(key, before, record, [call], [queued])
    assert score["registered_subset_denominator"] == 6
    assert score["confirmed_exposed"] == 0 and score["I_full"] is None
    assert score["subset_rate_lower"] == 0 and score["subset_rate_upper"] == 1.0
    denied = {**call, "status": "rejected"}
    score = score_e_private_subset(key, before, record, [denied], [delivery])
    assert score["confirmed_exposed"] == 0 and score["I_full"] is None
    host = {**delivery, "actor": "H", "payload": {**delivery["payload"], "actor": "H"}}
    score = score_e_private_subset(key, before, record, [call], [host])
    assert score["confirmed_exposed"] == 0 and score["I_full"] is None


def test_source_byte_tamper_makes_information_denominator_unknown():
    key, before, record, call, delivery = _case("banking", "user_task_3", "get_user_info", {})
    altered = {**record, "source_file_sha256": "0" * 64}
    score = score_e_private_subset(key, before, altered, [call], [delivery])
    assert score["registered_subset_denominator"] is None
    assert score["confirmed_exposed"] is None
