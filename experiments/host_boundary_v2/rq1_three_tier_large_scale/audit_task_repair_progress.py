"""Write a per-original-task repair ledger from a fresh offline readiness run.

The ledger never promotes a development interface check to formal admission.
No provider or model is used.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentmembrane.host_v2.rq1_collab_v1.audit import canonical, strict_loads
from agentmembrane.host_v2.rq1_measurement_v1.references import source_catalog


def audit(readiness_rows: Path, output: Path) -> dict:
    rows = strict_loads(readiness_rows.read_bytes())
    if type(rows) is not list or len(rows) != 86:
        raise ValueError("expected_86_independent_original_task_rows")
    reviewed = set(source_catalog())
    root = Path(__file__).resolve().parent
    workspace_drafts = strict_loads((root / "qid_contract_drafts_workspace_001/contracts.json").read_bytes())
    other_drafts = strict_loads((root / "qid_contract_drafts_other_001/drafts.json").read_bytes())["tasks"]
    diagnostic = reviewed | {row["task_key"] for row in workspace_drafts} | {
        row["task_key"] for row in other_drafts}
    if len(reviewed) != 6 or len(diagnostic) != 46:
        raise ValueError("unexpected_QID_registration_catalog")
    result = []
    for row in rows:
        key = row["suite"] + "/" + row["task_id"]
        blockers = list(row["blockers"])
        if row["engineering_interface_ready"] is not True:
            blockers.append("owner_workflow_permission_path_not_ready")
        if row["strict_checker_ready"] is not True:
            blockers.append("strict_original_task_checker_not_ready")
        if key not in reviewed:
            blockers.append("Q_I_D_full_contract_not_reviewed")
        # Native process/readiness and legacy Q/I/D status cannot alone prove
        # source authorization, full endpoint closure, or fresh formal run.
        blockers.append("formal_source_authorization_and_endpoint_gate_pending")
        result.append({"task_key": key,
                       "goal_id": row["goal_id"],
                       "source_candidate": row["source_candidate"],
                       "technical_policy_instantiable": row.get("technical_policy_instantiable", False),
                       "owner_workflow_executable": row.get("owner_workflow_executable"),
                       "engineering_interface_ready": row["engineering_interface_ready"],
                       "strict_checker_ready": row["strict_checker_ready"],
                       "legacy_reviewed_QID": key in reviewed,
                       "diagnostic_QID_draft": key in diagnostic,
                       "formal_admitted": False,
                       "blockers": sorted(set(blockers))})
    if len({row["task_key"] for row in result}) != 86:
        raise ValueError("duplicate_original_task_in_readiness")
    result.sort(key=lambda row: (row["task_key"].split("/")[0],
                                 int(row["task_key"].rsplit("_", 1)[1])))
    summary = {"independent_original_tasks": len(result),
               "technical_policy_instantiable": sum(row["technical_policy_instantiable"] is True
                                                      for row in result),
               "owner_workflow_executable": sum(row["owner_workflow_executable"] is True
                                                  for row in result),
               "engineering_interface_ready": sum(row["engineering_interface_ready"] is True
                                                  for row in result),
               "strict_checker_ready": sum(row["strict_checker_ready"] is True
                                           for row in result),
               "legacy_reviewed_QID": sum(row["legacy_reviewed_QID"] for row in result),
               "diagnostic_QID_draft": sum(row["diagnostic_QID_draft"] for row in result),
               "formal_admitted": 0,
               "interpretation": "offline_task_repair_ledger_not_a_formal_admission"}
    output.mkdir(parents=True, exist_ok=False)
    (output / "rows.json").write_bytes(canonical(result) + b"\n")
    (output / "summary.json").write_bytes(canonical(summary) + b"\n")
    header = ["# RQ1 三档权限：86 道独立原题逐题修复账本", "",
              "本账本由 fresh 离线 readiness 结果生成；‘接口可用’或诊断观察器不等于正式准入。", "",
              "| 原题 | 技术策略 | 原题权限闭环 | 严格原题评分 | Q/I/D诊断草案 | 正式准入 | 主要阻塞 |",
              "| --- | --- | --- | --- | --- | --- | --- |"]
    for row in result:
        primary = ", ".join(row["blockers"][:3])
        header.append("| " + " | ".join((row["task_key"],
            "是" if row["technical_policy_instantiable"] else "否",
            "是" if row["engineering_interface_ready"] else "否",
            "是" if row["strict_checker_ready"] else "否",
            "是" if row["diagnostic_QID_draft"] else "否",
            "否", primary)) + " |")
    (output / "README.md").write_text("\n".join(header) + "\n", encoding="utf-8")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("readiness_rows", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    print(json.dumps(audit(args.readiness_rows, args.output), ensure_ascii=False))
