"""Executable read-only public-source audits; discovery is not admission.

Original program evaluation is a private source-consistency check, never a new
answer dataset. Runtime products are confined to the requested output directory.
"""
from __future__ import annotations

import argparse
import ast
import calendar
from collections import Counter
import contextlib
import io
import json
from pathlib import Path
import sqlite3
import sys
from .native import file_digest, digest


def _load_functions(path: Path, names: set[str]) -> dict:
    """Load only reviewed original numerical checker functions, not CLI code."""
    module = ast.parse(path.read_text())
    nodes = [n for n in module.body if isinstance(n, ast.FunctionDef) and n.name in names]
    if {n.name for n in nodes} != names:
        raise ValueError("original checker function set changed")
    namespace = {"all_ops": ["add", "subtract", "multiply", "divide", "exp", "greater",
                              "table_max", "table_min", "table_sum", "table_average"]}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


def _finqa(base: Path) -> dict:
    path = base / "source_cache_round3/L04_local_answer/finqa_dev.json"
    checker = path.with_name("finqa_evaluate.py")
    records = json.loads(path.read_text())
    functions = _load_functions(checker, {"str_to_num", "process_row", "eval_program", "program_tokenization"})
    audits = []
    for task in records:
        qa = task.get("qa", {})
        complete = all(key in task for key in ("pre_text", "post_text", "table", "id")) and all(
            key in qa for key in ("question", "program", "exe_ans"))
        error, calculated = functions["eval_program"](functions["program_tokenization"](qa.get("program", "")), task.get("table", []))
        expected = qa.get("exe_ans")
        equal = error == 0 and (calculated == expected or
            isinstance(calculated, (int, float)) and isinstance(expected, (int, float)) and abs(calculated - expected) <= 1e-5)
        audits.append({"id": task["id"], "original_material_complete": complete,
                       "program_executes": error == 0, "program_matches_exe_ans": equal,
                       "report_group": "/".join(task["id"].split("/")[:2])})
    return {"source": "FinQA", "source_sha256": file_digest(path),
            "expected_sha256": "a847fb7e0d61a3125a1e2909852df6b89f1ee64d2c5ff1bf689e332214deee51",
            "checksum_matches_design": file_digest(path) == "a847fb7e0d61a3125a1e2909852df6b89f1ee64d2c5ff1bf689e332214deee51",
            "checker_sha256": file_digest(checker), "records": len(records),
            "complete_material_records": sum(r["original_material_complete"] for r in audits),
            "program_executed_records": sum(r["program_executes"] for r in audits),
            "program_matches_exe_ans_records": sum(r["program_matches_exe_ans"] for r in audits),
            "report_groups": len({r["report_group"] for r in audits}), "task_checks": audits,
            "admitted": 0, "runtime_adapter_ready": False,
            "blockers": ["task_semantics_units_and_known_errata_not_yet_independently_closed",
                         "actor_material_adapter_and_strict_numeric_unit_scorer_not_implemented",
                         "formal_group_split_and_paired_runtime_not_verified"]}


def _hotpot(cache: Path) -> dict:
    path = cache / "hotpot_fullwiki_validation.parquet"
    deps = cache / "eval_deps"
    if str(deps) not in sys.path:
        sys.path.insert(0, str(deps))
    import pyarrow.parquet as pq
    table = pq.read_table(path)
    rows = table.to_pylist()
    ids = [row.get("id", row.get("_id")) for row in rows]
    corpus = cache / "hotpot_abstracts.tar.bz2"
    expected = 1553565403
    complete = corpus.stat().st_size == expected
    return {"source": "HotpotQA_fullwiki", "source_sha256": file_digest(path),
            "checksum_matches_design": file_digest(path) == "78933c0a31a5f7b420d4effdf4cd4eed573b28c6a3da6179dcf7a02b39e51d03",
            "records_read": len(rows), "unique_ids": len(set(ids)), "columns": table.column_names,
            "questions_present": sum(bool(row.get("question")) for row in rows),
            "answers_present": sum(bool(row.get("answer")) for row in rows),
            "corpus_bytes": corpus.stat().st_size, "expected_corpus_bytes": expected,
            "corpus_size_complete": complete, "admitted": 0, "runtime_adapter_ready": False,
            "blockers": ["fullwiki_corpus_incomplete" if not complete else "fullwiki_corpus_checksum_not_verified",
                         "full_corpus_index_retrieval_open_adapter_not_implemented",
                         "group_split_and_independent_strict_scorer_not_verified"],
            "support_documents_are_not_a_fullwiki_retrieval_replacement": True}


def _crm(cache: Path) -> dict:
    database, source = cache / "crmarena_data.db", cache / "crmarena_tasks.json"
    tasks = json.loads(source.read_text())
    by_id = {t["idx"]: t for t in tasks}
    connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    tables = [r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    counts = {name: connection.execute('SELECT count(*) FROM "' + name.replace('"', '""') + '"').fetchone()[0] for name in tables}
    query = "SELECT substr(c.CreatedDate,6,2) AS month,count(*) AS n FROM 'Case' c JOIN OrderItem oi ON c.OrderItemId__c=oi.Id WHERE oi.Product2Id=? AND c.CreatedDate >= ? AND c.CreatedDate < ? GROUP BY month ORDER BY n DESC"
    checks = []
    for idx, product, start, end in ((130, "01tWs000002wQXGIA2", "2021-11-20", "2022-08-21"),
                                     (131, "01tWs000002wRgEIAU", "2019-04-23", "2020-02-24")):
        rows = [dict(r) for r in connection.execute(query, (product, start, end))]
        unique = bool(rows) and (len(rows) == 1 or rows[0]["n"] > rows[1]["n"])
        computed = calendar.month_name[int(rows[0]["month"])] if rows else None
        checks.append({"task_id": idx, "query": query, "parameters": [product, start, end],
                       "rows": rows, "unique_maximum": unique, "matches_original_answer": unique and computed == by_id[idx]["answer"]})
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    connection.close()
    return {"source": "CRMArena", "database_sha256": file_digest(database),
            "checksum_matches_design": file_digest(database) == "42cf7585e8491f3859a1caef17944ad04660fe24bc353722904b45dd991d336a",
            "task_sha256": file_digest(source), "records": len(tasks),
            "task_family_counts": dict(Counter(t["task"] for t in tasks)),
            "exact_match_records": sum(t["reward_metric"] == "exact_match" for t in tasks),
            "tables": counts, "integrity_check": integrity, "recomputed_development_tasks": checks,
            "base_worlds": 1, "admitted": 0, "runtime_adapter_ready": False,
            "blockers": ["local_SQLite_equivalent_of_native_Salesforce_tool_connector_not_implemented",
                         "request_only_authorization_and_read_result_hooks_not_integrated",
                         "private_original_scorer_and_paired_runtime_not_verified"]}


def _appworld(root: Path) -> dict:
    source = root / "data"
    splits = {p.stem: [line for line in p.read_text().splitlines() if line.strip()]
              for p in sorted((source / "datasets").glob("*.txt"))}
    ids = {t for values in splits.values() for t in values}
    tasks = [p for p in (source / "tasks").iterdir() if p.is_dir() and (p / "specs.json").is_file()]
    specs = []
    for path in tasks:
        spec = json.loads((path / "specs.json").read_text())
        specs.append({"id": path.name, "generator_group": path.name.rsplit("_", 1)[0],
                      "spec_sha256": digest(spec), "instruction_present": bool(spec.get("instruction")),
                      "diff_file_count": len(list((path / "dbs").glob("*.jsonl"))),
                      "native_evaluator_present": (path / "ground_truth/evaluation.py").is_file()})
    databases = []
    for db in sorted((source / "base_dbs").glob("*.db")):
        con = sqlite3.connect(db.as_uri() + "?mode=ro", uri=True)
        tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        databases.append({"name": db.name, "sha256": file_digest(db), "table_count": len(tables),
                          "integrity": con.execute("PRAGMA quick_check").fetchone()[0]})
        con.close()
    # Restore one original, explicitly development-exposed task in memory with
    # original upstream DB change statements. Never write the public base DB.
    task = source / "tasks/07bb666_1"
    original = sqlite3.connect((source / "base_dbs/amazon.db").as_uri() + "?mode=ro", uri=True)
    restored = sqlite3.connect(":memory:")
    original.backup(restored)
    original.close()
    statements = 0
    for line in (task / "dbs/amazon.jsonl").read_text().splitlines():
        statement, params, many = json.loads(line)
        # Original public trusted fixture only; no model SQL/code is executed.
        if not statement.upper().startswith(("INSERT ", "UPDATE ", "DELETE ")):
            raise ValueError("unexpected source fixture SQL")
        (restored.executemany if many else restored.execute)(statement, params)
        statements += 1
    restored.commit()
    rows = list(restored.execute("SELECT c.product_id,c.quantity,p.rating FROM cart_entries c JOIN products p ON p.id=c.product_id WHERE c.user_id=7 ORDER BY c.product_id"))
    restored.close()
    return {"source": "AppWorld", "data_version": (source / "version.txt").read_text().strip(),
            "task_directories_with_specs": len(specs), "split_unique_ids": len(ids),
            "split_counts": {k: len(v) for k, v in splits.items()},
            "registered_generator_groups": len({t.rsplit("_", 1)[0] for t in ids}),
            "directory_generator_groups_including_non_tasks": len({s["generator_group"] for s in specs}),
            "unregistered_directories_excluded": sorted(s["id"] for s in specs if s["id"] not in ids),
            "all_split_ids_present": ids <= {s["id"] for s in specs},
            "task_checks": specs, "databases": databases,
            "development_restore": {"task_id": "07bb666_1", "db": "amazon", "original_diff_statements": statements,
                                    "cart_count": len(rows), "below_4_2_count": sum(r[2] < 4.2 for r in rows),
                                    "native_API_executed": False, "native_evaluator_executed": False},
            "admitted": 0, "runtime_adapter_ready": False,
            "blockers": ["original_API_engine_and_private_evaluator_not_integrated",
                         "restored_DB_is_not_native_task_completion",
                         "permission_resource_hooks_and_all_task_semantics_not_verified"],
            "redistribution_notice": "Do not publish unencrypted source data or private gold bundles."}


def audit_public_sources(project_root: str, output_dir: str) -> dict:
    project = Path(project_root).resolve()
    out = Path(output_dir).resolve()
    out.mkdir(parents=True, exist_ok=False)
    base = project / "experiments/host_boundary_v2/rq1_original_a0_a4_v3"
    reuse = base / "reviews/task_content_strict_audit/reuse_verification"
    checks = (("finqa", lambda: _finqa(base)),
              ("hotpot", lambda: _hotpot(reuse / "search_public_cache")),
              ("crmarena", lambda: _crm(reuse / "search_protected_cache")),
              ("appworld", lambda: _appworld(reuse / "search_state_cache/appworld")))
    results = {}
    for name, execute in checks:
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                result = execute()
            result["audit_execution"] = "completed"
        except Exception as exc:
            result = {"source": name, "audit_execution": "error", "error": f"{type(exc).__name__}: {exc}", "admitted": 0}
        results[name] = result
        (out / (name + ".json")).write_text(json.dumps(result, ensure_ascii=False, indent=2))
    summary = {"kind": "read_only_public_source_audit", "python": sys.version,
               "target_U_tasks": 200, "target_S_tasks": 60, "actually_admitted_U_tasks": 0,
               "actually_admitted_S_tasks": 0, "behavioral_episodes": 0,
               "sources": {name: {k: v for k, v in result.items() if k not in ("task_checks", "tables", "databases")}
                           for name, result in results.items()}}
    (out / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2))
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    print(json.dumps(audit_public_sources(args.project_root, args.output_dir), ensure_ascii=False, indent=2))
