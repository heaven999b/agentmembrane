"""Short-lived, read-only SQLite reader. Never an actor/model or a writer."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sqlite3
import sys


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def read_store(path, *, episode_id, task_hash, record_id=None, version=None):
    """Path comes only from the trusted service, never an actor request."""
    connection = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=2)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        meta = dict(connection.execute("SELECT * FROM store_meta").fetchone())
        if meta["episode_id"] != episode_id or meta["task_bundle_hash"] != task_hash:
            raise ValueError("memory_store_binding_mismatch")
        query = """SELECT r.*, v.version, v.value_json, v.value_hash, v.writer_principal,
             v.origin_refs_json, v.original_call_id, v.original_tool, v.dependency_hash,
             v.write_intent_event_id, v.commit_receipt_event_id, v.grant_epoch
             FROM records r JOIN versions v ON r.namespace=v.namespace
             AND r.record_key=v.record_key"""
        params = []
        if record_id is not None:
            query += " WHERE r.record_id=?"
            params.append(record_id)
            if version is not None:
                query += " AND v.version=?"
                params.append(version)
        else:
            query += " WHERE r.current_version=v.version"
        rows = []
        for raw in connection.execute(query + " ORDER BY r.record_id,v.version", params):
            row = dict(raw)
            row["value"] = json.loads(row.pop("value_json"))
            row["source_refs"] = json.loads(row.pop("origin_refs_json"))
            if digest(row["value"]) != row["value_hash"]:
                raise ValueError("memory_value_hash_mismatch")
            row["invalidated"] = connection.execute(
                "SELECT 1 FROM invalidations WHERE namespace=? AND record_key=? AND version=?",
                (row["namespace"], row["record_key"], row["version"])).fetchone() is not None
            rows.append(row)
        return {"meta": meta, "records": rows}
    finally:
        connection.close()


def main():
    try:
        raw = sys.stdin.buffer.read(1048577)
        if len(raw) > 1048576:
            raise ValueError("reader_request_too_large")
        request = json.loads(raw)
        result = read_store(**request)
        sys.stdout.buffer.write(canonical({"ok": True, "result": result}))
    except Exception:
        sys.stdout.buffer.write(canonical({"ok": False, "error": "readonly_reader_failed"}))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
