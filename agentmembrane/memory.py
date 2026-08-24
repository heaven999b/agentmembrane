from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import replace
from typing import Any

from .kernel import AuthorizationError, CapabilityKernel
from .models import Artifact, Operation, Taint


class MemoryRuntime:
    """Quarantine-first memory runtime with a provenance ledger."""

    def __init__(self, kernel: CapabilityKernel, database: str = ":memory:") -> None:
        self.kernel = kernel
        self.connection = sqlite3.connect(database)
        self.connection.row_factory = sqlite3.Row
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS quarantine (
                artifact_id TEXT PRIMARY KEY,
                producer TEXT NOT NULL,
                receptor TEXT NOT NULL,
                payload TEXT NOT NULL,
                evidence_ids TEXT NOT NULL,
                semantic_type TEXT NOT NULL,
                taint TEXT NOT NULL,
                dependencies TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS persistent_memory (
                memory_id TEXT PRIMARY KEY,
                artifact_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                semantic_type TEXT NOT NULL,
                taint TEXT NOT NULL,
                promoted_by TEXT NOT NULL,
                promoted_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS ledger (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                principal TEXT NOT NULL,
                artifact_id TEXT,
                metadata TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            """
        )

    def _log(
        self,
        event_type: str,
        principal: str,
        artifact_id: str | None,
        metadata: dict[str, Any],
    ) -> None:
        self.connection.execute(
            "INSERT INTO ledger(event_type, principal, artifact_id, metadata, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (event_type, principal, artifact_id, json.dumps(metadata, sort_keys=True), time.time()),
        )
        self.connection.commit()

    def submit(self, artifact: Artifact, *, token: str) -> None:
        self.kernel.authorize(
            principal=artifact.producer,
            operation=Operation.SUBMIT_PROPOSAL,
            resource="quarantine",
            token=token,
        )
        self.connection.execute(
            "INSERT INTO quarantine VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                artifact.artifact_id,
                artifact.producer,
                artifact.receptor.value,
                json.dumps(artifact.payload, sort_keys=True),
                json.dumps(artifact.evidence_ids),
                artifact.semantic_type,
                artifact.taint.value,
                json.dumps(artifact.dependencies),
                time.time(),
            ),
        )
        self.connection.commit()
        self._log("quarantine_submit", artifact.producer, artifact.artifact_id, {})

    def external_direct_commit(self, artifact: Artifact, *, token: str | None = None) -> None:
        self.kernel.authorize(
            principal=artifact.producer,
            operation=Operation.PERSISTENT_COMMIT,
            resource="persistent-memory",
            token=token,
        )
        raise AssertionError("an external direct commit must never reach storage")

    def promote(
        self,
        artifact_id: str,
        *,
        steward: str,
        token: str,
        approved: bool,
        explicit_declassification: bool,
    ) -> str:
        self.kernel.authorize(
            principal=steward,
            operation=Operation.PERSISTENT_COMMIT,
            resource="persistent-memory",
            token=token,
        )
        row = self.connection.execute(
            "SELECT * FROM quarantine WHERE artifact_id = ?", (artifact_id,)
        ).fetchone()
        if row is None:
            raise KeyError(artifact_id)
        if not approved:
            self._log("promotion_denied", steward, artifact_id, {})
            raise AuthorizationError("promotion_not_approved")
        if row["taint"] == Taint.EXTERNAL.value and not explicit_declassification:
            self._log("promotion_denied", steward, artifact_id, {"reason": "taint"})
            raise AuthorizationError("explicit_declassification_required")

        memory_id = f"memory:{artifact_id}"
        taint = Taint.VERIFIED.value if explicit_declassification else row["taint"]
        self.connection.execute(
            "INSERT INTO persistent_memory VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                memory_id,
                artifact_id,
                row["payload"],
                row["semantic_type"],
                taint,
                steward,
                time.time(),
            ),
        )
        self.connection.commit()
        self._log(
            "promotion_approved",
            steward,
            artifact_id,
            {"memory_id": memory_id, "taint": taint},
        )
        return memory_id

    def call_sensitive_tool(
        self,
        *,
        principal: str,
        token: str | None,
        influencing_principals: tuple[str, ...] = (),
        influence_tokens: dict[str, str] | None = None,
    ) -> str:
        self.kernel.authorize(
            principal=principal,
            operation=Operation.CALL_SENSITIVE_TOOL,
            resource="sensitive-tool",
            token=token,
            influencing_principals=influencing_principals,
            influence_tokens=influence_tokens,
        )
        self._log("sensitive_tool_call", principal, None, {})
        return "tool-result"

    def count(self, table: str) -> int:
        if table not in {"quarantine", "persistent_memory", "ledger"}:
            raise ValueError(table)
        return int(self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

