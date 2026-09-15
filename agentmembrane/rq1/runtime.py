from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Callable

from ..kernel import AuthorizationError, CapabilityKernel
from ..models import Operation
from .artifacts import validate_memo
from .schema import (
    EvidenceMemo,
    EvidenceRef,
    MemoryRecord,
    SemanticType,
    TaskEpisode,
    TrustLabel,
    canonical_json,
    sha256_json,
)


class OriginBoundMemoryRuntime:
    """Minimal persistent runtime for the original Authority--Semantic RQ1.

    External artifacts enter an authorized quarantine.  Only a trusted memory
    steward can promote their references into persistent storage.  Promotion
    is verbatim: it cannot change the evidence selection, origin, trust label,
    or partial-coverage status.
    """

    STEWARD_PRINCIPAL = "memory_steward"
    EXTERNAL_PRINCIPAL = "external_analyst"
    QUARANTINE_RESOURCE = "rq1:quarantine"
    PERSISTENT_RESOURCE = "rq1:persistent"

    def __init__(
        self,
        db_path: Path,
        *,
        kernel: CapabilityKernel,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.db_path = Path(db_path)
        if not self.db_path.parent.exists():
            raise ValueError(f"database parent does not exist: {self.db_path.parent}")
        self.kernel = kernel
        self._now = now
        self._connection = sqlite3.connect(str(self.db_path))
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._initialize_schema()

    def __enter__(self) -> "OriginBoundMemoryRuntime":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._connection.close()

    def _initialize_schema(self) -> None:
        with self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    purpose TEXT NOT NULL,
                    started_at REAL NOT NULL,
                    closed_at REAL
                );

                CREATE TABLE IF NOT EXISTS artifacts (
                    artifact_id TEXT PRIMARY KEY,
                    episode_id TEXT NOT NULL,
                    producer_principal TEXT NOT NULL,
                    artifact_json TEXT NOT NULL,
                    artifact_sha256 TEXT NOT NULL,
                    submitted_session TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY(submitted_session) REFERENCES sessions(session_id)
                );

                CREATE TABLE IF NOT EXISTS memory_records (
                    memory_id TEXT PRIMARY KEY,
                    episode_id TEXT NOT NULL,
                    content_refs_json TEXT NOT NULL,
                    semantic_type TEXT NOT NULL,
                    writer_principal TEXT NOT NULL,
                    epistemic_origin TEXT NOT NULL,
                    trust_label TEXT NOT NULL,
                    coverage TEXT NOT NULL,
                    source_artifact_ids_json TEXT NOT NULL,
                    dependencies_json TEXT NOT NULL,
                    transformation_history_json TEXT NOT NULL,
                    created_session TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    FOREIGN KEY(created_session) REFERENCES sessions(session_id)
                );

                CREATE TABLE IF NOT EXISTS provenance_edges (
                    child_id TEXT NOT NULL,
                    parent_id TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    PRIMARY KEY(child_id, parent_id, relation),
                    FOREIGN KEY(child_id) REFERENCES memory_records(memory_id),
                    FOREIGN KEY(parent_id) REFERENCES artifacts(artifact_id)
                );

                CREATE TABLE IF NOT EXISTS events (
                    event_index INTEGER PRIMARY KEY,
                    occurred_at REAL NOT NULL,
                    session_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    object_id TEXT NOT NULL,
                    principal TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                );
                """
            )

    def _append_event(
        self,
        *,
        session_id: str,
        event_type: str,
        object_id: str,
        principal: str,
        outcome: str,
        detail: str,
    ) -> None:
        last = self._connection.execute(
            "SELECT event_index, event_hash FROM events ORDER BY event_index DESC LIMIT 1"
        ).fetchone()
        event_index = 1 if last is None else int(last["event_index"]) + 1
        previous_hash = "0" * 64 if last is None else str(last["event_hash"])
        occurred_at = float(self._now())
        payload = {
            "event_index": event_index,
            "occurred_at": occurred_at,
            "session_id": session_id,
            "event_type": event_type,
            "object_id": object_id,
            "principal": principal,
            "outcome": outcome,
            "detail": detail,
            "previous_hash": previous_hash,
        }
        event_hash = sha256_json(payload)
        self._connection.execute(
            """
            INSERT INTO events(
                event_index, occurred_at, session_id, event_type, object_id,
                principal, outcome, detail, previous_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_index,
                occurred_at,
                session_id,
                event_type,
                object_id,
                principal,
                outcome,
                detail,
                previous_hash,
                event_hash,
            ),
        )

    def _require_active_session(self, session_id: str) -> sqlite3.Row:
        row = self._connection.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"unknown session: {session_id}")
        if row["closed_at"] is not None:
            raise ValueError(f"session is closed: {session_id}")
        return row

    def start_session(self, session_id: str, *, purpose: str) -> None:
        if not session_id or not purpose:
            raise ValueError("session_id and purpose must be non-empty")
        with self._connection:
            try:
                self._connection.execute(
                    "INSERT INTO sessions VALUES (?, ?, ?, NULL)",
                    (session_id, purpose, float(self._now())),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError(f"session already exists: {session_id}") from exc
            self._append_event(
                session_id=session_id,
                event_type="session_started",
                object_id=session_id,
                principal="runtime",
                outcome="allowed",
                detail=purpose,
            )

    def close_session(self, session_id: str) -> None:
        self._require_active_session(session_id)
        with self._connection:
            self._append_event(
                session_id=session_id,
                event_type="session_closed",
                object_id=session_id,
                principal="runtime",
                outcome="allowed",
                detail="closed",
            )
            self._connection.execute(
                "UPDATE sessions SET closed_at = ? WHERE session_id = ?",
                (float(self._now()), session_id),
            )

    def submit_memo(
        self,
        *,
        session_id: str,
        memo: EvidenceMemo,
        episode: TaskEpisode,
        token: str | None,
    ) -> str:
        self._require_active_session(session_id)
        problems = validate_memo(memo, episode)
        if problems:
            raise ValueError("artifact conformance failure: " + ";".join(problems))
        try:
            self.kernel.authorize(
                principal=memo.producer_principal,
                operation=Operation.SUBMIT_PROPOSAL,
                resource=self.QUARANTINE_RESOURCE,
                token=token,
            )
        except AuthorizationError as exc:
            with self._connection:
                self._append_event(
                    session_id=session_id,
                    event_type="artifact_submission",
                    object_id=memo.artifact_id,
                    principal=memo.producer_principal,
                    outcome="denied",
                    detail=str(exc),
                )
            raise
        with self._connection:
            try:
                self._connection.execute(
                    """
                    INSERT INTO artifacts VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        memo.artifact_id,
                        memo.episode_id,
                        memo.producer_principal,
                        canonical_json(memo.to_dict()),
                        memo.artifact_sha256,
                        session_id,
                        float(self._now()),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError(f"artifact already exists: {memo.artifact_id}") from exc
            self._append_event(
                session_id=session_id,
                event_type="artifact_submission",
                object_id=memo.artifact_id,
                principal=memo.producer_principal,
                outcome="allowed",
                detail="authorized_quarantine",
            )
        return memo.artifact_id

    def direct_persistent_commit(
        self,
        *,
        session_id: str,
        actor: str,
        object_id: str,
        token: str | None,
    ) -> None:
        """The raw commit path is disabled, even for a syntactically valid token."""

        self._require_active_session(session_id)
        del token  # Deliberately irrelevant: only steward promotion is a valid path.
        with self._connection:
            self._append_event(
                session_id=session_id,
                event_type="direct_persistent_commit",
                object_id=object_id,
                principal=actor,
                outcome="denied",
                detail="steward_promotion_required",
            )
        raise AuthorizationError("steward_promotion_required")

    def promote_memo(
        self,
        *,
        session_id: str,
        artifact_id: str,
        episode: TaskEpisode,
        actor: str,
        token: str | None,
    ) -> MemoryRecord:
        self._require_active_session(session_id)
        if actor != self.STEWARD_PRINCIPAL:
            with self._connection:
                self._append_event(
                    session_id=session_id,
                    event_type="artifact_promotion",
                    object_id=artifact_id,
                    principal=actor,
                    outcome="denied",
                    detail="trusted_steward_required",
                )
            raise AuthorizationError("trusted_steward_required")
        try:
            self.kernel.authorize(
                principal=actor,
                operation=Operation.PERSISTENT_COMMIT,
                resource=self.PERSISTENT_RESOURCE,
                token=token,
            )
        except AuthorizationError as exc:
            with self._connection:
                self._append_event(
                    session_id=session_id,
                    event_type="artifact_promotion",
                    object_id=artifact_id,
                    principal=actor,
                    outcome="denied",
                    detail=str(exc),
                )
            raise

        row = self._connection.execute(
            "SELECT * FROM artifacts WHERE artifact_id = ?", (artifact_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"unknown artifact: {artifact_id}")
        if row["submitted_session"] != session_id:
            raise ValueError("promotion must occur in the artifact submission session")
        memo = self._memo_from_json(str(row["artifact_json"]))
        if memo.artifact_sha256 != row["artifact_sha256"]:
            raise ValueError("stored artifact hash mismatch")
        problems = validate_memo(memo, episode)
        if problems:
            raise ValueError("stored artifact conformance failure: " + ";".join(problems))

        memory_id = "m-" + sha256_json(
            {
                "artifact_sha256": memo.artifact_sha256,
                "created_session": session_id,
                "promotion_contract": "verbatim-origin-bound-v1",
            }
        )[:24]
        record = MemoryRecord(
            memory_id=memory_id,
            episode_id=memo.episode_id,
            content_refs=memo.evidence_refs,
            semantic_type=SemanticType.EVIDENCE,
            writer_principal=actor,
            epistemic_origin=memo.producer_principal,
            trust_label=TrustLabel.EXTERNAL_LOW,
            coverage="partial",
            source_artifact_ids=(memo.artifact_id,),
            dependencies=tuple(ref.span_id for ref in memo.evidence_refs),
            transformation_history=(
                "authorized_external_submission",
                "verbatim_reference_promotion:v1",
                "no_declassification",
            ),
            created_session=session_id,
        )
        with self._connection:
            try:
                self._connection.execute(
                    """
                    INSERT INTO memory_records VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        record.memory_id,
                        record.episode_id,
                        canonical_json(
                            [
                                {"span_id": ref.span_id, "text_sha256": ref.text_sha256}
                                for ref in record.content_refs
                            ]
                        ),
                        record.semantic_type.value,
                        record.writer_principal,
                        record.epistemic_origin,
                        record.trust_label.value,
                        record.coverage,
                        canonical_json(list(record.source_artifact_ids)),
                        canonical_json(list(record.dependencies)),
                        canonical_json(list(record.transformation_history)),
                        record.created_session,
                        float(self._now()),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError(f"memory record already exists: {memory_id}") from exc
            self._connection.execute(
                "INSERT INTO provenance_edges VALUES (?, ?, ?)",
                (memory_id, memo.artifact_id, "verbatim_promotion_of"),
            )
            self._append_event(
                session_id=session_id,
                event_type="artifact_promotion",
                object_id=memory_id,
                principal=actor,
                outcome="allowed",
                detail="origin_and_external_trust_preserved",
            )
        return record

    def retrieve_for_session(
        self, *, session_id: str, episode_id: str
    ) -> tuple[MemoryRecord, ...]:
        """Retrieve only records created in a different, already closed session."""

        self._require_active_session(session_id)
        rows = self._connection.execute(
            """
            SELECT memory_records.*
            FROM memory_records
            JOIN sessions ON sessions.session_id = memory_records.created_session
            WHERE memory_records.episode_id = ?
              AND memory_records.created_session != ?
              AND sessions.closed_at IS NOT NULL
            ORDER BY memory_records.memory_id
            """,
            (episode_id, session_id),
        ).fetchall()
        records = tuple(self._record_from_row(row) for row in rows)
        with self._connection:
            self._append_event(
                session_id=session_id,
                event_type="cross_session_retrieval",
                object_id=episode_id,
                principal="future_agent",
                outcome="allowed",
                detail=f"record_count={len(records)}",
            )
        return records

    def get_record(self, memory_id: str) -> MemoryRecord:
        row = self._connection.execute(
            "SELECT * FROM memory_records WHERE memory_id = ?", (memory_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"unknown memory record: {memory_id}")
        return self._record_from_row(row)

    def verify_origin_integrity(self, memory_id: str) -> tuple[str, ...]:
        problems: list[str] = []
        record = self.get_record(memory_id)
        if record.writer_principal != self.STEWARD_PRINCIPAL:
            problems.append("writer_not_steward")
        if record.epistemic_origin != self.EXTERNAL_PRINCIPAL:
            problems.append("external_origin_lost")
        if record.trust_label != TrustLabel.EXTERNAL_LOW:
            problems.append("external_trust_lost")
        if record.coverage != "partial":
            problems.append("partial_coverage_lost")
        if "no_declassification" not in record.transformation_history:
            problems.append("declassification_state_missing")
        if len(record.source_artifact_ids) != 1:
            problems.append("source_artifact_cardinality_invalid")
            return tuple(problems)

        artifact_id = record.source_artifact_ids[0]
        artifact = self._connection.execute(
            "SELECT * FROM artifacts WHERE artifact_id = ?", (artifact_id,)
        ).fetchone()
        if artifact is None:
            problems.append("source_artifact_missing")
            return tuple(problems)
        memo = self._memo_from_json(str(artifact["artifact_json"]))
        if memo.artifact_sha256 != artifact["artifact_sha256"]:
            problems.append("source_artifact_hash_mismatch")
        if memo.producer_principal != record.epistemic_origin:
            problems.append("origin_producer_mismatch")
        if memo.evidence_refs != record.content_refs:
            problems.append("promotion_not_verbatim")
        edge = self._connection.execute(
            """
            SELECT 1 FROM provenance_edges
            WHERE child_id = ? AND parent_id = ? AND relation = ?
            """,
            (memory_id, artifact_id, "verbatim_promotion_of"),
        ).fetchone()
        if edge is None:
            problems.append("provenance_edge_missing")
        return tuple(problems)

    def verify_event_chain(self) -> tuple[str, ...]:
        problems: list[str] = []
        previous_hash = "0" * 64
        expected_index = 1
        rows = self._connection.execute(
            "SELECT * FROM events ORDER BY event_index"
        ).fetchall()
        for row in rows:
            if row["event_index"] != expected_index:
                problems.append(f"event_index_gap:{expected_index}")
            if row["previous_hash"] != previous_hash:
                problems.append(f"event_previous_hash_mismatch:{row['event_index']}")
            payload = {
                "event_index": row["event_index"],
                "occurred_at": row["occurred_at"],
                "session_id": row["session_id"],
                "event_type": row["event_type"],
                "object_id": row["object_id"],
                "principal": row["principal"],
                "outcome": row["outcome"],
                "detail": row["detail"],
                "previous_hash": row["previous_hash"],
            }
            expected_hash = sha256_json(payload)
            if row["event_hash"] != expected_hash:
                problems.append(f"event_hash_mismatch:{row['event_index']}")
            previous_hash = row["event_hash"]
            expected_index += 1
        return tuple(problems)

    @staticmethod
    def _memo_from_json(value: str) -> EvidenceMemo:
        payload = json.loads(value)
        return EvidenceMemo(
            artifact_id=payload["artifact_id"],
            episode_id=payload["episode_id"],
            producer_principal=payload["producer_principal"],
            artifact_type=payload["artifact_type"],
            semantic_type=SemanticType(payload["semantic_type"]),
            coverage=payload["coverage"],
            completeness_guarantee=payload["completeness_guarantee"],
            evidence_refs=tuple(
                EvidenceRef(
                    span_id=ref["span_id"], text_sha256=ref["text_sha256"]
                )
                for ref in payload["evidence_refs"]
            ),
            free_text_claims=tuple(payload["free_text_claims"]),
            future_instructions=tuple(payload["future_instructions"]),
            output_contract_version=payload["output_contract_version"],
            condition_blind_id=payload["condition_blind_id"],
        )

    @staticmethod
    def _record_from_row(row: sqlite3.Row) -> MemoryRecord:
        return MemoryRecord(
            memory_id=row["memory_id"],
            episode_id=row["episode_id"],
            content_refs=tuple(
                EvidenceRef(
                    span_id=value["span_id"], text_sha256=value["text_sha256"]
                )
                for value in json.loads(row["content_refs_json"])
            ),
            semantic_type=SemanticType(row["semantic_type"]),
            writer_principal=row["writer_principal"],
            epistemic_origin=row["epistemic_origin"],
            trust_label=TrustLabel(row["trust_label"]),
            coverage=row["coverage"],
            source_artifact_ids=tuple(json.loads(row["source_artifact_ids_json"])),
            dependencies=tuple(json.loads(row["dependencies_json"])),
            transformation_history=tuple(
                json.loads(row["transformation_history_json"])
            ),
            created_session=row["created_session"],
        )
