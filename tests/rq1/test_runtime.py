from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agentmembrane.kernel import AuthorizationError, CapabilityKernel
from agentmembrane.models import Operation
from agentmembrane.rq1.artifacts import build_targeted_memo
from agentmembrane.rq1.runtime import OriginBoundMemoryRuntime
from agentmembrane.rq1.schema import TrustLabel

from .fixtures import toy_annotation, toy_episode


class PersistentRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.kernel = CapabilityKernel(b"rq1-test-secret-is-long-enough", now=lambda: 1000.0)
        self.episode = toy_episode()
        self.memo = build_targeted_memo(
            self.episode, toy_annotation(self.episode), blind_salt="held-secret"
        )
        self.submit_token = self.kernel.issue(
            requester=self.kernel.ROOT,
            principal=OriginBoundMemoryRuntime.EXTERNAL_PRINCIPAL,
            operation=Operation.SUBMIT_PROPOSAL,
            resource=OriginBoundMemoryRuntime.QUARANTINE_RESOURCE,
        )
        self.steward_token = self.kernel.issue(
            requester=self.kernel.ROOT,
            principal=OriginBoundMemoryRuntime.STEWARD_PRINCIPAL,
            operation=Operation.PERSISTENT_COMMIT,
            resource=OriginBoundMemoryRuntime.PERSISTENT_RESOURCE,
        )
        self.external_commit_token = self.kernel.issue(
            requester=self.kernel.ROOT,
            principal=OriginBoundMemoryRuntime.EXTERNAL_PRINCIPAL,
            operation=Operation.PERSISTENT_COMMIT,
            resource=OriginBoundMemoryRuntime.PERSISTENT_RESOURCE,
        )

    def test_authorized_submit_steward_promotion_and_real_cross_session_retrieval(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            db_path = Path(temporary) / "rq1.sqlite3"
            runtime = OriginBoundMemoryRuntime(db_path, kernel=self.kernel, now=lambda: 1000.0)
            runtime.start_session("session-1", purpose="artifact production")
            with self.assertRaises(AuthorizationError):
                runtime.submit_memo(
                    session_id="session-1",
                    memo=self.memo,
                    episode=self.episode,
                    token=None,
                )
            runtime.submit_memo(
                session_id="session-1",
                memo=self.memo,
                episode=self.episode,
                token=self.submit_token,
            )
            with self.assertRaisesRegex(AuthorizationError, "steward_promotion_required"):
                runtime.direct_persistent_commit(
                    session_id="session-1",
                    actor=OriginBoundMemoryRuntime.EXTERNAL_PRINCIPAL,
                    object_id=self.memo.artifact_id,
                    token=self.external_commit_token,
                )
            with self.assertRaisesRegex(AuthorizationError, "trusted_steward_required"):
                runtime.promote_memo(
                    session_id="session-1",
                    artifact_id=self.memo.artifact_id,
                    episode=self.episode,
                    actor=OriginBoundMemoryRuntime.EXTERNAL_PRINCIPAL,
                    token=self.external_commit_token,
                )
            record = runtime.promote_memo(
                session_id="session-1",
                artifact_id=self.memo.artifact_id,
                episode=self.episode,
                actor=OriginBoundMemoryRuntime.STEWARD_PRINCIPAL,
                token=self.steward_token,
            )
            self.assertEqual(runtime.retrieve_for_session(
                session_id="session-1", episode_id=self.episode.episode_id
            ), ())
            runtime.close_session("session-1")
            self.assertFalse(runtime.verify_origin_integrity(record.memory_id))
            self.assertFalse(runtime.verify_event_chain())
            runtime.close()

            restarted = OriginBoundMemoryRuntime(
                db_path, kernel=self.kernel, now=lambda: 1001.0
            )
            restarted.start_session("session-2", purpose="future decision")
            retrieved = restarted.retrieve_for_session(
                session_id="session-2", episode_id=self.episode.episode_id
            )
            self.assertEqual(len(retrieved), 1)
            self.assertEqual(retrieved[0].memory_id, record.memory_id)
            self.assertEqual(retrieved[0].content_refs, self.memo.evidence_refs)
            self.assertEqual(
                retrieved[0].epistemic_origin,
                OriginBoundMemoryRuntime.EXTERNAL_PRINCIPAL,
            )
            self.assertEqual(retrieved[0].trust_label, TrustLabel.EXTERNAL_LOW)
            self.assertFalse(restarted.verify_origin_integrity(record.memory_id))
            self.assertFalse(restarted.verify_event_chain())
            restarted.close()


if __name__ == "__main__":
    unittest.main()
