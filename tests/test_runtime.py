from __future__ import annotations

import unittest

from agentmembrane import (
    Artifact,
    AuthorizationError,
    CapabilityKernel,
    MemoryRuntime,
    Operation,
    Receptor,
)


class RuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.kernel = CapabilityKernel(b"0123456789abcdef0123456789abcdef")
        self.memory = MemoryRuntime(self.kernel)
        self.artifact = Artifact(
            artifact_id="a1",
            producer="external",
            receptor=Receptor.R2,
            payload={"inference": "bounded claim"},
            evidence_ids=("E1",),
            semantic_type="Inference",
        )

    def issue(self, principal: str, operation: Operation, resource: str) -> str:
        return self.kernel.issue(
            requester=CapabilityKernel.ROOT,
            principal=principal,
            operation=operation,
            resource=resource,
        )

    def test_no_ambient_authority(self) -> None:
        with self.assertRaisesRegex(AuthorizationError, "missing_capability"):
            self.memory.external_direct_commit(self.artifact)

    def test_no_self_grant(self) -> None:
        with self.assertRaisesRegex(AuthorizationError, "no_self_grant"):
            self.kernel.issue(
                requester="external",
                principal="external",
                operation=Operation.PERSISTENT_COMMIT,
                resource="persistent-memory",
            )

    def test_quarantine_then_explicit_promotion(self) -> None:
        submit = self.issue("external", Operation.SUBMIT_PROPOSAL, "quarantine")
        commit = self.issue("steward", Operation.PERSISTENT_COMMIT, "persistent-memory")
        self.memory.submit(self.artifact, token=submit)
        memory_id = self.memory.promote(
            "a1",
            steward="steward",
            token=commit,
            approved=True,
            explicit_declassification=True,
        )
        self.assertEqual(memory_id, "memory:a1")
        self.assertEqual(self.memory.count("quarantine"), 1)
        self.assertEqual(self.memory.count("persistent_memory"), 1)

    def test_taint_cannot_be_silently_laundered(self) -> None:
        submit = self.issue("external", Operation.SUBMIT_PROPOSAL, "quarantine")
        commit = self.issue("steward", Operation.PERSISTENT_COMMIT, "persistent-memory")
        self.memory.submit(self.artifact, token=submit)
        with self.assertRaisesRegex(AuthorizationError, "explicit_declassification_required"):
            self.memory.promote(
                "a1",
                steward="steward",
                token=commit,
                approved=True,
                explicit_declassification=False,
            )

    def test_forbidden_tool_requires_capability(self) -> None:
        with self.assertRaisesRegex(AuthorizationError, "missing_capability"):
            self.memory.call_sensitive_tool(principal="external", token=None)

    def test_confused_deputy_is_blocked(self) -> None:
        internal_token = self.issue(
            "internal", Operation.CALL_SENSITIVE_TOOL, "sensitive-tool"
        )
        with self.assertRaisesRegex(AuthorizationError, "confused_deputy_blocked"):
            self.memory.call_sensitive_tool(
                principal="internal",
                token=internal_token,
                influencing_principals=("external",),
            )

    def test_tampered_capability_is_rejected(self) -> None:
        token = self.issue("external", Operation.SUBMIT_PROPOSAL, "quarantine")
        tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
        with self.assertRaisesRegex(AuthorizationError, "invalid_capability_signature"):
            self.memory.submit(self.artifact, token=tampered)


if __name__ == "__main__":
    unittest.main()

