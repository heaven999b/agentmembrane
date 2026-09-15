import tempfile
import unittest
from pathlib import Path

from agentmembrane.host_v2.rq1_collab_v1.audit import canonical, strict_loads
from agentmembrane.host_v2.rq1_collab_v1.providers import HTTPReply
from agentmembrane.host_v2.rq1_collab_v4.model_probe import probe_profile, run


class Transport:
    def __init__(self, reply, secret=False):
        self.reply, self.secret, self.calls = reply, secret, []
    def prepare(self):
        pass
    def __call__(self, body):
        self.calls.append(strict_loads(body))
        return self.reply
    def contains_credential(self, body):
        return self.secret


class ProbeTests(unittest.TestCase):
    profile = {"model": "registered-model", "max_completion_tokens": 8192, "reasoning_effort": "medium"}

    def reply(self, model="registered-model", content="OK", status=200):
        return HTTPReply(status, canonical({"model": model, "choices": [{"message": {"role": "assistant", "content": content}}],
                                            "usage": {"prompt_tokens": 8, "completion_tokens": 1, "total_tokens": 9}}))

    def test_success_exact_model_no_native_tools(self):
        t = Transport(self.reply())
        row = probe_profile(self.profile, t)
        self.assertTrue(row["generation_verified"])
        self.assertEqual(len(t.calls), 1)
        self.assertNotIn("tools", t.calls[0])
        self.assertEqual(t.calls[0]["max_completion_tokens"], 512)
        self.assertFalse(row["model_identity_independently_attested"])

    def test_substitution_rejected(self):
        row = probe_profile(self.profile, Transport(self.reply("different")))
        self.assertFalse(row["generation_verified"])
        self.assertEqual(row["status"], "returned_model_mismatch")

    def test_error_body_not_copied(self):
        t = Transport(HTTPReply(404, canonical({"error": {"code": "model_not_found", "message": "PRIVATE-ERROR"}})))
        row = probe_profile(self.profile, t)
        self.assertEqual(row["error_code"], "model_not_found")
        self.assertNotIn(b"PRIVATE-ERROR", canonical(row))
        self.assertEqual(len(t.calls), 1)

    def test_credential_reflection_quarantined(self):
        row = probe_profile(self.profile, Transport(self.reply(), secret=True))
        self.assertEqual(row["status"], "response_quarantined")
        self.assertFalse(row["generation_verified"])

    def test_empty_response_not_generation(self):
        self.assertFalse(probe_profile(self.profile, Transport(self.reply(content="")))["generation_verified"])

    def test_explicit_flag_and_persistent_allocations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/"probe"
            with self.assertRaises(ValueError):
                run(root)
            def unavailable():
                self.assertTrue((root/"allocation.json").is_file())
                raise ValueError("SECRET-SETUP")
            result = run(root, execute_live=True, factory=unavailable)
            self.assertEqual(len(result["rows"]), 3)
            self.assertEqual(result["transport_invocations"], 0)
            self.assertNotIn(b"SECRET-SETUP", canonical(result))
            self.assertTrue((root/"summary.json").is_file())


if __name__ == "__main__":
    unittest.main()
