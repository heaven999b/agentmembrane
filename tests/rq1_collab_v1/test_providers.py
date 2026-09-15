import json
import unittest
from unittest.mock import patch
from agentmembrane.host_v2.rq1_collab_v1.providers import HTTPReply, HTTPTransport, ModelDriver, ProviderFailure


class Collector:
    def __init__(self): self.requests, self.events = [], []
    def record_model_request(self, **record): self.requests.append(record)
    def emit(self, kind, data, **context): self.events.append((kind, data, context))


class ProviderTests(unittest.TestCase):
    def make(self, transport=None, **limits):
        c = Collector()
        if transport is None:
            def transport(raw):
                return HTTPReply(200, json.dumps({"model":"locked-model", "choices":[{"finish_reason":"stop",
                    "message":{"content":'{"type":"final","content":"done"}'}}], "usage":{"prompt_tokens":20}}).encode(), "receipt")
        return c, ModelDriver({"model":"locked-model", "max_completion_tokens":100},
            {"H":"Host, return a strict JSON action.", "E":"External worker, return a strict JSON action."}, c, transport,
            request_limit=limits.pop("request_limit",2), **limits)

    def test_exact_transported_body_and_context_separation(self):
        sent=[]
        def transport(raw):
            sent.append(raw)
            return HTTPReply(200,b'{"model":"locked-model","choices":[{"finish_reason":"stop","message":{"content":"{}"}}]}')
        c,d=self.make(transport)
        d.next_action("H",{"history":["protected-H-only"],"reminder":"ephemeral"})
        d.next_action("E",{"history":["public-E-only"]})
        self.assertEqual([x["status"] for x in c.requests[:3]],["prepared_only","delivery_unknown","delivered"])
        self.assertTrue(all(x["serialized_body"]==sent[0] for x in c.requests[:3]))
        self.assertNotIn(b"protected-H-only",sent[1])
        self.assertIn(b"ephemeral",sent[0])
        self.assertFalse(json.loads(sent[0])["store"])

    def test_transport_failure_is_unknown_no_automatic_retry(self):
        def fail(raw): raise OSError("secret error text never logged")
        c,d=self.make(fail)
        with self.assertRaises(ProviderFailure) as e: d.next_action("E",{})
        self.assertEqual(e.exception.delivery,"delivery_unknown")
        self.assertEqual(d.requests,1)
        self.assertNotIn("secret error",repr(c.events))

    def test_request_budget(self):
        c,d=self.make(request_limit=1)
        d.next_action("H",{})
        with self.assertRaises(ProviderFailure): d.next_action("H",{})
        self.assertEqual(d.requests,1)

    def test_missing_credential_is_known_not_sent(self):
        import os
        transport=HTTPTransport("https://example.com/v1/chat/completions", "RQ1_TEST_MISSING_KEY")
        c,d=self.make(transport)
        with patch.dict(os.environ,{},clear=True), patch.object(transport.opener,"open") as opened:
            with self.assertRaises(ProviderFailure) as failure: d.next_action("H",{})
            self.assertEqual(failure.exception.delivery,"prepared_only")
            opened.assert_not_called()
        self.assertEqual([x["status"] for x in c.requests],["prepared_only"])

    def test_duplicate_response_keys_rejected(self):
        c,d=self.make(lambda _:HTTPReply(200,b'{"model":"locked-model","model":"other"}'))
        with self.assertRaises(ProviderFailure): d.next_action("H",{})

    def test_overflow_response_rejected_as_protocol_error(self):
        c,d=self.make(lambda _:HTTPReply(200,b'{"model":"locked-model","usage":{"tokens":1e999}}'))
        with self.assertRaises(ProviderFailure) as failure: d.next_action("H",{})
        self.assertEqual(failure.exception.code,"model_response_protocol_error")

    def test_model_substitution_rejected(self):
        c,d=self.make(lambda _:HTTPReply(200,b'{"model":"other","choices":[]}'))
        with self.assertRaises(ProviderFailure): d.next_action("H",{})

    def test_endpoint_and_budget_guards(self):
        for url in ("http://example.com/v1/chat/completions", "https://key@api.example.com/v1/chat/completions",
                    "https://api.example.com/v1/chat/completions?key=secret"):
            with self.assertRaises(ValueError): HTTPTransport(url,"RQ1_API_KEY")
        with self.assertRaises(ValueError): self.make(request_limit=True)
        with self.assertRaises(ProviderFailure): self.make()[1].next_action("controller",{})


if __name__ == "__main__": unittest.main()
