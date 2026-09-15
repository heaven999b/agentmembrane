"""Dedicated live route contract; uses a local fake model inventory, no inference."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from agentmembrane.host_v2.rq1_collab_v1.audit import strict_loads
from agentmembrane.host_v2.rq1_collab_v6.provider_route import (
    BoundRouteTransport, SHARED_IDENTITY, SHARED_PROXY_CREDENTIAL_ENV_ENV,
    SHARED_PROXY_ENDPOINT_ENV, SHARED_PROXY_LABEL_ENV, base_url, inventory,
    source_binding, validate_route, verify_binding,
)
from agentmembrane.host_v2.rq1_collab_v1.providers import ProviderFailure
from agentmembrane.host_v2.rq1_collab_v6 import workflow
from agentmembrane.host_v2.rq1_collab_v6.contract import matrix


SYNTHETIC_SHARED_ENDPOINT = "http://127.0.0.1:19876/v1/chat/completions"
SYNTHETIC_SHARED_CREDENTIAL_ENV = "RQ1_SYNTHETIC_SHARED_PROXY_KEY"
SYNTHETIC_SHARED_LABEL = "synthetic_shared_pool"
SYNTHETIC_DEDICATED_ENDPOINT = "http://127.0.0.1:19877/v1/chat/completions"
SYNTHETIC_DEDICATED_CREDENTIAL_ENV = "RQ1_SYNTHETIC_DEDICATED_KEY"
SYNTHETIC_ACCOUNT = "synthetic_account_a"
SHARED_POLICY_ENV = {
    SHARED_PROXY_ENDPOINT_ENV: SYNTHETIC_SHARED_ENDPOINT,
    SHARED_PROXY_CREDENTIAL_ENV_ENV: SYNTHETIC_SHARED_CREDENTIAL_ENV,
    SHARED_PROXY_LABEL_ENV: SYNTHETIC_SHARED_LABEL,
}


class _Reply:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, _limit):
        return json.dumps({"data": [{"id": "gpt-test-h"}, {"id": "gpt-test-e"}]}).encode()


class _Opener:
    def open(self, request, timeout):
        assert request.full_url == "http://127.0.0.1:19877/v1/models"
        assert request.get_header("Authorization") == "Bearer local-test-key"
        assert timeout == 10
        return _Reply()


class ProviderRouteTests(unittest.TestCase):
    def test_missing_external_shared_policy_fails_closed(self):
        route = {"schema_version": "rq1-provider-route/2",
                 "routing_mode": "shared_pool_unattributed",
                 "endpoint": SYNTHETIC_SHARED_ENDPOINT,
                 "credential_env": SYNTHETIC_SHARED_CREDENTIAL_ENV,
                 "account_label": SYNTHETIC_SHARED_LABEL}
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "shared_proxy_contract_configuration_required"):
                validate_route(route)

    def test_explicit_shared_proxy_is_unattributed_and_cannot_claim_account(self):
        route = {"schema_version": "rq1-provider-route/2",
                 "routing_mode": "shared_pool_unattributed",
                 "endpoint": SYNTHETIC_SHARED_ENDPOINT,
                 "credential_env": SYNTHETIC_SHARED_CREDENTIAL_ENV,
                 "account_label": SYNTHETIC_SHARED_LABEL}
        with patch.dict(os.environ, SHARED_POLICY_ENV):
            self.assertEqual(validate_route(route), route)
            with tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / "route.json"
                path.write_text(json.dumps(route))
                self.assertEqual(source_binding(path)["account_identity"], SHARED_IDENTITY)
            with self.assertRaisesRegex(ValueError, "shared_proxy_route_must_match_external_policy"):
                validate_route({**route, "account_label": "synthetic_account_b"})
            with self.assertRaisesRegex(ValueError, "shared_proxy_route_must_match_external_policy"):
                validate_route({**route, "endpoint": "http://127.0.0.1:19878/v1/chat/completions"})

    def test_shared_proxy_refused_even_with_account_label(self):
        route = {"schema_version": "rq1-provider-route/1",
                 "endpoint": SYNTHETIC_SHARED_ENDPOINT,
                 "credential_env": SYNTHETIC_DEDICATED_CREDENTIAL_ENV,
                 "account_label": SYNTHETIC_ACCOUNT}
        with patch.dict(os.environ, SHARED_POLICY_ENV):
            with self.assertRaisesRegex(ValueError, "known_shared_proxy"):
                validate_route(route)

    def test_dedicated_local_route_inventory_and_mutation_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            route_file = root / "route.json"
            route = {"schema_version": "rq1-provider-route/1",
                     "endpoint": SYNTHETIC_DEDICATED_ENDPOINT,
                     "credential_env": SYNTHETIC_DEDICATED_CREDENTIAL_ENV,
                     "account_label": SYNTHETIC_ACCOUNT}
            route_file.write_text(json.dumps(route))
            with patch.dict(os.environ, SHARED_POLICY_ENV):
                binding = source_binding(route_file)
                self.assertEqual(verify_binding(binding), route)
                self.assertEqual(base_url(route), "http://127.0.0.1:19877/v1")
            with (patch.dict(os.environ, {
                      **SHARED_POLICY_ENV,
                      SYNTHETIC_DEDICATED_CREDENTIAL_ENV: "local-test-key",
                  }),
                  patch("agentmembrane.host_v2.rq1_collab_v6.provider_route.urllib.request.build_opener",
                        return_value=_Opener())):
                receipt = inventory(route_file, root / "inventory.json")
            data = strict_loads((root / "inventory.json").read_bytes())
            self.assertEqual(data["provider_route_sha256"], binding["sha256"])
            self.assertEqual(data["model_ids"], ["gpt-test-e", "gpt-test-h"])
            self.assertEqual(data["model_calls"], 0)
            self.assertEqual(receipt["model_calls"], 0)
            with patch.dict(os.environ, SHARED_POLICY_ENV):
                transport = BoundRouteTransport(route, data, timeout_seconds=50)
            with patch.dict(os.environ, {
                **SHARED_POLICY_ENV,
                SYNTHETIC_DEDICATED_CREDENTIAL_ENV: "local-test-key",
            }):
                transport.prepare()
            with patch.dict(os.environ, {
                **SHARED_POLICY_ENV,
                SYNTHETIC_DEDICATED_CREDENTIAL_ENV: "switched-account-key",
            }):
                with self.assertRaisesRegex(ProviderFailure, "provider_route_credential_changed"):
                    transport.prepare()
            route_file.write_text(json.dumps({**route, "account_label": "other"}))
            with patch.dict(os.environ, SHARED_POLICY_ENV):
                with self.assertRaises(ValueError):
                    verify_binding(binding)

    def test_live_cell_refuses_switched_credential_before_model_or_native_call(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            route_file = root / "route.json"
            route = {"schema_version": "rq1-provider-route/1",
                     "endpoint": SYNTHETIC_DEDICATED_ENDPOINT,
                     "credential_env": SYNTHETIC_DEDICATED_CREDENTIAL_ENV,
                     "account_label": SYNTHETIC_ACCOUNT}
            route_file.write_text(json.dumps(route))
            with patch.dict(os.environ, SHARED_POLICY_ENV):
                cfg = matrix("a" * 64, "synthetic-route-lock", repeats=1,
                             mode="live_diagnostic", topologies=("H_E",),
                             levels=("medium",), regimes=("honest",))[0]
                bundle_hash = cfg["bundle_sha256"]
                manifest = {"manifest_sha256": "b" * 64, "cells": [cfg],
                            "provider_route_source": source_binding(route_file),
                            "attack_specs": {bundle_hash: {"synthetic": True}},
                            "bundles": {bundle_hash: {
                                "public": {"goal": {"goal": "synthetic goal"}},
                                "source_record": {
                                    "suite": "workspace", "task_id": "user_task_35",
                                    "initial_state_sha256": "c" * 64,
                                    "class_source_sha256": "d" * 64,
                                    "prompt_sha256": "e" * 64,
                                },
                            }},
                            "system_spec": {"system_profile": "synthetic"},
                            "system_spec_sha256": "f" * 64,
                            "upstream_hashes": {},
                            "regime_labels": {"honest": "control_no_attack"},
                            "phase_schedule_sha256": "1" * 64}
            salt = "00" * 32
            with patch.dict(os.environ, SHARED_POLICY_ENV):
                from agentmembrane.host_v2.rq1_collab_v6.provider_route import credential_fingerprint
                fingerprint = credential_fingerprint("original-key", salt)
            inv = {"schema_version": "rq1-provider-inventory/1",
                   "base_url": "http://127.0.0.1:19877/v1",
                   "provider_route_sha256": manifest["provider_route_source"]["sha256"],
                   "account_label": SYNTHETIC_ACCOUNT,
                   "account_identity": "operator_declared_dedicated_route_not_provider_attested",
                   "model_ids": [profile["model"] for profile in cfg["models"].values()],
                   "checked_at_unix": __import__("time").time(), "model_calls": 0,
                   "credential_salt": salt, "credential_fingerprint": fingerprint}
            inv_file = root / "inventory.json"
            inv_file.write_text(json.dumps(inv))
            with patch.dict(os.environ, {
                **SHARED_POLICY_ENV,
                SYNTHETIC_DEDICATED_CREDENTIAL_ENV: "switched-account-key",
            }), patch.object(workflow, "load_manifest", return_value=manifest), \
                    patch.object(workflow, "validate_attack_spec", return_value={
                        "attack_spec_id": "synthetic-attack", "spec_sha256": "2" * 64,
                    }):
                status = workflow.run_cell("synthetic-manifest", cfg["episode_id"],
                                           root / "run", execute_live=True,
                                           inventory=inv_file)
            self.assertEqual(status, {"status": "not_run", "reason": "provider_route_credential_changed",
                                      "model_calls": 0})
            self.assertFalse((root / "run" / "execution").exists())


if __name__ == "__main__":
    unittest.main()
