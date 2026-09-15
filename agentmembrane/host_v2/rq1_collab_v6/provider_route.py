"""Explicit, no-secret provider routing for bounded v6 live diagnostics.

An account label is an operator declaration. A generic OpenAI-compatible
``/models`` response cannot independently attest the upstream account. The
shared proxy contract is supplied by the operator through environment
configuration; this public module contains no machine-specific route.  The
shared pool is permitted only by the explicit shared-pool v2 route and is
always recorded as unattributed.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request

from ..rq1_collab_v1.audit import _write_new, canonical, file_hash, strict_loads
from ..rq1_collab_v1.providers import HTTPTransport, ProviderFailure


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


SHARED_PROXY_ENDPOINT_ENV = "AGENTMEMBRANE_SHARED_PROXY_ENDPOINT"
SHARED_PROXY_CREDENTIAL_ENV_ENV = "AGENTMEMBRANE_SHARED_PROXY_CREDENTIAL_ENV"
SHARED_PROXY_LABEL_ENV = "AGENTMEMBRANE_SHARED_PROXY_LABEL"
DEDICATED_IDENTITY = "operator_declared_dedicated_route_not_provider_attested"
SHARED_IDENTITY = "cli_proxy_shared_pool_upstream_account_unattributed"


def _safe_label(value):
    return (type(value) is str
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value) is not None)


def _shared_proxy_contract():
    """Return the operator-configured shared route or fail before route use."""

    endpoint = os.environ.get(SHARED_PROXY_ENDPOINT_ENV)
    credential_env = os.environ.get(SHARED_PROXY_CREDENTIAL_ENV_ENV)
    account_label = os.environ.get(SHARED_PROXY_LABEL_ENV)
    if not endpoint or not credential_env or not account_label:
        raise ValueError("shared_proxy_contract_configuration_required")
    if re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", credential_env) is None:
        raise ValueError("shared_proxy_credential_env_invalid")
    if not _safe_label(account_label):
        raise ValueError("shared_proxy_account_label_invalid")
    transport = HTTPTransport(endpoint, credential_env,
                              timeout_seconds=50, hard_timeout_seconds=50)
    parsed = urllib.parse.urlsplit(transport.endpoint)
    if (parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.port is None
            or parsed.path != "/v1/chat/completions"
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None):
        raise ValueError("shared_proxy_endpoint_must_be_explicit_loopback_chat_completions")
    return {
        "endpoint": transport.endpoint,
        "credential_env": credential_env,
        "account_label": account_label,
    }


def validate_route(route):
    if type(route) is not dict:
        raise ValueError("explicit_provider_route_fields_required")
    version = route.get("schema_version")
    if version == "rq1-provider-route/1":
        if set(route) != {"schema_version", "endpoint", "credential_env", "account_label"}:
            raise ValueError("explicit_provider_route_fields_required")
    elif version == "rq1-provider-route/2":
        if set(route) != {"schema_version", "routing_mode", "endpoint", "credential_env", "account_label"}:
            raise ValueError("explicit_shared_route_fields_required")
        shared_contract = _shared_proxy_contract()
        if (route["routing_mode"] != "shared_pool_unattributed"
                or any(route[key] != shared_contract[key] for key in shared_contract)):
            raise ValueError("shared_proxy_route_must_match_external_policy")
    else:
        raise ValueError("unsupported_provider_route_schema")
    label = route["account_label"]
    if not _safe_label(label):
        raise ValueError("safe_account_label_required")
    transport = HTTPTransport(route["endpoint"], route["credential_env"],
                              timeout_seconds=50, hard_timeout_seconds=50)
    parsed = urllib.parse.urlsplit(transport.endpoint)
    if version == "rq1-provider-route/1":
        shared_contract = _shared_proxy_contract()
        if transport.endpoint == shared_contract["endpoint"]:
            raise ValueError("known_shared_proxy_cannot_bind_requested_account")
    return dict(route)


def account_identity(route):
    return SHARED_IDENTITY if validate_route(route)["schema_version"] == "rq1-provider-route/2" else DEDICATED_IDENTITY


def load_route(path):
    return validate_route(strict_loads(Path(path).read_bytes()))


def source_binding(path):
    path = Path(path).resolve()
    route = load_route(path)
    return {"path": str(path), "sha256": file_hash(path), "route": route,
            "account_identity": account_identity(route)}


def verify_binding(binding):
    if (type(binding) is not dict or set(binding) != {"path", "sha256", "route", "account_identity"}
            or binding["account_identity"] != account_identity(binding["route"])
            or file_hash(binding["path"]) != binding["sha256"]
            or load_route(binding["path"]) != binding["route"]):
        raise ValueError("provider_route_binding_changed")
    return binding["route"]


def base_url(route):
    endpoint = validate_route(route)["endpoint"]
    return endpoint[:-len("/chat/completions")]


def credential_fingerprint(credential, salt_hex):
    if (type(credential) is not str or not credential
            or any(ord(c) < 33 or ord(c) > 126 for c in credential)
            or type(salt_hex) is not str or not re.fullmatch(r"[0-9a-f]{64}", salt_hex)):
        raise ValueError("provider_credential_or_salt_invalid")
    return hmac.new(bytes.fromhex(salt_hex),
                    b"rq1-route-credential-v1\x00" + credential.encode("ascii"),
                    hashlib.sha256).hexdigest()


class BoundRouteTransport(HTTPTransport):
    """Pin the inventory credential and bind an episode-local route diagnostic."""

    def __init__(self, route, inventory_record, *, timeout_seconds):
        route = validate_route(route)
        super().__init__(route["endpoint"], route["credential_env"],
                         timeout_seconds=timeout_seconds, hard_timeout_seconds=timeout_seconds)
        self._credential_salt = inventory_record["credential_salt"]
        self._credential_digest = inventory_record["credential_fingerprint"]
        self.shared_pool_unattributed = route["schema_version"] == "rq1-provider-route/2"
        if self.shared_pool_unattributed:
            # One transport is constructed for one episode.  The salt never
            # enters the seal; fingerprints compare selected proxy slots only
            # within this episode and cannot identify an upstream account.
            self.set_response_diagnostic_salt(secrets.token_bytes(32))

    def prepare(self):
        super().prepare()
        try:
            actual = credential_fingerprint(self._credential, self._credential_salt)
        except ValueError:
            actual = ""
        if not hmac.compare_digest(actual, self._credential_digest):
            self._credential = None
            raise ProviderFailure("provider_route_credential_changed", delivery="prepared_only", request_id="")


def inventory(route_path, output):
    binding = source_binding(route_path)
    route = binding["route"]
    credential = os.environ.get(route["credential_env"])
    if not credential or any(ord(c) < 33 or ord(c) > 126 for c in credential):
        raise ValueError("provider_credential_unavailable_or_invalid")
    url = base_url(route) + "/models"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + credential,
                                                     "Accept": "application/json"}, method="GET")
    try:
        with opener.open(request, timeout=10) as response:
            if response.status != 200:
                raise ValueError("provider_inventory_non_200")
            body = response.read(1_000_001)
    except urllib.error.HTTPError as exc:
        raise ValueError("provider_inventory_http_error") from exc
    if len(body) > 1_000_000:
        raise ValueError("provider_inventory_response_too_large")
    value = strict_loads(body)
    entries = value.get("data") if type(value) is dict else None
    if type(entries) is not list:
        raise ValueError("provider_inventory_invalid_models_shape")
    ids = [entry.get("id") for entry in entries if type(entry) is dict]
    if not ids or any(type(item) is not str or not item or len(item) > 200 for item in ids):
        raise ValueError("provider_inventory_invalid_model_ids")
    salt = secrets.token_hex(32)
    result = {"schema_version": "rq1-provider-inventory/1", "base_url": base_url(route),
              "provider_route_sha256": binding["sha256"], "account_label": route["account_label"],
              "account_identity": binding["account_identity"], "model_ids": sorted(set(ids)),
              "checked_at_unix": time.time(), "model_calls": 0,
              "credential_salt": salt,
              "credential_fingerprint": credential_fingerprint(credential, salt)}
    _write_new(Path(output), canonical(result) + b"\n")
    return {"inventory": str(Path(output).resolve()), "model_ids": result["model_ids"],
            "account_identity": result["account_identity"], "model_calls": 0}


def main():
    parser = argparse.ArgumentParser(description="Inspect an explicit v6 provider route without inference")
    sub = parser.add_subparsers(dest="command", required=True)
    probe = sub.add_parser("inventory")
    probe.add_argument("--route", required=True)
    probe.add_argument("--output", required=True)
    args = parser.parse_args()
    print(json.dumps(inventory(args.route, args.output), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
