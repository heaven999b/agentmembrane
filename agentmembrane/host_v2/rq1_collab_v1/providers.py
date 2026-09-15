"""Explicit-profile model transport. No model fallback and no implicit credential discovery.

This module is separately testable with an injected transport. Importing it does
not enable a model campaign. A caller must satisfy the campaign gates first.
API schema: https://developers.openai.com/api/reference/resources/chat/subresources/completions/methods/create
"""
from __future__ import annotations

import hashlib
import hmac
import base64
import http.client
import ipaddress
import json
import math
import os
import subprocess
import sys
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable


class ProviderFailure(RuntimeError):
    """Closed, non-secret failure metadata for the runtime adapter.

    A gateway response alone never proves acceptance by the requested model.
    No exception text, response content or authentication header is included.
    """
    def __init__(self, code: str, *, delivery: str, request_id: str,
                 kind: str = "model_service_error", http_status: int | None = None,
                 finish_reason: str | None = None, gateway_response: str = "not_observed",
                 model_acceptance: str | None = None):
        super().__init__(code)
        self.code, self.delivery, self.request_id = code, delivery, request_id
        self.kind, self.http_status, self.finish_reason = kind, http_status, finish_reason
        self.gateway_response = gateway_response
        self.model_acceptance = model_acceptance or (
            "not_attempted" if delivery == "prepared_only" else
            "response_observed" if delivery == "delivered" else "unknown")

    def audit_metadata(self) -> dict:
        return {"code": self.code, "kind": self.kind, "delivery": self.delivery,
                "request_id": self.request_id, "http_status": self.http_status,
                "finish_reason": self.finish_reason, "gateway_response": self.gateway_response,
                "model_acceptance": self.model_acceptance, "automatic_retry_allowed": False}


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate_json_key")
        out[key] = value
    return out


def _decode(raw: bytes):
    def reject(value):
        raise ValueError("nonfinite_json")
    def finite(value):
        number=float(value)
        if not math.isfinite(number): reject(value)
        return number
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                      parse_constant=reject, parse_float=finite)


def _body(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def build_action_payload(profile: dict, role_prompt: str, observation: dict,
                         action_protocol: str = "json_content_v1") -> dict:
    """Pure wire builder shared with the runtime's independent binding check.

    Native tool schemas remain in the observation. submit_action is only the
    transport envelope, never authorization to execute a native operation.
    """
    if action_protocol not in ("json_content_v1", "single_tool_v1"):
        raise ValueError("unsupported_action_protocol")
    if not isinstance(profile, dict) or not isinstance(observation, dict):
        raise ValueError("profile_and_observation_objects_required")
    if not isinstance(role_prompt, str) or not role_prompt:
        raise ValueError("nonempty_role_prompt_required")
    if not {"model", "max_completion_tokens"} <= profile.keys() or profile.keys() - {
            "model", "max_completion_tokens", "reasoning_effort", "temperature", "seed"}:
        raise ValueError("unsupported_or_missing_model_profile_field")
    payload = {**_decode(_body(profile)), "messages": [
        {"role": "system", "content": role_prompt},
        {"role": "user", "content": _body(observation).decode("utf-8")}],
        "stream": False, "store": False, "n": 1}
    if action_protocol == "single_tool_v1":
        payload.update(tools=[{"type": "function", "function": {
            "name": "submit_action", "description": "Submit exactly one runtime action.",
            "parameters": {"type": "object", "properties": {
                "type": {"type": "string", "enum": ["tool_action", "send_message", "final"]},
                "tool": {"type": "string", "maxLength": 256}, "arguments": {"type": "object"},
                "recipient": {"type": "string", "enum": ["H", "E"]},
                "content": {"type": "string", "maxLength": 32000}},
                "required": ["type"], "additionalProperties": False}}}],
            tool_choice={"type": "function", "function": {"name": "submit_action"}},
            parallel_tool_calls=False)
        if observation.get("protocol_version") == "rq1-multifactor/2":
            payload["tools"][0]["function"]["description"] = (
                "Submit exactly one runtime action using only the fields for its type: "
                "final {type, content}; send_message {type, recipient, content}; "
                "tool_action {type, tool, arguments} with optional acceptance_id; "
                "propose_action {type, tool, arguments, content}; "
                "accept_proposal {type, proposal_id, content_sha256}. "
                "Do not include recipient on final. Runtime validates before execution.")
            properties = payload["tools"][0]["function"]["parameters"]["properties"]
            properties["type"]["enum"].extend(["propose_action", "accept_proposal"])
            properties.update(proposal_id={"type": "string"}, content_sha256={"type": "string"},
                              acceptance_id={"type": "string"})
        elif observation.get("protocol_version") in {
                "rq1-three-actor/3", "rq1-three-actor/4", "rq1-three-actor/5"}:
            function = payload["tools"][0]["function"]
            function["description"] = (
                "Submit one action. tool_action: type, tool, arguments; "
                "send_message: type, recipient, content; final: type, content; "
                "delegate: type, recipient (S or E), content, tools. "
                "Optional source_refs must name evidence actually delivered to you. "
                "Only H can delegate; S final returns to H; E final hands off to H. "
                "No action grants extra authority. Runtime validates every field.")
            properties = function["parameters"]["properties"]
            properties["recipient"]["enum"] = ["H", "S", "E"]
            properties["type"]["enum"].append("delegate")
            properties.update(
                tools={"type": "array", "maxItems": 64, "uniqueItems": True,
                       "items": {"type": "string", "minLength": 1, "maxLength": 256}},
                source_refs={"type": "array", "maxItems": 64, "uniqueItems": True,
                             "items": {"type": "string", "minLength": 1, "maxLength": 256}})
            if observation.get("protocol_version") in {"rq1-three-actor/4", "rq1-three-actor/5"}:
                # Dynamic native argument objects intentionally remain non-strict.
                # The controller validates exact per-action/per-tool schemas.
                function["strict"] = False
                function["description"] += (
                    " memory.get/put/list are system tools, not native tools. "
                    "For native tool_action only, optional argument_refs maps a top-level "
                    "JSON argument pointer to an exact delivered memory version; "
                    "do not also provide that argument literally.")
                properties["argument_refs"] = {"type": "object", "minProperties": 1,
                    "maxProperties": 16,
                    "propertyNames": {"pattern": "^/[A-Za-z_][A-Za-z0-9_]{0,127}$"},
                    "additionalProperties": {"type": "object", "additionalProperties": False,
                        "required": ["record_id", "version", "field_pointer", "read_event_id", "projected_value_sha256"],
                        "properties": {"record_id": {"type": "string", "minLength": 1, "maxLength": 128},
                            "version": {"type": "integer", "minimum": 1},
                            "field_pointer": {"type": "string", "maxLength": 1024},
                            "read_event_id": {"type": "string", "minLength": 1, "maxLength": 256},
                            "projected_value_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}}}}
    return payload


def _single_tool_action(message: dict, finish: str | None, *, protocol_version=None) -> str:
    """Validate the one API call and return its EXACT arguments string."""
    if finish != "tool_calls" or message.get("function_call") is not None:
        raise ValueError("single_tool_finish_required")
    calls = message.get("tool_calls")
    if not isinstance(calls, list) or len(calls) != 1:
        raise ValueError("exactly_one_submit_action_required")
    call = calls[0]
    if (not isinstance(call, dict) or set(call) != {"id", "type", "function"}
            or call["type"] != "function" or not isinstance(call["id"], str) or not call["id"].strip()):
        raise ValueError("well_formed_function_call_required")
    call["id"].encode("utf-8")
    function = call["function"]
    if (not isinstance(function, dict) or set(function) != {"name", "arguments"}
            or function["name"] != "submit_action" or not isinstance(function["arguments"], str)):
        raise ValueError("submit_action_arguments_required")
    text = function["arguments"]
    value = _decode(text.encode("utf-8"))
    if protocol_version in {"rq1-three-actor/3", "rq1-three-actor/4", "rq1-three-actor/5"}:
        if not isinstance(value, dict) or value.get("type") not in {
                "tool_action", "send_message", "delegate", "final"}:
            raise ValueError("action_envelope_schema_mismatch")
        return text
    if protocol_version == "rq1-multifactor/2":
        # The provider validates the unique, finite JSON transport envelope.
        # Runtime validates action fields before any binding or dispatch and
        # returns its existing format_error feedback within the same budget.
        # A delivered final with an extra recipient is not transport ambiguity;
        # preserve its exact bytes instead of halting both participants here.
        if (not isinstance(value, dict) or value.get("type") not in
                ("tool_action", "send_message", "final", "propose_action", "accept_proposal")):
            raise ValueError("action_envelope_schema_mismatch")
        return text
    if (not isinstance(value, dict) or value.get("type") not in ("tool_action", "send_message", "final")
            or value.keys() - {"type", "tool", "arguments", "recipient", "content"}):
        raise ValueError("action_envelope_schema_mismatch")
    for key in ("tool", "recipient", "content"):
        if key in value and not isinstance(value[key], str):
            raise ValueError("action_envelope_string_required")
    if "arguments" in value and not isinstance(value["arguments"], dict):
        raise ValueError("action_arguments_object_required")
    if "recipient" in value and value["recipient"] not in ("H", "E"):
        raise ValueError("action_recipient_invalid")
    return text


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect_not_allowed", headers, fp)


_SAFE_ERROR_TYPES = frozenset({"invalid_request_error", "authentication_error", "permission_error",
    "not_found_error", "rate_limit_error", "server_error", "api_error", "overloaded_error"})
_SAFE_ERROR_CODES = frozenset({"model_not_found", "invalid_model", "unsupported_model",
    "invalid_api_key", "insufficient_quota", "rate_limit_exceeded", "invalid_request_error",
    "not_found", "auth_unavailable", "auth_not_found", "provider_not_found", "model_cooldown"})


def safe_response_metadata(value: Any) -> dict:
    """Closed output schema; arbitrary headers, identifiers and messages never pass."""
    if type(value) is not dict:
        return {}
    out = {}
    for key, allowed in (("error_type", _SAFE_ERROR_TYPES), ("error_code", _SAFE_ERROR_CODES)):
        item = value.get(key)
        if type(item) is str and item in allowed:
            out[key] = item
    fingerprint = value.get("route_fingerprint")
    if type(fingerprint) is str and re.fullmatch(r"[0-9a-f]{64}", fingerprint):
        out["route_fingerprint"] = fingerprint
    return out


def response_error_metadata(body: bytes) -> dict:
    """Classify exact enum fields only, never interpolate an upstream message."""
    try:
        value = _decode(body)
    except (ValueError, TypeError, UnicodeError):
        return {}
    error = value.get("error") if type(value) is dict else None
    if type(error) is not dict:
        return {}
    return safe_response_metadata({"error_type": error.get("type"), "error_code": error.get("code")})


@dataclass(frozen=True)
class HTTPReply:
    status: int
    body: bytes
    receipt_id: str | None = None
    body_complete: bool = True
    response_metadata: dict = field(default_factory=dict)


class HTTPTransport:
    """One bounded request; network destination comes only from trusted config."""
    def __init__(self, endpoint: str, credential_env: str, *, timeout_seconds: float = 60,
                 max_response_bytes: int = 2_000_000, hard_timeout_seconds: float | None = None):
        if not isinstance(endpoint, str) or any(ord(c) <= 32 or ord(c) == 127 for c in endpoint):
            raise ValueError("invalid_endpoint_text")
        parsed = urllib.parse.urlsplit(endpoint)
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("invalid_endpoint_port")
        local = False
        try:
            local = ipaddress.ip_address(parsed.hostname or "").is_loopback
        except ValueError:
            local = parsed.hostname == "localhost"
        if (parsed.scheme != "https" and not (parsed.scheme == "http" and local)) or not parsed.hostname:
            raise ValueError("https_or_explicit_loopback_required")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("credentials_query_fragment_not_allowed_in_endpoint")
        if not parsed.path.endswith("/chat/completions"):
            raise ValueError("explicit_chat_completions_endpoint_required")
        if not isinstance(credential_env, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", credential_env):
            raise ValueError("credential_env_name_required")
        if type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise ValueError("positive_timeout_required")
        if type(max_response_bytes) is not int or max_response_bytes <= 0:
            raise ValueError("positive_response_bound_required")
        if hard_timeout_seconds is not None and (type(hard_timeout_seconds) not in (int, float)
                or not math.isfinite(hard_timeout_seconds) or hard_timeout_seconds <= 0):
            raise ValueError("positive_hard_timeout_required")
        self._endpoint, self._credential_env = endpoint, credential_env
        self._timeout_seconds, self._max_response_bytes = timeout_seconds, max_response_bytes
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        self._credential = None
        self._hard_timeout_seconds = hard_timeout_seconds
        self._response_diagnostic_salt = None
        self.last_attempt_metadata = {}

    def set_response_diagnostic_salt(self, salt: bytes) -> None:
        """Local-only opt-in. Use one unpredictable salt per diagnostic, not per call.

        The salt and raw CPA trace header are never placed in audit metadata.
        Fingerprints identify the last selected route, not all upstream attempts.
        """
        if type(salt) is not bytes or len(salt) != 32:
            raise ValueError("response_diagnostic_salt_must_be_32_bytes")
        self._response_diagnostic_salt = salt

    @property
    def hard_timeout_seconds(self):
        return self._hard_timeout_seconds

    @property
    def endpoint(self):
        return self._endpoint

    @property
    def credential_env(self):
        return self._credential_env

    @property
    def timeout_seconds(self):
        return self._timeout_seconds

    @property
    def max_response_bytes(self):
        return self._max_response_bytes

    @property
    def route_metadata(self) -> dict:
        return {"transport": "rq1_explicit_chat_completions_v2",
                "endpoint_sha256": hashlib.sha256(self.endpoint.encode()).hexdigest(),
                "timeout_seconds": self.timeout_seconds,
                "timeout_semantics": ("killable_process_total_wall" if self.hard_timeout_seconds is not None
                                      else "socket_operation_not_total_wall_deadline"),
                "hard_timeout_seconds": self.hard_timeout_seconds,
                "termination_grace_seconds": 1.0 if self.hard_timeout_seconds is not None else None,
                "max_response_bytes": self.max_response_bytes, "automatic_retries": 0,
                "environment_proxy_disabled": True, "redirects_allowed": False}

    def prepare(self) -> None:
        """Local-only validation, before the durable transport-attempt marker."""
        key = os.environ.get(self.credential_env)
        self._credential = None
        if not key:
            raise ProviderFailure("credential_unavailable", delivery="prepared_only", request_id="")
        if any(ord(c) < 33 or ord(c) > 126 for c in key):
            raise ProviderFailure("credential_invalid", delivery="prepared_only", request_id="")
        self._credential = key

    def contains_credential(self, value: bytes) -> bool:
        """Never return the credential to an evidence writer."""
        if not self._credential:
            return False
        secret = self._credential.encode("ascii")
        forms = (secret, json.dumps(self._credential)[1:-1].encode(), base64.b64encode(secret))
        normalized = re.sub(rb"\\u00([0-9a-fA-F]{2})", lambda match: bytes([int(match[1], 16)]), value)
        return any(form in normalized or form in urllib.parse.unquote_to_bytes(normalized) for form in forms)

    def _read_reply(self, response, status: int) -> HTTPReply:
        """Check HTTP framing independently of whether the prefix is valid JSON.

        HTTPResponse.read(amt) can silently return fewer bytes than a declared
        Content-Length. Inspect the original headers, not its mutable remaining
        length. Chunk framing is checked by http.client; retain partial bytes
        when it reports an incomplete read. No retry or unbounded read is used.
        """
        headers = response.headers
        def values(name):
            if headers is None:
                return []
            if hasattr(headers, "get_all"):
                return headers.get_all(name, [])
            return [value for key, value in headers.items() if key.lower() == name.lower()]

        lengths, encodings = values("Content-Length"), values("Transfer-Encoding")
        declared = None
        framing_valid = True
        if encodings:
            # urllib only decodes a single chunked transfer coding. Conflicting
            # length/coding or other codings cannot attest a complete body here.
            framing_valid = (len(encodings) == 1 and encodings[0].strip().lower() == "chunked"
                             and not lengths)
        elif lengths:
            framing_valid = len(lengths) == 1 and re.fullmatch(r"[0-9]+", lengths[0].strip()) is not None
            if framing_valid:
                try:
                    declared = int(lengths[0].strip())
                except ValueError:
                    framing_valid = False
        try:
            body = response.read(self.max_response_bytes + 1)
        except http.client.IncompleteRead as exc:
            body, framing_valid = exc.partial, False
        complete = (framing_valid and len(body) <= self.max_response_bytes
                    and (declared is None or len(body) == declared))
        receipt = headers.get("x-request-id") if headers else None
        metadata = response_error_metadata(body) if complete and status != 200 else {}
        traces = values("X-CPA-TRACE-ID")
        if self._response_diagnostic_salt is not None and len(traces) == 1 and type(traces[0]) is str:
            # Installed CLIProxyAPI format: timestamp-authIndex-requestID.
            # Reject ambiguous/malformed headers. Hash only the stable index;
            # timestamp and request ID change for every request.
            match = re.fullmatch(r"[0-9]{14}-([A-Za-z0-9_]{1,128})-([A-Za-z0-9_-]{1,256})", traces[0])
            if match:
                metadata["route_fingerprint"] = hmac.new(self._response_diagnostic_salt,
                    b"rq1-cpa-route-v1\x00" + match[1].encode("ascii"), hashlib.sha256).hexdigest()
        return HTTPReply(status, body, receipt, complete, metadata)

    def __call__(self, body: bytes) -> HTTPReply:
        return self.request(body)

    def request(self, body: bytes, *, deadline_monotonic: float | None = None) -> HTTPReply:
        self.last_attempt_metadata = {}
        if self._credential is None:
            self.prepare()
        if self.hard_timeout_seconds is None:
            if deadline_monotonic is not None:
                raise ValueError("hard_transport_required_for_deadline")
            return self._request(body)
        started = time.monotonic()
        deadline = started + self.hard_timeout_seconds
        if deadline_monotonic is not None:
            deadline = min(deadline, deadline_monotonic)
        if deadline <= started:
            raise ProviderFailure("model_request_deadline_exhausted", delivery="prepared_only", request_id="",
                                  kind="budget_exhausted")
        # Only this isolated interpreter owns the socket. Credential travels on
        # a private stdin pipe, never argv/environment/logs. No background thread
        # is allowed to keep the request alive after the deadline returns.
        payload = _body({"endpoint": self.endpoint, "credential": self._credential,
                         "timeout": self.timeout_seconds, "max_bytes": self.max_response_bytes,
                         "body_hex": body.hex(), "response_diagnostic_salt_hex": (
                             self._response_diagnostic_salt.hex() if self._response_diagnostic_salt is not None else None)})
        root = str(Path(__file__).resolve().parents[3])
        worker = subprocess.Popen([sys.executable, "-I", "-S", "-c",
            "import sys; sys.path.insert(0, sys.argv[1]); "
            "from agentmembrane.host_v2.rq1_collab_v1.providers import _http_worker_main; _http_worker_main()", root],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            cwd=root, env={})
        timed_out = False
        cleanup_deadline = None
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(worker.args, 0)
            output, _ = worker.communicate(payload, timeout=remaining)
            if time.monotonic() >= deadline:
                timed_out = True
        except subprocess.TimeoutExpired:
            timed_out = True
            cleanup_deadline = time.monotonic() + 1.0
            worker.kill()
            try:
                output, _ = worker.communicate(timeout=1.0)
            except subprocess.TimeoutExpired:
                output = b""
        finally:
            if worker.poll() is None:
                worker.kill()
                try:
                    worker.wait(timeout=max(0, (cleanup_deadline or (time.monotonic() + 1.0)) - time.monotonic()))
                except subprocess.TimeoutExpired:
                    pass
            for stream in (worker.stdin, worker.stdout):
                if stream is not None:
                    stream.close()
            self.last_attempt_metadata = {"worker_pid": worker.pid, "worker_exit_code": worker.returncode,
                "local_worker_reaped": worker.poll() is not None, "deadline_exceeded": timed_out,
                "elapsed_seconds": time.monotonic() - started, "upstream_cancellation": "unknown"}
        if worker.poll() is None:
            raise ProviderFailure("model_local_termination_unconfirmed", delivery="delivery_unknown", request_id="",
                                  kind="transport_error")
        if timed_out:
            raise ProviderFailure("model_request_wall_deadline", delivery="delivery_unknown", request_id="",
                                  kind="transport_error")
        try:
            result = _decode(output)
            if worker.returncode != 0 or "error_class" in result:
                raise ValueError("worker_transport_error")
            return HTTPReply(result["status"], bytes.fromhex(result["body_hex"]),
                             result["receipt_id"], result["body_complete"],
                             safe_response_metadata(result.get("response_metadata")))
        except (ValueError, TypeError, KeyError):
            raise ProviderFailure("model_transport_worker_failure", delivery="delivery_unknown", request_id="",
                                  kind="transport_error") from None

    def _request(self, body: bytes) -> HTTPReply:
        request = urllib.request.Request(self.endpoint, body,
            {"Content-Type": "application/json", "Accept": "application/json",
             "Authorization": "Bearer " + self._credential}, method="POST")
        try:
            response = self.opener.open(request, timeout=self.timeout_seconds)
        except urllib.error.HTTPError as exc:
            # Only gateway response evidence. Always close the HTTP error stream.
            try:
                return self._read_reply(exc, exc.code)
            finally:
                exc.close()
        with response:
            return self._read_reply(response, response.status)


def _http_worker_main():
    """Private bounded protocol; no arbitrary object unpickling or error text."""
    try:
        config = _decode(sys.stdin.buffer.read())
        transport = HTTPTransport(config["endpoint"], "RQ1_ISOLATED_PIPE_CREDENTIAL",
                                  timeout_seconds=config["timeout"], max_response_bytes=config["max_bytes"])
        transport._credential = config["credential"]
        if config.get("response_diagnostic_salt_hex") is not None:
            transport.set_response_diagnostic_salt(bytes.fromhex(config["response_diagnostic_salt_hex"]))
        reply = transport._request(bytes.fromhex(config["body_hex"]))
        result = {"status": reply.status, "body_hex": reply.body.hex(),
                  "receipt_id": reply.receipt_id, "body_complete": reply.body_complete,
                  "response_metadata": safe_response_metadata(reply.response_metadata)}
    except Exception as exc:
        result = {"error_class": type(exc).__name__}
    sys.stdout.buffer.write(_body(result))
    sys.stdout.buffer.flush()


class ModelDriver:
    """Separate actor contexts supplied by runtime, exact payload auditing, bounded calls.

No repair/retry/fallback is performed here. Any retry must be another visible,
budgeted runtime decision. Token usage is recorded, not inferred from characters.
"""
    mode = "model"

    def __init__(self, profile: dict, role_prompts: dict[str, str], collector,
                 transport: Callable[[bytes], HTTPReply], *, request_limit: int,
                 max_request_bytes: int = 1_000_000, max_response_bytes: int = 2_000_000,
                 strict_usage: bool = False, actor_token_limits: dict[str, int] | None = None,
                 actor_request_limits: dict[str, int] | None = None,
                 action_protocol: str = "json_content_v1"):
        if not isinstance(profile, dict):
            raise ValueError("model_profile_object_required")
        required = {"model", "max_completion_tokens"}
        if not required <= profile.keys() or profile.keys() - required - {"reasoning_effort", "temperature", "seed"}:
            raise ValueError("unsupported_or_missing_model_profile_field")
        if (not isinstance(profile["model"], str) or not profile["model"]
                or len(profile["model"]) > 256 or any(ord(c) <= 32 or ord(c) == 127 for c in profile["model"])):
            raise ValueError("explicit_model_required")
        if type(profile["max_completion_tokens"]) is not int or profile["max_completion_tokens"] <= 0:
            raise ValueError("positive_output_budget_required")
        if "temperature" in profile and (type(profile["temperature"]) not in (int, float)
                or not math.isfinite(profile["temperature"]) or not 0 <= profile["temperature"] <= 2):
            raise ValueError("invalid_temperature")
        if "seed" in profile and (type(profile["seed"]) is not int
                or not -(2 ** 63) <= profile["seed"] < 2 ** 63):
            raise ValueError("invalid_seed")
        if "reasoning_effort" in profile and (not isinstance(profile["reasoning_effort"], str)
                or profile["reasoning_effort"] not in {"none", "minimal", "low", "medium", "high", "xhigh", "max"}):
            raise ValueError("invalid_reasoning_effort")
        for value in (request_limit, max_request_bytes, max_response_bytes):
            if type(value) is not int or value <= 0:
                raise ValueError("positive_integer_limits_required")
        if not isinstance(role_prompts, dict) or not role_prompts or any(
                not isinstance(k, str) or not k or not isinstance(v, str) or not v
                for k, v in role_prompts.items()):
            raise ValueError("explicit_role_prompts_required")
        if not callable(transport):
            raise ValueError("callable_transport_required")
        if action_protocol not in ("json_content_v1", "single_tool_v1"):
            raise ValueError("unsupported_action_protocol")
        if type(strict_usage) is not bool:
            raise ValueError("strict_usage_boolean_required")
        for limits in (actor_token_limits, actor_request_limits):
            if limits is not None and (not isinstance(limits, dict) or set(limits) != set(role_prompts)
                    or any(type(value) is not int or value <= 0 for value in limits.values())):
                raise ValueError("positive_limits_for_exact_actor_set_required")
        if strict_usage and (actor_token_limits is None or actor_request_limits is None):
            raise ValueError("strict_actor_limits_required")
        if strict_usage and isinstance(transport, HTTPTransport) and transport.hard_timeout_seconds is None:
            raise ValueError("strict_http_requires_hard_deadline")
        self._profile = _decode(_body(profile))
        self._role_prompts = _decode(_body(role_prompts))
        self.collector, self.transport = collector, transport
        self._request_limit, self._max_request_bytes, self._max_response_bytes = request_limit, max_request_bytes, max_response_bytes
        self.requests = 0
        self.records: list[dict] = []
        self.attempt_records: list[dict] = []
        self._mutex = threading.Lock()
        self._strict_usage = strict_usage
        self._action_protocol = action_protocol
        self._actor_token_limits = dict(actor_token_limits or {})
        self._actor_request_limits = dict(actor_request_limits or {})
        self._accounting = {actor: {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0,
                                  "requests": 0, "unverifiable_attempts": 0} for actor in role_prompts}
        self._halt_reason = None
        self._episode_deadline = None
        self._bindings = {}
        self._call_sequence = 0

    @property
    def strict_usage(self):
        return self._strict_usage

    @property
    def action_protocol(self):
        return self._action_protocol

    @property
    def request_limit(self):
        return self._request_limit

    @property
    def max_request_bytes(self):
        return self._max_request_bytes

    @property
    def max_response_bytes(self):
        return self._max_response_bytes

    @property
    def actor_token_limits(self):
        return dict(self._actor_token_limits)

    @property
    def actor_request_limits(self):
        return dict(self._actor_request_limits)

    def begin_episode(self, *, deadline_monotonic: float):
        with self._mutex:
            if self._episode_deadline is not None or self.requests:
                raise ValueError("episode_deadline_already_locked")
            if (type(deadline_monotonic) not in (int, float) or not math.isfinite(deadline_monotonic)
                    or deadline_monotonic <= time.monotonic()):
                raise ValueError("future_episode_deadline_required")
            self._episode_deadline = deadline_monotonic

    def last_completion_binding(self, actor: str) -> dict | None:
        binding = self._bindings.get(actor)
        return _decode(_body(binding)) if binding is not None else None

    def budget_snapshot(self) -> dict:
        return _decode(_body({"strict_usage": self.strict_usage, "actors": self._accounting,
            "actor_token_limits": self._actor_token_limits, "actor_request_limits": self._actor_request_limits,
            "requests": self.requests, "request_limit": self.request_limit,
            "halted": self._halt_reason is not None, "halt_reason": self._halt_reason,
            "episode_deadline_monotonic": self._episode_deadline,
            "accounting_semantics": "reported_usage_stop_line_not_exact_billing_preauthorization"}))

    @property
    def profile(self) -> dict:
        return _decode(_body(self._profile))

    @property
    def role_prompts(self) -> dict:
        return dict(self._role_prompts)

    def _record(self, request_id, raw, status, actor, **metadata):
        self.collector.record_model_request(request_id=request_id, serialized_body=raw,
            status=status, actor=actor, model_profile=self.profile,
            transport_profile=(self.transport.route_metadata if isinstance(self.transport, HTTPTransport)
                               else {"transport": "injected_test_transport", "attested": False}), **metadata)

    def next_action(self, actor: str, observation: dict) -> str:
        # Runtime scheduling is serial; this also prevents accidental concurrent
        # H/E calls racing the shared request reservation/budget.
        with self._mutex:
            self._call_sequence += 1
            if isinstance(actor, str):
                self._bindings.pop(actor, None)
            before = len(self.attempt_records)
            try:
                return self._next_action(actor, observation)
            except ProviderFailure as exc:
                if len(self.attempt_records) == before:
                    attempt = {"attempt_sequence": self._call_sequence, "request_id": exc.request_id,
                        "actor": actor if isinstance(actor, str) else None, "status": exc.code,
                        "delivery": exc.delivery, "usage": None, "usage_status": "unknown",
                        "failure": exc.audit_metadata()}
                    self.attempt_records.append(attempt)
                    self.collector.emit("model_attempt_outcome", attempt, actor=attempt["actor"])
                if self.strict_usage and exc.delivery == "delivery_unknown":
                    self._halt_reason = exc.code
                    if isinstance(actor, str) and actor in self._accounting:
                        self._accounting[actor]["unverifiable_attempts"] += 1
                raise

    def _next_action(self, actor: str, observation: dict) -> str:
        if not isinstance(actor, str) or actor not in self._role_prompts:
            raise ProviderFailure("unknown_actor", delivery="prepared_only", request_id="")
        if self._halt_reason:
            raise ProviderFailure("provider_halted", delivery="prepared_only", request_id="", kind="budget_exhausted")
        if self.strict_usage and self._episode_deadline is None:
            raise ProviderFailure("episode_deadline_not_set", delivery="prepared_only", request_id="", kind="budget_exhausted")
        if self._episode_deadline is not None and time.monotonic() >= self._episode_deadline:
            self._halt_reason = "episode_deadline_exhausted"
            raise ProviderFailure(self._halt_reason, delivery="prepared_only", request_id="", kind="budget_exhausted")
        accounting = self._accounting[actor]
        if actor in self._actor_request_limits and accounting["requests"] >= self._actor_request_limits[actor]:
            raise ProviderFailure("actor_request_budget_exhausted", delivery="prepared_only", request_id="", kind="budget_exhausted")
        if (actor in self._actor_token_limits and self._actor_token_limits[actor] - accounting["total_tokens"]
                < self._profile["max_completion_tokens"]):
            raise ProviderFailure("actor_token_budget_exhausted", delivery="prepared_only", request_id="", kind="budget_exhausted")
        if self.requests >= self.request_limit:
            raise ProviderFailure("model_request_budget_exhausted", delivery="prepared_only", request_id="",
                                  kind="budget_exhausted")
        try:
            if not isinstance(observation, dict):
                raise ValueError("observation_object_required")
            payload = build_action_payload(self._profile, self._role_prompts[actor], observation, self.action_protocol)
            raw = _body(payload)
        except (ValueError, TypeError, OverflowError, RecursionError):
            raise ProviderFailure("model_request_protocol_error", delivery="prepared_only",
                                  request_id="", kind="model_protocol_error") from None
        if len(raw) > self.max_request_bytes:
            raise ProviderFailure("request_byte_budget_exhausted", delivery="prepared_only", request_id="",
                                  kind="budget_exhausted")
        self.requests += 1
        accounting["requests"] += 1
        request_id = f"model-{self.requests:06d}-{hashlib.sha256(raw).hexdigest()[:12]}"
        start = time.monotonic()
        preparation_error = None
        if isinstance(self.transport, HTTPTransport):
            try:
                self.transport.prepare()
            except ProviderFailure as exc:
                preparation_error = exc
            if self.transport.contains_credential(raw):
                self.collector.emit("model_not_sent", {"request_id": request_id,
                    "reason": "credential_in_model_body", "delivery": "prepared_only",
                    "network_attempted": False}, actor=actor)
                raise ProviderFailure("credential_in_model_body", delivery="prepared_only", request_id=request_id)
        self._record(request_id, raw, "prepared_only", actor)
        if preparation_error is not None:
            exc = preparation_error
            self.collector.emit("model_not_sent", {"request_id":request_id, "reason":exc.code,
                "delivery":"prepared_only", "network_attempted":False}, actor=actor)
            raise ProviderFailure(exc.code, delivery="prepared_only", request_id=request_id) from None
        # A crash after this durable event must not be misread as definitely unsent.
        self._record(request_id, raw, "delivery_unknown", actor)
        try:
            reply = (self.transport.request(raw, deadline_monotonic=self._episode_deadline)
                     if isinstance(self.transport, HTTPTransport) and self.transport.hard_timeout_seconds is not None
                     else self.transport(raw))
        except ProviderFailure as exc:
            self.collector.emit("model_transport_failure", {"request_id": request_id,
                "failure": exc.audit_metadata(), "transport_evidence": (
                    dict(self.transport.last_attempt_metadata) if isinstance(self.transport, HTTPTransport) else {})}, actor=actor)
            raise ProviderFailure(exc.code, delivery=exc.delivery, request_id=request_id, kind=exc.kind,
                http_status=exc.http_status, gateway_response=exc.gateway_response,
                model_acceptance=exc.model_acceptance) from None
        except Exception as exc:
            self.collector.emit("model_transport_failure", {"request_id": request_id,
                "error_class": type(exc).__name__, "delivery": "delivery_unknown"}, actor=actor)
            raise ProviderFailure("model_transport_failure", delivery="delivery_unknown", request_id=request_id,
                                  kind="transport_error") from None
        if (not isinstance(reply, HTTPReply) or type(reply.status) is not int or not 100 <= reply.status <= 599
                or type(reply.body) is not bytes or type(reply.body_complete) is not bool):
            self.collector.emit("model_response_invalid", {"request_id": request_id,
                "reason": "invalid_transport_reply", "delivery": "delivery_unknown"}, actor=actor)
            raise ProviderFailure("model_response_protocol_error", delivery="delivery_unknown",
                                  request_id=request_id, kind="model_protocol_error")
        response_hash = hashlib.sha256(reply.body).hexdigest()
        credential_echo = isinstance(self.transport, HTTPTransport) and self.transport.contains_credential(reply.body)
        # HTTP errors are hash-only: arbitrary gateways may echo credentials or
        # headers. Redacted evidence never pretends to be the original bytes.
        capture_redacted = reply.status != 200 or credential_echo
        captured = b"" if capture_redacted else reply.body[:self.max_response_bytes]
        receipt_id = reply.receipt_id
        if (not isinstance(receipt_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", receipt_id)
                or (isinstance(self.transport, HTTPTransport)
                    and self.transport.contains_credential(receipt_id.encode("utf-8")))):
            receipt_id = None
        response_event = self.collector.emit("model_response", {"request_id": request_id, "status": reply.status,
            "response_sha256": response_hash, "response_bytes": len(reply.body),
            "response_hash_scope": "complete_body" if reply.body_complete else "observed_prefix",
            "raw_response_hex": captured.hex(), "captured_response_sha256": hashlib.sha256(captured).hexdigest(),
            "response_redacted": capture_redacted,
            "response_capture_complete": not capture_redacted and reply.body_complete and len(reply.body) <= self.max_response_bytes,
            "gateway_response": "received", "model_acceptance": "unknown",
            "latency_seconds": time.monotonic() - start}, actor=actor)
        if reply.status != 200:
            raise ProviderFailure("model_http_error", delivery="delivery_unknown", request_id=request_id,
                                  http_status=reply.status, gateway_response="received")
        if credential_echo:
            raise ProviderFailure("credential_in_model_response", delivery="delivery_unknown", request_id=request_id,
                                  http_status=reply.status, gateway_response="received")
        if len(reply.body) > self.max_response_bytes:
            raise ProviderFailure("model_response_too_large", delivery="delivery_unknown", request_id=request_id,
                                  kind="model_protocol_error", http_status=reply.status, gateway_response="received")
        if not reply.body_complete:
            raise ProviderFailure("model_http_body_incomplete", delivery="delivery_unknown", request_id=request_id,
                                  kind="transport_error", http_status=reply.status, gateway_response="received")
        try:
            result = _decode(reply.body)
            if not isinstance(result, dict) or result.get("error") is not None:
                raise ValueError("completion_object_required")
            if result.get("model") != self._profile["model"]:
                raise ValueError("model_identity_mismatch")
            choices = result["choices"]
            if not isinstance(choices, list) or len(choices) != 1:
                raise ValueError("single_choice_required")
            message = choices[0]["message"]
            if not isinstance(message, dict):
                raise ValueError("assistant_message_required")
        except (ValueError, TypeError, KeyError, AttributeError, IndexError, RecursionError):
            raise ProviderFailure("model_response_protocol_error", delivery="delivery_unknown", request_id=request_id,
                                  kind="model_protocol_error", http_status=reply.status, gateway_response="received") from None
        self._record(request_id, raw, "delivered", actor, receipt={
            "provider_request_id": receipt_id,
            "gateway_response": "received", "model_acceptance": "response_observed",
            "acceptance_evidence": {"http_status": reply.status, "response_sha256": response_hash,
                                    "event_id": (response_event or {}).get("event_id"),
                                    "response_model": result["model"]}})
        finish = choices[0].get("finish_reason")
        safe_finish = finish if finish in ("stop", "length", "content_filter", "tool_calls", "function_call") else None
        usage = result.get("usage")
        failure_code = None
        usage_status = "invalid" if usage is not None else "unknown"
        try:
            usage_status = self._validate_usage(usage)
            if isinstance(usage, dict) and usage.get("completion_tokens", 0) > self._profile["max_completion_tokens"]:
                raise ValueError("reported_output_budget_exceeded")
            if choices[0].get("index", 0) != 0 or type(choices[0].get("index", 0)) is not int:
                raise ValueError("invalid_choice_index")
            if message.get("role", "assistant") != "assistant":
                raise ValueError("assistant_role_required")
            if message.get("refusal") is not None and not isinstance(message["refusal"], str):
                raise ValueError("invalid_refusal")
            text = message.get("content")
            if text is not None and not isinstance(text, str):
                raise ValueError("text_content_only")
            if any(message.get(key) is not None for key in ("audio", "images", "image", "image_url")):
                raise ValueError("auxiliary_media_not_allowed")
            if message.get("function_call") is not None or message.get("function_calls") is not None:
                raise ValueError("legacy_function_call_not_allowed")
            if safe_finish == "content_filter":
                failure_code = "model_content_filter"
            elif message.get("refusal"):
                failure_code = "model_refusal"
            elif safe_finish == "length":
                failure_code = "model_response_truncated"
            elif self.action_protocol == "single_tool_v1":
                text = _single_tool_action(message, safe_finish,
                                           protocol_version=observation.get("protocol_version"))
            elif (safe_finish != "stop" or not isinstance(text, str) or not text.strip()
                  or message.get("tool_calls") not in (None, []) or message.get("function_call") is not None):
                raise ValueError("unexpected_or_ambiguous_output_channel")
            if isinstance(text, str):
                text.encode("utf-8")
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
            failure_code = "model_response_protocol_error"
        response_failure_code = failure_code
        if self.action_protocol == "single_tool_v1" and failure_code == "model_response_protocol_error":
            self._halt_reason = failure_code
        if self.strict_usage and usage_status == "reported":
            # This driver always sends nonempty system and user messages. A
            # nonempty completion cannot honestly consume zero output tokens.
            # This consistency check is not a tokenizer or billing attestation.
            nonempty_output = any(isinstance(message.get(key), str) and bool(message[key])
                                  for key in ("content", "refusal")) or bool(message.get("tool_calls"))
            if usage["prompt_tokens"] == 0 or (nonempty_output and usage["completion_tokens"] == 0):
                usage_status = "invalid"
        if usage_status == "reported":
            for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
                accounting[key] += usage[key]
        elif self.strict_usage:
            accounting["unverifiable_attempts"] += 1
            self._halt_reason = "model_usage_unverifiable"
            failure_code = self._halt_reason
        if (self.strict_usage and usage_status == "reported"
                and usage["completion_tokens"] > self._profile["max_completion_tokens"]):
            self._halt_reason = "reported_output_budget_exceeded"
            failure_code = self._halt_reason
        if (actor in self._actor_token_limits and accounting["total_tokens"] > self._actor_token_limits[actor]):
            failure_code = "actor_token_budget_exceeded"
        if self._episode_deadline is not None and time.monotonic() >= self._episode_deadline:
            self._halt_reason = "episode_deadline_exhausted"
            failure_code = self._halt_reason
        attempt = {"request_id": request_id, "actor": actor, "attempt_sequence": self._call_sequence,
                   "action_protocol": self.action_protocol,
                   "delivery": "delivered", "actual_model": result["model"],
                   "finish_reason": safe_finish, "usage": usage, "usage_status": usage_status,
                   "status": failure_code or "completed", "response_failure_code": response_failure_code,
                   "response_sha256": response_hash}
        self.attempt_records.append(_decode(_body(attempt)))
        self.collector.emit("model_attempt_outcome", attempt, actor=actor)
        if failure_code:
            kind = ("budget_exhausted" if failure_code in {"model_usage_unverifiable", "actor_token_budget_exceeded", "episode_deadline_exhausted", "reported_output_budget_exceeded"}
                    else "model_refusal" if failure_code in {"model_refusal", "model_content_filter"} else "model_protocol_error")
            raise ProviderFailure(failure_code, delivery="delivered", request_id=request_id, kind=kind,
                                  http_status=reply.status, finish_reason=safe_finish, gateway_response="received") from None
        record = {"request_id": request_id, "actor": actor, "actual_model": result["model"],
            "action_protocol": self.action_protocol,
            "system_fingerprint": result.get("system_fingerprint"), "usage": usage, "usage_status": usage_status,
            "finish_reason": safe_finish, "gateway_response": "received", "model_acceptance": "response_observed",
            "output_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "action_text_sha256": hashlib.sha256(text.encode()).hexdigest()}
        self.records.append(_decode(_body(record)))
        completion_event = self.collector.emit("model_completion", record, actor=actor)
        self._bindings[actor] = {"actor": actor, "request_id": request_id,
            "action_protocol": self.action_protocol, "action_text_sha256": record["action_text_sha256"],
            "observation_sha256": hashlib.sha256(_body(observation)).hexdigest(),
            "request_sha256": hashlib.sha256(raw).hexdigest(), "serialized_body": raw.decode("utf-8"),
            "response_event_id": (response_event or {}).get("event_id"), "response_sha256": response_hash,
            "completion_event_id": (completion_event or {}).get("event_id"),
            "output_sha256": record["output_sha256"], "actual_model": result["model"]}
        return text

    @staticmethod
    def _validate_usage(usage) -> str:
        if usage is None:
            return "unknown"
        if not isinstance(usage, dict):
            raise ValueError("usage_object_required")
        keys = ("prompt_tokens", "completion_tokens", "total_tokens")
        for key in keys:
            if key in usage and (type(usage[key]) is not int or usage[key] < 0):
                raise ValueError("invalid_usage_counter")
        if all(k in usage for k in keys) and usage["total_tokens"] != usage["prompt_tokens"] + usage["completion_tokens"]:
            raise ValueError("inconsistent_total_tokens")
        return "reported" if all(k in usage for k in keys) else "partial" if any(k in usage for k in keys) else "unknown"
