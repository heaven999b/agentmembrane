"""Formal H/E model driver using the reviewed v6 provider safety path.

The _next_action method is a reviewed local copy of the v1 ModelDriver method
at the source hash below. Its v6 wire imports and one sealed, anonymized
shared-proxy response diagnostic are intentional. Budget, HTTP transport and
completion binding remain identical. Do not update this copy without parity review.
"""
from __future__ import annotations

import hashlib
import re
import time

from ..rq1_collab_v1.providers import (
    HTTPReply, HTTPTransport, ModelDriver, ProviderFailure, _body, _decode,
    safe_response_metadata,
)
from ..rq1_collab_v6.provider_route import BoundRouteTransport
from .wire import _single_tool_action, build_action_payload


class FormalModelDriver(ModelDriver):
    """ModelDriver network path with the formal H/E-only action envelope."""

    V1_NEXT_ACTION_SHA256 = "596f7cde6e5e165de00f33c003355f255f203cd8597d6efef15eb8021fc85074"

    def _shared_route_evidence(self, reply: HTTPReply) -> dict:
        if not (isinstance(self.transport, BoundRouteTransport)
                and self.transport.shared_pool_unattributed):
            return {}
        fingerprint = safe_response_metadata(reply.response_metadata).get("route_fingerprint")
        return ({"shared_proxy_last_selected_slot_fingerprint": fingerprint}
                if fingerprint is not None else {})

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
            "latency_seconds": time.monotonic() - start,
            **self._shared_route_evidence(reply)}, actor=actor)
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
