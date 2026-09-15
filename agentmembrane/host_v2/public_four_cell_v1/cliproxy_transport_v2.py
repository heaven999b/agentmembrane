"""One-attempt CLIProxy transport with bounded HTTP-error evidence.

This is the versioned transport for the ``_002`` Host-mediated RQ1b canary.
Successful responses are returned as the exact bytes delivered by the local
proxy.  HTTP status failures expose a small, deterministic evidence capsule so
the wire-v3 planner can publish the status and safe body bytes in its immutable
attempt artifact.  Credential-bearing bodies are replaced before they reach an
exception, log, or artifact.

The module performs no discovery, DNS lookup, retry, or credential lookup.
Only an explicit literal loopback ``/v1/chat/completions`` endpoint is valid.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
from typing import Any, Callable, Protocol
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


CLIPROXY_TRANSPORT_ID = "public-four-cell-cliproxy-transport-v2"
CLIPROXY_ROUTE_ID = "local-cli-proxy"
CHAT_COMPLETIONS_PATH = "/v1/chat/completions"
DEFAULT_MAX_REQUEST_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_ERROR_BODY_BYTES = 4096
_REDACTED_BODY = b"[redacted credential-bearing HTTP error body]"
_UNAVAILABLE_BODY = b"[HTTP error body unavailable as exact bytes]"
_CREDENTIAL_MARKER = re.compile(
    rb"authorization|api[ _-]?key|bearer[ \t]+", re.IGNORECASE
)


class CLIProxyTransportError(RuntimeError):
    """The local route or exact Sol request contract was violated."""


class CLIProxyHTTPStatusError(CLIProxyTransportError):
    """A non-200 response with safe, bounded, deterministic body evidence."""

    def __init__(
        self,
        *,
        http_status: int,
        error_body_bytes: bytes,
        error_body_truncated: bool,
        error_body_redacted: bool,
    ) -> None:
        if (
            not isinstance(http_status, int)
            or isinstance(http_status, bool)
            or not 100 <= http_status <= 599
        ):
            raise CLIProxyTransportError("HTTP status is not a canonical status code")
        if type(error_body_bytes) is not bytes:
            raise CLIProxyTransportError("HTTP error evidence must be exact bytes")
        if type(error_body_truncated) is not bool or type(error_body_redacted) is not bool:
            raise CLIProxyTransportError("HTTP error evidence flags must be booleans")
        self.http_status = http_status
        self.error_body_bytes = error_body_bytes
        self.error_body_length = len(error_body_bytes)
        self.error_body_sha256 = hashlib.sha256(error_body_bytes).hexdigest()
        self.error_body_truncated = error_body_truncated
        self.error_body_redacted = error_body_redacted
        # Only the already-sanitized evidence is rendered.  The source
        # HTTPError and its reason/body are deliberately not chained.
        super().__init__(
            "CLIProxy HTTP status evidence:"
            + json.dumps(
                self.to_attempt_error_evidence(),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
        )

    def to_attempt_error_evidence(self) -> dict[str, Any]:
        """Return fields safe to copy verbatim into an attempt artifact."""

        return {
            "error_body_bytes_base64": base64.b64encode(
                self.error_body_bytes
            ).decode("ascii"),
            "error_body_length": self.error_body_length,
            "error_body_redacted": self.error_body_redacted,
            "error_body_sha256": self.error_body_sha256,
            "error_body_truncated": self.error_body_truncated,
            "http_status": self.http_status,
        }


class _HTTPResponse(Protocol):
    status: int

    def read(self, amount: int = -1) -> bytes: ...

    def __enter__(self) -> "_HTTPResponse": ...

    def __exit__(self, *args: object) -> object: ...


_Opener = Callable[..., _HTTPResponse]


def validate_loopback_chat_completions_endpoint(value: str) -> str:
    """Return the exact endpoint after strict literal-loopback validation."""

    if not isinstance(value, str) or not value:
        raise CLIProxyTransportError("endpoint must be non-empty text")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.path != CHAT_COMPLETIONS_PATH
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or parsed.hostname is None
        or parsed.port is None
    ):
        raise CLIProxyTransportError(
            "endpoint must be explicit http loopback /v1/chat/completions"
        )
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise CLIProxyTransportError(
            "endpoint host must be a literal loopback IP"
        ) from exc
    if not address.is_loopback:
        raise CLIProxyTransportError("endpoint is not loopback")
    if not 1 <= parsed.port <= 65535:
        raise CLIProxyTransportError("endpoint port is invalid")
    return value


class CLIProxySolTransport:
    """One synchronous HTTP attempt to an explicit local CLIProxy route."""

    def __init__(
        self,
        *,
        endpoint: str,
        api_key: str,
        timeout_seconds: float,
        max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        max_error_body_bytes: int = DEFAULT_MAX_ERROR_BODY_BYTES,
        _opener: _Opener = urlopen,
    ) -> None:
        self._endpoint = validate_loopback_chat_completions_endpoint(endpoint)
        if not isinstance(api_key, str) or not api_key:
            raise CLIProxyTransportError("api_key must be supplied explicitly")
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or not 0 < float(timeout_seconds) <= 3600
        ):
            raise CLIProxyTransportError("timeout_seconds must be in (0, 3600]")
        for value, label in (
            (max_request_bytes, "max_request_bytes"),
            (max_response_bytes, "max_response_bytes"),
            (max_error_body_bytes, "max_error_body_bytes"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise CLIProxyTransportError(f"{label} must be positive")
        if not callable(_opener):
            raise CLIProxyTransportError("HTTP opener must be callable")
        self._api_key = api_key
        self._api_key_bytes = api_key.encode("utf-8")
        self._timeout = float(timeout_seconds)
        self._max_request_bytes = max_request_bytes
        self._max_response_bytes = max_response_bytes
        self._max_error_body_bytes = max_error_body_bytes
        self._opener = _opener
        self._attempt_count = 0

    @property
    def route_metadata(self) -> dict[str, Any]:
        """Credential- and endpoint-free metadata safe for result artifacts."""

        return {
            "transport_id": CLIPROXY_TRANSPORT_ID,
            "provider_route_id": CLIPROXY_ROUTE_ID,
            "loopback_only": True,
            "chat_completions_path": CHAT_COMPLETIONS_PATH,
            "request_level_transport_retries": 0,
            "timeout_seconds": self._timeout,
            "max_error_body_bytes": self._max_error_body_bytes,
        }

    def _safe_error_body(
        self, reader: Callable[[int], object]
    ) -> tuple[bytes, bool, bool]:
        try:
            observed = reader(self._max_error_body_bytes + 1)
        except Exception as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit, GeneratorExit)):
                raise
            return _UNAVAILABLE_BODY, False, True
        if type(observed) is not bytes:
            return _UNAVAILABLE_BODY, False, True
        truncated = len(observed) > self._max_error_body_bytes
        bounded = observed[: self._max_error_body_bytes]
        if self._api_key_bytes in bounded or _CREDENTIAL_MARKER.search(bounded):
            return _REDACTED_BODY, truncated, True
        return bounded, truncated, False

    def _status_error(
        self, *, status: int, reader: Callable[[int], object]
    ) -> CLIProxyHTTPStatusError:
        body, truncated, redacted = self._safe_error_body(reader)
        return CLIProxyHTTPStatusError(
            http_status=status,
            error_body_bytes=body,
            error_body_truncated=truncated,
            error_body_redacted=redacted,
        )

    def invoke(self, request_wire: bytes) -> bytes:
        if type(request_wire) is not bytes or not request_wire:
            raise CLIProxyTransportError("request_wire must be nonempty exact bytes")
        if len(request_wire) > self._max_request_bytes:
            raise CLIProxyTransportError("request_wire exceeds the byte ceiling")
        self._attempt_count += 1
        http_request = Request(
            self._endpoint,
            data=request_wire,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with self._opener(http_request, timeout=self._timeout) as response:
                if response.status != 200:
                    raise self._status_error(
                        status=response.status, reader=response.read
                    )
                payload = response.read(self._max_response_bytes + 1)
        except HTTPError as exc:
            # HTTPError is also a readable response.  Consume at most the
            # bounded limit, never stringify it, and never retain it as a
            # chained exception because its reason may contain route data.
            try:
                status_error = self._status_error(status=exc.code, reader=exc.read)
            finally:
                try:
                    exc.close()
                except Exception:
                    pass
            raise status_error from None
        except CLIProxyTransportError:
            raise
        except Exception as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit, GeneratorExit)):
                raise
            raise CLIProxyTransportError(
                "CLIProxy request failed before a response was delivered: "
                f"{type(exc).__name__}"
            ) from None
        if len(payload) > self._max_response_bytes:
            raise CLIProxyTransportError("CLIProxy response exceeds the byte ceiling")
        if type(payload) is not bytes:
            raise CLIProxyTransportError("CLIProxy response was not exact bytes")
        return payload


__all__ = [
    "CHAT_COMPLETIONS_PATH",
    "CLIPROXY_ROUTE_ID",
    "CLIPROXY_TRANSPORT_ID",
    "CLIProxyHTTPStatusError",
    "CLIProxySolTransport",
    "CLIProxyTransportError",
    "DEFAULT_MAX_ERROR_BODY_BYTES",
    "validate_loopback_chat_completions_endpoint",
]
