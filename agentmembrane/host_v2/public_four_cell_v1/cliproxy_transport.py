"""Exact, one-attempt CLIProxy transport for the public four-cell overlay.

The transport accepts only the final request bytes emitted by
:mod:`sol_planner_wire_v2`, targets one explicit loopback
``/v1/chat/completions`` endpoint, and returns the provider bytes unchanged.
It never parses, normalizes, or re-serializes either direction.  It has no
retry loop and does not read credentials from the environment; the authorized
entrypoint resolves one explicitly named environment variable.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

CLIPROXY_TRANSPORT_ID = "public-four-cell-cliproxy-transport-v1"
CLIPROXY_ROUTE_ID = "local-cli-proxy"
CHAT_COMPLETIONS_PATH = "/v1/chat/completions"
DEFAULT_MAX_REQUEST_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class CLIProxyTransportError(RuntimeError):
    """The local route or exact Sol request contract was violated."""


class _HTTPResponse(Protocol):
    status: int

    def read(self, amount: int = -1) -> bytes: ...

    def __enter__(self) -> "_HTTPResponse": ...

    def __exit__(self, *args: object) -> object: ...


_Opener = Callable[..., _HTTPResponse]


def validate_loopback_chat_completions_endpoint(value: str) -> str:
    """Return a normalized exact endpoint or fail closed.

    A literal loopback IP is required.  Hostnames, redirects, query strings,
    fragments, embedded credentials, and non-HTTP schemes are rejected.
    Requiring a literal address avoids delegating the route decision to DNS.
    """

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
        raise CLIProxyTransportError("endpoint host must be a literal loopback IP") from exc
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
        ):
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value <= 0
            ):
                raise CLIProxyTransportError(f"{label} must be positive")
        if not callable(_opener):
            raise CLIProxyTransportError("HTTP opener must be callable")
        self._api_key = api_key
        self._timeout = float(timeout_seconds)
        self._max_request_bytes = max_request_bytes
        self._max_response_bytes = max_response_bytes
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
        }

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
                    raise CLIProxyTransportError(
                        f"CLIProxy returned unexpected HTTP status {response.status}"
                    )
                payload = response.read(self._max_response_bytes + 1)
        except CLIProxyTransportError:
            raise
        except Exception as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit, GeneratorExit)):
                raise
            raise CLIProxyTransportError(
                f"CLIProxy request failed before a response was delivered: {type(exc).__name__}"
            ) from exc
        if len(payload) > self._max_response_bytes:
            raise CLIProxyTransportError("CLIProxy response exceeds the byte ceiling")
        if type(payload) is not bytes:
            raise CLIProxyTransportError("CLIProxy response was not exact bytes")
        return payload


__all__ = [
    "CHAT_COMPLETIONS_PATH",
    "CLIPROXY_ROUTE_ID",
    "CLIPROXY_TRANSPORT_ID",
    "CLIProxySolTransport",
    "CLIProxyTransportError",
    "validate_loopback_chat_completions_endpoint",
]
