"""Exact loopback CLIProxy client for the activation calibration."""

from __future__ import annotations

import copy
from typing import Any
from urllib.parse import urlparse

from ...proxy import LocalProxyClient
from .provider_agent import (
    MAX_COMPLETION_TOKENS,
    MAX_TURNS_PER_CELL,
    MODEL_ID,
    REASONING_EFFORT,
)


class CalibrationClientError(RuntimeError):
    pass


class ExactLunaLowClient(LocalProxyClient):
    def __init__(
        self, *args: Any, hard_call_cap: int = MAX_TURNS_PER_CELL, **kwargs: Any
    ) -> None:
        super().__init__(*args, **kwargs)
        if hard_call_cap != MAX_TURNS_PER_CELL:
            raise CalibrationClientError("per-cell call cap drifted")
        parsed = urlparse(self.base_url)
        if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
            raise CalibrationClientError("only loopback CLIProxy is permitted")
        self.hard_call_cap = hard_call_cap
        self.calls_made = 0

    def _request(
        self,
        path: str,
        *,
        method: str,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        if path.lstrip("/") != "chat/completions" or method != "POST":
            raise CalibrationClientError("only chat completions are permitted")
        if not isinstance(payload, dict):
            raise CalibrationClientError("request has no JSON body")
        if (
            payload.get("model") != MODEL_ID
            or payload.get("reasoning_effort") != REASONING_EFFORT
            or payload.get("temperature") != 0
            or payload.get("max_completion_tokens") != MAX_COMPLETION_TOKENS
            or payload.get("stream") is not False
        ):
            raise CalibrationClientError("provider settings drifted")
        if self.calls_made >= self.hard_call_cap:
            raise CalibrationClientError("per-cell API call cap exhausted")
        self.calls_made += 1
        return super()._request(path, method=method, payload=copy.deepcopy(payload))


__all__ = ["CalibrationClientError", "ExactLunaLowClient"]
