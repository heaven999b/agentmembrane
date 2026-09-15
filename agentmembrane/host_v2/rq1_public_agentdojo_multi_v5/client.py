"""Exact loopback-only GPT-5.4 Mini/low client for the RQ1 v5 baseline."""

from __future__ import annotations

import copy
from typing import Any
from urllib.parse import urlparse

from ...proxy import LocalProxyClient
from .provider_agent import MAX_COMPLETION_TOKENS, MODEL_ID, REASONING_EFFORT


class RQ1V5ClientError(RuntimeError):
    """The production request differs from the frozen weak-model contract."""


class ExactRQ1GPT54MiniLowClient(LocalProxyClient):
    """Enforce one model, one effort, loopback transport, and six calls/cell."""

    def __init__(self, *args: Any, hard_call_cap: int = 6, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        if hard_call_cap != 6:
            raise RQ1V5ClientError("RQ1 v5 hard call cap must be six per cell")
        parsed = urlparse(self.base_url)
        if parsed.scheme != "http" or parsed.hostname not in {
            "127.0.0.1",
            "localhost",
        }:
            raise RQ1V5ClientError("RQ1 v5 permits only the loopback CLI proxy")
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
            raise RQ1V5ClientError("RQ1 v5 permits only chat completions")
        if not isinstance(payload, dict):
            raise RQ1V5ClientError("RQ1 v5 request has no JSON body")
        if (
            payload.get("model") != MODEL_ID
            or payload.get("reasoning_effort") != REASONING_EFFORT
            or payload.get("temperature") != 0
            or payload.get("max_completion_tokens") != MAX_COMPLETION_TOKENS
            or payload.get("stream") is not False
        ):
            raise RQ1V5ClientError("RQ1 v5 request settings drifted")
        if self.calls_made >= self.hard_call_cap:
            raise RQ1V5ClientError("RQ1 v5 per-cell API call cap exhausted")
        exact_payload = copy.deepcopy(payload)
        self.calls_made += 1
        return super()._request(path, method=method, payload=exact_payload)


__all__ = ["ExactRQ1GPT54MiniLowClient", "RQ1V5ClientError"]
