from __future__ import annotations

import json
import os
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ProxyError(RuntimeError):
    pass


@dataclass(frozen=True)
class Completion:
    text: str
    model: str
    latency_ms: int
    input_tokens: int | None
    output_tokens: int | None
    total_tokens: int | None


def _parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip().strip("\"").strip("'")
    return values


def load_local_proxy_settings() -> tuple[str, str, str | None]:
    """Load the local-only proxy settings without logging the credential."""

    workspace = Path(__file__).resolve().parents[2]
    local_env = _parse_env_file(workspace / "family-ai-chat" / ".env.local")
    base_url = (
        os.getenv("AGENTMEMBRANE_PROXY_BASE_URL")
        or os.getenv("AI_BASE_URL")
        or local_env.get("AI_BASE_URL")
        or "http://127.0.0.1:8317/v1"
    ).rstrip("/")
    api_key = (
        os.getenv("AGENTMEMBRANE_PROXY_API_KEY")
        or os.getenv("AI_API_KEY")
        or local_env.get("AI_API_KEY")
    )
    preferred_model = (
        os.getenv("AGENTMEMBRANE_MODEL")
        or os.getenv("AI_MODEL")
        or local_env.get("AI_MODEL")
    )

    parsed = urllib.parse.urlparse(base_url)
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost"}
        or parsed.port != 8317
        or parsed.path.rstrip("/") != "/v1"
    ):
        raise ProxyError("non_local_proxy_rejected")
    if not api_key or not re.fullmatch(r"sk-[A-Za-z0-9._-]{8,}", api_key):
        raise ProxyError("local_proxy_key_missing")
    return base_url, api_key, preferred_model


class LocalProxyClient:
    FALLBACK_MODELS = (
        "gpt-5.4-mini",
        "gpt-5.4",
        "gpt-5.6-luna",
        "gpt-5.6-terra",
        "gpt-5.6-sol",
        "gpt-5.5",
    )

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        timeout_seconds: float = 120.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self.timeout_seconds = timeout_seconds

    @classmethod
    def from_local_config(cls, *, timeout_seconds: float = 120.0) -> "LocalProxyClient":
        base_url, api_key, _ = load_local_proxy_settings()
        return cls(base_url=base_url, api_key=api_key, timeout_seconds=timeout_seconds)

    def _request(self, path: str, *, method: str, payload: dict[str, Any] | None = None) -> Any:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/{path.lstrip('/')}",
            data=body,
            method=method,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
            return json.loads(response.read().decode("utf-8"))

    def list_models(self) -> list[str]:
        payload = self._request("models", method="GET")
        rows = payload.get("data", []) if isinstance(payload, dict) else []
        return [row["id"] for row in rows if isinstance(row, dict) and isinstance(row.get("id"), str)]

    def select_model(self, preferred: str | None = None) -> str:
        available = self.list_models()
        for candidate in (preferred, *self.FALLBACK_MODELS):
            if candidate and candidate in available:
                return candidate
        raise ProxyError("no_supported_model")

    def complete(
        self,
        *,
        model: str,
        system: str,
        user: str,
        max_completion_tokens: int = 900,
        retries: int = 4,
    ) -> Completion:
        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            "max_completion_tokens": max_completion_tokens,
            "stream": False,
        }
        last_error: Exception | None = None
        for attempt in range(retries + 1):
            started = time.monotonic()
            try:
                response = self._request("chat/completions", method="POST", payload=payload)
                latency_ms = round((time.monotonic() - started) * 1000)
                choices = response.get("choices", [])
                text = choices[0].get("message", {}).get("content") if choices else None
                if not isinstance(text, str) or not text.strip():
                    raise ProxyError("empty_completion")
                usage = response.get("usage", {})
                input_tokens = usage.get("prompt_tokens", usage.get("input_tokens"))
                output_tokens = usage.get("completion_tokens", usage.get("output_tokens"))
                total_tokens = usage.get("total_tokens")
                if total_tokens is None and isinstance(input_tokens, int) and isinstance(output_tokens, int):
                    total_tokens = input_tokens + output_tokens
                return Completion(
                    text=text,
                    model=model,
                    latency_ms=latency_ms,
                    input_tokens=input_tokens if isinstance(input_tokens, int) else None,
                    output_tokens=output_tokens if isinstance(output_tokens, int) else None,
                    total_tokens=total_tokens if isinstance(total_tokens, int) else None,
                )
            except urllib.error.HTTPError as exc:
                last_error = ProxyError(f"proxy_http_{exc.code}")
                if exc.code not in {408, 409, 429, 500, 502, 503, 504} or attempt >= retries:
                    raise last_error from None
            except (TimeoutError, urllib.error.URLError) as exc:
                last_error = ProxyError("proxy_connection_failed")
                if attempt >= retries:
                    raise last_error from exc
            if attempt < retries:
                time.sleep(min(12.0, 1.5 * (2**attempt)) + random.random() * 0.25)
        raise last_error or ProxyError("completion_failed")


def parse_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped, flags=re.IGNORECASE)
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        value = json.loads(stripped)
        if isinstance(value, dict):
            return value
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    for index, character in enumerate(stripped):
        if character != "{":
            continue
        try:
            value, _ = decoder.raw_decode(stripped[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise ProxyError("completion_not_json")

