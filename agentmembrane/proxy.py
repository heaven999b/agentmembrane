from __future__ import annotations

import json
import hashlib
import os
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal


RETRYABLE_HTTP_STATUS = frozenset({408, 409, 429, 500, 502, 503, 504})
ReasoningEffort = Literal[
    "none",
    "minimal",
    "low",
    "medium",
    "high",
    "xhigh",
    "max",
]
REASONING_EFFORTS: frozenset[str] = frozenset(
    {"none", "minimal", "low", "medium", "high", "xhigh", "max"}
)


class ProxyError(RuntimeError):
    """Stable proxy failure with non-secret audit metadata."""

    def __init__(
        self,
        code: str,
        *,
        http_status: int | None = None,
        upstream_code: str | None = None,
        response_body_sha256: str | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.http_status = http_status
        self.upstream_code = upstream_code
        self.response_body_sha256 = response_body_sha256

    def audit_metadata(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "http_status": self.http_status,
            "upstream_code": self.upstream_code,
            "response_body_sha256": self.response_body_sha256,
        }


def is_retryable_proxy_error(error: Any) -> bool:
    code = error.code if isinstance(error, ProxyError) else error
    if not isinstance(code, str):
        return False
    if code in {"proxy_connection_failed", "proxy_auth_unavailable"}:
        return True
    if not code.startswith("proxy_http_"):
        return False
    try:
        return int(code.rsplit("_", 1)[1]) in RETRYABLE_HTTP_STATUS
    except ValueError:
        return False


def _proxy_error_metadata(status_code: int, response_body: str) -> dict[str, Any]:
    upstream_code = None
    try:
        payload = json.loads(response_body)
        if isinstance(payload, dict):
            error = payload.get("error")
            if isinstance(error, dict) and isinstance(error.get("code"), str):
                upstream_code = error["code"]
            elif isinstance(payload.get("code"), str):
                upstream_code = payload["code"]
    except json.JSONDecodeError:
        pass
    return {
        "http_status": status_code,
        "upstream_code": upstream_code,
        "response_body_sha256": hashlib.sha256(response_body.encode("utf-8")).hexdigest(),
    }


def classify_proxy_http_error(status_code: int, response_body: str) -> str:
    """Recover stable upstream failure classes hidden by the local proxy status."""

    normalized = response_body.lower()
    if "cyber_policy" in normalized:
        return "proxy_policy_cyber"
    if "auth_unavailable" in normalized or "no auth available" in normalized:
        return "proxy_auth_unavailable"
    return f"proxy_http_{status_code}"


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


def _parse_local_proxy_api_keys(path: Path) -> tuple[str, ...]:
    """Read only the top-level ``api-keys`` sequence from CLIProxy's YAML.

    CLIProxyAPI's local config is intentionally not copied into the repository.
    A small purpose-built parser is sufficient here and avoids adding a YAML
    dependency merely to recover the client credential for the loopback-only
    endpoint.
    """

    if not path.is_file():
        return ()
    keys: list[str] = []
    in_api_keys = False
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not in_api_keys:
            if line == "api-keys:" or stripped == "api-keys:":
                in_api_keys = True
            continue
        if line and not line[0].isspace():
            break
        if not stripped or stripped.startswith("#"):
            continue
        if not stripped.startswith("-"):
            break
        value = stripped[1:].strip().strip('"').strip("'")
        if value:
            keys.append(value)
    return tuple(keys)


def load_local_proxy_settings() -> tuple[str, str, str | None]:
    """Load an explicitly configured loopback route without logging its key."""

    base_url_value = (
        os.getenv("AGENTMEMBRANE_PROXY_BASE_URL")
        or os.getenv("AI_BASE_URL")
    )
    base_url = base_url_value.rstrip("/") if base_url_value else ""
    api_key = (
        os.getenv("AGENTMEMBRANE_PROXY_API_KEY")
        or os.getenv("AI_API_KEY")
    )
    if not api_key:
        configured_path = os.getenv("AGENTMEMBRANE_PROXY_CONFIG")
        if configured_path:
            configured_keys = _parse_local_proxy_api_keys(Path(configured_path).expanduser())
            api_key = next(
                (
                    value
                    for value in configured_keys
                    if re.fullmatch(r"sk-[A-Za-z0-9._-]{8,}", value)
                ),
                None,
            )
    preferred_model = (
        os.getenv("AGENTMEMBRANE_MODEL")
        or os.getenv("AI_MODEL")
    )

    parsed = urllib.parse.urlparse(base_url)
    try:
        port = parsed.port
    except ValueError:
        raise ProxyError("non_local_proxy_rejected") from None
    if (
        parsed.scheme != "http"
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or port is None
        or parsed.path.rstrip("/") != "/v1"
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
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
        reasoning_effort: ReasoningEffort | None = None,
    ) -> Completion:
        if reasoning_effort is not None and reasoning_effort not in REASONING_EFFORTS:
            allowed = ", ".join(sorted(REASONING_EFFORTS))
            raise ValueError(f"reasoning_effort must be one of: {allowed}")

        payload: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            "max_completion_tokens": max_completion_tokens,
            "stream": False,
        }
        if reasoning_effort is not None:
            payload["reasoning_effort"] = reasoning_effort
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
                try:
                    response_body = exc.read().decode("utf-8", errors="replace")
                except Exception:
                    response_body = ""
                error_class = classify_proxy_http_error(exc.code, response_body)
                last_error = ProxyError(
                    error_class,
                    **_proxy_error_metadata(exc.code, response_body),
                )
                retryable = is_retryable_proxy_error(last_error)
                if not retryable or attempt >= retries:
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
