"""Offline, fail-closed proof of the public four-cell provider route.

The checker consumes already captured bytes.  It never opens a file, socket,
or subprocess.  A client request is not treated as evidence of the effective
provider request: the two JSON documents are decoded independently from the
downstream bytes and the sole CLIProxy detail-log record.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping


ROUTE_RESOLUTION_ARTIFACT_TYPE = (
    "agentmembrane_public_four_cell_route_resolution_v1"
)
EXPECTED_DOWNSTREAM_PATH = "/v1/responses"
EXPECTED_UPSTREAM_URL = "https://chatgpt.com/backend-api/codex/responses"
EXPECTED_MODEL = "gpt-5.6-sol"
EXPECTED_REASONING = {"effort": "max", "summary": "auto"}
EXPECTED_MAX_OUTPUT_TOKENS = 1100

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_HEADING = re.compile(r"(?m)^=== ([^\r\n=]+) ===\r?$")
_EXPECTED_HEADINGS = (
    "REQUEST INFO",
    "HEADERS",
    "REQUEST BODY",
    "API REQUEST 1",
    "API RESPONSE",
    "RESPONSE",
)
_PROBE_BINDING_KEYS = {
    "result_path",
    "result_sha256",
    "detail_log_path",
    "detail_log_sha256",
    "request_sha256",
    "http_status",
    "counts",
}
_PROBE_COUNTS = {
    "client_attempts": 1,
    "local_proxy_http_attempts": 1,
    "provider_accepted_requests": 0,
    "delivered_model_responses": 0,
    "token_bearing_calls": 0,
    "input_tokens": 0,
    "output_tokens": 0,
    "total_tokens": 0,
}
_ZERO_EXECUTION_COUNTS = {
    "api_calls": 0,
    "model_calls": 0,
    "native_checker_calls": 0,
    "native_dispatches": 0,
    "native_resets": 0,
    "network_calls": 0,
    "provider_calls": 0,
    "task_executions": 0,
}
_RESPONSE_USAGE_KEYS = {
    "usage",
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "prompt_tokens",
    "completion_tokens",
}


class RouteResolutionError(RuntimeError):
    """Captured route evidence is incomplete, ambiguous, or unsafe to use."""


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _reject_constant(value: str) -> None:
    raise RouteResolutionError(f"non-finite JSON constant is forbidden: {value}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise RouteResolutionError(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def _reject_surrogates(value: Any) -> None:
    if isinstance(value, str):
        if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
            raise RouteResolutionError("unpaired Unicode surrogate is forbidden")
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            _reject_surrogates(key)
            _reject_surrogates(item)
        return
    if isinstance(value, list):
        for item in value:
            _reject_surrogates(item)


def _strict_json_object(value: bytes | str, *, label: str) -> dict[str, Any]:
    if isinstance(value, bytes):
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RouteResolutionError(f"{label} is not UTF-8") from exc
    elif isinstance(value, str):
        text = value
    else:
        raise RouteResolutionError(f"{label} must be exact bytes or text")
    if not text or "\x00" in text:
        raise RouteResolutionError(f"{label} is empty or contains NUL")
    try:
        decoded = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except RouteResolutionError:
        raise
    except (json.JSONDecodeError, UnicodeError, ValueError) as exc:
        raise RouteResolutionError(f"{label} is not one exact JSON value") from exc
    if not isinstance(decoded, dict):
        raise RouteResolutionError(f"{label} must contain one JSON object")
    _reject_surrogates(decoded)
    return decoded


def _exact_keys(value: Mapping[str, Any], expected: set[str], *, label: str) -> None:
    if set(value) != expected:
        raise RouteResolutionError(f"{label} fields differ from the exact contract")


def _canonical_sha(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise RouteResolutionError(f"{label} is not a canonical SHA-256")
    return value


def _path_text(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise RouteResolutionError(f"{label} is not non-empty path text")
    return value


def _validate_probe_binding(
    value: Mapping[str, Any], *, request_bytes: bytes, detail_log_bytes: bytes
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RouteResolutionError("probe_result_binding must be a mapping")
    _exact_keys(value, _PROBE_BINDING_KEYS, label="probe_result_binding")
    result_path = _path_text(value["result_path"], label="probe result path")
    detail_path = _path_text(value["detail_log_path"], label="detail log path")
    result_sha = _canonical_sha(value["result_sha256"], label="probe result SHA")
    detail_sha = _canonical_sha(value["detail_log_sha256"], label="detail log SHA")
    request_sha = _canonical_sha(value["request_sha256"], label="request SHA")
    if request_sha != _sha256(request_bytes):
        raise RouteResolutionError("probe request SHA does not bind downstream bytes")
    if detail_sha != _sha256(detail_log_bytes):
        raise RouteResolutionError("probe detail-log SHA does not bind log bytes")
    if value["http_status"] != 400 or isinstance(value["http_status"], bool):
        raise RouteResolutionError("probe must bind the sole HTTP 400 rejection")
    counts = value["counts"]
    if not isinstance(counts, Mapping) or dict(counts) != _PROBE_COUNTS:
        raise RouteResolutionError("probe counts are not the exact zero-usage contract")
    return {
        "probe_result": {"path": result_path, "sha256": result_sha},
        "detail_log": {"path": detail_path, "sha256": detail_sha},
        "downstream_request": {
            "sha256": request_sha,
            "size_bytes": len(request_bytes),
        },
    }


def _sections(detail_log_bytes: bytes) -> dict[str, str]:
    if type(detail_log_bytes) is not bytes or not detail_log_bytes:
        raise RouteResolutionError("detail_log_bytes must be non-empty exact bytes")
    try:
        text = detail_log_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RouteResolutionError("detail log is not UTF-8") from exc
    if "\x00" in text:
        raise RouteResolutionError("detail log contains NUL")
    matches = list(_HEADING.finditer(text))
    headings = tuple(match.group(1) for match in matches)
    if headings != _EXPECTED_HEADINGS:
        raise RouteResolutionError(
            "detail log must contain exactly one ordered request and API request"
        )
    result: dict[str, str] = {}
    for index, match in enumerate(matches):
        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        result[match.group(1)] = text[start:end].strip("\r\n")
    return result


def _key_value_lines(text: str, *, label: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if not line:
            continue
        if ": " not in line:
            raise RouteResolutionError(f"{label} contains a non key/value line")
        key, value = line.split(": ", 1)
        if not key or not value or key in result:
            raise RouteResolutionError(f"{label} contains a missing/duplicate field")
        result[key] = value
    return result


def _parse_log(
    detail_log_bytes: bytes, *, downstream_request_bytes: bytes
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    sections = _sections(detail_log_bytes)
    request_info = _key_value_lines(sections["REQUEST INFO"], label="request info")
    if request_info.get("URL") != EXPECTED_DOWNSTREAM_PATH:
        raise RouteResolutionError("detail log did not capture the direct Responses route")
    if request_info.get("Method") != "POST":
        raise RouteResolutionError("detail log request method is not POST")

    logged_request_text = sections["REQUEST BODY"]
    if logged_request_text.encode("utf-8") != downstream_request_bytes:
        raise RouteResolutionError("logged downstream request bytes differ")
    logged_request = _strict_json_object(
        logged_request_text, label="logged downstream request"
    )

    api_request = sections["API REQUEST 1"]
    if api_request.count("\nBody:\n") != 1:
        raise RouteResolutionError("API request has missing or repeated Body section")
    api_metadata_and_headers, upstream_text = api_request.split("\nBody:\n", 1)
    if api_metadata_and_headers.count("\n\nHeaders:\n") != 1:
        raise RouteResolutionError("API request headers section is ambiguous")
    api_metadata, _headers = api_metadata_and_headers.split("\n\nHeaders:\n", 1)
    api_info = _key_value_lines(api_metadata, label="API request metadata")
    if api_info.get("Upstream URL") != EXPECTED_UPSTREAM_URL:
        raise RouteResolutionError("actual upstream URL differs")
    if api_info.get("HTTP Method") != "POST":
        raise RouteResolutionError("upstream HTTP method is not POST")
    upstream_request = _strict_json_object(
        upstream_text.strip("\r\n"), label="upstream request body"
    )

    api_response = sections["API RESPONSE"]
    if "\n" not in api_response:
        raise RouteResolutionError("API response body is missing")
    timestamp_line, api_response_text = api_response.split("\n", 1)
    if not timestamp_line.startswith("Timestamp: "):
        raise RouteResolutionError("API response timestamp is missing")
    upstream_response = _strict_json_object(
        api_response_text.strip("\r\n"), label="upstream response body"
    )

    response = sections["RESPONSE"]
    if response.count("\n\n") != 1:
        raise RouteResolutionError("downstream response headers/body are ambiguous")
    response_headers, response_text = response.split("\n\n", 1)
    response_info = _key_value_lines(response_headers, label="response headers")
    status_text = response_info.get("Status")
    if status_text is None or not status_text.isascii() or not status_text.isdigit():
        raise RouteResolutionError("downstream HTTP status is missing")
    status = int(status_text)
    if 200 <= status <= 299:
        raise RouteResolutionError("2xx evidence is forbidden for route resolution")
    if status != 400:
        raise RouteResolutionError("detail log status differs from probe HTTP 400")
    downstream_response = _strict_json_object(
        response_text.strip("\r\n"), label="downstream response body"
    )
    if upstream_response != downstream_response:
        raise RouteResolutionError("upstream and downstream rejection bodies differ")
    if _contains_response_usage(upstream_response):
        raise RouteResolutionError("usage/token-bearing response evidence is forbidden")
    return logged_request, upstream_request, upstream_response


def _contains_response_usage(value: Any) -> bool:
    if isinstance(value, Mapping):
        if any(key in _RESPONSE_USAGE_KEYS for key in value):
            return True
        return any(_contains_response_usage(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_response_usage(item) for item in value)
    return False


def _tool_summary(request: Mapping[str, Any], *, label: str) -> dict[str, Any]:
    tools = request.get("tools")
    if not isinstance(tools, list):
        raise RouteResolutionError(f"{label} tools is missing or not a list")
    function_tools = [
        tool
        for tool in tools
        if isinstance(tool, Mapping) and tool.get("type") == "function"
    ]
    image_present = any(
        isinstance(tool, Mapping) and tool.get("type") == "image_generation"
        for tool in tools
    )
    sole_function = len(tools) == 1 and len(function_tools) == 1
    name: str | None = None
    strict = False
    forced = False
    if function_tools:
        tool = function_tools[0]
        name_value = tool.get("name")
        name = name_value if isinstance(name_value, str) and name_value else None
        strict = tool.get("strict") is True and isinstance(tool.get("parameters"), Mapping)
        forced = request.get("tool_choice") == {"type": "function", "name": name}
    return {
        "tool_count": len(tools),
        "tool_types": [
            tool.get("type") if isinstance(tool, Mapping) else None for tool in tools
        ],
        "function_name": name,
        "sole_function": sole_function,
        "strict_function": strict,
        "forced_function": forced,
        "image_generation_present": image_present,
    }


def _validate_client_request(request: Mapping[str, Any]) -> dict[str, Any]:
    required = {
        "input",
        "max_output_tokens",
        "model",
        "parallel_tool_calls",
        "reasoning",
        "store",
        "stream",
        "tool_choice",
        "tools",
    }
    if set(request) not in (required, required | {"temperature"}):
        raise RouteResolutionError("downstream request fields differ")
    if request["model"] != EXPECTED_MODEL:
        raise RouteResolutionError("downstream model differs")
    if request["reasoning"] != EXPECTED_REASONING:
        raise RouteResolutionError("downstream reasoning contract differs")
    if request["max_output_tokens"] != EXPECTED_MAX_OUTPUT_TOKENS or isinstance(
        request["max_output_tokens"], bool
    ):
        raise RouteResolutionError("downstream max_output_tokens differs")
    if request["parallel_tool_calls"] is not False:
        raise RouteResolutionError("downstream parallel_tool_calls must be false")
    if request["stream"] is not False or request["store"] is not False:
        raise RouteResolutionError("downstream stream/store must be false")
    if not isinstance(request["input"], list) or not request["input"]:
        raise RouteResolutionError("downstream input must be a non-empty list")
    temperature = request.get("temperature")
    if "temperature" in request and (
        isinstance(temperature, bool) or temperature not in (0, 0.0)
    ):
        raise RouteResolutionError("downstream temperature, when present, must be zero")
    tool = _tool_summary(request, label="downstream request")
    if not (
        tool["sole_function"]
        and tool["strict_function"]
        and tool["forced_function"]
        and not tool["image_generation_present"]
    ):
        raise RouteResolutionError(
            "downstream request is not one forced strict function tool"
        )
    return {
        "endpoint_path": EXPECTED_DOWNSTREAM_PATH,
        "model": request["model"],
        "reasoning": dict(request["reasoning"]),
        "max_output_tokens": request["max_output_tokens"],
        "parallel_tool_calls": request["parallel_tool_calls"],
        "stream": request["stream"],
        "store": request["store"],
        "temperature": temperature,
        "temperature_present": "temperature" in request,
        **tool,
    }


def _effective_summary(
    upstream: Mapping[str, Any], *, client: Mapping[str, Any]
) -> dict[str, Any]:
    required = {
        "input",
        "max_output_tokens",
        "model",
        "parallel_tool_calls",
        "reasoning",
        "store",
        "stream",
        "tool_choice",
        "tools",
    }
    if not required.issubset(upstream):
        raise RouteResolutionError("upstream request is missing a required control")
    allowed = required | {
        "include",
        "instructions",
        "prompt_cache_key",
        "temperature",
    }
    if not set(upstream).issubset(allowed):
        raise RouteResolutionError("upstream request contains an unknown control")
    if upstream["input"] != client["input"]:
        raise RouteResolutionError("upstream input differs from downstream input")
    if upstream["store"] is not False:
        raise RouteResolutionError("upstream store must be false")
    temperature = upstream.get("temperature")
    if "temperature" in upstream and (
        isinstance(temperature, bool) or temperature not in (0, 0.0)
    ):
        raise RouteResolutionError("upstream temperature, when present, must be zero")
    return {
        "upstream_url": EXPECTED_UPSTREAM_URL,
        "protocol": "codex_responses",
        "model": upstream["model"],
        "reasoning": upstream["reasoning"],
        "max_output_tokens": upstream["max_output_tokens"],
        "parallel_tool_calls": upstream["parallel_tool_calls"],
        "stream": upstream["stream"],
        "store": upstream["store"],
        "temperature": temperature,
        "temperature_present": "temperature" in upstream,
        **_tool_summary(upstream, label="upstream request"),
    }


def resolve_route(
    *,
    downstream_request_bytes: bytes,
    detail_log_bytes: bytes,
    probe_result_binding: Mapping[str, Any],
) -> dict[str, Any]:
    """Return exact route-resolution JSON or reject ambiguous evidence.

    ``resolution_status`` is ``resolved`` only if every provider-effective
    control, including an explicitly observed zero temperature, is proven.
    Structurally invalid evidence raises :class:`RouteResolutionError`.
    """

    if type(downstream_request_bytes) is not bytes or not downstream_request_bytes:
        raise RouteResolutionError(
            "downstream_request_bytes must be non-empty exact bytes"
        )
    if type(detail_log_bytes) is not bytes or not detail_log_bytes:
        raise RouteResolutionError("detail_log_bytes must be non-empty exact bytes")
    evidence = _validate_probe_binding(
        probe_result_binding,
        request_bytes=downstream_request_bytes,
        detail_log_bytes=detail_log_bytes,
    )
    request = _strict_json_object(
        downstream_request_bytes, label="downstream request bytes"
    )
    logged_request, upstream, _response = _parse_log(
        detail_log_bytes, downstream_request_bytes=downstream_request_bytes
    )
    if logged_request != request:
        raise RouteResolutionError("logged request object differs from downstream object")
    client = _validate_client_request(request)
    effective = _effective_summary(upstream, client=request)

    client_tool = request["tools"][0]
    upstream_tools = upstream["tools"]
    function_preserved = (
        len(upstream_tools) == 1
        and isinstance(upstream_tools[0], Mapping)
        and dict(upstream_tools[0]) == client_tool
    )
    forced_name = client["function_name"]
    controls = {
        "upstream_url_exact": effective["upstream_url"] == EXPECTED_UPSTREAM_URL,
        "model_exact": effective["model"] == EXPECTED_MODEL,
        "reasoning_exact": effective["reasoning"] == EXPECTED_REASONING,
        "max_output_tokens_1100": (
            effective["max_output_tokens"] == EXPECTED_MAX_OUTPUT_TOKENS
            and not isinstance(effective["max_output_tokens"], bool)
        ),
        "parallel_tool_calls_false": effective["parallel_tool_calls"] is False,
        "stream_false": effective["stream"] is False,
        "store_false": effective["store"] is False,
        "sole_forced_strict_function_tool": bool(
            function_preserved
            and effective["sole_function"]
            and effective["strict_function"]
            and effective["forced_function"]
            and effective["function_name"] == forced_name
        ),
        "no_image_generation": not effective["image_generation_present"],
        "temperature_zero": bool(
            client["temperature_present"]
            and effective["temperature_present"]
            and client["temperature"] in (0, 0.0)
            and effective["temperature"] in (0, 0.0)
            and not isinstance(client["temperature"], bool)
            and not isinstance(effective["temperature"], bool)
        ),
    }
    not_proven = [name for name, proven in controls.items() if not proven]
    return {
        "schema_version": 1,
        "artifact_type": ROUTE_RESOLUTION_ARTIFACT_TYPE,
        "resolution_status": "resolved" if not not_proven else "no_go",
        "required_controls": controls,
        "not_proven": not_proven,
        "client_requested": client,
        "effective_upstream": effective,
        "evidence_bindings": evidence,
        "actual_execution_counts": dict(_ZERO_EXECUTION_COUNTS),
    }


__all__ = [
    "EXPECTED_DOWNSTREAM_PATH",
    "EXPECTED_MAX_OUTPUT_TOKENS",
    "EXPECTED_MODEL",
    "EXPECTED_REASONING",
    "EXPECTED_UPSTREAM_URL",
    "ROUTE_RESOLUTION_ARTIFACT_TYPE",
    "RouteResolutionError",
    "resolve_route",
]
