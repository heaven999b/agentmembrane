from __future__ import annotations

import argparse
import json
import os
import re
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


BASE_URL_ENV = "AGENTMEMBRANE_PROXY_ADMIN_BASE_URL"
INSTRUCTIONS_ENV = "AGENTMEMBRANE_PROXY_ADMIN_INSTRUCTIONS"


def _settings() -> tuple[str, Path]:
    base_url = os.environ.get(BASE_URL_ENV)
    instructions = os.environ.get(INSTRUCTIONS_ENV)
    if not base_url or not instructions:
        raise RuntimeError("explicit_proxy_admin_configuration_required")
    parsed = urllib.parse.urlsplit(base_url)
    try:
        port = parsed.port
    except ValueError:
        raise RuntimeError("proxy_admin_base_url_must_be_explicit_loopback_management_route") from None
    if (parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or port is None
            or parsed.path.rstrip("/") != "/v0/management"
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None):
        raise RuntimeError("proxy_admin_base_url_must_be_explicit_loopback_management_route")
    return base_url.rstrip("/"), Path(instructions).expanduser()


def _management_key(instructions: Path) -> str:
    contents = instructions.read_text(encoding="utf-8")
    match = re.search(r"管理面板密码（secret）：`([^`\r\n]+)`", contents)
    if not match:
        raise RuntimeError("management_key_not_found")
    return match.group(1).strip()


def _request(path: str, *, method: str = "GET", payload: dict[str, Any] | None = None) -> Any:
    base_url, instructions = _settings()
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"{base_url}/{path.lstrip('/')}",
        method=method,
        data=body,
        headers={
            "Authorization": f"Bearer {_management_key(instructions)}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def auth_status(
    provider: str | None = "codex",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    payload = _request("auth-files")
    files = payload.get("files", []) if isinstance(payload, dict) else []
    selected = [
        row
        for row in files
        if isinstance(row, dict) and (provider is None or row.get("provider") == provider)
    ]
    safe = [
        {
            "provider": row.get("provider"),
            "status": row.get("status"),
            "status_message": re.sub(
                r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+", "[REDACTED_EMAIL]", str(row.get("status_message"))
            ),
            "disabled": row.get("disabled"),
            "unavailable": row.get("unavailable"),
            "success": row.get("success"),
            "failed": row.get("failed"),
        }
        for row in selected
    ]
    return selected, safe


def reset_codex_quota() -> dict[str, Any]:
    codex, before = auth_status()
    if len(codex) != 1 or not codex[0].get("auth_index"):
        raise RuntimeError(f"expected_one_codex_auth_found_{len(codex)}")
    response = _request(
        "reset-quota",
        method="POST",
        payload={"auth_index": codex[0]["auth_index"]},
    )
    _, after = auth_status()
    return {
        "status": response.get("status") if isinstance(response, dict) else None,
        "models_reset": response.get("models", []) if isinstance(response, dict) else [],
        "before": before,
        "after": after,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Safe local CLIProxyAPI quota diagnostics")
    parser.add_argument("command", choices=("status", "status-all", "reset-codex-quota"))
    args = parser.parse_args()
    if args.command == "status":
        _, result = auth_status()
    elif args.command == "status-all":
        _, result = auth_status(provider=None)
    else:
        result = reset_codex_quota()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
