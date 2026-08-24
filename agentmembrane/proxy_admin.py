from __future__ import annotations

import argparse
import json
import re
import urllib.request
from pathlib import Path
from typing import Any


BASE_URL = "http://127.0.0.1:8317/v0/management"
INSTRUCTIONS = Path.home() / "Desktop" / "桌面 - 衣海文的MacBook Air" / "CLIProxyAPI-使用说明.md"


def _management_key() -> str:
    contents = INSTRUCTIONS.read_text(encoding="utf-8")
    match = re.search(r"管理面板密码（secret）：`([^`\r\n]+)`", contents)
    if not match:
        raise RuntimeError("management_key_not_found")
    return match.group(1).strip()


def _request(path: str, *, method: str = "GET", payload: dict[str, Any] | None = None) -> Any:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"{BASE_URL}/{path.lstrip('/')}",
        method=method,
        data=body,
        headers={
            "Authorization": f"Bearer {_management_key()}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode("utf-8"))


def auth_status() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    payload = _request("auth-files")
    files = payload.get("files", []) if isinstance(payload, dict) else []
    codex = [row for row in files if isinstance(row, dict) and row.get("provider") == "codex"]
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
        for row in codex
    ]
    return codex, safe


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
    parser.add_argument("command", choices=("status", "reset-codex-quota"))
    args = parser.parse_args()
    if args.command == "status":
        _, result = auth_status()
    else:
        result = reset_codex_quota()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

