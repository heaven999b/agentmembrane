from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATUS_PATH = PROJECT_ROOT / "monitor" / "status.json"


def _deep_merge(target: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(target.get(key), dict):
            target[key] = _deep_merge(dict(target[key]), value)
        else:
            target[key] = value
    return target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload", required=True)
    parser.add_argument("--event")
    args = parser.parse_args()

    patch = json.loads(args.payload)
    if not isinstance(patch, dict):
        raise ValueError("payload must be a JSON object")
    current: dict[str, Any] = {}
    if STATUS_PATH.exists():
        loaded = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            current = loaded
    result = _deep_merge(current, patch)
    result["updated_at"] = datetime.now(UTC).isoformat()
    events = result.get("event_log", [])
    if not isinstance(events, list):
        events = []
    if args.event:
        events.append({"at": result["updated_at"], "event": args.event})
    result["event_log"] = events[-100:]

    STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = STATUS_PATH.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(STATUS_PATH)
    print(STATUS_PATH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
