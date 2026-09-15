"""Read-only live web monitor for durable RQ1 v5 run namespaces."""

from __future__ import annotations

import argparse
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse


_HTML = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RQ1 v5 Live Monitor</title>
<style>
:root{color-scheme:dark;--bg:#081018;--panel:#101c27;--line:#223446;--text:#eef5fb;--muted:#8fa8ba;--cyan:#45d7c4;--blue:#72a7ff;--red:#ff7185;--amber:#ffc764;--green:#78e08f}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 12% 0,#142a3b 0,transparent 35%),var(--bg);color:var(--text);font:14px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}
main{max-width:1440px;margin:auto;padding:24px}.top{display:flex;justify-content:space-between;gap:16px;align-items:flex-end;margin-bottom:18px}h1{font:700 28px/1.1 ui-sans-serif,system-ui;margin:0}.sub{color:var(--muted);margin-top:7px}.pulse{width:10px;height:10px;border-radius:50%;display:inline-block;background:var(--green);box-shadow:0 0 15px var(--green);margin-right:8px}
.grid{display:grid;grid-template-columns:repeat(6,minmax(140px,1fr));gap:12px}.card,.panel{background:linear-gradient(145deg,#122230,#0d1822);border:1px solid var(--line);border-radius:12px;box-shadow:0 10px 35px #0005}.card{padding:15px}.label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.1em}.value{font-size:25px;font-weight:700;margin-top:5px}.cyan{color:var(--cyan)}.blue{color:var(--blue)}.red{color:var(--red)}.amber{color:var(--amber)}.green{color:var(--green)}
.bar{height:10px;background:#071018;border:1px solid var(--line);border-radius:999px;overflow:hidden;margin:18px 0}.fill{height:100%;background:linear-gradient(90deg,var(--cyan),var(--blue));transition:width .4s}.panels{display:grid;grid-template-columns:1fr 1.7fr;gap:14px;margin-top:14px}.panel{padding:16px}h2{font:650 15px ui-sans-serif,system-ui;margin:0 0 12px}.kv{display:grid;grid-template-columns:1fr auto;gap:8px 18px}.kv div:nth-child(odd){color:var(--muted)}
table{border-collapse:collapse;width:100%;font-size:12px}th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:500;position:sticky;top:0;background:#101c27}.scroll{max-height:520px;overflow:auto}.pill{padding:2px 7px;border-radius:999px;background:#26384a;white-space:nowrap}.completed{background:#143b2c;color:var(--green)}.running{background:#183650;color:var(--blue)}.failed{background:#4a1e28;color:var(--red)}.pending{color:var(--muted)}
@media(max-width:1000px){.grid{grid-template-columns:repeat(2,1fr)}.panels{grid-template-columns:1fr}}
</style></head><body><main>
<div class="top"><div><h1>RQ1 v5 · Tool-Knowledge Stress</h1><div class="sub" id="namespace">loading…</div></div><div><span class="pulse"></span><span id="clock">connecting</span></div></div>
<div class="grid">
<div class="card"><div class="label">Cells completed</div><div class="value cyan" id="cells">—</div></div>
<div class="card"><div class="label">Provider calls</div><div class="value blue" id="calls">—</div></div>
<div class="card"><div class="label">Known tokens</div><div class="value" id="tokens">—</div></div>
<div class="card"><div class="label">Target proposals V / P</div><div class="value amber" id="targets">—</div></div>
<div class="card"><div class="label">Protected target denials</div><div class="value green" id="denials">—</div></div>
<div class="card"><div class="label">Native effects V / P</div><div class="value red" id="effects">—</div></div>
</div>
<div class="bar"><div class="fill" id="fill" style="width:0"></div></div>
<div class="panels"><section class="panel"><h2>Run integrity</h2><div class="kv" id="integrity"></div></section><section class="panel"><h2>Cell ledger</h2><div class="scroll"><table><thead><tr><th>#</th><th>workflow</th><th>coordinate</th><th>status</th><th>calls</th><th>utility</th><th>effect</th><th>target</th><th>denied</th></tr></thead><tbody id="rows"></tbody></table></div></section></div>
</main><script>
const fmt=n=>Number(n||0).toLocaleString(); const pill=s=>{let c=s==='completed'?'completed':s==='running'?'running':s==='pending'?'pending':'failed';return `<span class="pill ${c}">${s}</span>`};
async function refresh(){try{const r=await fetch('/api/status',{cache:'no-store'});const d=await r.json();
document.getElementById('namespace').textContent=d.namespace+' · '+d.phase;document.getElementById('clock').textContent=new Date().toLocaleTimeString();
document.getElementById('cells').textContent=d.cells.completed+' / '+d.cells.assigned;document.getElementById('calls').textContent=d.calls.reservations+' / '+d.calls.cap;
document.getElementById('tokens').textContent=fmt(d.calls.known_total_tokens);document.getElementById('targets').textContent=d.attack.vulnerable_target_proposals+' / '+d.attack.protected_target_proposals;
document.getElementById('denials').textContent=d.attack.protected_target_denials;document.getElementById('effects').textContent=d.attack.vulnerable_effects+' / '+d.attack.protected_effects;
document.getElementById('fill').style.width=(100*d.cells.completed/d.cells.assigned)+'%';
const kv={phase:d.phase,completed:d.cells.completed,pending:d.cells.pending,failed:d.cells.failed,reservations:d.calls.reservations,terminals:d.calls.terminals,open_reservations:d.calls.open_reservations,provider_errors:d.calls.provider_errors,usage_unknown:d.calls.usage_unknown,report_eligible:d.report_evidence_eligible};
document.getElementById('integrity').innerHTML=Object.entries(kv).map(([k,v])=>`<div>${k}</div><div>${v}</div>`).join('');
document.getElementById('rows').innerHTML=d.rows.map(x=>`<tr><td>${x.ordinal}</td><td>${x.workflow}</td><td>${x.coordinate}</td><td>${pill(x.status)}</td><td>${x.calls}</td><td>${x.utility??'—'}</td><td>${x.effect??'—'}</td><td>${x.target??'—'}</td><td>${x.denied??'—'}</td></tr>`).join('');
}catch(e){document.getElementById('clock').textContent='monitor read error'}}refresh();setInterval(refresh,2000);
</script></body></html>"""


def _read(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _attempt_id(path: Path) -> str:
    return f"{path.parent.name}/{path.name.split('.', 1)[0]}"


def snapshot(run_dir: Path) -> dict[str, Any]:
    root = Path(run_dir).resolve()
    schedule_value: Any = None
    try:
        schedule_value = json.loads((root / "schedule.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        pass
    schedule = schedule_value if isinstance(schedule_value, list) else []
    cells_by_ordinal: dict[int, dict[str, Any]] = {}
    for path in sorted((root / "cells").glob("cell-*.json")):
        record = _read(path)
        if record is None:
            continue
        assignment = record.get("assignment")
        if isinstance(assignment, Mapping):
            ordinal = assignment.get("execution_ordinal")
            if type(ordinal) is int:
                cells_by_ordinal[ordinal] = record
    reservations = sorted((root / "attempts").glob("cell-*/turn-*.reservation.json"))
    terminals = sorted((root / "attempts").glob("cell-*/turn-*.terminal.json"))
    terminal_ids = {_attempt_id(path) for path in terminals}
    terminal_rows = [row for path in terminals if (row := _read(path)) is not None]
    known_usage = [
        row["usage"]
        for row in terminal_rows
        if row.get("usage_known") is True and isinstance(row.get("usage"), Mapping)
    ]
    statuses = Counter(str(row.get("status")) for row in cells_by_ordinal.values())
    rows: list[dict[str, Any]] = []
    attack = Counter()
    for assignment in schedule:
        if not isinstance(assignment, Mapping):
            continue
        ordinal = assignment.get("execution_ordinal")
        if type(ordinal) is not int:
            continue
        record = cells_by_ordinal.get(ordinal)
        status = str(record.get("status")) if record is not None else "pending"
        if record is None and any(
            path.parent.name == f"cell-{ordinal:02d}" for path in reservations
        ):
            status = "running"
        checker = record.get("native_checker_observed") if record else None
        attribution = record.get("attack_attribution") if record else None
        role = str(assignment.get("pair_role"))
        arm = str(assignment.get("host_arm"))
        if role == "adversarial" and isinstance(attribution, Mapping):
            if attribution.get("attack_target_proposed") is True:
                attack[f"{arm}_target_proposals"] += 1
            if (
                arm == "protected"
                and attribution.get("attack_target_denied_pre_dispatch") is True
            ):
                attack["protected_target_denials"] += 1
        if role == "adversarial" and isinstance(checker, Mapping):
            if checker.get("security") is True:
                attack[f"{arm}_effects"] += 1
        calls = int(record.get("provider_call_reservations", 0)) if record else sum(
            path.parent.name == f"cell-{ordinal:02d}" for path in reservations
        )
        rows.append(
            {
                "ordinal": ordinal,
                "workflow": assignment.get("workflow_key"),
                "coordinate": f"{role}/{arm}",
                "status": status,
                "calls": calls,
                "utility": checker.get("utility") if isinstance(checker, Mapping) else None,
                "effect": checker.get("security") if isinstance(checker, Mapping) else None,
                "target": attribution.get("attack_target_proposed") if isinstance(attribution, Mapping) else None,
                "denied": attribution.get("attack_target_denied_pre_dispatch") if isinstance(attribution, Mapping) else None,
            }
        )
    assigned = len(schedule) or 28
    report = _read(root / "report.json")
    canary = _read(root / "canary-report.json")
    open_reservations = sum(
        _attempt_id(path) not in terminal_ids for path in reservations
    )
    if report:
        phase = "final"
    elif canary and open_reservations:
        phase = "continuation_running"
    elif canary:
        phase = "canary_complete"
    elif open_reservations:
        phase = "canary_running"
    else:
        phase = "prepared"
    result = {
        "namespace": root.name,
        "phase": phase,
        "cells": {
            "assigned": assigned,
            "completed": statuses.get("completed", 0),
            "failed": sum(count for status, count in statuses.items() if status != "completed"),
            "pending": assigned - len(cells_by_ordinal),
            "status_counts": dict(statuses),
        },
        "calls": {
            "reservations": len(reservations),
            "terminals": len(terminals),
            "open_reservations": open_reservations,
            "provider_errors": sum(row.get("status") == "provider_error" for row in terminal_rows),
            "usage_unknown": len(terminal_rows) - len(known_usage),
            "known_input_tokens": sum(int(row.get("input_tokens", 0)) for row in known_usage),
            "known_output_tokens": sum(int(row.get("output_tokens", 0)) for row in known_usage),
            "known_total_tokens": sum(int(row.get("total_tokens", 0)) for row in known_usage),
            "cap": 168,
        },
        "attack": {
            "vulnerable_target_proposals": attack["vulnerable_target_proposals"],
            "protected_target_proposals": attack["protected_target_proposals"],
            "protected_target_denials": attack["protected_target_denials"],
            "vulnerable_effects": attack["vulnerable_effects"],
            "protected_effects": attack["protected_effects"],
        },
        "report_evidence_eligible": report.get("evidence_eligible") if report else None,
        "rows": rows,
    }
    return result


class _Handler(BaseHTTPRequestHandler):
    run_dir: Path

    def do_GET(self) -> None:  # noqa: N802
        route = urlparse(self.path).path
        if route == "/api/status":
            payload = json.dumps(snapshot(self.run_dir), separators=(",", ":")).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
        elif route == "/":
            payload = _HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
        else:
            payload = b"not found"
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:
        return


def serve(run_dir: Path, *, host: str, port: int) -> None:
    handler = type("RQ1V4MonitorHandler", (_Handler,), {"run_dir": Path(run_dir).resolve()})
    server = ThreadingHTTPServer((host, port), handler)
    print(f"RQ1 v5 monitor: http://{host}:{port}/", flush=True)
    server.serve_forever()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    if args.once:
        print(json.dumps(snapshot(args.run_dir), indent=2, sort_keys=True))
        return 0
    serve(args.run_dir, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["serve", "snapshot"]
