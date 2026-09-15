"""Read-only live monitor for smoke and 50-session activation runs."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse


_HTML = r"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RQ1 Activation Calibration</title>
<style>:root{color-scheme:dark;--bg:#071019;--p:#101e2b;--l:#24384b;--t:#edf7ff;--m:#8da9bd;--c:#44dac5;--b:#78a9ff;--r:#ff7087;--a:#ffc96b}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 10% 0,#173149,transparent 38%),var(--bg);color:var(--t);font:14px ui-monospace,monospace}main{max-width:1500px;margin:auto;padding:24px}h1{font:700 28px system-ui;margin:0}.sub{color:var(--m);margin:7px 0 18px}.grid{display:grid;grid-template-columns:repeat(7,1fr);gap:10px}.card,.panel{background:linear-gradient(145deg,#132534,#0d1923);border:1px solid var(--l);border-radius:12px;padding:14px}.label{color:var(--m);font-size:11px;text-transform:uppercase}.value{font-size:24px;font-weight:700;margin-top:6px}.c{color:var(--c)}.b{color:var(--b)}.r{color:var(--r)}.a{color:var(--a)}.bar{height:9px;background:#050b10;border:1px solid var(--l);border-radius:9px;margin:16px 0;overflow:hidden}.fill{height:100%;background:linear-gradient(90deg,var(--c),var(--b))}.panels{display:grid;grid-template-columns:1fr 2fr;gap:12px}.kv{display:grid;grid-template-columns:1fr auto;gap:8px 14px}.kv div:nth-child(odd){color:var(--m)}table{border-collapse:collapse;width:100%;font-size:12px}th,td{padding:7px;border-bottom:1px solid var(--l);text-align:left}th{color:var(--m);position:sticky;top:0;background:#101e2b}.scroll{max-height:560px;overflow:auto}@media(max-width:1000px){.grid{grid-template-columns:repeat(2,1fr)}.panels{grid-template-columns:1fr}}</style></head><body><main><h1>RQ1 · Natural Attack Activation</h1><div class="sub" id="ns">loading</div><div class="grid"><div class="card"><div class="label">Cells</div><div class="value c" id="cells">—</div></div><div class="card"><div class="label">Calls</div><div class="value b" id="calls">—</div></div><div class="card"><div class="label">Tokens</div><div class="value" id="tokens">—</div></div><div class="card"><div class="label">Exposed</div><div class="value a" id="exposed">—</div></div><div class="card"><div class="label">Targets</div><div class="value a" id="targets">—</div></div><div class="card"><div class="label">Dispatched</div><div class="value r" id="dispatched">—</div></div><div class="card"><div class="label">Effects</div><div class="value r" id="effects">—</div></div></div><div class="bar"><div class="fill" id="fill"></div></div><div class="panels"><section class="panel"><div class="kv" id="kv"></div></section><section class="panel"><div class="scroll"><table><thead><tr><th>#</th><th>workflow</th><th>strength</th><th>status</th><th>calls</th><th>exposed</th><th>target</th><th>effect</th></tr></thead><tbody id="rows"></tbody></table></div></section></div></main><script>const f=n=>Number(n||0).toLocaleString();async function go(){try{let d=await(await fetch('/api/status',{cache:'no-store'})).json();ns.textContent=d.namespace+' · '+d.phase;cells.textContent=d.cells.completed+' / '+d.cells.assigned;calls.textContent=d.calls.reservations+' / '+d.calls.cap;tokens.textContent=f(d.calls.known_total_tokens);exposed.textContent=d.funnel.exposed;targets.textContent=d.funnel.targets;dispatched.textContent=d.funnel.dispatched;effects.textContent=d.funnel.effects;fill.style.width=(100*d.cells.recorded/d.cells.assigned)+'%';kv.innerHTML=Object.entries({phase:d.phase,failed:d.cells.failed,pending:d.cells.pending,open_reservations:d.calls.open_reservations,provider_errors:d.calls.provider_errors,usage_unknown:d.calls.usage_unknown}).map(([k,v])=>`<div>${k}</div><div>${v}</div>`).join('');rows.innerHTML=d.rows.map(x=>`<tr><td>${x.ordinal}</td><td>${x.workflow}</td><td>${x.strength}</td><td>${x.status}</td><td>${x.calls}</td><td>${x.exposed??'—'}</td><td>${x.target??'—'}</td><td>${x.effect??'—'}</td></tr>`).join('')}catch(e){ns.textContent='read error'}}go();setInterval(go,2000)</script></body></html>"""


def _read(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None


def snapshot(run_dir: Path) -> dict[str, Any]:
    root = Path(run_dir).resolve()
    schedule = _read(root / "schedule.json")
    schedule = schedule if isinstance(schedule, list) else []
    records: dict[int, Mapping[str, Any]] = {}
    for path in sorted((root / "cells").glob("cell-*.json")):
        row = _read(path)
        if isinstance(row, Mapping) and isinstance(row.get("assignment"), Mapping):
            ordinal = row["assignment"].get("execution_ordinal")
            if type(ordinal) is int:
                records[ordinal] = row
    reservations = sorted((root / "attempts").glob("cell-*/turn-*.reservation.json"))
    terminals = sorted((root / "attempts").glob("cell-*/turn-*.terminal.json"))
    terminal_ids = {(p.parent.name, p.name.replace(".terminal.json", "")) for p in terminals}
    open_count = sum((p.parent.name, p.name.replace(".reservation.json", "")) not in terminal_ids for p in reservations)
    terminal_rows = [row for p in terminals if isinstance((row := _read(p)), Mapping)]
    usage = [row["usage"] for row in terminal_rows if row.get("usage_known") is True and isinstance(row.get("usage"), Mapping)]
    statuses = Counter(str(row.get("status")) for row in records.values())
    funnel = Counter()
    rows = []
    for assignment in schedule:
        ordinal = assignment.get("execution_ordinal") if isinstance(assignment, Mapping) else None
        if type(ordinal) is not int:
            continue
        row = records.get(ordinal)
        f = row.get("activation_funnel") if row else None
        if isinstance(f, Mapping):
            funnel["exposed"] += f.get("carrier_exposed") is True
            funnel["targets"] += f.get("target_proposed") is True
            funnel["dispatched"] += f.get("target_native_dispatched") is True
            funnel["effects"] += f.get("native_attack_effect") is True
        calls = sum(p.parent.name == f"cell-{ordinal:02d}" for p in reservations)
        status = str(row.get("status")) if row else ("running" if calls else "pending")
        rows.append({"ordinal":ordinal,"workflow":assignment.get("workflow_key"),"strength":assignment.get("attack_strength"),"status":status,"calls":calls,"exposed":f.get("carrier_exposed") if isinstance(f,Mapping) else None,"target":f.get("target_proposed") if isinstance(f,Mapping) else None,"effect":f.get("native_attack_effect") if isinstance(f,Mapping) else None})
    assigned = len(schedule)
    completed = statuses.get("completed", 0)
    report = _read(root / "report.json")
    phase = "final" if isinstance(report, Mapping) else ("running" if reservations else "prepared")
    return {"namespace":root.name,"phase":phase,"cells":{"assigned":assigned,"recorded":len(records),"completed":completed,"failed":len(records)-completed,"pending":assigned-len(records)},"calls":{"reservations":len(reservations),"terminals":len(terminals),"open_reservations":open_count,"provider_errors":sum(r.get("status")=="provider_error" for r in terminal_rows),"usage_unknown":len(terminal_rows)-len(usage),"known_total_tokens":sum(int(r.get("total_tokens",0)) for r in usage),"cap":assigned*8},"funnel":dict(funnel),"rows":rows}


class _Handler(BaseHTTPRequestHandler):
    run_dir: Path
    def do_GET(self) -> None:  # noqa: N802
        route = urlparse(self.path).path
        if route == "/api/status":
            payload = json.dumps(snapshot(self.run_dir), separators=(",", ":")).encode(); code=200; content="application/json; charset=utf-8"
        elif route == "/": payload=_HTML.encode(); code=200; content="text/html; charset=utf-8"
        else: payload=b"not found"; code=404; content="text/plain; charset=utf-8"
        self.send_response(code); self.send_header("Content-Type",content); self.send_header("Cache-Control","no-store"); self.send_header("Content-Length",str(len(payload))); self.end_headers(); self.wfile.write(payload)
    def log_message(self, format: str, *args: Any) -> None: return


def serve(run_dir: Path, *, host: str, port: int) -> None:
    handler = type("RQ1ActivationHandler", (_Handler,), {"run_dir":Path(run_dir).resolve()})
    print(f"RQ1 activation monitor: http://{host}:{port}/", flush=True)
    ThreadingHTTPServer((host,port),handler).serve_forever()


def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("run_dir",type=Path); parser.add_argument("--host",default="127.0.0.1"); parser.add_argument("--port",type=int,default=8768); parser.add_argument("--once",action="store_true"); args=parser.parse_args()
    if args.once: print(json.dumps(snapshot(args.run_dir),indent=2,sort_keys=True)); return 0
    serve(args.run_dir,host=args.host,port=args.port); return 0


if __name__ == "__main__": raise SystemExit(main())


__all__=["serve","snapshot"]
