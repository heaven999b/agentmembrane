"""Read-only dashboard for an RQ1 conditional-protection report."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlparse


_HTML = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>RQ1 Conditional Protection</title><style>
:root{color-scheme:dark;--bg:#071018;--panel:#0e1b26;--line:#26394b;--text:#edf6fb;--muted:#91a9ba;--green:#78e08f;--cyan:#49d8c6;--red:#ff7185;--blue:#76a9ff}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 10% 0,#153247 0,transparent 38%),var(--bg);color:var(--text);font:14px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace}main{max-width:1280px;margin:auto;padding:26px}
h1{font:700 28px ui-sans-serif,system-ui;margin:0}.sub{color:var(--muted);margin:7px 0 20px}.grid{display:grid;grid-template-columns:repeat(6,1fr);gap:12px}.card,.panel{background:linear-gradient(145deg,#132534,#0c1721);border:1px solid var(--line);border-radius:12px;box-shadow:0 12px 32px #0006}.card{padding:15px}.label{font-size:11px;color:var(--muted);text-transform:uppercase}.value{font-size:25px;font-weight:700;margin-top:5px}.green{color:var(--green)}.cyan{color:var(--cyan)}.red{color:var(--red)}.blue{color:var(--blue)}
.panel{padding:16px;margin-top:14px}h2{font:650 15px ui-sans-serif,system-ui;margin:0 0 12px}table{border-collapse:collapse;width:100%;font-size:12px}th,td{text-align:left;padding:9px;border-bottom:1px solid var(--line)}th{color:var(--muted);font-weight:500}.ok{color:var(--green)}.bad{color:var(--red)}
@media(max-width:900px){.grid{grid-template-columns:repeat(2,1fr)}}
</style></head><body><main><h1>RQ1 · Conditional Protection Replay</h1><div class="sub" id="name">loading…</div>
<div class="grid"><div class="card"><div class="label">Baseline</div><div class="value green" id="pass">—</div></div><div class="card"><div class="label">Matched pairs</div><div class="value cyan" id="pairs">—</div></div><div class="card"><div class="label">Vulnerable effects</div><div class="value red" id="ve">—</div></div><div class="card"><div class="label">Protected denials</div><div class="value green" id="pd">—</div></div><div class="card"><div class="label">Protected effects</div><div class="value blue" id="pe">—</div></div><div class="card"><div class="label">Benign utility V / P</div><div class="value" id="bu">—</div></div></div>
<section class="panel"><h2>Workflow-level paired replay</h2><table><thead><tr><th>workflow</th><th>benign utility V/P</th><th>same target action</th><th>shadow parity</th><th>vulnerable effect</th><th>protected denied</th><th>protected effect</th></tr></thead><tbody id="rows"></tbody></table></section>
</main><script>const yn=x=>`<span class="${x?'ok':'bad'}">${x?'yes':'no'}</span>`;async function load(){const r=await fetch('/api/status',{cache:'no-store'});const d=await r.json();document.getElementById('name').textContent=d.namespace+' · zero-model scripted conditional evidence';document.getElementById('pass').textContent=d.baseline_passed?'PASS':'FAIL';document.getElementById('pairs').textContent=d.summary.matched_pairs_passed+' / '+d.summary.matched_pair_count;document.getElementById('ve').textContent=d.summary.conditional_attack.vulnerable_native_effect_true+' / 7';document.getElementById('pd').textContent=d.summary.conditional_attack.protected_denied_pre_dispatch+' / 7';document.getElementById('pe').textContent=d.summary.conditional_attack.protected_native_effect_true+' / 7';document.getElementById('bu').textContent=d.summary.benign.vulnerable_utility_true+' / '+d.summary.benign.protected_utility_true;document.getElementById('rows').innerHTML=d.rows.map(x=>`<tr><td>${x.workflow}</td><td>${yn(x.benign_vulnerable_utility)} / ${yn(x.benign_protected_utility)}</td><td>${yn(x.same_target_action)}</td><td>${yn(x.same_shadow_decision)}</td><td>${yn(x.vulnerable_effect)}</td><td>${yn(x.protected_denied)}</td><td>${yn(x.protected_effect)}</td></tr>`).join('')}load();</script></body></html>"""


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise RuntimeError("conditional report must be an object")
    return value


def snapshot(report_path: Path) -> dict[str, Any]:
    report = _read(Path(report_path).resolve())
    cases: dict[tuple[str, str, str], Mapping[str, Any]] = {}
    for row in report.get("cases", []):
        if not isinstance(row, Mapping) or not isinstance(row.get("assignment"), Mapping):
            continue
        assignment = row["assignment"]
        cases[(assignment["workflow_key"], assignment["replay_mode"], assignment["host_arm"])] = row
    pair_audits = {
        (row["workflow_key"], row["replay_mode"]): row
        for row in report.get("pair_audits", [])
        if isinstance(row, Mapping)
    }
    workflows = []
    for assignment in report.get("schedule", []):
        if isinstance(assignment, Mapping) and assignment.get("workflow_key") not in workflows:
            workflows.append(assignment["workflow_key"])
    rows = []
    for workflow in workflows:
        benign_v = cases[(workflow, "benign_ground_truth", "vulnerable")]
        benign_p = cases[(workflow, "benign_ground_truth", "protected")]
        attack_v = cases[(workflow, "paired_attack_target", "vulnerable")]
        attack_p = cases[(workflow, "paired_attack_target", "protected")]
        audit = pair_audits[(workflow, "paired_attack_target")]
        rows.append(
            {
                "workflow": workflow,
                "benign_vulnerable_utility": benign_v["native_checker_observed"]["utility"],
                "benign_protected_utility": benign_p["native_checker_observed"]["utility"],
                "same_target_action": audit["same_action_sequence"],
                "same_shadow_decision": audit["same_shadow_authority_decisions"],
                "vulnerable_effect": attack_v["native_checker_observed"]["security"],
                "protected_denied": attack_p["attack_attribution"]["attack_target_denied_pre_dispatch"],
                "protected_effect": attack_p["native_checker_observed"]["security"],
            }
        )
    return {
        "namespace": report_path.parent.name,
        "baseline_passed": report.get("baseline_passed"),
        "execution_counts": report.get("execution_counts"),
        "summary": report.get("summary"),
        "rows": rows,
    }


class _Handler(BaseHTTPRequestHandler):
    report_path: Path

    def do_GET(self) -> None:  # noqa: N802
        route = urlparse(self.path).path
        if route == "/api/status":
            payload = json.dumps(snapshot(self.report_path), separators=(",", ":")).encode()
            content_type = "application/json; charset=utf-8"
            status = 200
        elif route == "/":
            payload = _HTML.encode()
            content_type = "text/html; charset=utf-8"
            status = 200
        else:
            payload = b"not found"
            content_type = "text/plain; charset=utf-8"
            status = 404
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:
        return


def serve(report_path: Path, *, host: str, port: int) -> None:
    handler = type(
        "RQ1ConditionalMonitorHandler",
        (_Handler,),
        {"report_path": Path(report_path).resolve()},
    )
    server = ThreadingHTTPServer((host, port), handler)
    print(f"RQ1 conditional monitor: http://{host}:{port}/", flush=True)
    server.serve_forever()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8767)
    args = parser.parse_args()
    serve(args.report, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["serve", "snapshot"]
