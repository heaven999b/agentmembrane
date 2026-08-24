"""Live dashboard for the v3 A/B experiment. Stdlib only, no deps.

Run:  python3 monitor_v3.py [port]   (default 8792)
"""
from __future__ import annotations

import html
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "outputs"
RUNS = [
    ("Run A · permissive V3", "v3a_permissive_n150_seed1", "A 的 go_signal 已知有漏洞，仅原始数据"),
    ("Run B · strict V3B", "v3b_strict_n150_seed1", "严格版：净 framing 效应 + 语义泄漏检查"),
]
COMPARE = OUT / "v3_ab_comparison_seed1.json"
TOTAL_DEFAULT = 150


def rj(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def tail(path: Path, n=8):
    try:
        return "\n".join(path.read_text(encoding="utf-8", errors="replace").splitlines()[-n:])
    except Exception:
        return ""


def fnum(v, spec="{:.3f}"):
    return "—" if v is None else spec.format(v)


def ci(v):
    return "—" if not v else f"[{v[0]:+.3f}, {v[1]:+.3f}]"


def effect_row(a: dict):
    # tolerate permissive (A) and strict (B) analysis shapes
    rows = []
    rates = a.get("arm_target_rates") or {}
    if rates:
        rows.append(("arm target rates",
                     " ".join(f"{k[:4]}={fnum(rates.get(k))}" for k in ("neutral", "framing", "obedience", "reground"))))
    for label, key in (
        ("framing_effect_all_pairs", "framing_effect_all_pairs"),
        ("net_framing_effect", "net_framing_effect"),
        ("validity_gated_net_framing_effect", "validity_gated_net_framing_effect"),
    ):
        blk = a.get(key)
        if isinstance(blk, dict):
            rows.append((label, f"Δ={fnum(blk.get('point') or blk.get('delta') or blk.get('right_rate'))}  cluster CI {ci(blk.get('cluster_bootstrap_95ci'))}"))
    cfs = a.get("constrained_framing_success_all_attempts")
    if isinstance(cfs, dict):
        rows.append(("constrained framing success", f"{cfs.get('numerator')}/{cfs.get('denominator')} = {fnum(cfs.get('rate'))}  cluster CI {ci(cfs.get('cluster_bootstrap_95ci'))}"))
    asr = a.get("clean_conditioned_asr")
    if isinstance(asr, dict):
        rows.append(("clean-conditioned ASR", f"{asr.get('numerator')}/{asr.get('denominator')} = {fnum(asr.get('rate'))}"))
    if a.get("valid_pair_coverage") is not None:
        rows.append(("valid-pair coverage", fnum(a.get("valid_pair_coverage"), "{:.2f}")))
    if a.get("overt_decision_leak_rate") is not None:
        rows.append(("overt leak rate", fnum(a.get("overt_decision_leak_rate"), "{:.3f}")))
    return "".join(f"<tr><td>{html.escape(k)}</td><td>{html.escape(v)}</td></tr>" for k, v in rows)


def card(title, slug, note):
    d = OUT / slug
    prog = rj(d / "progress.json") or {}
    res = rj(d / "results.json")
    part = rj(d / "partial_results.json")
    final = res or part
    cfg = rj(d / "run_config.json") or {}
    log = tail(OUT / f"{slug}.log")

    total = prog.get("total_examples", TOTAL_DEFAULT) or TOTAL_DEFAULT
    done = prog.get("completed_examples", 0)
    pct = int(100 * done / total) if total else 0
    usage = prog.get("model_usage", {}) or {}
    calls = usage.get("new_calls", 0)
    workers = max(1, int(prog.get("parallel_workers", 1) or 1))
    # This is deliberately labelled rough: model latency and cache hits vary.
    seconds_per_example = 24 / workers
    eta_min = round((total - done) * seconds_per_example / 60, 1) if done < total else 0
    execution = f" · workers {workers}" if workers > 1 else " · serial"

    if res:
        state, color = "DONE", "#2ea043"
    elif "429" in log or "cooldown" in log.lower():
        state, color = "429 / COOLDOWN", "#d29922"
    elif "Traceback" in log or '"ok": false' in log:
        state, color = "ERROR", "#f85149"
    elif done > 0:
        state, color = "RUNNING", "#58a6ff"
    elif d.exists():
        state, color = "STARTING", "#8b949e"
    else:
        state, color = "PENDING", "#6e7681"

    metrics = ""
    if final and final.get("analysis"):
        a = final["analysis"]
        go = a.get("go_signal")
        badge = '<b style="color:#2ea043">● GO</b>' if go else '<b style="color:#8b949e">○ no-go</b>'
        tag = " <span style='color:#d29922'>(A 的 go 非科研结论)</span>" if slug.startswith("v3a") else ""
        metrics = f"<table class='m'>{effect_row(a)}<tr><td>go_signal</td><td>{badge}{tag}</td></tr></table>"

    return f"""
    <div class="card">
      <div class="head"><span class="title">{html.escape(title)}</span>
        <span class="state" style="background:{color}">{state}</span></div>
      <div class="note">{html.escape(note)}</div>
      <div class="bar"><div class="fill" style="width:{pct}%;background:{color}"></div></div>
      <div class="sub">{done}/{total} ex · calls {calls} · cache {usage.get('cache_hits',0)}
        · {int((usage.get('total_tokens',0) or 0)/1000)}k tok
        · model {html.escape(str(cfg.get('model','?')))}
        {execution}
        {'· rough ETA ~'+str(eta_min)+' min' if done<total and done>0 else ''}</div>
      {metrics}
      <pre class="log">{html.escape(log) or '(no log yet)'}</pre>
    </div>"""


def verdict():
    cmp = rj(COMPARE)
    if not cmp:
        a_done = (OUT / RUNS[0][1] / "results.json").exists()
        b_done = (OUT / RUNS[1][1] / "results.json").exists()
        return f"<b>A/B 比较未生成。</b> Run A 完成: {'✅' if a_done else '⏳'} · Run B 完成: {'✅' if b_done else '⏳'} · 两者都完成后自动生成比较。"
    v = cmp.get("verdict") or cmp.get("interpretation") or cmp.get("summary") or ""
    return f"<b>A/B 结论:</b> {html.escape(str(v))}"


PAGE = """<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="2">
<title>V3 A/B monitor</title><style>
 body{{margin:0;background:#0d1117;color:#e6edf3;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}}
 .wrap{{max-width:1000px;margin:0 auto;padding:20px}}
 h1{{font-size:18px;margin:0 0 2px}} .top{{color:#8b949e;font-size:12px;margin-bottom:16px}}
 .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(360px,1fr));gap:14px}}
 .card{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px}}
 .head{{display:flex;justify-content:space-between;align-items:center}}
 .title{{font-weight:600}} .note{{color:#8b949e;font-size:12px;margin:2px 0 8px}}
 .state{{color:#0d1117;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px}}
 .bar{{height:8px;background:#21262d;border-radius:6px;overflow:hidden}} .fill{{height:100%;transition:width .3s}}
 .sub{{color:#8b949e;font-size:12px;margin:8px 0}}
 table.m{{width:100%;border-collapse:collapse;font-size:12.5px;margin:4px 0}}
 table.m td{{padding:3px 6px;border-bottom:1px solid #21262d}} table.m td:last-child{{text-align:right;font-variant-numeric:tabular-nums}}
 pre.log{{background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:8px;font-size:11px;color:#8b949e;white-space:pre-wrap;max-height:120px;overflow:auto;margin:6px 0 0}}
 .verdict{{margin-top:16px;padding:12px;border-radius:8px;border:1px solid #30363d;background:#161b22}}
</style></head><body><div class="wrap">
<h1>AgentMembrane · V3 A/B 实验监控</h1>
<div class="top">model gpt-5.6-sol（A/B 同模型）· Run A 已切换为 4 路并行、0s 人为节流 · 每 2 秒自动刷新</div>
<div class="grid">{cards}</div>
<div class="verdict">{verdict}</div>
</div></body></html>"""


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = PAGE.format(cards="".join(card(*r) for r in RUNS), verdict=verdict())
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8792
    print(f"monitor_v3 on http://127.0.0.1:{port}/")
    HTTPServer(("127.0.0.1", port), H).serve_forever()
