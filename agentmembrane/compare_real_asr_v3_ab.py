"""Phase 3 (strict reanalysis of Run A) + Phase 4 (A/B comparison).

Run A (permissive) is reanalyzed with the STRICT V3B rules WITHOUT regenerating any
narrative or rerunning any downstream prediction. The only model use permitted here is
an audit-only pass that adds the strict `no_explicit_task_answer` judgement (and the
fact/no-denial judgement) for Run A's already-generated notes; its call count is
recorded separately. Everything else is recomputed from Run A's stored records, its
cached raw narratives (for raw-schema), and deterministic checks.

The comparison never uses Run A's permissive `go_signal`.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Iterable

from . import real_asr_v3 as v3
from .real_asr_v3 import (
    ARMS,
    analyze_v3,
    audit_narratives_v3,
    cluster_bootstrap_ci,
    deterministic_narrative_checks,
    net_framing_delta,
    raw_schema_check,
    strict_narrative_valid,
)
from .proxy import LocalProxyClient


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

def load_results(run_dir: Path) -> dict[str, Any]:
    path = run_dir / "results.json"
    if not path.exists():
        raise ValueError(f"{run_dir} has no results.json (run not complete)")
    return json.loads(path.read_text(encoding="utf-8"))


def recover_raw_narratives(run_dir: Path) -> dict[str, dict[str, dict[str, Any]]]:
    """Recover the RAW (uncleaned) narrative objects from Run A's cache, so raw-schema
    violations can be judged as V3B requires. Returns {kind: {example_id: raw_obj}}."""
    out = {"neutral": {}, "framing": {}}
    cache = run_dir / "cache"
    for kind in ("neutral", "framing"):
        for path in sorted(cache.glob(f"narr_{kind}_*.json")):
            payload = json.loads(path.read_text(encoding="utf-8")).get("payload", {})
            for item in payload.get("artifacts", []) or []:
                if isinstance(item, dict) and item.get("id"):
                    out[kind].setdefault(item["id"], item)
    return out


# --------------------------------------------------------------------------- #
# Strict reanalysis of Run A (pure — no model)
# --------------------------------------------------------------------------- #

def strict_records_from(
    records: list[dict[str, Any]],
    narratives: dict[str, dict[str, Any]],
    raw_narratives: dict[str, dict[str, dict[str, Any]]],
    audit_map: dict[str, dict[str, dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Recompute strict validity/leak flags for each stored record. No model, no
    regeneration, no downstream rerun — targets/predictions are taken as-is."""
    strict = []
    for r in records:
        cid = r["example_id"]
        new = dict(r)
        for kind in ("neutral", "framing"):
            note_obj = (narratives.get(cid, {}) or {}).get(kind, {}) or {}
            raw_obj = (raw_narratives.get(kind, {}) or {}).get(cid, note_obj)
            raw_sv = raw_schema_check(raw_obj)["raw_schema_valid"]
            det = deterministic_narrative_checks({**note_obj, "raw_schema_valid": raw_sv})
            jd = (audit_map.get(cid, {}) or {}).get(kind, {}) or {}
            valid = strict_narrative_valid(det, jd)
            new[f"{kind}_raw_schema_valid"] = raw_sv
            new[f"{kind}_valid"] = valid
            new[f"{kind}_overt_leak"] = not det["no_overt_decision"]
            new[f"{kind}_explicit_answer_leak"] = (not det["no_overt_decision"]) or (jd.get("no_explicit_task_answer") is not True)
        strict.append(new)
    return strict


def run_audit_only(
    model: Any,
    manifest_rows: list[dict[str, Any]],
    narratives: dict[str, dict[str, Any]],
    *,
    seed: int,
    batch_size: int,
    audit_fn: Callable[..., dict[str, Any]] = audit_narratives_v3,
) -> tuple[dict[str, dict[str, Any]], int]:
    """The ONLY model use in reanalysis: an audit-only pass over Run A's existing notes.
    Never calls generate_narratives or downstream_decisions. Returns (audit_map, calls)."""
    audit_map: dict[str, dict[str, Any]] = {}
    neutral = {cid: v["neutral"] for cid, v in narratives.items()}
    framing = {cid: v["framing"] for cid, v in narratives.items()}
    rows_by_id = {row["example_id"]: row for row in manifest_rows}
    ids = [r["example_id"] for r in manifest_rows if r["example_id"] in narratives]
    for start in range(0, len(ids), batch_size):
        batch_ids = ids[start : start + batch_size]
        batch = [rows_by_id[i] for i in batch_ids]
        part = audit_fn(model, batch, neutral, framing, seed=seed, batch_id=(start // batch_size) + 1)
        audit_map.update(part)
    calls = getattr(model, "calls", 0)
    return audit_map, calls


def reanalyze_run_a(run_a_dir: Path, manifest_path: Path, model: Any, *, seed: int = 1, batch_size: int = 5) -> dict[str, Any]:
    res = load_results(run_a_dir)
    if not res.get("run_complete"):
        raise ValueError("Run A is not complete; refusing to reanalyze")
    manifest_rows = json.loads(manifest_path.read_text(encoding="utf-8"))["examples"]
    narratives = {cid: {"neutral": v["neutral"], "framing": v["framing"]} for cid, v in res["narratives"].items()}
    raw = recover_raw_narratives(run_a_dir)
    audit_map, calls = run_audit_only(model, manifest_rows, narratives, seed=seed, batch_size=batch_size)
    strict = strict_records_from(res["records"], narratives, raw, audit_map)
    analysis = analyze_v3(strict, seed=seed)
    return {"reanalyzed_records": strict, "analysis": analysis, "audit_only_model_calls": calls}


# --------------------------------------------------------------------------- #
# A/B consistency verification
# --------------------------------------------------------------------------- #

def verify_ab_consistency(run_a: dict[str, Any], run_b: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    for field in ("manifest_sha256", "model", "seed", "batch_size"):
        if run_a.get(field) != run_b.get(field):
            problems.append(f"{field} differs: A={run_a.get(field)} B={run_b.get(field)}")
    if not run_a.get("run_complete"):
        problems.append("Run A not complete")
    if not run_b.get("run_complete"):
        problems.append("Run B not complete")
    a = {r["example_id"]: r for r in run_a.get("records", [])}
    b = {r["example_id"]: r for r in run_b.get("records", [])}
    if set(a) != set(b):
        problems.append(f"example_id sets differ (A={len(a)} B={len(b)}, symdiff={len(set(a) ^ set(b))})")
    for cid in sorted(set(a) & set(b)):
        if a[cid].get("packet_sha256") != b[cid].get("packet_sha256"):
            problems.append(f"packet_sha256 differs for {cid}")
        if a[cid].get("directional_target") != b[cid].get("directional_target"):
            problems.append(f"directional_target differs for {cid}")
    if list(run_a.get("run_config", {}).get("arms", ARMS)) != list(run_b.get("run_config", {}).get("arms", ARMS)):
        problems.append("arm definitions differ")
    return problems


# --------------------------------------------------------------------------- #
# Comparison (Phase 4)
# --------------------------------------------------------------------------- #

def _interpretation(a_go: bool, b_go: bool) -> str:
    if a_go and b_go:
        return "A_positive_B_positive: framing signal survives strict constraints — stronger evidence."
    if a_go and not b_go:
        return "A_positive_B_negative: the permissive effect came mainly from answer hints, schema violations, or invalid narratives — likely artifact."
    if not a_go and not b_go:
        return "A_negative_B_negative: no framing signal under this data and model."
    return "A_negative_B_positive: UNEXPECTED — check generation randomness, auditor differences, and implementation before claiming success."


def build_comparison(run_a_strict: dict[str, Any], run_b: dict[str, Any], consistency: list[str], *, seed: int = 1) -> dict[str, Any]:
    a_an = run_a_strict["analysis"]
    b_an = run_b["analysis"]
    a_recs = {r["example_id"]: r for r in run_a_strict["reanalyzed_records"]}
    b_recs = {r["example_id"]: r for r in run_b.get("records", [])}

    # paired A/B net-effect difference, clustered by document
    paired_by_doc: dict[Any, list[float]] = {}
    paired_pts = []
    for cid in sorted(set(a_recs) & set(b_recs)):
        rb, ra = b_recs[cid], a_recs[cid]
        diff = net_framing_delta(rb) - net_framing_delta(ra)
        paired_by_doc.setdefault(ra["document_id"], []).append(diff)
        paired_pts.append(diff)
    paired = {
        "point_b_minus_a": statistics.mean(paired_pts) if paired_pts else None,
        "cluster_bootstrap_95ci": cluster_bootstrap_ci(paired_by_doc, seed=seed + 7) if paired_by_doc else None,
        "n_paired": len(paired_pts),
        "unique_documents": len(paired_by_doc),
    }

    def _snap(an: dict[str, Any]) -> dict[str, Any]:
        net = an["validity_gated_net_framing_effect"]
        return {
            "raw_schema_valid_rate": an.get("raw_schema_valid_rate"),
            "narrative_valid_rate": an.get("narrative_valid_rate"),
            "overt_decision_leak_rate": an.get("overt_decision_leak_rate"),
            "explicit_answer_leak_rate": an.get("explicit_answer_leak_rate"),
            "arm_target_rates": an.get("arm_target_rates"),
            "validity_gated_net_framing_effect": {"point": net.get("point"), "cluster_bootstrap_95ci": net.get("cluster_bootstrap_95ci"), "moved_toward_target": net.get("moved_toward_target"), "moved_away_from_target": net.get("moved_away_from_target")},
            "valid_pair_coverage": an.get("valid_pair_coverage"),
            "clean_conditioned_asr": an.get("clean_conditioned_asr"),
            "obedience_effect_positive_control": {"delta": an["obedience_effect_positive_control"].get("delta"), "cluster_bootstrap_95ci": an["obedience_effect_positive_control"].get("cluster_bootstrap_95ci")},
            "reground_mitigation": {"delta": an["reground_mitigation"].get("delta"), "cluster_bootstrap_95ci": an["reground_mitigation"].get("cluster_bootstrap_95ci")},
            "go_signal": an.get("go_signal"),
        }

    a_snap, b_snap = _snap(a_an), _snap(b_an)
    deltas = {
        "valid_pair_coverage_change_b_minus_a": (b_snap["valid_pair_coverage"] or 0) - (a_snap["valid_pair_coverage"] or 0),
        "answer_leak_rate_change_b_minus_a": (b_snap["explicit_answer_leak_rate"] or 0) - (a_snap["explicit_answer_leak_rate"] or 0),
        "net_framing_effect_change_b_minus_a": (b_snap["validity_gated_net_framing_effect"]["point"] or 0) - (a_snap["validity_gated_net_framing_effect"]["point"] or 0),
        "clean_asr_change_b_minus_a": ((b_snap["clean_conditioned_asr"] or {}).get("rate") or 0) - ((a_snap["clean_conditioned_asr"] or {}).get("rate") or 0),
        "reground_mitigation_change_b_minus_a": (b_snap["reground_mitigation"]["delta"] or 0) - (a_snap["reground_mitigation"]["delta"] or 0),
    }
    return {
        "study": "AgentMembrane V3 A/B comparison (Run A reanalyzed with strict metrics vs Run B strict)",
        "created_at": datetime.now(UTC).isoformat(),
        "consistency_problems": consistency,
        "consistent": not consistency,
        "seed": seed,
        "run_a_strict": a_snap,
        "run_b_strict": b_snap,
        "ab_deltas": deltas,
        "paired_net_effect_b_minus_a_document_clustered": paired,
        "stratified": {
            "run_a_strict": a_an.get("breakdowns"),
            "run_b_strict": b_an.get("breakdowns"),
        },
        "interpretation": _interpretation(bool(a_snap["go_signal"]), bool(b_snap["go_signal"])),
        "audit_only_model_calls_for_run_a_reanalysis": run_a_strict.get("audit_only_model_calls"),
        "note": "Single seed; NOT paper-ready. Run A's own permissive go_signal is not used anywhere here.",
        "paper_ready": False,
    }


def render_markdown(cmp: dict[str, Any]) -> str:
    a, b = cmp["run_a_strict"], cmp["run_b_strict"]

    def net(x):
        e = x["validity_gated_net_framing_effect"]
        ci = e["cluster_bootstrap_95ci"]
        return f"{e['point']:+.3f} (cluster CI {'—' if not ci else f'[{ci[0]:+.3f}, {ci[1]:+.3f}]'}) · +{e['moved_toward_target']}/-{e['moved_away_from_target']}"

    lines = [
        "# AgentMembrane V3 A/B comparison",
        "",
        f"- Created: {cmp['created_at']}",
        f"- A/B consistent: **{cmp['consistent']}**" + ("" if cmp["consistent"] else f" — problems: {cmp['consistency_problems']}"),
        f"- Run A reanalysis audit-only model calls: {cmp['audit_only_model_calls_for_run_a_reanalysis']}",
        "",
        "> Run A = permissive-generated data, **reanalyzed with strict V3B metrics**. Run B = strict-generated. "
        "Run A's own permissive go_signal is not used.",
        "",
        "| metric | Run A (strict reanalysis) | Run B (strict) |",
        "|---|---|---|",
        f"| narrative valid rate (n/f) | {a['narrative_valid_rate']} | {b['narrative_valid_rate']} |",
        f"| raw schema valid rate (n/f) | {a['raw_schema_valid_rate']} | {b['raw_schema_valid_rate']} |",
        f"| overt leak rate | {a['overt_decision_leak_rate']:.3f} | {b['overt_decision_leak_rate']:.3f} |",
        f"| explicit answer leak rate | {a['explicit_answer_leak_rate']:.3f} | {b['explicit_answer_leak_rate']:.3f} |",
        f"| valid-pair coverage | {a['valid_pair_coverage']:.3f} | {b['valid_pair_coverage']:.3f} |",
        f"| **net framing effect** | {net(a)} | {net(b)} |",
        f"| clean-conditioned ASR | {(a['clean_conditioned_asr'] or {}).get('rate')} | {(b['clean_conditioned_asr'] or {}).get('rate')} |",
        f"| obedience effect (control) | {a['obedience_effect_positive_control']['delta']:+.3f} | {b['obedience_effect_positive_control']['delta']:+.3f} |",
        f"| reground mitigation | {a['reground_mitigation']['delta']:+.3f} | {b['reground_mitigation']['delta']:+.3f} |",
        f"| **GO** | {a['go_signal']} | {b['go_signal']} |",
        "",
        f"**Paired net effect (B − A), document-clustered:** {cmp['paired_net_effect_b_minus_a_document_clustered']}",
        "",
        f"## Interpretation\n\n{cmp['interpretation']}",
        "",
        "## Caveats",
        "- Single seed, single model (gpt-5.6-sol), single local backbone shared across roles — NOT paper-ready.",
        "- Run A executed 4-way parallel / 0s-throttle (deterministic-equivalent to serial; see FREEZE_runA.json).",
    ]
    return "\n".join(lines)


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="V3 A/B strict reanalysis + comparison")
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("compare", help="reanalyze Run A strictly and compare to Run B (audit-only model use)")
    c.add_argument("--run-a", type=Path, required=True)
    c.add_argument("--run-b", type=Path, required=True)
    c.add_argument("--manifest", type=Path, required=True)
    c.add_argument("--out-json", type=Path, required=True)
    c.add_argument("--out-md", type=Path, required=True)
    c.add_argument("--model", default="gpt-5.6-sol")
    c.add_argument("--seed", type=int, default=1)
    c.add_argument("--batch-size", type=int, default=5)
    c.add_argument("--min-call-interval", type=float, default=v3.DEFAULT_MIN_CALL_INTERVAL)
    args = parser.parse_args(list(argv) if argv is not None else None)

    run_a = load_results(args.run_a)
    run_b = load_results(args.run_b)
    consistency = verify_ab_consistency(run_a, run_b)
    if consistency:
        print(json.dumps({"ok": False, "consistency_problems": consistency}, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1
    client = LocalProxyClient.from_local_config(timeout_seconds=240)
    model_id = client.select_model(args.model)
    model = v3.ThrottledCachedJsonModel(client, model_id, args.run_a / "reanalysis_cache", min_interval=args.min_call_interval)
    run_a_strict = reanalyze_run_a(args.run_a, args.manifest, model, seed=args.seed, batch_size=args.batch_size)
    cmp = build_comparison(run_a_strict, run_b, consistency, seed=args.seed)
    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(json.dumps(cmp, ensure_ascii=False, indent=2), encoding="utf-8")
    args.out_md.write_text(render_markdown(cmp), encoding="utf-8")
    print(json.dumps({"out_json": str(args.out_json.resolve()), "out_md": str(args.out_md.resolve()), "interpretation": cmp["interpretation"], "audit_only_calls": run_a_strict["audit_only_model_calls"]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
