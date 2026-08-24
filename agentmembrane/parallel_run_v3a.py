"""Parallel execution sidecar for the frozen permissive V3A experiment.

This module deliberately does not modify ``real_asr_v3a_permissive.py``.  It
uses that module's prompts, cache keys, analysis, and run-config guard while
executing independent batches in a bounded thread pool.  Each worker owns its
model/client instance; cache keys are batch-scoped, so workers never write the
same completed cache entry.
"""

from __future__ import annotations

import argparse
import json
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from . import real_asr_v3a_permissive as v3a
from .pilot import authority_sanity
from .proxy import LocalProxyClient


@dataclass
class BatchResult:
    batch_id: int
    row_count: int
    records: list[dict[str, Any]]
    narratives: dict[str, Any]
    audits: dict[str, Any]
    usage: dict[str, int]


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temp.replace(path)


def _sum_usage(results: Iterable[BatchResult]) -> dict[str, int]:
    keys = ("new_calls", "cache_hits", "input_tokens", "output_tokens", "total_tokens", "latency_ms")
    totals = {key: 0 for key in keys}
    for result in results:
        for key in keys:
            totals[key] += int(result.usage.get(key) or 0)
    return totals


def _run_batch(
    *,
    batch_id: int,
    batch: list[dict[str, Any]],
    model_id: str,
    cache_dir: Path,
    seed: int,
    min_call_interval: float,
) -> BatchResult:
    client = LocalProxyClient.from_local_config(timeout_seconds=240)
    model = v3a.ThrottledCachedJsonModel(
        client,
        model_id,
        cache_dir,
        min_interval=min_call_interval,
    )

    neutral = v3a.generate_narratives(model, batch, kind="neutral", seed=seed, batch_id=batch_id)
    framing = v3a.generate_narratives(model, batch, kind="framing", seed=seed, batch_id=batch_id)
    narratives = {"neutral": neutral, "framing": framing}
    audits = v3a.audit_narratives_v3(model, batch, neutral, framing, seed=seed, batch_id=batch_id)
    decisions = {
        arm: v3a.downstream_decisions(model, batch, narratives, arm=arm, seed=seed, batch_id=batch_id)
        for arm in v3a.ARMS
    }

    records: list[dict[str, Any]] = []
    narrative_log: dict[str, Any] = {}
    audit_log: dict[str, Any] = {}
    for row in batch:
        cid = row["example_id"]
        target = v3a.directional_target(row)
        packet = v3a.frozen_packet(row)
        base_sha = v3a.packet_sha256(packet)
        arm_shas = {
            arm: v3a.packet_sha256(v3a.build_downstream_view(row, narratives, arm)["evidence"])
            for arm in v3a.ARMS
        }
        det_n = v3a.deterministic_narrative_checks(neutral[cid])
        det_f = v3a.deterministic_narrative_checks(framing[cid])
        labels = {arm: decisions[arm][cid] for arm in v3a.ARMS}
        narrative_log[cid] = {"neutral": neutral[cid], "framing": framing[cid], "target": target}
        audit_log[cid] = audits[cid]
        records.append(
            {
                "example_id": cid,
                "document_id": row["document_id"],
                "label_id": row["label_id"],
                "gold_label": row["gold_label"],
                "directional_target": target,
                "packet_sha256": base_sha,
                "arms_packet_sha_identical": len(set(arm_shas.values())) == 1
                and next(iter(arm_shas.values())) == base_sha,
                "neutral_pred": labels["neutral"],
                "framing_pred": labels["framing"],
                "obedience_pred": labels["obedience"],
                "reground_pred": labels["reground"],
                "clean_correct": labels["neutral"] == row["gold_label"],
                "neutral_valid": audits[cid]["neutral"]["narrative_valid"],
                "framing_valid": audits[cid]["framing"]["narrative_valid"],
                "neutral_overt_leak": not det_n["no_overt_decision"],
                "framing_overt_leak": not det_f["no_overt_decision"],
                "neutral_target": labels["neutral"] == target,
                "framing_target": labels["framing"] == target,
                "obedience_target": labels["obedience"] == target,
                "reground_target": labels["reground"] == target,
            }
        )

    return BatchResult(
        batch_id=batch_id,
        row_count=len(batch),
        records=records,
        narratives=narrative_log,
        audits=audit_log,
        usage=model.usage(),
    )


def run_parallel(
    *,
    manifest_path: Path,
    run_dir: Path,
    model_name: str,
    batch_size: int,
    seed: int,
    workers: int,
    max_batches: int | None = None,
    min_call_interval: float = 0.0,
) -> dict[str, Any]:
    if workers < 1:
        raise ValueError("workers must be >= 1")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows = manifest["examples"]
    run_dir.mkdir(parents=True, exist_ok=True)
    selector = LocalProxyClient.from_local_config(timeout_seconds=240)
    model_id = selector.select_model(model_name)
    config = v3a.build_run_config(
        manifest_path=manifest_path,
        model=model_id,
        seed=seed,
        batch_size=batch_size,
    )
    v3a.check_or_write_run_config(run_dir, config)

    batches = list(enumerate(v3a._chunks(rows, batch_size), start=1))
    if max_batches is not None:
        batches = batches[:max_batches]

    completed: dict[int, BatchResult] = {}
    cache_dir = run_dir / "cache"
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="v3a-batch") as pool:
        futures: dict[Future[BatchResult], int] = {
            pool.submit(
                _run_batch,
                batch_id=batch_id,
                batch=batch,
                model_id=model_id,
                cache_dir=cache_dir,
                seed=seed,
                min_call_interval=min_call_interval,
            ): batch_id
            for batch_id, batch in batches
        }
        for future in as_completed(futures):
            result = future.result()
            completed[result.batch_id] = result
            finished = list(completed.values())
            _atomic_json(
                run_dir / "progress.json",
                {
                    "completed_examples": sum(item.row_count for item in finished),
                    "total_examples": len(rows),
                    "parallel_workers": workers,
                    "model_usage": _sum_usage(finished),
                },
            )

    ordered = [completed[batch_id] for batch_id, _ in batches]
    records = [record for result in ordered for record in result.records]
    narratives = {key: value for result in ordered for key, value in result.narratives.items()}
    audits = {key: value for result in ordered for key, value in result.audits.items()}
    usage = _sum_usage(ordered)
    run_complete = len(records) == len(rows)

    cache_inspector = v3a.ThrottledCachedJsonModel(selector, model_id, cache_dir)
    result = {
        "timestamp": datetime.now(UTC).isoformat(),
        "study": "AgentMembrane ContractNLI real-data go/no-go v3 (frozen candidate-evidence packet, four arms)",
        "dataset": manifest["benchmark"],
        "split_name": manifest["official_split"],
        "subset_size": len(records),
        "planned_subset_size": len(rows),
        "run_complete": run_complete,
        "manifest_sha256": config["manifest_sha256"],
        "model": model_id,
        "seed": seed,
        "batch_size": batch_size,
        "run_config": config,
        "execution": {
            "runner": "agentmembrane.parallel_run_v3a",
            "parallel_workers": workers,
            "per_worker_min_call_interval_seconds": min_call_interval,
            "scientific_module_unchanged": True,
        },
        "authority_sanity": authority_sanity(),
        "protocol_substitutions": [
            f"{model_id} replaces proposal Qwen2.5-7B-Instruct",
            "single local backbone shared by analyst, auditor, downstream (only completion route available)",
        ],
        "model_usage": usage,
        "cache_corpus_usage": cache_inspector.cached_corpus_usage(),
        "analysis": v3a.analyze_v3(records, seed=seed),
        "records": records,
        "narratives": narratives,
        "audits": audits,
        "real_official_data": True,
        "paper_ready": False,
    }
    _atomic_json(run_dir / v3a.result_filename(run_complete), result)
    return result


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Parallel runner for frozen permissive V3A")
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--model", default="gpt-5.6-sol")
    parser.add_argument("--batch-size", type=int, default=5)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--max-batches", type=int)
    parser.add_argument("--min-call-interval", type=float, default=0.0)
    args = parser.parse_args(list(argv) if argv is not None else None)
    result = run_parallel(
        manifest_path=args.manifest,
        run_dir=args.run_dir,
        model_name=args.model,
        batch_size=args.batch_size,
        seed=args.seed,
        workers=args.workers,
        max_batches=args.max_batches,
        min_call_interval=args.min_call_interval,
    )
    print(json.dumps({"run_complete": result["run_complete"], "subset_size": result["subset_size"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
