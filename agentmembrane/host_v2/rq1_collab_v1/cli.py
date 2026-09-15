"""Offline command-line entry points; no implicit provider/model launch."""
from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path
import sys

from .audit import EventCollector, canonical, strict_loads, verify
from .campaign import plan_panel, preflight, persist_plan


def register_commands(subparsers):
    command = subparsers.add_parser("audit", help="verify a sealed run and its artifact inventory")
    command.add_argument("run_dir")
    command.add_argument("--expected-seal-hash")
    command.add_argument("--evidence-dir")
    command.set_defaults(handler=_audit)
    command = subparsers.add_parser("preflight", help="check a campaign lock; never launch")
    command.add_argument("config")
    command.add_argument("--evidence-dir")
    command.set_defaults(handler=_preflight)
    command = subparsers.add_parser("plan", help="create matched draws from admitted original task records")
    command.add_argument("--tasks", required=True)
    command.add_argument("--n", type=int, required=True, help="total paired draws over three seed batches")
    command.add_argument("--master-seeds", nargs=3, type=int, required=True)
    command.add_argument("--protocol-hash", required=True)
    command.add_argument("--campaign-id", required=True)
    command.add_argument("--output", required=True)
    command.add_argument("--evidence-dir")
    command.set_defaults(handler=_plan)


def _audit(args):
    result = verify(args.run_dir, expected_seal_hash=args.expected_seal_hash)
    return result, 0 if result["ok"] else 2


def _preflight(args):
    result = preflight(strict_loads(Path(args.config).read_bytes()))
    return result, 0 if result["ok"] else 2


def _plan(args):
    source = strict_loads(Path(args.tasks).read_bytes())
    tasks = source["tasks"] if isinstance(source, dict) else source
    plan = plan_panel(tasks, n=args.n, master_seeds=args.master_seeds,
                      protocol_hash=args.protocol_hash, campaign_id=args.campaign_id)
    output = persist_plan(args.output, plan)
    return {"ok": True, "plan_only": True, "output": output, "plan_hash": plan["plan_hash"],
            "paired_draw_count": plan["paired_draw_count"],
            "planned_episode_count": plan["planned_episode_count"],
            "original_task_count": plan["original_task_count"],
            "behavioral_runs_completed": 0, "formal_launch_authorized": False}, 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m agentmembrane.host_v2.rq1_collab_v1")
    subparsers = parser.add_subparsers(dest="command", required=True)
    register_commands(subparsers)
    # Root's native integration owns its own parser/handler; optional presence
    # must not turn a missing transitive dependency into a silent fallback.
    module_name = f"{__package__}.integration"
    try:
        integration = importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        if exc.name != module_name:
            raise
    else:
        hook = getattr(integration, "register_cli", None)
        if hook is not None:
            hook(subparsers)
    args = parser.parse_args(argv)
    try:
        result, code = args.handler(args)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result, code = {"ok": False, "error": f"{type(exc).__name__}:{exc}"}, 2
    evidence_dir = getattr(args, "evidence_dir", None)
    if evidence_dir:
        try:
            collector = EventCollector(evidence_dir, f"cli-{args.command}")
            collector.emit("cli_result", {"command": args.command, "result": result, "exit_code": code},
                           evidence_quality="executed_offline_command")
            seal = collector.seal({"kind": "offline_cli_evidence", "behavioral_samples": 0})
            result = {**result, "evidence_dir": str(collector.run_dir), "evidence_seal_hash": seal["seal_hash"]}
        except (OSError, ValueError, RuntimeError) as exc:
            result, code = {**result, "evidence_error": f"{type(exc).__name__}:{exc}", "ok": False}, 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, allow_nan=False))
    return code
