"""Executable, immutable experiment cells and strict role/model contracts."""
from __future__ import annotations

import itertools
import re

from ..rq1_collab_v1.audit import canonical, sha256, strict_loads

PROTOCOL = "rq1-three-actor/3"
LEVELS = {"low": "A0", "medium": "A3", "high": "A4"}
TOPOLOGIES = ("H_E", "H_S_E")
PRINCIPALS = {"H": "host", "S": "internal_worker", "E": "external"}
DEFAULT_MODELS = {
    # Explicit snapshots avoid alias->snapshot response mismatch and drift.
    "H": {"model": "gpt-5-2025-08-07", "reasoning_effort": "medium", "max_completion_tokens": 8192},
    "S": {"model": "gpt-4o-2024-08-06", "max_completion_tokens": 8192},
    "E": {"model": "gpt-5-2025-08-07", "reasoning_effort": "high", "max_completion_tokens": 8192},
}
DEFAULT_BUDGET = {"internal_decisions": 40, "external_decisions": 16,
                  "internal_tokens": 120000, "external_tokens": 48000,
                  "max_delegations": 2, "wall_seconds": 600}


def clone(value):
    return strict_loads(canonical(value))


def digest(value):
    return sha256(canonical(value))


def actor_ids(topology):
    if topology not in TOPOLOGIES:
        raise ValueError("unknown_topology")
    return ("H", "S", "E") if topology == "H_S_E" else ("H", "E")


def validate_profiles(profiles, actors):
    profiles = clone(profiles)
    if type(profiles) is not dict or set(profiles) != set(actors):
        raise ValueError("exact_actor_model_profiles_required")
    for actor, profile in profiles.items():
        if type(profile) is not dict or not {"model", "max_completion_tokens"} <= set(profile) or set(profile) - {
                "model", "max_completion_tokens", "reasoning_effort"}:
            raise ValueError("unsupported_model_profile")
        model = profile["model"]
        if type(model) is not str or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,256}", model):
            raise ValueError("invalid_model_id")
        if type(profile["max_completion_tokens"]) is not int or not 1 <= profile["max_completion_tokens"] <= 16384:
            raise ValueError("invalid_output_budget")
        if model == "gpt-4o" or model.startswith("gpt-4o-"):
            if "reasoning_effort" in profile:
                raise ValueError("gpt4o_has_no_reasoning_effort")
        elif "reasoning_effort" in profile and profile["reasoning_effort"] not in {"minimal", "low", "medium", "high"}:
            raise ValueError("unsupported_reasoning_effort")
    return profiles


def validate_config(config):
    cfg = clone(config)
    required = {"protocol_version", "episode_id", "topology", "level", "regime", "repeat",
                "models", "budget", "internal_level", "execution_mode", "bundle_sha256"}
    if type(cfg) is not dict or set(cfg) != required or cfg["protocol_version"] != PROTOCOL:
        raise ValueError("exact_v3_config_required")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,120}", str(cfg["episode_id"])):
        raise ValueError("unsafe_episode_id")
    actors = actor_ids(cfg["topology"])
    if cfg["level"] not in LEVELS or cfg["regime"] not in {"honest", "malicious"}:
        raise ValueError("invalid_experimental_condition")
    if cfg["internal_level"] != "A3":
        raise ValueError("internal_authority_fixed_task_scoped")
    if type(cfg["repeat"]) is not int or cfg["repeat"] < 0:
        raise ValueError("invalid_repeat")
    if cfg["execution_mode"] not in {"engineering", "live_diagnostic"}:
        raise ValueError("formal_execution_not_admitted")
    if not re.fullmatch(r"[0-9a-f]{64}", str(cfg["bundle_sha256"])):
        raise ValueError("bound_task_bundle_required")
    cfg["models"] = validate_profiles(cfg["models"], actors)
    budget = cfg["budget"]
    if type(budget) is not dict or set(budget) != set(DEFAULT_BUDGET):
        raise ValueError("exact_budget_contract_required")
    for key, ceiling in DEFAULT_BUDGET.items():
        if type(budget[key]) is not int or not 1 <= budget[key] <= ceiling:
            raise ValueError("invalid_budget:" + key)
    return cfg


def make_config(bundle_hash, task_name, topology, level, regime, repeat=0, *,
                mode="engineering", models=None, budget=None):
    profiles = DEFAULT_MODELS if models is None else models
    cfg = {"protocol_version": PROTOCOL,
           "episode_id": f"{task_name}-{topology}-{level}-{regime}-r{repeat}",
           "topology": topology, "level": level, "regime": regime, "repeat": repeat,
           "models": {a: profiles[a] for a in actor_ids(topology)},
           "budget": DEFAULT_BUDGET if budget is None else budget, "internal_level": "A3",
           "execution_mode": mode, "bundle_sha256": bundle_hash}
    return validate_config(cfg)


def matrix(bundle_hash, task_name, *, repeats=3, mode="engineering", models=None):
    if type(repeats) is not int or not 1 <= repeats <= 3:
        raise ValueError("bounded_one_to_three_repeats_required")
    return [make_config(bundle_hash, task_name, t, l, r, seed, mode=mode, models=models)
            for t, l, r, seed in itertools.product(TOPOLOGIES, LEVELS, ("honest", "malicious"), range(repeats))]


def model_readiness(config, inventory):
    cfg = validate_config(config)
    if type(inventory) is not dict or type(inventory.get("model_ids")) is not list:
        raise ValueError("model_inventory_required")
    required = sorted({p["model"] for p in cfg["models"].values()})
    missing = sorted(set(required) - set(inventory["model_ids"]))
    return {"listed": not missing, "missing_models": missing, "required_models": required,
            "generation_verified": False, "automatic_substitution": False}
