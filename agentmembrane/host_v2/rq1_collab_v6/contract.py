"""Closed v6 cell contract for task-scoped permission-gradient diagnostics.

The cell object intentionally keeps the exact v3 field shape.  Scheduling is a
separate, content-addressed system contract so an older cell can never acquire
new phase semantics merely by being read by newer code.
"""
from __future__ import annotations

import itertools
import re

from ..rq1_collab_v3.contract import (
    DEFAULT_MODELS,
    LEVELS,
    PRINCIPALS,
    TOPOLOGIES,
    actor_ids,
    clone,
    digest,
    validate_profiles,
)
from ..rq1_collab_v4.contract import MEMORY_PROFILE, NATIVE_PROFILE
from .permissions import (VERSION as PERMISSION_VERSION,
                          NATIVE_PURPOSE_GUARDED_PROFILE)

# The guarded profile is an explicitly separate operational policy, never an
# implicit rewrite of the ambient experimental A4 arm. Both disable memory.
PROFILES = (NATIVE_PROFILE, NATIVE_PURPOSE_GUARDED_PROFILE)


PROTOCOL = "rq1-three-actor/6"
DECISION_REPLAY_SCHEMA = "rq1-decision-replay/1"
REGIMES = ("honest", "malicious")

# Keep these keys identical to the v3 budget schema.  The values are the only
# budget admitted by v6: eight shared internal work decisions plus one H-only
# finalization decision, preceded by a six-decision E phase (including final).
DEFAULT_BUDGET = {
    "internal_decisions": 9,
    "external_decisions": 6,
    "internal_tokens": 120000,
    "external_tokens": 48000,
    "max_delegations": 1,
    "wall_seconds": 420,
}
FIXED_BUDGET = DEFAULT_BUDGET

# This exact object is embedded in system_spec and bound by its own digest in
# addition to the enclosing system-spec digest used by the workflow.
PHASE_SCHEDULE = {
    "schema_version": "rq1-phase-schedule/1",
    "external_max_decisions": 6,
    "internal_work_max_decisions": 8,
    "host_finalization_decisions": 1,
    "external_phase_seconds": 180,
    "host_finalization_reserve_seconds": 60,
    "closure_reserve_seconds": 30,
    "model_request_hard_timeout_seconds": 50,
    "transport_termination_grace_seconds": 1,
    "target_step_backend_dispatch_cap": 1,
    "external_phase_permanently_closes": True,
}
PHASE_SCHEDULE_SHA256 = digest(PHASE_SCHEDULE)


def validate_phase_schedule():
    """Fail closed if code mutation breaks the frozen schedule/budget relation."""
    if (digest(PHASE_SCHEDULE) != PHASE_SCHEDULE_SHA256
            or PHASE_SCHEDULE["external_max_decisions"] != DEFAULT_BUDGET["external_decisions"]
            or PHASE_SCHEDULE["internal_work_max_decisions"]
               + PHASE_SCHEDULE["host_finalization_decisions"]
               != DEFAULT_BUDGET["internal_decisions"]
            or PHASE_SCHEDULE["external_phase_seconds"]
               + PHASE_SCHEDULE["host_finalization_reserve_seconds"]
               + PHASE_SCHEDULE["closure_reserve_seconds"]
               > DEFAULT_BUDGET["wall_seconds"]
            or PHASE_SCHEDULE["model_request_hard_timeout_seconds"]
               + PHASE_SCHEDULE["transport_termination_grace_seconds"]
               > PHASE_SCHEDULE["host_finalization_reserve_seconds"]):
        raise ValueError("phase_schedule_definition_changed")
    return clone(PHASE_SCHEDULE)


def _ordered_subset(values, allowed, name):
    if not isinstance(values, (list, tuple)) or not values:
        raise ValueError(f"nonempty_{name}_selection_required")
    if len(values) != len(set(values)) or any(value not in allowed for value in values):
        raise ValueError(f"invalid_or_duplicate_{name}_selection")
    return tuple(value for value in allowed if value in values)


def validate_config(config):
    """Validate the unchanged v3-shaped cell and the exact bounded v6 budget."""
    validate_phase_schedule()
    cfg = clone(config)
    required = {
        "protocol_version", "episode_id", "topology", "level", "regime",
        "repeat", "models", "budget", "internal_level", "execution_mode",
        "bundle_sha256",
    }
    if type(cfg) is not dict or set(cfg) != required or cfg["protocol_version"] != PROTOCOL:
        raise ValueError("exact_v6_config_required")
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
    if type(cfg["budget"]) is not dict or cfg["budget"] != DEFAULT_BUDGET:
        raise ValueError("exact_v6_bounded_budget_required")
    return cfg


def make_config(bundle_hash, task_name, topology, level, regime, repeat=0, *,
                mode="engineering", models=None, budget=None):
    profiles = DEFAULT_MODELS if models is None else models
    cfg = {
        "protocol_version": PROTOCOL,
        "episode_id": f"{task_name}-{topology}-{level}-{regime}-r{repeat}",
        "topology": topology,
        "level": level,
        "regime": regime,
        "repeat": repeat,
        "models": {actor: profiles[actor] for actor in actor_ids(topology)},
        "budget": DEFAULT_BUDGET if budget is None else budget,
        "internal_level": "A3",
        "execution_mode": mode,
        "bundle_sha256": bundle_hash,
    }
    return validate_config(cfg)


def matrix(bundle_hash, task_name, *, repeats=3, mode="engineering", models=None,
           budget=None, topologies=TOPOLOGIES, levels=tuple(LEVELS),
           regimes=REGIMES):
    """Build a full matrix or an explicitly declared paired diagnostic slice."""
    if type(repeats) is not int or not 1 <= repeats <= 3:
        raise ValueError("bounded_one_to_three_repeats_required")
    topologies = _ordered_subset(topologies, TOPOLOGIES, "topology")
    levels = _ordered_subset(levels, tuple(LEVELS), "level")
    regimes = _ordered_subset(regimes, REGIMES, "regime")
    return [
        make_config(bundle_hash, task_name, topology, level, regime, repeat,
                    mode=mode, models=models, budget=budget)
        for topology, level, regime, repeat in itertools.product(
            topologies, levels, regimes, range(repeats)
        )
    ]


def system_spec(profile=NATIVE_PROFILE):
    if profile not in PROFILES:
        raise ValueError("unregistered_system_profile")
    phase_schedule = validate_phase_schedule()
    value = {
        "protocol_version": PROTOCOL,
        "system_profile": profile,
        "cell_contract_version": PROTOCOL,
        "measurement_version": "rq1-measurement/1",
        "permission_contract_version": PERMISSION_VERSION,
        "native_enforcement": ("task_purpose_guarded_high"
                               if profile == NATIVE_PURPOSE_GUARDED_PROFILE
                               else "ambient_experimental_high"),
        "memory_enabled": profile == MEMORY_PROFILE,
        "source_task_unchanged": True,
        "direct_external_worker_route": False,
        "phase_schedule": phase_schedule,
        "phase_schedule_sha256": PHASE_SCHEDULE_SHA256,
    }
    if profile == MEMORY_PROFILE:
        from ..rq1_collab_v4.task_memory import PROFILE
        value["memory_profile"] = clone(PROFILE)
    return value


def model_readiness(config, inventory):
    cfg = validate_config(config)
    if type(inventory) is not dict or type(inventory.get("model_ids")) is not list:
        raise ValueError("model_inventory_required")
    required = sorted({profile["model"] for profile in cfg["models"].values()})
    missing = sorted(set(required) - set(inventory["model_ids"]))
    return {
        "listed": not missing,
        "missing_models": missing,
        "required_models": required,
        "generation_verified": False,
        "automatic_substitution": False,
    }
