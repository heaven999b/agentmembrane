"""Keep experimental cells fixed; separately bind the changed system profile."""
import itertools

from ..rq1_collab_v3.contract import (LEVELS, TOPOLOGIES, PRINCIPALS, actor_ids,
    clone, digest, validate_config, make_config, model_readiness)

PROTOCOL = "rq1-three-actor/4"
NATIVE_PROFILE = "three_actor_native_observed_v1"
MEMORY_PROFILE = "three_actor_task_memory_v1"
PROFILES = (NATIVE_PROFILE, MEMORY_PROFILE)
REGIMES = ("honest", "malicious")


def _ordered_subset(values, allowed, name):
    if not isinstance(values, (list, tuple)) or not values:
        raise ValueError(f"nonempty_{name}_selection_required")
    if len(values) != len(set(values)) or any(value not in allowed for value in values):
        raise ValueError(f"invalid_or_duplicate_{name}_selection")
    return tuple(value for value in allowed if value in values)


def matrix(bundle_hash, task_name, *, repeats=3, mode="engineering", models=None,
           budget=None, topologies=TOPOLOGIES, levels=tuple(LEVELS), regimes=REGIMES):
    """Build either the full matrix or a predeclared paired diagnostic slice."""
    if type(repeats) is not int or not 1 <= repeats <= 3:
        raise ValueError("bounded_one_to_three_repeats_required")
    topologies = _ordered_subset(topologies, TOPOLOGIES, "topology")
    levels = _ordered_subset(levels, tuple(LEVELS), "level")
    regimes = _ordered_subset(regimes, REGIMES, "regime")
    return [make_config(bundle_hash, task_name, topology, level, regime, repeat,
                        mode=mode, models=models, budget=budget)
            for topology, level, regime, repeat in itertools.product(
                topologies, levels, regimes, range(repeats))]


def system_spec(profile=MEMORY_PROFILE):
    if profile not in PROFILES:
        raise ValueError("unregistered_system_profile")
    value = {"protocol_version": PROTOCOL, "system_profile": profile,
             "cell_contract_version": "rq1-three-actor/3",
             "measurement_version": "rq1-measurement/1",
             "memory_enabled": profile == MEMORY_PROFILE,
             "source_task_unchanged": True, "direct_external_worker_route": False}
    if profile == MEMORY_PROFILE:
        from .task_memory import PROFILE
        value["memory_profile"] = clone(PROFILE)
    return value
