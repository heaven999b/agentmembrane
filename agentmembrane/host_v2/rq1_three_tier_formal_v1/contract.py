"""Closed condition matrix for a future three-tier formal sub-study.

The operational high tier in the existing runtime is named ``A4``.  The
canonical proposal explicitly maps that legacy ambient tier to canonical A5;
canonical A4 instead means constrained delegation.  This module records both
identities and refuses the misleading A0/A3/A4 canonical interpretation.
"""
from __future__ import annotations

import itertools
import re

from ..rq1_collab_v3.contract import clone, digest, validate_profiles
from ..rq1_collab_v6.contract import FIXED_BUDGET, PHASE_SCHEDULE


FORMAL_PROTOCOL = "rq1-agentdojo-three-tier-formal/1"
FORMAL_MANIFEST_SCHEMA = "rq1-agentdojo-three-tier-formal-manifest/1"
TASK_COUNT = 46
CELL_COUNT = 276
TOPOLOGY = "H_E"
REGIMES = ("honest", "malicious")
REPEATS_PER_CELL = 1

MODEL_PROFILES = {
    "H": {
        "model": "gpt-5.6-luna",
        "reasoning_effort": "low",
        "max_completion_tokens": 2048,
    },
    "E": {
        "model": "gpt-5.6-luna",
        "reasoning_effort": "low",
        "max_completion_tokens": 2048,
    },
}

LEVEL_BINDINGS = {
    "low": {
        "runtime_level": "A0",
        "implementation_profile": "A0",
        "canonical_ladder_level_claimed": None,
        "legacy_canonical_analog": "A0",
        "meaning": "external_no_business_tools",
    },
    "medium": {
        "runtime_level": "A3",
        "implementation_profile": "A3",
        "canonical_ladder_level_claimed": None,
        "legacy_canonical_analog": "A3",
        "meaning": "external_task_purpose_guarded",
    },
    "high": {
        "runtime_level": "A4",
        "implementation_profile": "A4_ambient_experimental_high",
        "canonical_ladder_level_claimed": None,
        "legacy_canonical_analog": "A5",
        "meaning": "external_suite_ambient",
    },
}

DESIGN = {
    "design_id": "agentdojo_external_business_tool_authority_three_tier",
    "design_version": "0.2.0",
    "construct_id": "external_agent_business_tool_authority_gradient",
    "construct_version": "1.0.0",
    "legacy_canonical_ladder_reference": "authority_admission_a0_a5/1.0.0",
    "proposal_alignment": "RQ1_public_benchmark_external_validity_three_tier_substudy",
    "claim_scope": "fixed_46_task_external_business_tool_authority_substudy",
    "implementation_labels_are_not_canonical_ladder_claims": True,
    "canonical_full_ladder_answerable": False,
    "global_A_star_identifiable": False,
    "host_authority_runtime_level": "A4",
    "host_authority_canonical_level": "A5",
    "host_authority_held_fixed": True,
    "host_mediated_endpoint_reported_separately": True,
    "goal_cluster_required": True,
    "cross_goal_population_generalization_permitted": False,
    "pooling_with_canonical_full_ladder": False,
    "pooling_with_v6_or_prior_campaigns": False,
}


def _task_slug(task_key: str) -> str:
    if type(task_key) is not str or re.fullmatch(
            r"(banking|slack|travel|workspace)/user_task_(0|[1-9][0-9]*)",
            task_key) is None:
        raise ValueError("valid_agentdojo_task_key_required")
    return task_key.replace("/", "-")


def make_cells(task_bindings: list[dict], model_profiles: dict) -> list[dict]:
    """Build exactly six pre-outcome cells for each of 46 distinct tasks."""
    profiles = validate_profiles(model_profiles, ("H", "E"))
    if profiles != MODEL_PROFILES:
        raise ValueError("exact_registered_H_E_model_profiles_required")
    if type(task_bindings) is not list or len(task_bindings) != TASK_COUNT:
        raise ValueError("exact_46_formal_task_bindings_required")
    task_keys = [row.get("task_key") for row in task_bindings]
    if len(set(task_keys)) != TASK_COUNT:
        raise ValueError("unique_formal_task_keys_required")
    cells = []
    for task, level, regime in itertools.product(
            task_bindings, LEVEL_BINDINGS, REGIMES):
        task_key = task.get("task_key")
        _task_slug(task_key)
        task_hash = task.get("formal_task_binding_sha256")
        goal_cluster = task.get("goal_cluster_id")
        if type(task_hash) is not str or re.fullmatch(r"[0-9a-f]{64}", task_hash) is None:
            raise ValueError("formal_task_binding_hash_required")
        if (type(goal_cluster) is not str
                or re.fullmatch(r"(banking|slack|travel|workspace)/injection_task_[0-9]+/[0-9a-f]{64}",
                                goal_cluster) is None):
            raise ValueError("formal_goal_cluster_binding_required")
        cells.append({
            "protocol_version": FORMAL_PROTOCOL,
            "episode_id": f"{_task_slug(task_key)}-H_E-{level}-{regime}-r0",
            "task_key": task_key,
            "formal_task_binding_sha256": task_hash,
            "goal_cluster_id": goal_cluster,
            "topology": TOPOLOGY,
            "level": level,
            "runtime_external_level": LEVEL_BINDINGS[level]["runtime_level"],
            "legacy_canonical_analog": LEVEL_BINDINGS[level][
                "legacy_canonical_analog"],
            "canonical_ladder_level_claimed": None,
            "regime": regime,
            "repeat": 0,
            "models": clone(profiles),
            "budget": clone(FIXED_BUDGET),
            "phase_schedule": clone(PHASE_SCHEDULE),
            "execution_mode": "formal_live",
            "automatic_retry": False,
            "replacement_cell_permitted": False,
        })
    return validate_cells(cells, task_bindings, profiles)


def validate_cells(cells: list[dict], task_bindings: list[dict],
                   model_profiles: dict) -> list[dict]:
    """Validate the complete paired matrix without accepting a partial slice."""
    profiles = validate_profiles(model_profiles, ("H", "E"))
    if profiles != MODEL_PROFILES:
        raise ValueError("exact_registered_H_E_model_profiles_required")
    if type(cells) is not list or len(cells) != CELL_COUNT:
        raise ValueError("exact_276_formal_cells_required")
    task_bindings_by_key = {
        row.get("task_key"): {
            "formal_task_binding_sha256": row.get("formal_task_binding_sha256"),
            "goal_cluster_id": row.get("goal_cluster_id"),
        }
        for row in task_bindings
    }
    if len(task_bindings_by_key) != TASK_COUNT:
        raise ValueError("exact_46_unique_formal_tasks_required")
    expected_keys = {
        (task_key, level, regime, 0)
        for task_key, level, regime in itertools.product(
            task_bindings_by_key, LEVEL_BINDINGS, REGIMES)
    }
    observed_keys, episode_ids = set(), set()
    required = {
        "protocol_version", "episode_id", "task_key",
        "formal_task_binding_sha256", "goal_cluster_id", "topology", "level",
        "runtime_external_level", "legacy_canonical_analog",
        "canonical_ladder_level_claimed", "regime",
        "repeat", "models", "budget", "phase_schedule", "execution_mode",
        "automatic_retry", "replacement_cell_permitted",
    }
    for cell in cells:
        if type(cell) is not dict or set(cell) != required:
            raise ValueError("exact_formal_cell_shape_required")
        key = (cell["task_key"], cell["level"], cell["regime"], cell["repeat"])
        binding = LEVEL_BINDINGS.get(cell["level"])
        if (cell["protocol_version"] != FORMAL_PROTOCOL
                or cell["topology"] != TOPOLOGY
                or binding is None
                or cell["runtime_external_level"] != binding["runtime_level"]
                or cell["legacy_canonical_analog"]
                != binding["legacy_canonical_analog"]
                or cell["canonical_ladder_level_claimed"] is not None
                or cell["regime"] not in REGIMES
                or cell["repeat"] != 0
                or cell["models"] != profiles
                or cell["budget"] != FIXED_BUDGET
                or cell["phase_schedule"] != PHASE_SCHEDULE
                or cell["execution_mode"] != "formal_live"
                or cell["automatic_retry"] is not False
                or cell["replacement_cell_permitted"] is not False
                or cell["formal_task_binding_sha256"]
                != task_bindings_by_key.get(cell["task_key"], {}).get(
                    "formal_task_binding_sha256")
                or cell["goal_cluster_id"]
                != task_bindings_by_key.get(cell["task_key"], {}).get(
                    "goal_cluster_id")
                or cell["episode_id"]
                != f"{_task_slug(cell['task_key'])}-H_E-{cell['level']}-{cell['regime']}-r0"):
            raise ValueError("formal_cell_contract_mismatch")
        if key in observed_keys or cell["episode_id"] in episode_ids:
            raise ValueError("duplicate_formal_cell")
        observed_keys.add(key)
        episode_ids.add(cell["episode_id"])
    if observed_keys != expected_keys:
        raise ValueError("incomplete_formal_paired_matrix")
    return clone(cells)


def design_sha256() -> str:
    return digest({"design": DESIGN, "levels": LEVEL_BINDINGS})
