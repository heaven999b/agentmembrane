"""Descriptive allocation-first summaries; identification bounds are not CIs.

Allocations contain ``config`` and pre-run ``system_profile``,
``system_spec_sha256``, ``source_version``, ``task_binding``, and
``independent_world_id``. Unbound allocations remain separate unknown rows.
Reports are an episode-ID mapping, either measurement results or v4 reports.
No inference about formal sample adequacy or statistical significance is made.
"""
from __future__ import annotations

from collections import defaultdict
from itertools import combinations
import json
import math

from ..rq1_scorecard_v5.core import DEFAULT_WEIGHTS

DIMENSIONS = ("Q", "I", "D", "M", "K", "C", "T")
AXES = ("topology", "level", "regime")
META = ("system_profile", "system_spec_sha256", "source_version")


def _key(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _unknown():
    return {"lower": 0.0, "upper": 100.0, "point": None}


def _interval(value):
    if not isinstance(value, dict):
        raise ValueError("missing_score_interval")
    lo, hi, point = value.get("lower"), value.get("upper"), value.get("point")
    valid = lambda n: type(n) in (int, float) and math.isfinite(n)
    if not valid(lo) or not valid(hi) or not 0 <= lo <= hi <= 100:
        raise ValueError("invalid_score_bounds")
    if point is not None and (not valid(point) or not lo == point == hi):
        raise ValueError("point_requires_exact_bounds")
    return {"lower": float(lo), "upper": float(hi), "point": point}


def _mean(rows):
    return {d: {"lower": sum(r[d]["lower"] for r in rows) / len(rows),
                "upper": sum(r[d]["upper"] for r in rows) / len(rows),
                "point": sum(r[d]["point"] for r in rows) / len(rows)
                if all(r[d]["point"] is not None for r in rows) else None}
            for d in DIMENSIONS}


def _context(allocation):
    cfg = allocation["config"]
    context = {k: allocation.get(k) for k in META}
    context.update({k: cfg.get(k) for k in AXES})
    context["execution_mode"] = cfg.get("execution_mode")
    # Keep different model/budget protocols apart. For topology contrasts only,
    # the optional S model is omitted in _pair_conditions, not in summaries.
    context["other_conditions"] = {k: v for k, v in cfg.items()
        if k not in (*AXES, "episode_id", "repeat", "bundle_sha256", "execution_mode")}
    return context


def _pair_conditions(row, axis):
    context = json.loads(_key(row["context"]))
    context.pop(axis)
    if axis == "topology":
        context["other_conditions"].get("models", {}).pop("S", None)
    return _key([context, row["task_binding"], row["repeat"], row["world"]])


def aggregate(allocations, reports):
    """Retain every allocation and report conservative paired mean bounds.

    Invalid/missing scores become [0,100]; conflicting episode identity fails
    closed. Metadata absent before execution is not reconstructed from success.
    Means weight assigned episodes equally, not nominal tasks or worlds.
    """
    if not isinstance(reports, dict):
        raise ValueError("reports_must_be_episode_mapping")
    rows, seen, contracts, sources, methods = [], set(), {}, {}, {}
    for a in allocations:
        cfg = a.get("config", {})
        eid = cfg.get("episode_id")
        if type(eid) is not str or not eid or eid in seen:
            raise ValueError("unique_allocated_episode_required")
        seen.add(eid)
        context = _context(a)
        binding = a.get("task_binding")
        bound = (all(a.get(k) for k in META) and isinstance(binding, dict)
                 and all(binding.get(k) for k in ("source", "suite", "task_id", "initial_state_sha256"))
                 and type(a.get("independent_world_id")) is str
                 and all(cfg.get(k) for k in (*AXES, "execution_mode"))
                 and type(cfg.get("repeat")) is int)
        reasons = [] if bound else ["allocation_metadata_unbound"]
        if bound:
            expected_world = ":".join(binding[k] for k in ("source", "suite", "initial_state_sha256"))
            if a["independent_world_id"] != expected_world:
                raise ValueError("allocation_world_not_source_bound")
            source_key = _key([a["source_version"], *(binding[k] for k in ("source", "suite", "task_id"))])
            if source_key in sources and sources[source_key] != binding:
                raise ValueError("same_source_version_has_conflicting_task")
            sources[source_key] = binding
        if not bound:
            context["unbound_episode_id"] = eid
        values = {d: _unknown() for d in DIMENSIONS}
        outer = reports.get(eid)
        m = outer.get("measurement") if isinstance(outer, dict) and "measurement" in outer else outer
        if isinstance(outer, dict) and outer.get("episode_id", eid) != eid:
            raise ValueError("outer_report_episode_mismatch")
        present = isinstance(m, dict)
        if not present:
            reasons.append("missing_measurement")
        elif bound:
            if m.get("episode_id") != eid or m.get("config") != cfg:
                raise ValueError("report_allocation_identity_mismatch")
            if any(m.get(k) != a[k] for k in ("system_profile", "system_spec_sha256")):
                raise ValueError("report_profile_mismatch")
            actual_binding = m.get("task_binding", m.get("contract", {}).get("task_binding"))
            if not isinstance(actual_binding, dict) or any(actual_binding.get(k) != v for k, v in binding.items()):
                raise ValueError("report_source_binding_mismatch")
            if m.get("independent_world_id") != a["independent_world_id"]:
                raise ValueError("report_world_mismatch")
            if "source_version" in m and m["source_version"] != a["source_version"]:
                raise ValueError("report_source_version_mismatch")
            ck = _key([a["system_profile"], a["system_spec_sha256"], a["source_version"], binding])
            signature = [m.get("schema_version"), m.get("contract_sha256"),
                         m.get("contract", {}).get("measurement_version"), m.get("weights"),
                         m.get("alpha"), m.get("severity_map")]
            if ck in contracts and contracts[ck] != signature:
                raise ValueError("within_task_scoring_contract_changed")
            contracts[ck] = signature
            mk = _key([a[k] for k in META])
            method = [signature[i] for i in (0, 2, 3, 4, 5)]
            if mk in methods and methods[mk] != method:
                raise ValueError("mixed_scoring_methods")
            methods[mk] = method
            for d in DIMENSIONS[:-1]:
                try:
                    values[d] = _interval(m.get("dimensions", {}).get(d))
                except ValueError as exc:
                    reasons.append(d + ":" + str(exc))
            # Recompute the total from the validated components, including any
            # component downgraded to unknown. A stale cached total must never
            # remain precise after its inputs were rejected.
            if m.get("weights", DEFAULT_WEIGHTS) != DEFAULT_WEIGHTS:
                reasons.append("T:unexpected_scoring_weights")
            else:
                total = {edge: math.fsum(DEFAULT_WEIGHTS[d] * values[d][edge]
                                        for d in DEFAULT_WEIGHTS) for edge in ("lower", "upper")}
                total["point"] = total["lower"] if all(values[d]["point"] is not None for d in DEFAULT_WEIGHTS) else None
                try:
                    declared = _interval(m.get("overall"))
                    if any(not math.isclose(declared[k], total[k], abs_tol=1e-9, rel_tol=0)
                           for k in ("lower", "upper")):
                        reasons.append("T:overall_component_mismatch")
                        total["point"] = None
                    elif declared["point"] is None:
                        total["point"] = None
                except ValueError as exc:
                    reasons.append("T:" + str(exc))
                    total["point"] = None
                values["T"] = total
        rows.append({"episode_id": eid, "context": context, "scores": values,
                     "task_binding": binding, "repeat": cfg.get("repeat"), "bound": bool(bound),
                     "world": a.get("independent_world_id") if bound else None,
                     "report_present": present, "issues": reasons})
    if set(reports) - seen:
        raise ValueError("unallocated_report")
    grouped = defaultdict(list)
    for row in rows:
        grouped[_key(row["context"])].append(row)
    groups = []
    for key, members in sorted(grouped.items()):
        worlds = sorted({r["world"] for r in members if r["world"]})
        groups.append({"conditions": json.loads(key), "allocated_episodes": len(members),
                       "reports_present": sum(r["report_present"] for r in members),
                       "missing_reports": sum(not r["report_present"] for r in members),
                       "unique_task_count": len({_key(r["task_binding"]) for r in members if r["bound"]}),
                       "independent_world_count": len(worlds), "independent_world_ids": worlds,
                       "unbound_world_episode_count": sum(not r["bound"] for r in members),
                       "scores": _mean([r["scores"] for r in members]),
                       "episode_ids": [r["episode_id"] for r in members]})
    paired = []
    order = {"level": ["low", "medium", "high"], "topology": ["H_E", "H_S_E"],
             "regime": ["honest", "malicious"]}
    for axis in AXES:
        matched = defaultdict(dict)
        for row in rows:
            if row["bound"]:
                key, arm = _pair_conditions(row, axis), row["context"][axis]
                if arm in matched[key]:
                    raise ValueError("duplicate_allocated_matched_cell")
                matched[key][arm] = row
        for key, arms in sorted(matched.items()):
            labels = sorted(arms, key=lambda x: (order[axis].index(x) if x in order[axis] else 99, x))
            for left, right in combinations(labels, 2):
                a, b = arms[right], arms[left]
                differences = {d: {"lower": a["scores"][d]["lower"] - b["scores"][d]["upper"],
                    "upper": a["scores"][d]["upper"] - b["scores"][d]["lower"],
                    "point": a["scores"][d]["point"] - b["scores"][d]["point"]
                    if a["scores"][d]["point"] is not None and b["scores"][d]["point"] is not None else None}
                    for d in DIMENSIONS}
                paired.append({"axis": axis, "contrast": right + "-" + left,
                    "matching_conditions": json.loads(key), "a_episode_id": a["episode_id"],
                    "b_episode_id": b["episode_id"], "scores": differences,
                    "both_reports_present": a["report_present"] and b["report_present"]})
    return {"schema_version": "rq1-descriptive-report/1", "formal_ready": False,
            "allocated_episodes": len(rows), "groups": groups, "paired_differences": paired,
            "issues": [{"episode_id": r["episode_id"], "issues": r["issues"]} for r in rows if r["issues"]],
            "weighting": "equal_assigned_episodes_including_missing", "missing_scores_renormalized": False,
            "uncertainty": "identification_bounds_not_confidence_intervals",
            "statistical_significance_tested": False, "research_sample_count_inferred": False,
            "limitations": ["descriptive_only", "distinct_worlds_not_tasks_or_repeats_define_independent_n",
                            "no_unallocated_arm_imputation", "no_engineering_real_model_pooling"]}
