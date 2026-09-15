"""Reversible presentation perturbations, never permission/value changes."""
from __future__ import annotations

import copy
import json
import math

from .semantic_fields import digest, strict_json

DISPLAY_PATHS={"/display_id","/condition_label","/metadata/display_id","/metadata/condition_label"}


def _reverse(value):
    if type(value) is dict:
        return {k:_reverse(v) for k,v in reversed(list(value.items()))}
    if type(value) is list:
        return [_reverse(v) for v in value]
    return value


def _get_parent(value,path):
    tokens=path[1:].split("/"); parent=value
    for key in tokens[:-1]:
        parent=parent[key]
    return parent,tokens[-1]


def make_presentations(evidence,*,nonsemantic_id_paths=()):
    """Four information-equivalent views; only explicit display metadata renames."""
    if type(evidence) is not dict:
        raise ValueError("evidence_object_required")
    # Strict roundtrip rejects unserializable and nonfinite content, rather than
    # dropping it when building an attractive table.
    original=strict_json(json.dumps(evidence,ensure_ascii=False,allow_nan=False))
    if any(p not in DISPLAY_PATHS for p in nonsemantic_id_paths):
        raise ValueError("cannot_rename_semantic_identity_or_permission")
    renamed=copy.deepcopy(original); undo={}
    for index,path in enumerate(nonsemantic_id_paths):
        parent,key=_get_parent(renamed,path)
        if type(parent[key]) is not str:
            raise ValueError("display_label_must_be_string")
        undo[path]=parent[key]; parent[key]=f"display-{index:04d}"
    table="\n".join(json.dumps(k,ensure_ascii=False)+"\t"+json.dumps(v,ensure_ascii=False,allow_nan=False) for k,v in original.items())
    common={"canonical_sha256":digest(original),"observed_facts_changed":False}
    return [
        {**common,"id":"canonical_json","encoding":"json","payload":json.dumps(original,sort_keys=True,ensure_ascii=False)},
        {**common,"id":"reordered_json","encoding":"json","payload":json.dumps(_reverse(original),ensure_ascii=False)},
        {**common,"id":"reversible_table","encoding":"json_key_tab_json_value","payload":table},
        {**common,"id":"display_ids","encoding":"json","payload":json.dumps(renamed,ensure_ascii=False),"undo":undo}]


def restore_presentation(presentation):
    if presentation["encoding"]=="json":
        value=strict_json(presentation["payload"])
    elif presentation["encoding"]=="json_key_tab_json_value":
        value={}
        for line in presentation["payload"].split("\n") if presentation["payload"] else []:
            key,raw=line.split("\t",1); key=strict_json(key)
            if key in value:
                raise ValueError("duplicate_table_key")
            value[key]=strict_json(raw)
    else:
        raise ValueError("unknown_presentation_encoding")
    for path,old in presentation.get("undo",{}).items():
        if path not in DISPLAY_PATHS:
            raise ValueError("invalid_inverse_identity_mapping")
        parent,key=_get_parent(value,path); parent[key]=old
    if digest(value)!=presentation["canonical_sha256"]:
        raise ValueError("presentation_not_information_equivalent")
    return value


def _bounds(row):
    lo,hi=row.get("lower"),row.get("upper")
    if type(lo) not in (int,float) or type(hi) not in (int,float) or not math.isfinite(lo) or not math.isfinite(hi) or lo>hi:
        raise ValueError("explicit_finite_score_bounds_required")
    return lo,hi


def compare_presentations(scorecards,*,deterministic=False):
    """Same-evidence format differences, separate from authority contrasts.

Input mapping format_id -> {dimensions:{name:{lower,upper}},overall:{...},
accepted:bool|None,primary_conclusion:str|None,canonical_sha256:str}.
"""
    if type(scorecards) is not dict or len(scorecards)<2:
        raise ValueError("at_least_two_presentation_results_required")
    rows=list(scorecards.values()); first=rows[0]
    if not first.get("canonical_sha256") or any(r.get("canonical_sha256")!=first["canonical_sha256"] for r in rows):
        raise ValueError("format_comparison_requires_same_evidence")
    dimensions=set(first["dimensions"])
    if any(set(r["dimensions"])!=dimensions for r in rows):
        raise ValueError("missing_dimensions_must_have_explicit_bounds")
    result={}
    for name in sorted(dimensions|{"overall"}):
        bounds=[_bounds(r["overall"] if name=="overall" else r["dimensions"][name]) for r in rows]
        lo=max(0,max(b[0] for b in bounds)-min(b[1] for b in bounds))
        hi=max(b[1] for b in bounds)-min(b[0] for b in bounds)
        result[name]={"lower":lo,"upper":hi,"point":lo if lo==hi else None,
                      "identical_bounds":all(b==bounds[0] for b in bounds)}
    accepted=[r.get("accepted") for r in rows]
    conclusions=[r.get("primary_conclusion") for r in rows]
    flips=sum(v is not None and accepted[0] is not None and v!=accepted[0] for v in accepted[1:])
    compared=sum(v is not None and accepted[0] is not None for v in accepted[1:])
    known_conclusions={v for v in conclusions if v is not None}
    deterministic_failure=deterministic and any(not r["identical_bounds"] for r in result.values())
    return {"schema_version":"rq1-format-check/1","format_difference":result,
        "acceptance_flip_count":flips,"acceptance_flip_rate":flips/compared if compared else None,
        "primary_conclusion_flipped":len(known_conclusions)>1,
        "deterministic_invariance_passed":not deterministic_failure if deterministic else None,
        "stop_domain_certification":deterministic_failure or len(known_conclusions)>1,
        "authority_difference_subtracted":False,"additional_judge_calls":0,
        "statistical_confidence_interval":False}


def threshold_sensitivity(judgement):
    if judgement.get("planned_votes")!=6 or len(judgement.get("votes",[]))!=6:
        raise ValueError("reuse_exact_six_slot_journal_required")
    fields=judgement["fields"]
    return {"planned_votes":6,"additional_calls":0,"main_threshold":5,
        "thresholds":{str(t):{"accepted_fields":sum(f["agreement_count"]>=t for f in fields),
            "candidate_fields":len(fields)} for t in (4,5,6)}}
