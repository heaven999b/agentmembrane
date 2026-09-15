"""Source-level, full-record calibration. No model calls or self-created gold.

The lock must precede predictions. Repeated votes, fields and records from one
world cannot enlarge the exact-binomial sample. Engineering fixtures never
certify an empirical claim, even when their arithmetic passes.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re


def _digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def cp_upper(k, n, alpha=.05):
    """One-sided Clopper-Pearson upper limit; undefined when n is zero."""
    if type(k) is not int or type(n) is not int or not 0 <= k <= n:
        raise ValueError("invalid_binomial_counts")
    if type(alpha) not in (int, float) or not math.isfinite(alpha) or not 0 < alpha < 1:
        raise ValueError("invalid_alpha")
    if n == 0:
        return None
    if k == n:
        return 1.0
    if k == 0:
        return -math.expm1(math.log(alpha) / n)
    coefficients = [math.lgamma(n + 1)-math.lgamma(i + 1)-math.lgamma(n-i + 1) for i in range(k+1)]
    def cdf(p):
        if p <= 0:
            return 1.0
        if p >= 1:
            return 0.0
        vals = [c + i*math.log(p)+(n-i)*math.log1p(-p) for i,c in enumerate(coefficients)]
        peak=max(vals)
        return math.exp(peak)*math.fsum(math.exp(v-peak) for v in vals)
    lo,hi=0.0,1.0
    for _ in range(90):
        mid=(lo+hi)/2
        if cdf(mid)>alpha:
            lo=mid
        else:
            hi=mid
    return hi


def _text(value):
    if type(value) is not str or not value.strip():
        raise ValueError("nonempty_identifier_required")
    return value


def lock_manifest(records, certification_family, *, selection_seed,
                  independent_sources=False, representative_sources=False,
                  provenance=None, dataset_role="engineering"):
    """Enumerated independent gold only; this function never sees predictions.

records: [{record_id, domain_id, source_cluster, full_record_hash,
           status:'supported', items:[{field_id, gold:bool}], ...}].
family: [{domain_id, endpoint:'FPR'|'FNR'}]. Provenance is documented evidence,
not independently authenticated by this arithmetic routine.
"""
    from .semantic_fields import domain_spec
    _text(selection_seed)
    if dataset_role not in {"engineering", "heldout"}:
        raise ValueError("explicit_dataset_role_required")
    if type(independent_sources) is not bool or type(representative_sources) is not bool:
        raise ValueError("explicit_source_assumptions_required")
    if type(provenance) is not dict or not provenance:
        raise ValueError("independent_gold_provenance_required")
    if dataset_role=="heldout":
        for key in ("source_manifest_sha256","gold_rule_sha256","sampling_protocol_sha256"):
            if type(provenance.get(key)) is not str or not re.fullmatch(r"[0-9a-f]{64}",provenance[key]):
                raise ValueError("heldout_provenance_hashes_required")
        if type(provenance.get("development_source_clusters")) is not list or type(provenance.get("heldout_source_clusters")) is not list:
            raise ValueError("source_partition_required")
        if set(provenance["development_source_clusters"]) & set(provenance["heldout_source_clusters"]):
            raise ValueError("source_partition_leakage")
    family=[]
    for entry in certification_family:
        if type(entry) is not dict or set(entry)!={"domain_id","endpoint"} or entry["endpoint"] not in {"FPR","FNR"}:
            raise ValueError("invalid_certification_family")
        domain_spec(entry["domain_id"])
        if entry in family:
            raise ValueError("duplicate_certification_endpoint")
        family.append(copy.deepcopy(entry))
    rows=[]; seen=set(); buckets={}
    if type(records) is not list:
        raise ValueError("gold_records_must_be_list")
    for record in records:
        if type(record) is not dict:
            raise ValueError("invalid_gold_record")
        rid=_text(record.get("record_id"))
        if rid in seen:
            raise ValueError("duplicate_gold_record")
        seen.add(rid)
        domain=_text(record.get("domain_id")); domain_spec(domain)
        cluster=_text(record.get("source_cluster")); _text(record.get("full_record_hash"))
        if dataset_role=="heldout" and (cluster not in provenance["heldout_source_clusters"] or record.get("independent_of_judge") is not True or record.get("uses_production_task_scorer") is not False or not re.fullmatch(r"[0-9a-f]{64}",record["full_record_hash"])):
            raise ValueError("heldout_independent_gold_record_required")
        if record.get("status")!="supported" or type(record.get("items")) is not list:
            raise ValueError("supported_independent_gold_required")
        item_ids=set()
        for item in record["items"]:
            if type(item) is not dict or type(item.get("gold")) is not bool or not _text(item.get("field_id")) or item["field_id"] in item_ids:
                raise ValueError("invalid_or_duplicate_gold_item")
            item_ids.add(item["field_id"])
        row=copy.deepcopy(record); rows.append(row)
        for gold_class in {i["gold"] for i in row["items"]}:
            key=(domain,cluster,gold_class)
            rank=_digest({"seed":selection_seed,"record":rid,"hash":record["full_record_hash"],"domain":domain,"class":gold_class})
            candidate=(rank,rid)
            if key not in buckets or candidate<buckets[key]:
                buckets[key]=candidate
    selected=[{"domain_id":d,"source_cluster":s,"gold_class":c,"record_id":rank[1]}
              for (d,s,c),rank in sorted(buckets.items())]
    value={"schema_version":"rq1-calibration-lock/1","records":rows,
        "certification_family":family,"selection_seed":selection_seed,"selected":selected,
        "independent_sources":independent_sources,"representative_sources":representative_sources,
        "dataset_role":dataset_role,"provenance":copy.deepcopy(provenance),
        "provenance_authenticated_by_this_function":False,"locked_before_predictions":True}
    value["lock_sha256"]=_digest(value)
    return value


def aggregate_record_class(items, predictions, gold_class):
    """Any known error wins; otherwise any rejection is one unknown."""
    if type(gold_class) is not bool:
        raise ValueError("boolean_gold_class_required")
    selected=[i for i in items if i["gold"] is gold_class]
    if not selected:
        return None
    values=[]
    for item in selected:
        value=predictions.get(item["field_id"])
        if value is not None and type(value) is not bool:
            raise ValueError("prediction_must_be_boolean_or_unknown")
        values.append(value)
    error=any(v is not None and v is not gold_class for v in values)
    unknown=not error and any(v is None for v in values)
    return {"error":int(error),"unknown":int(unknown),"items":len(selected)}


def certify(locked_gold_manifest, predictions):
    """Return source-equally-weighted record-class risks, never field accuracy."""
    from .semantic_fields import domain_spec
    manifest=copy.deepcopy(locked_gold_manifest)
    expected=manifest.pop("lock_sha256",None)
    if expected!=_digest(manifest) or manifest.get("schema_version")!="rq1-calibration-lock/1":
        raise ValueError("calibration_lock_changed")
    records={r["record_id"]:r for r in manifest["records"]}
    if type(predictions) is not dict or set(predictions)-set(records):
        raise ValueError("predictions_outside_locked_records")
    for rid, values in predictions.items():
        if type(values) is not dict or set(values)-{i["field_id"] for i in records[rid]["items"]}:
            raise ValueError("predictions_outside_exhaustive_gold")
        if any(v is not None and type(v) is not bool for v in values.values()):
            raise ValueError("prediction_must_be_boolean_or_unknown")
    family=manifest["certification_family"]; m=len(family); alpha=.05/m if m else None
    endpoints=[]
    for spec in family:
        domain=domain_spec(spec["domain_id"])
        category=spec["endpoint"]=="FNR"
        selected=[s for s in manifest["selected"] if s["domain_id"]==spec["domain_id"] and s["gold_class"] is category]
        rows=[aggregate_record_class(records[s["record_id"]]["items"],predictions.get(s["record_id"],{}),category) for s in selected]
        n=len(rows); errors=sum(r["error"] for r in rows); unknown=sum(r["unknown"] for r in rows)
        upper=cp_upper(errors+unknown,n,alpha)
        threshold=.10 if category else .05
        reasons=[]
        if domain["gold_constructor"] is None:
            reasons.append("uncertifiable_without_independent_labels")
        if not n:
            reasons.append("gold_class_missing")
        if not manifest["independent_sources"] or not manifest["representative_sources"]:
            reasons.append("source_independence_or_representativeness_unverified")
        if manifest["dataset_role"]!="heldout":
            reasons.append("engineering_data_not_empirical_certification")
        if upper is None or upper>threshold:
            reasons.append("worst_case_exact_upper_exceeds_threshold")
        coverage=(n-unknown)/n if n else None
        if coverage is None or coverage<.90:
            reasons.append("sample_coverage_below_threshold")
        endpoints.append({**spec,"N":n,"errors":errors,"unknown":unknown,"alpha":alpha,
            "sample_coverage":coverage,"accepted_error_rate":errors/(n-unknown) if n>unknown else None,
            "identified_risk_bounds":[errors/n,(errors+unknown)/n] if n else [None,None],
            "worst_case_exact_upper":upper,"threshold":threshold,"passed":not reasons,
            "reasons":reasons,"selected_record_ids":[s["record_id"] for s in selected]})
    # Every declared domain needs both classes; passing only negatives is not a
    # full classifier certificate, even if the user requested just one endpoint.
    domain_rows={s["domain_id"] for s in family}
    complete_family=all({s["endpoint"] for s in family if s["domain_id"]==d}=={"FPR","FNR"} for d in domain_rows)
    return {"schema_version":"rq1-calibration-report/1","lock_sha256":expected,"family_size":m,
        "alpha_per_endpoint":alpha,"endpoints":endpoints,
        "certified":bool(m) and complete_family and all(e["passed"] for e in endpoints),
        "complete_endpoint_family":complete_family,"measurement_unit":"source_selected_complete_record_gold_class_any_error_or_unknown",
        "field_level_accuracy_claimed":False,"human_review_required":False,"model_calls":0,
        "formal_RQ1_certified":False}
