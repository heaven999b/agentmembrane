"""Read-only fresh public-source and effective permission export; no model calls."""
import argparse
from datetime import date,timedelta
from pathlib import Path

from ..rq1_collab_v1.process_backend import ProcessNativeTask
from ..rq1_collab_v1.policy import make_task_policy
from .contract import digest
from .permissions import VERSION,authorize_native,native_tools
from .workflow import load_manifest,write


def probe_cases(record,policy,snapshot):
    task=record["original_id"]
    if record["suite"]=="workspace":
        if task=="user_task_8":
            target=policy.target_ids(snapshot)[0]
            good=("add_calendar_event_participants",{"event_id":target,"participants":list(policy.facts["requested_participants"])})
            bad=(good[0],{**good[1],"participants":["unrequested-engineering-probe@example.invalid"]})
        elif task=="user_task_24":
            good=("get_unread_emails",{});bad=("get_received_emails",{})
        else:
            good=("list_files",{});bad=("delete_file",{"file_id":next(iter(snapshot["cloud_drive"]["files"]))})
    elif task=="user_task_0":
        facts=policy.facts
        good=("reserve_hotel",{"hotel":facts["hotel_name"],"start_day":facts["start_day"],"end_day":facts["end_day"]})
        bad=(good[0],{**good[1],"end_day":str(date.fromisoformat(facts["end_day"])+timedelta(days=1))})
    else:
        good=("get_all_restaurants_in_city",{"city":policy.facts["city"]})
        bad=(good[0],{"city":"Outside requested city (engineering probe)"})
    rows=[]
    for kind,(tool,args) in (("original_task_scope",good),("outside_requested_scope",bad)):
        for level in ("A0","A3","A4"):
            allowed,reason=authorize_native(policy,record,level,tool,args,snapshot)
            expected=level=="A4" or level=="A3" and kind=="original_task_scope"
            rows.append(dict(kind=kind,level=level,tool=tool,arguments=args,allowed=allowed,reason=reason,
                             expected=expected,passed=allowed==expected,backend_executed=False))
    return rows


def run(manifest_path,output):
    manifest=load_manifest(manifest_path)
    rows=[]
    for bh,record in manifest["bundles"].items():
        task=ProcessNativeTask(manifest["native_python"],manifest["source_root"],record["suite"],record["original_id"],timeout=30)
        try:
            snapshot=task.snapshot()
            if digest(snapshot)!=record["source_record"]["initial_state_sha256"]:
                raise ValueError("preflight_initial_world_changed")
            if any(task.record.get(k)!=v for k,v in record["source_record"].items()):
                raise ValueError("preflight_source_identity_changed")
            policy=make_task_policy(record["suite"],record["original_id"],task.prompt,record["task_policy"],[s["name"] for s in task.tool_specs])
            rows.append({"suite":record["suite"],"task_id":record["original_id"],"bundle_sha256":bh,
                "world_id":record["world_id"],"source_record":record["source_record"],"public_request":task.prompt,
                "original_goal":record["public"]["goal"],"source_policy":record["task_policy"],
                "permission_contract_version":VERSION,"grant_lifetime":"one_episode_and_current_delegation_only",
                "actual_tool_sets":{level:native_tools(policy,record,level) for level in ("A0","A3","A4")},
                "argument_schemas":task.tool_specs,"initial_resource_labels":{l:policy.labels(l,snapshot) for l in ("A0","A3","A4")},
                "actor_level_assignment":{"H":"A4","S":"A3_with_H_delegation","E":"A0_or_A3_or_A4"},
                "probes":probe_cases(record,policy,snapshot),
                "v5_coverage": ["Q","D"] if record["suite"]=="workspace" else [],
                "unimplemented_v5_dimensions":list("IMKC") if record["suite"]=="workspace" else list("QIDMKC"),
                "native_task_and_goal_checkers_available":True})
        finally:task.shutdown()
    result={"schema_version":"rq1-preflight/3","manifest_sha256":manifest["manifest_sha256"],"tasks":rows,
            "public_original_tasks":len(rows),"independent_worlds":len({r["world_id"] for r in rows}),
            "all_permission_probes_passed":all(p["passed"] for r in rows for p in r["probes"]),
            "read_only_rule_probes":True,"model_calls":0,"formal_ready":False}
    write(output,result)
    return result


if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("--manifest",required=True);parser.add_argument("--output",required=True)
    args=parser.parse_args();result=run(args.manifest,args.output)
    print({k:v for k,v in result.items() if k!="tasks"})
    raise SystemExit(0 if result["all_permission_probes_passed"] else 1)
