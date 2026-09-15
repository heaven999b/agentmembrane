"""Exercise the real launcher and verify historical files remain byte-identical."""
import argparse
import json
from pathlib import Path
import subprocess
import time

from agentmembrane.host_v2.rq1_collab_v1.audit import _write_new, file_hash, strict_loads
from agentmembrane.host_v2.rq1_scorecard_v5.workflow import write


def tree(root):
    return {str(p):file_hash(p) for p in sorted(Path(root).rglob("*")) if p.is_file()}


def main():
    parser=argparse.ArgumentParser()
    for name in ("manifest","runs","v4-scores","output"):
        parser.add_argument("--"+name,required=True)
    args=parser.parse_args()
    output=Path(args.output).resolve()
    output.mkdir(parents=True,exist_ok=False)
    before={**tree(args.runs),**tree(args.v4_scores),str(Path(args.manifest)):file_hash(args.manifest)}
    command=["bash","run_rq1_three_actor.sh","score","--manifest",str(Path(args.manifest).resolve()),
             "--runs",str(Path(args.runs).resolve()),"--output",str(output/"scores"),"--progress"]
    result=subprocess.run(command,capture_output=True,timeout=120,check=False)
    _write_new(output/"stdout.txt",result.stdout)
    _write_new(output/"progress.txt",result.stderr)
    after={**tree(args.runs),**tree(args.v4_scores),str(Path(args.manifest)):file_hash(args.manifest)}
    summary=strict_loads((output/"scores/summary.json").read_bytes())
    changes=[]
    for path in sorted((output/"scores/episodes").glob("*.json")):
        new=strict_loads(path.read_bytes())
        old=strict_loads((Path(args.v4_scores)/"episodes"/path.name).read_bytes())
        changes.append({"episode_id":new["episode_id"],"config":{k:new["config"][k] for k in ("topology","level","regime")},
                        "Q_old":old["dimensions"]["Q"]["point"],"Q_new":new["dimensions"]["Q"]["point"],
                        "D_old":old["dimensions"]["D"]["point"],"D_new":new["dimensions"]["D"]["point"],
                        "overall_new":new["overall"]})
    checks={"real_launcher_exit_zero":result.returncode==0,"historical_files_unchanged":before==after,
            "assigned48_scored48":summary["assigned_episodes"]==summary["scored_episodes"]==48,
            "all_conditions_accounted":summary["all_allocations_accounted_for"],
            "Q_D_observed_only":summary["dimensions_with_point_scores"]==dict(Q=48,I=0,D=48,M=0,K=0,C=0),
            "no_manufactured_full_scores":summary["full_six_dimension_point_scores"]==0,
            "zero_new_model_calls":summary["model_calls"]==0,"zero_behavioral_n":summary["behavioral_episode_count"]==0,
            "all96_pairs_retained":summary["matched_contrast_count"]==summary["scored_contrast_count"]==96,
            "eight_observed_grade3_incidents":summary["episodes_with_critical_incident"]==8}
    report={"passed":all(checks.values()),"checks":checks,"historical_file_count":len(before),
            "historical_file_sha256":before,"changes":changes,"command":command,
            "launcher_sha256":file_hash("run_rq1_three_actor.sh"),
            "checked_at_unix":time.time(),"new_model_generation_calls":0,
            "formal_ready":False,"interpretation":"historical_engineering_replay_not_new_behavioral_experiment"}
    write(output/"verification.json",report)
    print(json.dumps({k:v for k,v in report.items() if k not in ("historical_file_sha256","changes")},ensure_ascii=False))
    return 0 if report["passed"] else 1


if __name__=="__main__":
    raise SystemExit(main())
