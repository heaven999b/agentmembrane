"""Twelve real-public-task engineering baselines, never model research samples."""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from pathlib import Path
from .workflow import prepare, load_manifest, run_cell, write, code_fingerprint

TASKS = ["workspace:user_task_"+str(i) for i in (8,24,26,35)] + ["travel:user_task_0","travel:user_task_2"]


def run(output, *, workers=3):
    if type(workers) is not int or not 1 <= workers <= 3:
        raise ValueError("smoke_workers_one_to_three")
    root = Path(output)
    prepared = prepare(root, tasks=TASKS, repeats=1, mode="engineering")
    path = root / 'run-manifest.json'
    manifest = load_manifest(path)
    selected = [c for c in manifest['cells'] if c['level']=='low' and c['regime']=='honest']
    write(root/'smoke-selection.json', {'selection_rule':'all_six_public_tasks_both_topologies_low_honest',
        'episode_ids':[c['episode_id'] for c in selected], 'workers':workers, 'research_samples':0, 'model_calls':0})
    rows = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        pending = {executor.submit(run_cell, path, c['episode_id'], root/'runs'/c['episode_id']):c for c in selected}
        for future in as_completed(pending):
            status = future.result()
            cfg = pending[future]
            report_path = root/'runs'/cfg['episode_id']/'report.json'
            if report_path.is_file():
                report = json.loads(report_path.read_text())
                measurement = report.get('measurement') or {}
                status.update(Q=measurement.get('dimensions',{}).get('Q'),
                              score_overall=measurement.get('overall'),
                              observer_errors=measurement.get('observer_errors'))
            rows.append(status)
            print(json.dumps({'completed':len(rows),'assigned':len(selected),'episode_id':cfg['episode_id'],
                              'status':status['status'],'native_task_success':status.get('native_task_success')},ensure_ascii=False),flush=True)
    result = {'schema_version':'rq1-engineering-smoke/1', 'assigned':len(selected),
        'completed':sum(r['status']=='completed' for r in rows),
        'native_successes':sum(r.get('native_task_success') is True for r in rows),
        'source_public_tasks':6,'independent_worlds':2,'research_samples':0,'model_calls':0,'workers':workers,
        'formal_ready':False,'code_unchanged':code_fingerprint()==manifest['code_sha256'],
        'not_an_attack_strength_or_permission_trend_test':True,'rows':rows}
    write(root/'smoke-summary.json', result)
    from ..rq1_measurement_v1.reporting import aggregate
    allocations, reports = [], {}
    for cfg in selected:
        folder = root/'runs'/cfg['episode_id']
        allocations.append(json.loads((folder/'allocation.json').read_text()))
        if (folder/'report.json').is_file():
            reports[cfg['episode_id']] = json.loads((folder/'report.json').read_text())
    write(root/'descriptive-summary.json', aggregate(allocations, reports))
    return result


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',required=True)
    parser.add_argument('--workers',type=int,default=3)
    args=parser.parse_args()
    r=run(args.output,workers=args.workers)
    print(json.dumps({k:v for k,v in r.items() if k!='rows'},ensure_ascii=False))
    return 0 if r['completed']==r['assigned'] and r['code_unchanged'] else 1


if __name__=='__main__': raise SystemExit(main())
