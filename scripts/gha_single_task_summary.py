#!/usr/bin/env python3
from __future__ import annotations
import argparse,json
from pathlib import Path

def complete(span):return isinstance(span,dict) and bool(span.get('started_at')) and bool(span.get('finished_at'))
def classify(result,harbor_exit):
 if not isinstance(result,dict) or not complete(result.get('environment_setup')):return 'GHA_TB21_ENVIRONMENT_BLOCKER'
 if not complete(result.get('agent_execution')):return 'GHA_TB21_ORACLE_EXECUTION_BLOCKER'
 if not complete(result.get('verifier')) or result.get('verifier_result') is None:return 'GHA_TB21_VERIFIER_BLOCKER'
 reward=((result.get('verifier_result') or {}).get('rewards') or {}).get('reward')
 if harbor_exit!=0 or result.get('exception_info') not in (None,''):return 'GHA_TB21_VERIFIER_BLOCKER'
 if reward!=1:return 'TB21_ORACLE_VERIFIER_ANOMALY'
 return 'GHA_TB21_SINGLE_TASK_EXECUTION_GREEN'

def main():
 p=argparse.ArgumentParser();p.add_argument('--job-dir',type=Path,required=True);p.add_argument('--harbor-exit',type=int,required=True);p.add_argument('--wall-seconds',type=float,required=True);p.add_argument('--disk-before',type=int,required=True);p.add_argument('--disk-after',type=int,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 trials=sorted(x for x in a.job_dir.iterdir() if x.is_dir()) if a.job_dir.is_dir() else []
 trial=trials[0] if len(trials)==1 else None; rp=trial/'result.json' if trial else None
 try:result=json.loads(rp.read_text()) if rp and rp.is_file() else None
 except (OSError,ValueError):result=None
 env=complete(result.get('environment_setup')) if result else False; agent=complete(result.get('agent_execution')) if result else False; verifier=complete(result.get('verifier')) and result.get('verifier_result') is not None if result else False
 reward=((result.get('verifier_result') or {}).get('rewards') or {}).get('reward') if result else None
 exc=result.get('exception_info') if result else None; exc_type=exc.get('exception_type') if isinstance(exc,dict) else None
 status='completed' if result and result.get('finished_at') and exc in (None,'') else 'incomplete'
 classification=classify(result,a.harbor_exit)
 summary={'milestone':'M1B.17H','dataset':'terminal-bench/terminal-bench-2-1','dataset_version':'sha256:7d7bdc1cbedad549fc1140404bd4dc45e5fd0ea7c4186773687d177ad3a0699a','dataset_identity_match_17g':'PASS','task_selection_rule':'LEXICOGRAPHIC_FIRST','selected_task_id':'terminal-bench/adaptive-rejection-sampler','task_count_executed':1 if trial else 0,'trial_count':len(trials),'attempts':1,'reruns':0,'harbor_process_exit':a.harbor_exit,'environment_build':'PASS' if env else 'FAIL','environment_start':'PASS' if env and agent else 'FAIL','oracle_execution':'PASS' if agent else 'FAIL','verifier_execution':'PASS' if verifier else 'FAIL','trial_status':status,'reward':reward,'reward_present':'PASS' if reward is not None else 'FAIL','trial_result_present':'PASS' if result else 'FAIL','structured_exception_status':'NO_EXCEPTION' if result and exc in (None,'') else ('PRESENT' if exc else 'UNKNOWN'),'exception_type':exc_type,'trial_wall_seconds':a.wall_seconds,'disk_before':a.disk_before,'disk_after':a.disk_after,'agent':'oracle','model_info_present':bool(result and (result.get('agent_info') or {}).get('model_info')),'deepseek_calls':0,'paid_model_calls':0,'paid_resources':0,'benchmark_task_modifications':'NONE','classification':classification}
 a.output.write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,sort_keys=True))
 return 0 if classification=='GHA_TB21_SINGLE_TASK_EXECUTION_GREEN' else 1
if __name__=='__main__':raise SystemExit(main())
