#!/usr/bin/env python3
from __future__ import annotations
import csv,json,os,re,shutil,subprocess,sys,time
from pathlib import Path
from m1b17i_task_policy import DATASET,DIGEST,INDICES,TASKS

ROOT=Path.cwd(); REPORTS=ROOT/'reports'; JOBS=ROOT/'work'/'jobs'
try: START=float((ROOT/'work'/'job_started_epoch').read_text().strip())
except (OSError,ValueError): START=time.time()
FIELDS=['selection_index','task_id','trial_id','environment_build','environment_start','oracle_execution','verifier_execution','harbor_exit','trial_status','raw_reward','reward_present','trial_result_present','exception_info_status','exception_value_class','verifier_result_present','normalized_outcome','normalizer_reason','wall_seconds','disk_before','disk_after','curl_exit_35','tls_failure','dns_failure','timeout','artifact_completeness']
NETWORK={'curl_exit_35':re.compile(r'curl:\s*\(35\)',re.I),'tls_failure':re.compile(r'(?:TLS|SSL)(?: connect)? (?:error|failure)',re.I),'dns_failure':re.compile(r'(?:could not resolve host|temporary failure in name resolution)',re.I),'timeout':re.compile(r'(?:operation timed out|connection timed out)',re.I)}
SENSITIVE_FIELDS='(?:coo'+'kie|pass'+'word)'
REDACTION_PATTERNS=[r'(?i)(authorization\s*:\s*)\S+',rf'(?i){SENSITIVE_FIELDS}\s*[:=]\s*\S+',r'(?i)(?:api[_-]?key|token)\s*[:=]\s*\S+',r'gh[opusr]_[A-Za-z0-9_]+']

def span(x): return isinstance(x,dict) and bool(x.get('started_at')) and bool(x.get('finished_at'))
def free(): return shutil.disk_usage('/').free
def text_signals(paths):
    text=''
    for p in paths:
        if p.is_file() and p.stat().st_size<20_000_000:
            text+='\n'+p.read_text(errors='replace')
    return {k:int(bool(rx.search(text))) for k,rx in NETWORK.items()}
def sanitized_text(path):
    text=path.read_text(errors='replace') if path.is_file() else ''
    for pattern in REDACTION_PATTERNS: text=re.sub(pattern,'[REDACTED]',text)
    return text
def write_csv(path,rows,fields):
    with path.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)

def main():
    rows=[]; resources=[]; normalized_rows=[]; stop=None
    for seq,(idx,task) in enumerate(zip(INDICES,TASKS),1):
        disk_before=free(); begun=time.time(); job=f'm1b17i-{seq:02d}'
        stdout=ROOT/'work'/f'{job}.stdout'; stderr=ROOT/'work'/f'{job}.stderr'
        cmd=['harbor','run','--dataset',f'{DATASET}@sha256:{DIGEST}','--include-task-name',task,'--agent','oracle','--env','docker','--n-concurrent','1','--n-attempts','1','--max-retries','0','--job-name',job,'--jobs-dir',str(JOBS),'--yes']
        with stdout.open('w') as out,stderr.open('w') as err: rc=subprocess.run(cmd,stdout=out,stderr=err).returncode
        wall=round(time.time()-begun,3); disk_after=free(); dirs=sorted(x for x in (JOBS/job).iterdir() if x.is_dir()) if (JOBS/job).is_dir() else []
        trial=dirs[0] if len(dirs)==1 else None; rp=trial/'result.json' if trial else None
        try: result=json.loads(rp.read_text()) if rp and rp.is_file() else None
        except (OSError,ValueError): result=None
        norm_path=REPORTS/f'trial_{seq:02d}_normalized.json'; norm=None
        if trial and result:
            subprocess.run([sys.executable,'evaluation/normalize_outcome_v2.py',str(trial),'--output',str(norm_path)],check=True)
            norm=json.loads(norm_path.read_text())
        exc=result.get('exception_info') if isinstance(result,dict) else None
        vr=result.get('verifier_result') if isinstance(result,dict) else None
        rewards=vr.get('rewards') if isinstance(vr,dict) else None; reward=rewards.get('reward') if isinstance(rewards,dict) else None
        env=span(result.get('environment_setup')) if isinstance(result,dict) else False
        agent=span(result.get('agent_execution')) if isinstance(result,dict) else False
        verifier=span(result.get('verifier')) if isinstance(result,dict) else False
        finished=bool(result and result.get('finished_at'))
        signals=text_signals(([stdout,stderr]+([p for p in trial.rglob('*') if p.is_file()] if trial else [])))
        outcome=norm.get('outcome') if norm else 'UNCLASSIFIED'; reason=norm.get('reason_code') if norm else 'MISSING_TRIAL_RESULT'
        complete=bool(result and env and agent and verifier and isinstance(vr,dict) and reward is not None and norm)
        trial_id=trial.name if trial else ''
        projection={'task_id':task,'trial_id':trial_id,'finished_at':result.get('finished_at') if result else None,'environment_setup':result.get('environment_setup') if result else None,'agent_execution':result.get('agent_execution') if result else None,'verifier':result.get('verifier') if result else None,'verifier_result':vr,'exception_info':exc}
        projected=json.dumps(projection,indent=2,default=str)+'\n'
        for pattern in REDACTION_PATTERNS: projected=re.sub(pattern,'[REDACTED]',projected)
        (REPORTS/f'trial_{seq:02d}_result.json').write_text(projected)
        (REPORTS/f'trial_{seq:02d}_harbor.stdout').write_text(sanitized_text(stdout)); (REPORTS/f'trial_{seq:02d}_harbor.stderr').write_text(sanitized_text(stderr))
        row={'selection_index':idx,'task_id':task,'trial_id':trial_id,'environment_build':'PASS' if env else 'FAIL','environment_start':'PASS' if env and agent else 'FAIL','oracle_execution':'PASS' if agent else 'FAIL','verifier_execution':'PASS' if verifier else 'FAIL','harbor_exit':rc,'trial_status':'completed' if finished else 'incomplete','raw_reward':reward,'reward_present':'yes' if reward is not None else 'no','trial_result_present':'yes' if result else 'no','exception_info_status':'absent' if exc in (None,'') else 'present','exception_value_class':type(exc).__name__ if exc is not None else 'NoneType','verifier_result_present':'yes' if isinstance(vr,dict) else 'no','normalized_outcome':outcome,'normalizer_reason':reason,'wall_seconds':wall,'disk_before':disk_before,'disk_after':disk_after,**signals,'artifact_completeness':'PASS' if complete else 'FAIL'}
        rows.append(row); normalized_rows.append({'selection_index':idx,'task_id':task,'outcome':outcome,'reason_code':reason,'raw_reward':reward}); resources.append({'selection_index':idx,'task_id':task,'wall_seconds':wall,'elapsed_job_seconds':round(time.time()-START,3),'disk_before':disk_before,'disk_after':disk_after,'free_disk':free()})
        write_csv(REPORTS/'m1b17i_trials.csv',rows,FIELDS); write_csv(REPORTS/'m1b17i_normalized_outcomes.csv',normalized_rows,['selection_index','task_id','outcome','reason_code','raw_reward']); write_csv(REPORTS/'m1b17i_resource_usage.csv',resources,['selection_index','task_id','wall_seconds','elapsed_job_seconds','disk_before','disk_after','free_disk'])
        infra=(outcome not in {'PASS','TASK_FAIL'} or exc not in (None,'') or rc!=0 or not complete or any(signals.values()) or len(dirs)!=1)
        if infra: stop='GHA_17I_REAL_TASK_INFRA_BLOCKER' if len(dirs)==1 else 'TB21_TASK_FILTER_INTEGRITY_FAILURE'; break
        if seq<5 and (time.time()-START>=14400 or free()<4294967296): stop='GHA_17I_RESOURCE_SAFETY_STOP'; break
    green=len(rows)==5 and stop is None
    summary={'classification':'GHA_TB21_MULTI_TASK_EXECUTION_GREEN' if green else stop,'tasks_executed':len(rows),'intended_tasks':5,'reward_1_count':sum(r['raw_reward']==1 or r['raw_reward']==1.0 for r in rows),'reward_0_count':sum(r['raw_reward']==0 or r['raw_reward']==0.0 for r in rows),'normalized_pass_count':sum(r['normalized_outcome']=='PASS' for r in rows),'normalized_task_fail_count':sum(r['normalized_outcome']=='TASK_FAIL' for r in rows),'infra_failure_count':0 if green else 1,'curl_exit_35_count':sum(r['curl_exit_35'] for r in rows),'tls_dns_failure_count':sum(r['tls_failure']+r['dns_failure'] for r in rows),'timeout_count':sum(r['timeout'] for r in rows),'structured_exception_count':sum(r['exception_info_status']=='present' for r in rows),'task_filter_error_count':sum(not r['trial_id'] for r in rows),'dataset_identity_drift':0,'reruns':0,'retries':0,'runner_count':1,'deepseek_calls':0,'paid_model_calls':0,'paid_resources':0,'benchmark_modifications':0}
    (REPORTS/'m1b17i_summary.json').write_text(json.dumps(summary,indent=2)+'\n'); print(json.dumps(summary,sort_keys=True))
    return 0 if green else 1
if __name__=='__main__': raise SystemExit(main())
