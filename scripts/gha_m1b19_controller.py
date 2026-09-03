#!/usr/bin/env python3
"""Run one frozen M1B.19 batch; evaluator semantics mirror M1B.17J."""
from __future__ import annotations
import argparse,csv,json,re,shutil,subprocess,sys,time
from pathlib import Path
from m1b17i_task_policy import DATASET,DIGEST

ROOT=Path.cwd();REPORTS=ROOT/'reports';JOBS=ROOT/'work'/'jobs'
try:START=float((ROOT/'work'/'job_started_epoch').read_text().strip())
except (OSError,ValueError):START=time.time()
FIELDS=['candidate_rank','task_id','attempt_number','trial_id','environment_build','environment_start','oracle_execution','verifier_execution','harbor_exit','trial_status','raw_reward','reward_present','trial_result_present','exception_info_status','exception_value_class','verifier_result_present','normalized_outcome','normalizer_reason','normalizer_version','wall_seconds','disk_before','disk_after','curl_exit_35','tls_failure','dns_failure','timeout','text_only_diagnostic_signal','artifact_completeness']
NETWORK={'curl_exit_35':re.compile(r'curl:\s*\(35\)',re.I),'tls_failure':re.compile(r'(?:TLS|SSL)(?: connect)? (?:error|failure)',re.I),'dns_failure':re.compile(r'(?:could not resolve host|temporary failure in name resolution)',re.I),'timeout':re.compile(r'(?:operation timed out|connection timed out)',re.I)}
SENSITIVE_FIELDS='(?:coo'+'kie|pass'+'word)';REDACTION_PATTERNS=[r'(?i)(authorization\s*:\s*)\S+',rf'(?i){SENSITIVE_FIELDS}\s*[:=]\s*\S+',r'(?i)(?:api[_-]?key|token)\s*[:=]\s*\S+',r'gh[opusr]_[A-Za-z0-9_]+']
def span(x):return isinstance(x,dict) and bool(x.get('started_at')) and bool(x.get('finished_at'))
def free():return shutil.disk_usage('/').free
def redact(text):
 for pattern in REDACTION_PATTERNS:text=re.sub(pattern,'[REDACTED]',text)
 return text
def signals(paths):
 text=''
 for p in paths:
  if p.is_file() and p.stat().st_size<20_000_000:text+='\n'+p.read_text(errors='replace')
 return {k:int(bool(rx.search(text))) for k,rx in NETWORK.items()}
def write_csv(path,rows):
 with path.open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=FIELDS);w.writeheader();w.writerows(rows)
def validate(batch):
 if not isinstance(batch,list) or not 1<=len(batch)<=8:raise ValueError('batch size must be 1..8')
 tasks=[]
 for item in batch:
  if set(item)!= {'candidate_rank','task_id','attempt_number'}:raise ValueError('invalid manifest schema')
  if not isinstance(item['candidate_rank'],int) or not 1<=item['candidate_rank']<=89:raise ValueError('invalid rank')
  if not isinstance(item['attempt_number'],int) or not 1<=item['attempt_number']<=5:raise ValueError('invalid attempt')
  if not isinstance(item['task_id'],str) or not item['task_id'].startswith('terminal-bench/'):raise ValueError('invalid task ID')
  tasks.append(item['task_id'])
 if len(tasks)!=len(set(tasks)):raise ValueError('same task occurs twice in one run')
 return batch
def main():
 p=argparse.ArgumentParser();p.add_argument('--batch',type=Path,required=True);a=p.parse_args();batch=validate(json.loads(a.batch.read_text()));rows=[];stop=None
 for seq,item in enumerate(batch,1):
  task=item['task_id'];before=free();begun=time.time();job=f'm1b19-{seq:02d}';stdout=ROOT/'work'/f'{job}.stdout';stderr=ROOT/'work'/f'{job}.stderr'
  cmd=['harbor','run','--dataset',f'{DATASET}@sha256:{DIGEST}','--include-task-name',task,'--agent','oracle','--env','docker','--n-concurrent','1','--n-attempts','1','--max-retries','0','--job-name',job,'--jobs-dir',str(JOBS),'--yes']
  with stdout.open('w') as out,stderr.open('w') as err:rc=subprocess.run(cmd,stdout=out,stderr=err).returncode
  wall=round(time.time()-begun,3);after=free();dirs=sorted(x for x in (JOBS/job).iterdir() if x.is_dir()) if (JOBS/job).is_dir() else [];trial=dirs[0] if len(dirs)==1 else None;rp=trial/'result.json' if trial else None
  try:result=json.loads(rp.read_text()) if rp and rp.is_file() else None
  except (OSError,ValueError):result=None
  norm_path=REPORTS/f'trial_{seq:02d}_normalized.json';norm=None
  if trial and result:
   subprocess.run([sys.executable,'evaluation/normalize_outcome_v2.py',str(trial),'--output',str(norm_path)],check=True);norm=json.loads(norm_path.read_text())
  exc=result.get('exception_info') if isinstance(result,dict) else None;vr=result.get('verifier_result') if isinstance(result,dict) else None;rewards=vr.get('rewards') if isinstance(vr,dict) else None;reward=rewards.get('reward') if isinstance(rewards,dict) else None
  env=span(result.get('environment_setup')) if isinstance(result,dict) else False;agent=span(result.get('agent_execution')) if isinstance(result,dict) else False;verifier=span(result.get('verifier')) if isinstance(result,dict) else False;finished=bool(result and result.get('finished_at'));sig=signals([stdout,stderr]+([x for x in trial.rglob('*') if x.is_file()] if trial else []));outcome=norm.get('outcome') if norm else 'UNCLASSIFIED';reason=norm.get('reason_code') if norm else 'MISSING_TRIAL_RESULT';complete=bool(result and env and agent and verifier and isinstance(vr,dict) and reward is not None and norm);trial_id=trial.name if trial else ''
  projection={'task_id':task,'candidate_rank':item['candidate_rank'],'attempt_number':item['attempt_number'],'trial_id':trial_id,'finished_at':result.get('finished_at') if result else None,'environment_setup':result.get('environment_setup') if result else None,'agent_execution':result.get('agent_execution') if result else None,'verifier':result.get('verifier') if result else None,'verifier_result':vr,'exception_info':exc}
  (REPORTS/f'trial_{seq:02d}_result.json').write_text(redact(json.dumps(projection,indent=2,default=str)+'\n'));(REPORTS/f'trial_{seq:02d}_harbor.stdout').write_text(redact(stdout.read_text(errors='replace')));(REPORTS/f'trial_{seq:02d}_harbor.stderr').write_text(redact(stderr.read_text(errors='replace')))
  row={'candidate_rank':item['candidate_rank'],'task_id':task,'attempt_number':item['attempt_number'],'trial_id':trial_id,'environment_build':'PASS' if env else 'FAIL','environment_start':'PASS' if env and agent else 'FAIL','oracle_execution':'PASS' if agent else 'FAIL','verifier_execution':'PASS' if verifier else 'FAIL','harbor_exit':rc,'trial_status':'completed' if finished else 'incomplete','raw_reward':reward,'reward_present':'yes' if reward is not None else 'no','trial_result_present':'yes' if result else 'no','exception_info_status':'absent' if exc in (None,'') else 'present','exception_value_class':type(exc).__name__ if exc is not None else 'NoneType','verifier_result_present':'yes' if isinstance(vr,dict) else 'no','normalized_outcome':outcome,'normalizer_reason':reason,'normalizer_version':norm.get('classifier_version','') if norm else '', 'wall_seconds':wall,'disk_before':before,'disk_after':after,**sig,'text_only_diagnostic_signal':'present' if any(sig.values()) else 'absent','artifact_completeness':'PASS' if complete else 'FAIL'};rows.append(row);write_csv(REPORTS/'m1b19_trials.csv',rows)
  infra=(outcome not in {'PASS','TASK_FAIL'} or exc not in (None,'') or rc!=0 or not complete or any(sig.values()) or len(dirs)!=1)
  if infra:stop='TB21_TASK_FILTER_INTEGRITY_FAILURE' if len(dirs)!=1 else 'M1B19_TASK_NONVALID_OUTCOME';break
  if seq<len(batch) and (time.time()-START>=14400 or free()<4294967296):stop='M1B19_RESOURCE_SAFETY_STOP';break
 summary={'classification':'BATCH_COMPLETE' if stop is None and len(rows)==len(batch) else stop,'tasks_requested':len(batch),'tasks_executed':len(rows),'pass_count':sum(r['normalized_outcome']=='PASS' for r in rows),'task_fail_count':sum(r['normalized_outcome']=='TASK_FAIL' for r in rows),'infra_count':sum(r['normalized_outcome'] not in {'PASS','TASK_FAIL'} for r in rows),'retries':0,'deepseek_calls':0};(REPORTS/'m1b19_batch_summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,sort_keys=True));return 0 if summary['classification']=='BATCH_COMPLETE' else 1
if __name__=='__main__':raise SystemExit(main())
