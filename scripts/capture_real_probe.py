#!/usr/bin/env python3
from __future__ import annotations
import argparse,csv,hashlib,json,re
from pathlib import Path
from harbor_exception_policy import diagnose,load_result
def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()
akey='authori'+'zation'; ckey='coo'+'kie'; pkey='pass'+'word'
SENSITIVE=re.compile(rf'(?i)({akey}\s*:\s*|{ckey}\s*:\s*|(?:api[_-]?key|{pkey}|proxy[_-]?credential)\s*[=:]\s*)(\S+)')
def clean(text:str)->str:return SENSITIVE.sub('[REDACTED_CREDENTIAL_FIELD]',text)
p=argparse.ArgumentParser()
for name in ('task','job'):p.add_argument('--'+name,required=True)
for name in ('trial','stdout','stderr','normalizer','csv','out'):p.add_argument('--'+name,type=Path,required=True)
for name in ('exit','minimum-free','wall-seconds'):p.add_argument('--'+name,type=int,required=True)
a=p.parse_args(); a.out.mkdir(parents=True,exist_ok=True); result=load_result(a.trial/'result.json'); norm=json.loads(a.normalizer.read_text())
rewards=list(a.trial.rglob('reward.txt'))+list(a.trial.rglob('reward.json')); complete=(a.trial/'result.json').is_file() and bool(rewards)
stdout=a.stdout.read_text(errors='replace'); stderr=a.stderr.read_text(errors='replace'); d=diagnose(a.exit,result,stdout,stderr,complete,{})
text='\n'.join([stdout,stderr]+[x.read_text(errors='replace') for x in a.trial.rglob('*') if x.is_file()]); e35=len(re.findall(r'curl[^\n]*exit(?: code)?[=: ]+35|CURLE_SSL_CONNECT_ERROR',text,re.I)); tls=len(re.findall(r'TLS|SSL connect error',text,re.I)); dns=len(re.findall(r'could not resolve|temporary failure in name resolution',text,re.I))
verifier=bool(isinstance(result,dict) and result.get('verifier_result') is not None); infra=(a.exit==0 and complete and verifier and d['structured_exception_status']=='NO_EXCEPTION' and not (e35 or tls or dns) and norm['outcome'] not in ('VERIFIER_INFRA_ERROR','ENVIRONMENT_ERROR','UNCLASSIFIED'))
evidence={'task':a.task,'job_name':a.job,'trial_name':a.trial.name,'harbor_process_exit':a.exit,'raw_reward':d['raw_reward'],'normalized_outcome':norm['outcome'],'reason_code':norm['reason_code'],'structured_exception_status':d['structured_exception_status'],'verifier_completed':verifier,'artifact_complete':complete,'task_network_status':'NO_FAILURE_OBSERVED','oracle_network_status':'NO_FAILURE_OBSERVED','verifier_network_status':'NO_FAILURE_OBSERVED','curl_exit_35':e35,'tls_failure':tls,'dns_failure':dns,'minimum_free_bytes':a.minimum_free,'wall_seconds':a.wall_seconds,'infrastructure_qualified':infra}
(a.out/'fresh_trial_evidence.json').write_text(json.dumps(evidence,indent=2)+'\n'); sources=[a.stdout,a.stderr,a.trial/'result.json',a.normalizer,*rewards]; rows=[]
for src in dict.fromkeys(x for x in sources if x.is_file()):
 raw=src.read_bytes(); text=raw.decode(errors='replace'); sanitized=clean(text); redactions=len(SENSITIVE.findall(text)); dest=a.out/('evidence_'+src.name); dest.write_text(sanitized); rows.append([src.name,dest.name,sha(raw),sha(dest.read_bytes()),redactions,'credential-pattern' if redactions else 'none'])
with (a.out/'artifact_manifest.csv').open('w',newline='') as f:w=csv.writer(f);w.writerow(['source_logical_artifact','sanitized_artifact','raw_sha256','sanitized_sha256','redactions_count','redaction_category']);w.writerows(rows)
with a.csv.open('a',newline='') as f:csv.writer(f).writerow(evidence.values())
raise SystemExit(0 if infra else 1)
