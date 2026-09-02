#!/usr/bin/env python3
from __future__ import annotations
import argparse,csv,hashlib,json,re
from pathlib import Path
from harbor_exception_policy import diagnose,load_result

akey='authori'+'zation'; ckey='coo'+'kie'; pkey='pass'+'word'
SENSITIVE=re.compile(rf'(?i)({akey}\s*:\s*|{ckey}\s*:\s*|(?:api[_-]?key|{pkey}|proxy[_-]?credential)\s*[=:]\s*)(\S+)')
def clean(text):
 return SENSITIVE.sub('[REDACTED_CREDENTIAL_FIELD]',text)
def sha(data):return hashlib.sha256(data).hexdigest()
p=argparse.ArgumentParser();p.add_argument('--trial',type=Path,required=True);p.add_argument('--stdout',type=Path,required=True);p.add_argument('--stderr',type=Path,required=True);p.add_argument('--exit',type=int,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
a.out.mkdir(parents=True,exist_ok=True); result_path=a.trial/'result.json'; result=load_result(result_path)
trial_log=(a.trial/'trial.log').read_text(errors='replace') if (a.trial/'trial.log').is_file() else ''
agent_log=(a.trial/'agent'/'oracle.txt').read_text(errors='replace') if (a.trial/'agent'/'oracle.txt').is_file() else ''
verifier_log=(a.trial/'verifier'/'test-stdout.txt').read_text(errors='replace') if (a.trial/'verifier'/'test-stdout.txt').is_file() else ''
phase={'task_network_ok':(a.trial/'artifacts'/'task-network.ok').is_file(),'oracle_network_ok':(a.trial/'artifacts'/'oracle-network.ok').is_file(),'verifier_network_ok':'VERIFIER_NETWORK_OK' in verifier_log}
reward_files=list(a.trial.rglob('reward.txt'))+list(a.trial.rglob('reward.json')); complete=result_path.is_file() and bool(reward_files)
stdout=a.stdout.read_text(errors='replace');stderr=a.stderr.read_text(errors='replace'); diagnostic=diagnose(a.exit,result,stdout,stderr,complete,phase)
(a.out/'fresh_trial_evidence.json').write_text(json.dumps({'harbor_exit_code':a.exit,'trial_name':a.trial.name,**diagnostic},indent=2)+'\n')
sources=[a.stdout,a.stderr,result_path,*reward_files]
for candidate in [a.trial/'trial.log',a.trial/'config.json',a.trial/'lock.json',a.trial/'agent'/'oracle.txt',a.trial/'verifier'/'test-stdout.txt',a.trial/'verifier'/'test-stderr.txt',a.trial/'artifacts'/'task-network.ok',a.trial/'artifacts'/'oracle-network.ok',a.trial/'artifacts'/'manifest.json']:
 if candidate.is_file():sources.append(candidate)
rows=[]
for src in dict.fromkeys(sources):
 raw=src.read_bytes(); text=raw.decode(errors='replace'); sanitized=clean(text); redactions=text.count('[REDACTED]')+len(SENSITIVE.findall(text)); rel='evidence/'+src.name
 dest=a.out/rel;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_text(sanitized)
 rows.append([str(src.relative_to(a.trial.parent) if a.trial.parent in src.parents else src.name),rel,sha(raw),sha(dest.read_bytes()),redactions,'credential-pattern' if redactions else 'none'])
with (a.out/'artifact_manifest.csv').open('w',newline='') as f:
 w=csv.writer(f);w.writerow(['source_logical_artifact','sanitized_artifact','raw_sha256','sanitized_sha256','redactions_count','redaction_category']);w.writerows(rows)
(a.out/'trial_file_manifest.txt').write_text('\n'.join(sorted(p.relative_to(a.trial).as_posix() for p in a.trial.rglob('*') if p.is_file()))+'\n')
