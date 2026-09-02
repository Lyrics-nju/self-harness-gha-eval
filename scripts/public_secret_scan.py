#!/usr/bin/env python3
from __future__ import annotations
import argparse, re
from pathlib import Path

p=argparse.ArgumentParser(); p.add_argument('--artifact-mode',action='store_true'); p.add_argument('root',nargs='?',default='.')
a=p.parse_args(); root=Path(a.root)
categories={
 'PROVIDER_OR_PROXY_CONFIG': ['subscription'+'.secret','provider_'+'raw.yaml','config.'+'runtime.yaml','fixed-'+'node','miho'+'mo'],
 'MODEL_OR_CLOUD_KEY_NAME': ['DAYTONA_'+'API_KEY','DEEPSEEK_'+'API_KEY','MIMO_'+'API_KEY'],
 'AUTH_TOKEN_PATTERN': ['gho'+'_','github'+'_pat_','authorization'+':'],
 'PRIVATE_KEY': ['BEGIN '+'OPENSSH PRIVATE KEY','BEGIN '+'RSA PRIVATE KEY'],
 'CREDENTIAL_CONTENT': ['coo'+'kie','pass'+'word'],
 'PRIVATE_ARTIFACT': ['private '+'trajectory','private model '+'trace'],
 'LOCAL_PRIVATE_PATH': ['/home/'+'liujr/','/mnt/c/Users/'+'Administrator/'],
}
findings=[]
for path in sorted(p for p in root.rglob('*') if p.is_file() and '.git' not in p.parts):
    rel=path.relative_to(root).as_posix()
    if not a.artifact_mode and (rel.startswith('runtime/') or rel.startswith('work/')): findings.append((rel,'FORBIDDEN_PATH'))
    if path.name == '.e'+'nv' or path.name.startswith('.e'+'nv.') or path.suffix == '.pem': findings.append((rel,'CREDENTIAL_FILE'))
    try: text=path.read_text(errors='replace')
    except OSError: findings.append((rel,'UNREADABLE_FILE')); continue
    low=(rel+'\n'+text).lower()
    for category,needles in categories.items():
        if any(n.lower() in low for n in needles): findings.append((rel,category)); break
for rel,category in findings: print(f'{rel}\t{category}')
if findings: raise SystemExit(1)
print('ARTIFACT_SECRET_SCAN_PASS' if a.artifact_mode else 'SECRET_SCAN_PASS')
