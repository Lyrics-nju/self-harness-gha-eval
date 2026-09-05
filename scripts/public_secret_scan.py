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
    # The live workflow needs the credential *name* in two exact GitHub
    # expressions, and the public profile declares only that environment name.
    # Remove only these reviewed, value-free declarations before scanning; any
    # other occurrence of the key name still fails closed.
    key_name = 'DEEPSEEK_'+'API_KEY'
    safe_key_lines = {
      '.github/workflows/gha-m1c1-live.yml': {
        f'          M1C_SECRET_AVAILABLE: ${{{{ secrets.{key_name} != \'\' }}}}',
        f'          {key_name}: ${{{{ secrets.{key_name} }}}}',
      },
      'configs/model_profile_deepseek_v4_pro_v1.yaml': {
        f'credential_environment_name: {key_name}',
      },
    }
    if rel in safe_key_lines:
        lines=text.splitlines()
        allowed=safe_key_lines[rel]
        text='\n'.join(line for line in lines if line not in allowed)
    low=(rel+'\n'+text).lower()
    for category,needles in categories.items():
        if any(n.lower() in low for n in needles): findings.append((rel,category)); break
for rel,category in findings: print(f'{rel}\t{category}')
if findings: raise SystemExit(1)
print('ARTIFACT_SECRET_SCAN_PASS' if a.artifact_mode else 'SECRET_SCAN_PASS')
