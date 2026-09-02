#!/usr/bin/env python3
from __future__ import annotations
import json, subprocess, sys
from pathlib import Path

jobs=Path(sys.argv[1]); output=Path(sys.argv[2]); results=[]
for trial in sorted(p for p in jobs.glob('*/*') if p.is_dir()):
    target=output.parent/'normalizer'/f'{trial.name}.json'
    target.parent.mkdir(parents=True,exist_ok=True)
    subprocess.run([sys.executable,'evaluation/normalize_outcome_v2.py',str(trial),'--output',str(target)],check=True)
    data=json.loads(target.read_text()); data['artifact_relative_path']=trial.relative_to(jobs).as_posix(); results.append(data)
output.write_text(json.dumps(results,indent=2)+'\n')
