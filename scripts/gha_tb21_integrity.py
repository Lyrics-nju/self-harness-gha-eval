#!/usr/bin/env python3
from __future__ import annotations
import hashlib, sys
from pathlib import Path

root=Path(sys.argv[1]); expected_tasks=int(sys.argv[2]); expected_files=int(sys.argv[3]); expected_digest=sys.argv[4]
files=sorted(p for p in root.rglob('*') if p.is_file())
tasks=sum(1 for p in root.iterdir() if p.is_dir())
d=hashlib.sha256()
for p in files:
    d.update(p.relative_to(root).as_posix().encode()); d.update(b'\0'); d.update(hashlib.sha256(p.read_bytes()).digest())
actual=d.hexdigest()
print(f'tasks={tasks} files={len(files)} digest={actual}')
if (tasks,len(files),actual)!=(expected_tasks,expected_files,expected_digest): raise SystemExit(1)
