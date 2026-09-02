#!/usr/bin/env python3
from __future__ import annotations
import hashlib,importlib.util,sys
from pathlib import Path
root=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('policy',root/'scripts'/'tb21_dataset_policy.py'); assert spec and spec.loader
p=importlib.util.module_from_spec(spec); sys.modules[spec.name]=p; spec.loader.exec_module(p)

r=p.resolve_for_harbor_021('terminal-bench/terminal-bench-2-1')
assert (r.name,r.ref,r.resolver_family)==('terminal-bench/terminal-bench-2-1','latest','package_dataset'); print('PASS canonical_slug')
for name,label in [('terminal-bench@2.1','legacy_pair_rejected'),('does-not-exist/nope','invalid_rejected'),('terminal-bench/terminal-bench','fallback_v1_rejected'),('terminal-bench/terminal-bench-2','fallback_v2_rejected')]:
 try:p.resolve_for_harbor_021(name); raise AssertionError(name)
 except ValueError:print('PASS',label)
assert p.EXPECTED_TASK_COUNT==89; print('PASS expected_task_count')
assert len(p.EXPECTED_TASK_ID_SHA256)==64 and int(p.EXPECTED_TASK_ID_SHA256,16)>=0; print('PASS task_id_digest')
assert hashlib.sha256(b'').hexdigest()!=p.EXPECTED_TASK_ID_SHA256; print('PASS no_empty_fallback')
print('TB21_DATASET_POLICY=8/8 PASS')
