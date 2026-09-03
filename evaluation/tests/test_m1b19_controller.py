#!/usr/bin/env python3
from __future__ import annotations
import importlib.util,sys
from pathlib import Path
root=Path(__file__).resolve().parents[2];sys.path.insert(0,str(root/'scripts'));spec=importlib.util.spec_from_file_location('c',root/'scripts'/'gha_m1b19_controller.py');assert spec and spec.loader;c=importlib.util.module_from_spec(spec);sys.modules[spec.name]=c;spec.loader.exec_module(c)
good=[{'candidate_rank':i+1,'task_id':f'terminal-bench/t{i}','attempt_number':1} for i in range(8)];assert c.validate(good)==good;print('PASS valid_eight')
bad=[[],good+[{'candidate_rank':9,'task_id':'terminal-bench/t8','attempt_number':1}],good[:1]*2,[{'candidate_rank':0,'task_id':'terminal-bench/x','attempt_number':1}],[{'candidate_rank':1,'task_id':'x','attempt_number':1}],[{'candidate_rank':1,'task_id':'terminal-bench/x','attempt_number':6}],[{'candidate_rank':1,'task_id':'terminal-bench/x'}]]
for i,x in enumerate(bad):
 try:c.validate(x);raise AssertionError(x)
 except ValueError:print('PASS reject',i)
print('M1B19_CONTROLLER=8/8 PASS')
