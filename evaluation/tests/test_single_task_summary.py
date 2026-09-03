#!/usr/bin/env python3
from __future__ import annotations
import importlib.util,sys
from pathlib import Path
root=Path(__file__).resolve().parents[2];spec=importlib.util.spec_from_file_location('summary',root/'scripts'/'gha_single_task_summary.py');assert spec and spec.loader
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
span={'started_at':'a','finished_at':'b'}
def r(reward=1,env=span,agent=span,verifier=span,vr=True,exc=None):return {'environment_setup':env,'agent_execution':agent,'verifier':verifier,'verifier_result':{'rewards':{'reward':reward}} if vr else None,'exception_info':exc}
cases=[('green',r(),0,'GHA_TB21_SINGLE_TASK_EXECUTION_GREEN'),('no_result',None,1,'GHA_TB21_ENVIRONMENT_BLOCKER'),('env',r(env=None),1,'GHA_TB21_ENVIRONMENT_BLOCKER'),('oracle',r(agent=None),1,'GHA_TB21_ORACLE_EXECUTION_BLOCKER'),('verifier',r(verifier=None),1,'GHA_TB21_VERIFIER_BLOCKER'),('reward',r(reward=0),0,'TB21_ORACLE_VERIFIER_ANOMALY'),('exception',r(exc={'exception_type':'X'}),1,'GHA_TB21_VERIFIER_BLOCKER')]
for name,result,rc,want in cases:assert m.classify(result,rc)==want;print('PASS',name)
print('SINGLE_TASK_SUMMARY=7/7 PASS')
