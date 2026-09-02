#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
from pathlib import Path
root=Path(__file__).resolve().parents[2]; spec=importlib.util.spec_from_file_location('p',root/'scripts'/'harbor_exception_policy.py'); assert spec and spec.loader
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
def result(exc=None,reward=1,include=True):
 d={'verifier_result':{'rewards':{'reward':reward}}}
 if include:d['exception_info']=exc
 return d
cases=[
 ('null',m.diagnose(0,result(None),artifact_complete=True),'NO_EXCEPTION','CLEAN_SUCCESS'),
 ('empty',m.diagnose(0,result(''),artifact_complete=True),'NO_EXCEPTION','CLEAN_SUCCESS'),
 ('harmless_text',m.diagnose(0,result(None),stdout='completed with no errors',artifact_complete=True),'NO_EXCEPTION','TEXT_MATCH_FALSE_POSITIVE'),
 ('fatal',m.diagnose(0,result({'exception_type':'HealthcheckError'}),artifact_complete=True),'STRUCTURED_FATAL_EXCEPTION','TRUE_FATAL_HARBOR_EXCEPTION'),
 ('nonzero_fatal',m.diagnose(2,result({'exception_type':'RuntimeError'}),artifact_complete=True),'STRUCTURED_FATAL_EXCEPTION','TRUE_FATAL_HARBOR_EXCEPTION'),
 ('reward_zero',m.diagnose(0,result(None,0),artifact_complete=True),'NO_EXCEPTION','OTHER_EVIDENCE_BACKED_FAILURE'),
 ('valid_pass',m.diagnose(0,result(None,1),artifact_complete=True),'NO_EXCEPTION','CLEAN_SUCCESS'),
 ('missing_structured',m.diagnose(0,result(include=False),artifact_complete=False),'PARSER_AMBIGUOUS','PARSER_AMBIGUOUS'),
]
for name,got,status,classification in cases:
 assert got['structured_exception_status']==status,(name,got); assert got['diagnostic_classification']==classification,(name,got); print('PASS',name)
print('HARBOR_EXCEPTION_POLICY=8/8 PASS')
