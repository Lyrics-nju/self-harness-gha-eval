#!/usr/bin/env python3
from __future__ import annotations
import importlib.util, json, tempfile
from pathlib import Path

root=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('normalizer_v2',root/'evaluation'/'normalize_outcome_v2.py')
assert spec and spec.loader
normalizer=importlib.util.module_from_spec(spec); spec.loader.exec_module(normalizer)

def make(base: Path, name: str, *, reward=None, artifact=None, failed=None, exception=None, verifier_text='', agent_text='') -> Path:
    trial=base/name; (trial/'verifier').mkdir(parents=True); (trial/'agent').mkdir()
    data={'config':{'environment':{'type':'docker'}},'verifier_result':{'rewards':{}}}
    if reward is not None: data['verifier_result']['rewards']['reward']=reward
    if exception: data['exception_info']={'exception_type':exception}
    else: data['exception_info']=None
    (trial/'result.json').write_text(json.dumps(data))
    if artifact is not None: (trial/'verifier'/'reward.txt').write_text(str(artifact))
    if failed is not None: (trial/'verifier'/'ctrf.json').write_text(json.dumps({'results':{'summary':{'tests':1,'failed':failed}}}))
    if verifier_text: (trial/'verifier'/'test-stdout.txt').write_text(verifier_text)
    if agent_text: (trial/'agent'/'stdout.txt').write_text(agent_text)
    return trial

def expect(trial: Path, outcome: str, reason: str | None=None):
    got=normalizer.classify_trial(trial); assert got['outcome']==outcome,got
    if reason is not None: assert got['reason_code']==reason,got

with tempfile.TemporaryDirectory() as td:
    b=Path(td)
    cases=[
      ('pass',make(b,'pass',reward=1.0,artifact=1),'PASS',None),
      ('task_fail',make(b,'task_fail',reward=0.0,failed=1),'TASK_FAIL',None),
      ('v2_network',make(b,'v2_network',verifier_text='dependency bootstrap failed to download https://example.invalid/a; curl: (35) SSL connect error'),'VERIFIER_INFRA_ERROR','VERIFIER_DEPENDENCY_NETWORK_FAILURE'),
      ('v1_network',make(b,'v1_network',verifier_text='downloading uv 0.9.5 x86_64-unknown-linux-gnu\ncurl: (56) Failure when receiving data from the peer\nfailed to download https://github.com/astral-sh/uv/releases/download/0.9.5/'),'VERIFIER_INFRA_ERROR','VERIFIER_DEPENDENCY_NETWORK_FAILURE'),
      ('agent_timeout',make(b,'agent_timeout',exception='AgentTimeoutError'),'AGENT_TIMEOUT',None),
      ('environment',make(b,'environment',exception='EnvironmentStartTimeoutError'),'ENVIRONMENT_ERROR',None),
      ('ambiguous',make(b,'ambiguous',reward=0.0),'UNCLASSIFIED',None),
      ('agent_github',make(b,'agent_github',agent_text='pip install failed; curl: (35) against GitHub'),'UNCLASSIFIED',None),
      ('agent_cpython',make(b,'agent_cpython',agent_text='dependency failed to download CPython; curl: (35)'),'UNCLASSIFIED',None),
    ]
    for name,trial,outcome,reason in cases:
        expect(trial,outcome,reason); print('PASS',name)
print('NORMALIZER_V2=9/9 PASS')
