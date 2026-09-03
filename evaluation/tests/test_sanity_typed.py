#!/usr/bin/env python3
from __future__ import annotations
import importlib.util,sys,tempfile
from pathlib import Path
root=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('sanity_typed',root/'scripts'/'sanity_typed.py'); assert spec and spec.loader
p=importlib.util.module_from_spec(spec);sys.modules[spec.name]=p;spec.loader.exec_module(p)

cases=[(True,True),(False,False),('true',True),('false',False),(1,True),(0,False),('1',True),('0',False)]
for value,want in cases: assert p.parse_bool(value) is want; print('PASS',repr(value))
for value in ('yes','',None):
    try:p.parse_bool(value);raise AssertionError(value)
    except p.ParserError:print('PASS reject',repr(value))
fixture='''operation,category,target,success,exit_code,http_status,tls_failure,dns_failure,timeout
1,host_github,https://github.com/,1,0,200,0,0,0
2,host_github,https://github.com/,1,0,200,0,0,0
3,docker_registry,https://registry-1.docker.io/v2/,1,0,401,false,false,false
4,docker_registry,https://registry-1.docker.io/v2/,1,0,401,false,false,false
5,container_github,https://github.com/,1,0,200,0,0,0
6,container_github,https://github.com/,1,0,200,0,0,0
'''
with tempfile.TemporaryDirectory() as td:
    path=Path(td)/'17i.csv';path.write_text(fixture);doc=p.convert_csv(path);result=p.aggregate(doc)
    assert result['overall_pass'] is True and result['pass_counts']=={'host_github':2,'docker_registry':2,'container_github':2}
    assert all(result[k]==0 for k in ('curl_exit_35','tls_failure','dns_failure','timeout'));print('PASS preserved_17i_fixture')
print('SANITY_TYPED_BOOLEAN=12/12 PASS')
