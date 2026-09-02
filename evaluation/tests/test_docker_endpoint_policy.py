#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
from pathlib import Path

root=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('policy',root/'scripts'/'docker_endpoint_policy.py'); assert spec and spec.loader
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
api='Docker-Distribution-API-Version: registry/2.0\n'
challenge='WWW-Authenticate: Bearer realm="https://auth.example.invalid/token"\n'
cases=[
 ('registry_200',('docker_registry_v2',0,200,api),True),
 ('registry_401_challenge',('docker_registry_v2',0,401,api+challenge),True),
 ('registry_401_no_challenge',('docker_registry_v2',0,401,api),False),
 ('registry_500',('docker_registry_v2',0,500,api),False),
 ('registry_tls_35',('docker_registry_v2',35,0,''),False),
 ('generic_200',('generic_https',0,200,''),True),
 ('generic_401',('generic_https',0,401,challenge),False),
]
for name,args,want in cases:
    got=m.evaluate(*args); assert (got['final_operation_result']=='PASS') is want,(name,got); print('PASS',name)
print('DOCKER_ENDPOINT_POLICY=7/7 PASS')
