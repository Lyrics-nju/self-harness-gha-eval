#!/usr/bin/env python3
from __future__ import annotations
import argparse, re
from pathlib import Path

def evaluate(endpoint_class: str, curl_exit: int, http_status: int, headers: str) -> dict:
    low=headers.lower()
    transport_ok=curl_exit==0
    auth=bool(re.search(r'(?im)^www-authenticate:\s*(?:bearer|basic)\b',headers))
    api=bool(re.search(r'(?im)^docker-distribution-api-version:\s*registry/2\.0\s*$',headers))
    tls=curl_exit==35; dns=curl_exit==6; timeout=curl_exit==28
    if endpoint_class=='docker_registry_v2':
        expected='200 or 401+registry-auth-challenge'
        passed=transport_ok and (http_status==200 or (http_status==401 and auth and api))
    elif endpoint_class=='generic_https':
        expected='200'
        passed=transport_ok and http_status==200
    else: raise ValueError(f'unknown endpoint class: {endpoint_class}')
    return {'endpoint_class':endpoint_class,'transport_ok':transport_ok,'curl_exit_code':curl_exit,'http_status':http_status,'expected_status':expected,'auth_challenge_present':auth,'registry_api_header_present':api,'tls_failure':tls,'dns_failure':dns,'timeout':timeout,'final_operation_result':'PASS' if passed else 'FAIL'}

def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument('endpoint_class'); p.add_argument('curl_exit',type=int); p.add_argument('http_status',type=int); p.add_argument('headers',type=Path); a=p.parse_args()
    r=evaluate(a.endpoint_class,a.curl_exit,a.http_status,a.headers.read_text(errors='replace'))
    print(','.join(str(r[k]).lower() if isinstance(r[k],bool) else str(r[k]) for k in ('transport_ok','curl_exit_code','http_status','expected_status','auth_challenge_present','registry_api_header_present','tls_failure','dns_failure','timeout','final_operation_result')))
    return 0 if r['final_operation_result']=='PASS' else 1
if __name__=='__main__': raise SystemExit(main())
