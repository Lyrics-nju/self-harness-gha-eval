#!/usr/bin/env python3
"""Strictly convert legacy sanity CSV booleans, then aggregate typed JSON."""
from __future__ import annotations
import argparse,csv,json,sys
from pathlib import Path

class ParserError(ValueError): pass

def parse_bool(value):
    if isinstance(value,bool): return value
    if isinstance(value,int) and not isinstance(value,bool):
        if value in (0,1): return value==1
        raise ParserError(f'invalid integer boolean: {value!r}')
    if isinstance(value,str):
        if value in ('true','1'): return True
        if value in ('false','0'): return False
    raise ParserError(f'invalid boolean encoding: {value!r}')

def convert_csv(path:Path,docker_basic=True)->dict:
    operations=[]
    with path.open(newline='') as f:
        for row in csv.DictReader(f):
            try:
                operations.append({'operation':int(row['operation']),'category':row['category'],'target':row['target'],'operation_pass':parse_bool(row['success']),'curl_exit_code':int(row['exit_code']),'http_status':int(row['http_status']),'curl_exit_35':int(row['exit_code'])==35,'tls_failure':parse_bool(row['tls_failure']),'dns_failure':parse_bool(row['dns_failure']),'timeout':parse_bool(row['timeout'])})
            except (KeyError,TypeError,ValueError) as exc: raise ParserError(f'invalid operation row: {exc}') from exc
    return {'schema_version':'1.0.0','docker_basic':parse_bool(docker_basic),'operations':operations}

def aggregate(document:dict)->dict:
    if not isinstance(document,dict) or not isinstance(document.get('operations'),list): raise ParserError('operations must be a list')
    ops=document['operations']; docker_basic=document.get('docker_basic')
    if not isinstance(docker_basic,bool): raise ParserError('docker_basic must be JSON boolean')
    for op in ops:
        if not isinstance(op,dict): raise ParserError('operation must be an object')
        for key in ('operation_pass','curl_exit_35','tls_failure','dns_failure','timeout'):
            if not isinstance(op.get(key),bool): raise ParserError(f'{key} must be JSON boolean')
    counts={name:sum(op.get('category')==name and op['operation_pass'] for op in ops) for name in ('host_github','docker_registry','container_github')}
    expected={'host_github':2,'docker_registry':2,'container_github':2}
    failures={key:sum(op[key] for op in ops) for key in ('curl_exit_35','tls_failure','dns_failure','timeout')}
    passed=docker_basic and len(ops)==6 and counts==expected and all(op['operation_pass'] for op in ops) and not any(failures.values())
    return {'schema_version':'1.0.0','docker_basic':docker_basic,'operation_count':len(ops),'pass_counts':counts,'expected_counts':expected,**failures,'parser_errors':0,'overall_pass':passed,'classification':'PASS' if passed else 'GHA_17J_SANITY_INFRA_BLOCKER'}

def main():
    p=argparse.ArgumentParser();p.add_argument('--csv',type=Path,required=True);p.add_argument('--docker-basic',required=True);p.add_argument('--structured',type=Path,required=True);p.add_argument('--aggregate',type=Path,required=True);a=p.parse_args()
    try:
        document=convert_csv(a.csv,a.docker_basic); a.structured.write_text(json.dumps(document,indent=2)+'\n')
        # Deliberately round-trip: aggregation consumes JSON booleans, not CSV text.
        result=aggregate(json.loads(a.structured.read_text())); a.aggregate.write_text(json.dumps(result,indent=2)+'\n')
    except ParserError as exc:
        print(f'GHA_17J_SANITY_PARSER_BLOCKER PARSER_ERROR: {exc}',file=sys.stderr); return 3
    print(json.dumps(result,sort_keys=True))
    return 0 if result['overall_pass'] else 2
if __name__=='__main__': raise SystemExit(main())
