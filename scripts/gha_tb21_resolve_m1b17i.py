#!/usr/bin/env python3
from __future__ import annotations
import asyncio, json
from pathlib import Path
from harbor.auth.credentials import resolve_api_key
from harbor.db.client import RegistryDB
from harbor.registry.client.package import PackageDatasetClient
from m1b17i_task_policy import DATASET,DIGEST,TASK_COUNT,INDICES,TASKS,select,task_id_sha256

async def main():
    if resolve_api_key() is not None: raise SystemExit('anonymous public resolution required')
    org,name=DATASET.split('/',1)
    kind=await RegistryDB().get_package_type(org=org,name=name)
    metadata=await PackageDatasetClient().get_dataset_metadata(f'{DATASET}@sha256:{DIGEST}')
    ids=sorted((x.get_name() for x in metadata.task_ids),key=lambda s:s.encode())
    selected=select(ids)
    ok=(kind=='dataset' and metadata.name==DATASET and metadata.dataset_version_content_hash==DIGEST and len(ids)==TASK_COUNT and tuple(selected)==TASKS)
    evidence={'harbor_version':'0.21.0','anonymous_public_access':True,'requested_identifier':DATASET,'requested_immutable_version':f'sha256:{DIGEST}','resolved_identifier':metadata.name,'resolved_version':metadata.version,'resolved_content_hash':metadata.dataset_version_content_hash,'task_count':len(ids),'task_id_sha256':task_id_sha256(ids),'selection_indices':list(INDICES),'selected_tasks':selected,'identity_match_17g_17h':'PASS' if ok else 'FAIL'}
    Path('reports/dataset_resolution.json').write_text(json.dumps(evidence,indent=2)+'\n')
    Path('reports/m1b17i_selected_tasks.json').write_text(json.dumps({'selection_order':'C_BYTEWISE','population':TASK_COUNT,'indices':list(INDICES),'tasks':selected},indent=2)+'\n')
    print(json.dumps(evidence,sort_keys=True))
    if not ok: raise SystemExit('TB21_DATASET_IDENTITY_DRIFT')
asyncio.run(main())
