#!/usr/bin/env python3
from __future__ import annotations
import asyncio,json
from pathlib import Path
from harbor.auth.credentials import resolve_api_key
from harbor.db.client import RegistryDB
from harbor.registry.client.package import PackageDatasetClient

SLUG='terminal-bench/terminal-bench-2-1'
DIGEST='7d7bdc1cbedad549fc1140404bd4dc45e5fd0ea7c4186773687d177ad3a0699a'
SELECTED='terminal-bench/adaptive-rejection-sampler'
async def main():
 if resolve_api_key() is not None:raise SystemExit('anonymous public resolution required')
 org,name=SLUG.split('/',1); kind=await RegistryDB().get_package_type(org=org,name=name)
 metadata=await PackageDatasetClient().get_dataset_metadata(f'{SLUG}@sha256:{DIGEST}')
 ids=sorted(x.get_name() for x in metadata.task_ids)
 ok=kind=='dataset' and metadata.name==SLUG and metadata.dataset_version_content_hash==DIGEST and len(ids)==89 and SELECTED in ids
 evidence={'harbor_version':'0.21.0','anonymous_public_access':True,'requested_identifier':SLUG,'requested_immutable_version':f'sha256:{DIGEST}','resolved_identifier':metadata.name,'resolved_version':metadata.version,'resolved_content_hash':metadata.dataset_version_content_hash,'task_count':len(ids),'selected_task_present':SELECTED in ids,'identity_match_17g':ok}
 Path('reports/dataset_resolution.json').write_text(json.dumps(evidence,indent=2)+'\n');print(json.dumps(evidence,sort_keys=True))
 if not ok:raise SystemExit(1)
asyncio.run(main())
