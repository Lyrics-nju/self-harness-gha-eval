#!/usr/bin/env python3
from __future__ import annotations
import argparse,asyncio,hashlib,json,os,subprocess,time
from pathlib import Path
from harbor.auth.credentials import resolve_api_key
from harbor.db.client import RegistryDB
from harbor.registry.client.package import PackageDatasetClient
from tb21_dataset_policy import CANONICAL_SLUG,EXPECTED_TASK_COUNT,EXPECTED_TASK_ID_SHA256,resolve_for_harbor_021

def digest_file(path:Path)->str:return hashlib.sha256(path.read_bytes()).hexdigest()
def tree_digest(root:Path,files:list[Path])->str:
 h=hashlib.sha256()
 for p in files:h.update(p.relative_to(root).as_posix().encode());h.update(b'\0');h.update(bytes.fromhex(digest_file(p)))
 return h.hexdigest()
async def discover():
 ref=resolve_for_harbor_021(CANONICAL_SLUG); org,name=ref.name.split('/',1)
 kind=await RegistryDB().get_package_type(org=org,name=name)
 if kind!='dataset':raise RuntimeError(f'expected dataset package, got {kind!r}')
 metadata=await PackageDatasetClient().get_dataset_metadata(f'{ref.name}@{ref.ref}')
 return ref,metadata

pa=argparse.ArgumentParser();pa.add_argument('--output-dir',type=Path,required=True);pa.add_argument('--reports',type=Path,required=True);a=pa.parse_args()
a.reports.mkdir(parents=True,exist_ok=True);a.output_dir.mkdir(parents=True,exist_ok=True)
anonymous=resolve_api_key() is None
if not anonymous:raise SystemExit('Refusing credentialed diagnostic; public anonymous access is required')
start=time.monotonic(); before=os.statvfs('/'); before_free=before.f_bavail*before.f_frsize
ref,metadata=asyncio.run(discover())
metadata_ids=sorted(x.get_name() for x in metadata.task_ids)
if len(metadata_ids)!=EXPECTED_TASK_COUNT:raise SystemExit(f'metadata task count {len(metadata_ids)} != 89')
stdout=a.reports/'materialization.stdout';stderr=a.reports/'materialization.stderr'
with stdout.open('w') as so,stderr.open('w') as se:
 proc=subprocess.run(['harbor','download',CANONICAL_SLUG,'--output-dir',str(a.output_dir),'--export'],stdout=so,stderr=se,text=True,check=False)
if proc.returncode:raise SystemExit(f'harbor download failed with exit {proc.returncode}')
root=a.output_dir/'terminal-bench-2-1'
if not root.is_dir():raise SystemExit(f'expected export root missing: {root}')
task_dirs=sorted(p for p in root.iterdir() if p.is_dir())
task_ids=sorted(f'terminal-bench/{p.name}' for p in task_dirs)
(a.reports/'task_ids.txt').write_text('\n'.join(task_ids)+'\n')
ids_sha=digest_file(a.reports/'task_ids.txt')
if task_ids!=metadata_ids:raise SystemExit('materialized task IDs differ from resolved metadata')
if len(task_ids)!=EXPECTED_TASK_COUNT or ids_sha!=EXPECTED_TASK_ID_SHA256:raise SystemExit('task-ID identity mismatch')
files=sorted(p for d in task_dirs for p in d.rglob('*') if p.is_file())
with (a.reports/'content_manifest.txt').open('w') as f:
 for p in files:f.write(f'{digest_file(p)}  {p.relative_to(root).as_posix()}\n')
all_files=sorted(p for p in root.rglob('*') if p.is_file()); after=os.statvfs('/'); after_free=after.f_bavail*after.f_frsize
identity={'harbor_version':'0.21.0','anonymous_public_access':anonymous,'requested_identifier':CANONICAL_SLUG,'resolver_family':ref.resolver_family,'resolver_ref':ref.ref,'resolved_identifier':metadata.name,'resolved_version':metadata.version,'dataset_version_id':metadata.dataset_version_id,'dataset_version_content_hash':metadata.dataset_version_content_hash,'metadata_task_count':len(metadata_ids),'materialized_task_count':len(task_ids),'task_id_sha256':ids_sha,'task_id_identity':task_ids==metadata_ids and ids_sha==EXPECTED_TASK_ID_SHA256,'materialized_path':str(root),'canonical_task_file_count':len(files),'canonical_content_manifest_sha256':digest_file(a.reports/'content_manifest.txt'),'full_export_file_count':len(all_files),'full_export_tree_digest':tree_digest(root,all_files),'historical_local_tree_digest_match':len(all_files)==946 and tree_digest(root,all_files)=='2326c348875770eecf68f7097a25c8a5fbaed60976a0ce6ca1b12b8d8519bd7c','disk_before_bytes':before_free,'disk_after_bytes':after_free,'wall_seconds':round(time.monotonic()-start,3),'harbor_process_exit':proc.returncode,'benchmark_trials_executed':0}
(a.reports/'dataset_identity.json').write_text(json.dumps(identity,indent=2)+'\n')
print(json.dumps(identity,sort_keys=True))
