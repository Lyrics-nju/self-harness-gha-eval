import hashlib, json
from pathlib import Path

ALLOWED = {"schema_version","candidate_id","parent_candidate_id","base_dsh_commit","experiment_status","instruction_bundle","runtime_policy_reference","skill_bundle_references","memory_bootstrap_reference","provenance","content_hashes"}
REQUIRED = {"schema_version","candidate_id","base_dsh_commit","experiment_status","instruction_bundle","runtime_policy_reference","skill_bundle_references","memory_bootstrap_reference","provenance","content_hashes"}

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",",":"), ensure_ascii=False).encode()

def digest(value): return hashlib.sha256(canonical(value)).hexdigest()

def confined(root: Path, relative: str) -> Path:
    if Path(relative).is_absolute(): raise ValueError("absolute path forbidden")
    target=(root/relative).resolve()
    if target != root.resolve() and root.resolve() not in target.parents: raise ValueError("path escape")
    return target

def load_spec(path: Path):
    value=json.loads(path.read_text())
    unknown=set(value)-ALLOWED
    missing=REQUIRED-set(value)
    if unknown: raise ValueError(f"unsupported fields: {sorted(unknown)}")
    if missing: raise ValueError(f"missing fields: {sorted(missing)}")
    if value["schema_version"]!="1.0.0": raise ValueError("unsupported schema")
    for key in ("source","created_by","purpose"):
        if not value["provenance"].get(key): raise ValueError(f"missing provenance.{key}")
    return value

def materialize(spec_path: Path, root: Path):
    spec=load_spec(spec_path); root=root.resolve(); root.mkdir(parents=True,exist_ok=True)
    candidate=confined(root,spec["candidate_id"]); candidate.mkdir(parents=False,exist_ok=False)
    patch=spec["instruction_bundle"].get("cordis_patch","plugins: []\n")
    (candidate/"candidate.cordis.patch.yml").write_text(patch)
    (candidate/"spec.json").write_bytes(canonical(spec)+b"\n")
    manifest={"candidate_id":spec["candidate_id"],"candidate_spec_sha256":digest(spec),"materialized_candidate_sha256":hashlib.sha256(patch.encode()).hexdigest()}
    (candidate/"manifest.json").write_text(json.dumps(manifest,sort_keys=True,indent=2)+"\n")
    return candidate,manifest

def create_run(root: Path, run_id: str):
    run=confined(root,run_id); run.mkdir(parents=True,exist_ok=False)
    paths={name:confined(run,name) for name in ["dsh-home","work","memory","artifacts","stdout.txt","stderr.txt","events"]}
    for name,p in paths.items():
        if p.suffix: p.touch()
        else: p.mkdir()
    return paths
