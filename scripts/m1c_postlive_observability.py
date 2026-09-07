#!/usr/bin/env python3
"""Raw-first, failure-safe evidence handling for the M1C.1 live workflow."""
from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

MAX_FILE_BYTES = 20_000_000


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def trial_candidates(jobs_dir: Path, job_name: str) -> list[Path]:
    """Follow Harbor 0.21.0's job/<dynamic trial id> contract."""
    job = jobs_dir / job_name
    if not job.is_dir():
        return []
    return sorted(path for path in job.iterdir() if path.is_dir()
                  and ((path / "config.json").is_file() or (path / "result.json").is_file()))


def discover_trial(jobs_dir: Path, job_name: str) -> dict:
    candidates = trial_candidates(jobs_dir, job_name)
    results = [path for path in candidates if (path / "result.json").is_file()]
    if len(candidates) == 1 and len(results) == 1:
        trial = candidates[0]
        return {"status": "PRESENT", "trial_dir": str(trial), "trial_id": trial.name,
                "result_path": str(trial / "result.json"), "candidate_count": 1}
    if not candidates:
        return {"status": "ABSENT", "trial_dir": None, "trial_id": None, "result_path": None,
                "candidate_count": 0, "blocker": "M1C_HARBOR_TRIAL_NOT_FOUND"}
    if len(candidates) == 1:
        return {"status": "ABSENT", "trial_dir": str(candidates[0]), "trial_id": candidates[0].name,
                "result_path": None, "candidate_count": 1, "blocker": "M1C_TRIAL_RESULT_ABSENT"}
    return {"status": "PARSE_FAILED", "trial_dir": None, "trial_id": None, "result_path": None,
            "candidate_count": len(candidates), "candidates": [p.name for p in candidates],
            "blocker": "M1C_HARBOR_TRIAL_AMBIGUOUS"}


def _safe_copy_tree(source: Path, target: Path, credential: str, credential_name: str = "") -> list[dict]:
    records: list[dict] = []
    if not source.exists():
        return records
    paths = [source] if source.is_file() else sorted(p for p in source.rglob("*") if p.is_file())
    for path in paths:
        relative = Path(path.name) if source.is_file() else path.relative_to(source)
        record = {"path": relative.as_posix()}
        try:
            size = path.stat().st_size
            if size > MAX_FILE_BYTES:
                record.update(status="NOT_AVAILABLE", reason="FILE_TOO_LARGE", size=size)
                records.append(record)
                continue
            data = path.read_bytes()
            if credential:
                data = data.replace(credential.encode(), b"[REDACTED]")
            if credential_name:
                data = data.replace(credential_name.encode(), b"[REDACTED_CREDENTIAL_NAME]")
            destination = target / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
            record.update(status="PRESENT", size=len(data), sha256=sha256(destination))
        except OSError as exc:
            record.update(status="NOT_AVAILABLE", reason=type(exc).__name__)
        records.append(record)
    return records


def capture_raw(root: Path, job_name: str, credential: str = "", credential_name: str = "") -> dict:
    """Capture process/job evidence before parsing or normalization."""
    raw = root / "reports/raw-evidence"
    if raw.exists():
        shutil.rmtree(raw)
    raw.mkdir(parents=True)
    sources = {
        "harbor-stdout": root / "work/runtime/stdout.txt",
        "harbor-stderr": root / "work/runtime/stderr.txt",
        "harbor-job": root / "work/jobs" / job_name,
    }
    records: dict[str, object] = {}
    for name, source in sources.items():
        records[name] = (_safe_copy_tree(source, raw / name, credential, credential_name) if source.exists()
                         else [{"path": ".", "status": "ABSENT"}])
    marker_records = []
    for marker in ("PRE_MODEL_GATE_COMPLETED", "MODEL_EXPOSURE_START", "harbor-process.json"):
        path = root / "reports" / marker
        marker_records.extend(_safe_copy_tree(path, raw / "markers" / marker, credential, credential_name) if path.exists()
                              else [{"path": marker, "status": "ABSENT"}])
    records["markers"] = marker_records
    discovery = discover_trial(root / "work/jobs", job_name)
    write_json(raw / "result-discovery.json", discovery)
    event_files = sorted(
        path.relative_to(raw).as_posix() for path in raw.rglob("*")
        if path.is_file() and path.suffix in {".jsonl", ".sqlite", ".db"}
        and ("session" in path.as_posix().lower() or "event" in path.as_posix().lower())
    )
    request = provider_evidence(raw)
    scientific = {
        "trial_result": discovery["status"],
        "dsh_event_or_session_evidence": "PRESENT" if event_files else "ABSENT",
        "dsh_event_or_session_paths": event_files,
        "provider_request_evidence": request["status"],
        "provider_request_count": request["provider_request_count"],
        "usage_metadata": "NOT_AVAILABLE",
        "derived_normalization": "NOT_REACHED",
    }
    manifest = {"schema_version": 1, "raw_capture": "PASS", "sources": records,
                "result_discovery": discovery, "scientific_evidence": scientific}
    write_json(root / "reports/raw-capture-manifest.json", manifest)
    return manifest


def parse_result(discovery: dict) -> tuple[dict | None, str]:
    if discovery.get("status") != "PRESENT":
        return None, str(discovery.get("status", "NOT_AVAILABLE"))
    try:
        value = json.loads(Path(str(discovery["result_path"])).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, "PARSE_FAILED"
    return (value, "PRESENT") if isinstance(value, dict) else (None, "PARSE_FAILED")


def provider_evidence(raw_root: Path) -> dict:
    """Use only explicit counters or request-start events already emitted by DSH."""
    explicit = []
    event_names = {"provider_request", "provider_request_started", "llm_request", "model_request"}
    for path in sorted(p for p in raw_root.rglob("*") if p.is_file() and p.stat().st_size <= MAX_FILE_BYTES):
        try:
            for line_no, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
                try:
                    value = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(value, dict):
                    continue
                for key in ("provider_request_count", "api_request_count", "request_count"):
                    count = value.get(key)
                    if isinstance(count, int) and count >= 0:
                        explicit.append({"path": str(path), "line": line_no, "kind": key, "count": count})
                event = value.get("event") or value.get("type") or value.get("name")
                if event in event_names:
                    explicit.append({"path": str(path), "line": line_no, "kind": "event", "count": 1})
        except OSError:
            continue
    if not explicit:
        return {"status": "NOT_AVAILABLE", "provider_request_count": None, "evidence": []}
    return {"status": "PRESENT", "provider_request_count": sum(e["count"] for e in explicit),
            "evidence": explicit}


def build_partial_manifest(root: Path, stage_root: Path, expected: dict[str, str]) -> dict:
    """Stage available evidence; optional absence is represented, never fatal."""
    if stage_root.exists():
        shutil.rmtree(stage_root)
    stage_root.mkdir(parents=True)
    entries = []
    for name, relative in sorted(expected.items()):
        source = root / relative
        if source.is_dir():
            copied = _safe_copy_tree(source, stage_root / relative, "")
            entries.append({"name": name, "status": "PRESENT", "path": relative, "files": len(copied)})
        elif source.is_file():
            target = stage_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            entries.append({"name": name, "status": "PRESENT", "path": relative})
        else:
            entries.append({"name": name, "status": "ABSENT", "path": relative})
    manifest = {"schema_version": 1,
                "status_vocabulary": ["PRESENT", "ABSENT", "NOT_REACHED", "PARSE_FAILED", "NOT_AVAILABLE"],
                "entries": entries}
    write_json(stage_root / "EVIDENCE_MANIFEST.json", manifest)
    files = sorted(p for p in stage_root.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
    (stage_root / "SHA256SUMS").write_text(
        "".join(f"{sha256(path)}  {path.relative_to(stage_root).as_posix()}\n" for path in files),
        encoding="utf-8")
    return manifest
