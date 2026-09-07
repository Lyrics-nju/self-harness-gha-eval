#!/usr/bin/env python3
"""Deterministic no-model qualification for secret scanning and safe-core survival."""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from m1c_postlive_observability import build_safe_core, sha256, write_json
from public_secret_scan import scan_tree


def main() -> int:
    root = Path.cwd()
    work = root / "work/evidence-safety-probe"
    if work.exists(): shutil.rmtree(work)
    safe_bulk = work / "safe-bulk"
    unsafe_bulk = work / "unsafe-bulk"
    safe_bulk.mkdir(parents=True); unsafe_bulk.mkdir(parents=True)
    key = "DEEPSEEK_" + "API_KEY"
    write_json(safe_bulk / "sanitized-trial-result.json", {"credential_environment_name": key, key: "REDACTED"})
    write_json(unsafe_bulk / "synthetic-unsafe.json", {key: "synthetic-fixture-value-not-a-real-credential"})
    safe_bulk_findings = scan_tree(safe_bulk, artifact_mode=True)
    unsafe_bulk_findings = scan_tree(unsafe_bulk, artifact_mode=True)
    if safe_bulk_findings or not unsafe_bulk_findings:
        return 1
    os.environ["M1C_BULK_STATUS"] = "BLOCKED_BY_SECRET_SCAN"
    evidence = build_safe_core(work, "synthetic-job", "terminal-bench/synthetic-no-model")
    safe_core_findings = scan_tree(work / "safe-core-stage", artifact_mode=True)
    if safe_core_findings or evidence["provider_request_status"] != "NOT_REACHED":
        return 1
    artifact = root / "evidence-safety-artifact"
    if artifact.exists(): shutil.rmtree(artifact)
    shutil.copytree(work / "safe-core-stage", artifact)
    write_json(artifact / "qualification.json", {
        "classification": "M1C_GHA_EVIDENCE_SAFETY_QUALIFIED",
        "credential_name_redacted_value": "PASS",
        "synthetic_credential_value_rejected": True,
        "unsafe_bulk_uploaded": False,
        "safe_core_uploadable": True,
        "bulk_status": "BLOCKED_BY_SECRET_SCAN",
        "provider_requests": 0,
        "deepseek_requests": 0,
        "live_trials": 0,
        "dsh_live_sessions": 0,
        "secret_accesses": 0,
    })
    files = sorted(p for p in artifact.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    (artifact / "SHA256SUMS").write_text("".join(f"{sha256(p)}  {p.name}\n" for p in files))
    return 0 if not scan_tree(artifact, artifact_mode=True) else 1


if __name__ == "__main__": raise SystemExit(main())
