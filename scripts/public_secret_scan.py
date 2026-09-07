#!/usr/bin/env python3
"""Fail-closed public artifact scanner with value-aware structured handling."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

SAFE_SENTINELS = {"REDACTED", "[REDACTED]", "***", "MASKED", "NOT_AVAILABLE", "ABSENT", "NULL"}
SENSITIVE_KEYS = {
    "DEEPSEEK_API_KEY", "DAYTONA_API_KEY", "MIMO_API_KEY", "AWS_SECRET_ACCESS_KEY",
    "AZURE_CLIENT_SECRET", "GOOGLE_API_KEY", "GITHUB_TOKEN", "AUTHORIZATION", "PASSWORD", "COOKIE",
}
KEY_ASSIGNMENT = re.compile(r"(?i)\b(" + "|".join(re.escape(k) for k in sorted(SENSITIVE_KEYS)) + r")\b\s*[:=]\s*(.+?)\s*$")
BEARER = re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+(\S+)")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:OPENSSH|RSA|EC|DSA|PRIVATE) PRIVATE KEY-----")
KNOWN_TOKEN = re.compile(r"\b(?:gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")


@dataclass(frozen=True)
class Finding:
    path: str
    rule_id: str
    location: str
    field_name: str | None = None
    candidate_length: int | None = None
    candidate_digest: str | None = None

    def diagnostic(self) -> str:
        fields = [self.path, self.rule_id, self.location]
        if self.field_name:
            fields.append("field=" + self.field_name)
        if self.candidate_length is not None:
            fields.append("candidate_length=" + str(self.candidate_length))
        if self.candidate_digest:
            fields.append("candidate_sha256=" + self.candidate_digest)
        return "\t".join(fields)


def _safe(value: object) -> bool:
    return value is None or (isinstance(value, str) and value.strip().upper() in SAFE_SENTINELS)


def _safe_text_value(value: str) -> bool:
    clean = value.strip().strip('"\'')
    return clean.upper() in SAFE_SENTINELS or bool(re.fullmatch(r"\$\{\{\s*secrets\.[A-Z0-9_]+\s*\}\}", clean, re.I))


def _finding(path: str, rule: str, location: str, value: object = None, field: str | None = None) -> Finding:
    raw = value if isinstance(value, str) else json.dumps(value, sort_keys=True, separators=(",", ":"))
    encoded = raw.encode("utf-8", errors="replace")
    return Finding(path, rule, location, field, len(encoded), hashlib.sha256(encoded).hexdigest()[:16])


def _scan_structured(value: object, rel: str, location: str = "$") -> list[Finding]:
    findings: list[Finding] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{location}.{key}"
            if key.upper() in SENSITIVE_KEYS and not _safe(item):
                findings.append(_finding(rel, "SENSITIVE_FIELD_UNREDACTED", child, item, key))
            findings.extend(_scan_structured(item, rel, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(_scan_structured(item, rel, f"{location}[{index}]"))
    return findings


def _scan_text(text: str, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        for match in KEY_ASSIGNMENT.finditer(line):
            value = match.group(2).strip().strip('"\'')
            if not _safe_text_value(value):
                findings.append(_finding(rel, "SENSITIVE_ASSIGNMENT_UNREDACTED", f"line:{line_no}", value, match.group(1).upper()))
        match = BEARER.search(line)
        if match and match.group(1).upper() not in SAFE_SENTINELS:
            findings.append(_finding(rel, "AUTHORIZATION_BEARER_VALUE", f"line:{line_no}", match.group(1), "AUTHORIZATION"))
        match = KNOWN_TOKEN.search(line)
        if match:
            findings.append(_finding(rel, "KNOWN_TOKEN_FORMAT", f"line:{line_no}", match.group(0)))
        if PRIVATE_KEY.search(line):
            findings.append(Finding(rel, "PRIVATE_KEY_MATERIAL", f"line:{line_no}"))
    return findings


def scan_tree(root: Path, artifact_mode: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts
                       and "__pycache__" not in p.parts and p.suffix != ".pyc"):
        rel = path.relative_to(root).as_posix()
        if not artifact_mode and (rel.startswith("runtime/") or rel.startswith("work/")):
            findings.append(Finding(rel, "FORBIDDEN_PATH", "path"))
        if path.name == ".env" or path.name.startswith(".env.") or path.suffix == ".pem":
            findings.append(Finding(rel, "CREDENTIAL_FILE", "path"))
        try:
            text = path.read_text(errors="replace")
        except OSError:
            findings.append(Finding(rel, "UNREADABLE_FILE", "path")); continue
        parsed = None
        if path.suffix.lower() == ".json":
            try:
                parsed = json.loads(text)
            except ValueError:
                parsed = None
        findings.extend(_scan_structured(parsed, rel) if parsed is not None else _scan_text(text, rel))
        low = (rel + "\n" + text).lower()
        provider_needles = ("subscription" + ".secret", "provider_" + "raw.yaml", "config." + "runtime.yaml", "fixed-" + "node", "miho" + "mo")
        if any(n in low for n in provider_needles):
            findings.append(Finding(rel, "PROVIDER_OR_PROXY_CONFIG", "content"))
        private_needles = ("private " + "trajectory", "private model " + "trace")
        if any(n in low for n in private_needles):
            findings.append(Finding(rel, "PRIVATE_ARTIFACT", "content"))
        local_needles = ("/home/" + "liujr/", "/mnt/c/users/" + "administrator/")
        if any(n in low for n in local_needles):
            findings.append(Finding(rel, "LOCAL_PRIVATE_PATH", "content"))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-mode", action="store_true")
    parser.add_argument("root", nargs="?", default=".")
    args = parser.parse_args()
    findings = scan_tree(Path(args.root), args.artifact_mode)
    for finding in findings:
        print(finding.diagnostic())
    if findings:
        return 1
    print("ARTIFACT_SECRET_SCAN_PASS" if args.artifact_mode else "SECRET_SCAN_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
