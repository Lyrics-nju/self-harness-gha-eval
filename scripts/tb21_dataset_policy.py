#!/usr/bin/env python3
"""Frozen TB2.1 dataset identifier policy for Harbor 0.21.0."""
from __future__ import annotations
from dataclasses import dataclass

CANONICAL_SLUG = "terminal-bench/terminal-bench-2-1"
EXPECTED_TASK_COUNT = 89
EXPECTED_TASK_ID_SHA256 = "8b7594d8cda7f423a5a487dfe30a83499bb76ab23384f6249484181b947441c2"
FORBIDDEN_FALLBACKS = {
    "terminal-bench/terminal-bench",
    "terminal-bench/terminal-bench-2",
}

@dataclass(frozen=True)
class DatasetReference:
    name: str
    ref: str
    resolver_family: str

def resolve_for_harbor_021(identifier: str) -> DatasetReference:
    """Accept only the canonical package-dataset slug; never reinterpret legacy labels."""
    if identifier in FORBIDDEN_FALLBACKS:
        raise ValueError("forbidden TB fallback")
    if identifier == "terminal-bench@2.1":
        raise ValueError("legacy name@version is not canonical TB2.1")
    if identifier != CANONICAL_SLUG:
        raise ValueError("unknown dataset identifier")
    return DatasetReference(name=CANONICAL_SLUG, ref="latest", resolver_family="package_dataset")
