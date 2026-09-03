#!/usr/bin/env python3
from __future__ import annotations

import hashlib

DATASET = "terminal-bench/terminal-bench-2-1"
DIGEST = "7d7bdc1cbedad549fc1140404bd4dc45e5fd0ea7c4186773687d177ad3a0699a"
TASK_COUNT = 89
INDICES = (0, 22, 44, 66, 88)
TASKS = (
    "terminal-bench/adaptive-rejection-sampler",
    "terminal-bench/extract-elf",
    "terminal-bench/make-doom-for-mips",
    "terminal-bench/pytorch-model-recovery",
    "terminal-bench/write-compressor",
)


def select(sorted_ids: list[str]) -> list[str]:
    if len(sorted_ids) != TASK_COUNT or sorted_ids != sorted(sorted_ids, key=lambda s: s.encode()):
        raise ValueError("task list is not the frozen 89-entry C/bytewise ordering")
    selected = [sorted_ids[i] for i in INDICES]
    if tuple(selected) != TASKS:
        raise ValueError("frozen task selection drift")
    return selected


def task_id_sha256(ids: list[str]) -> str:
    return hashlib.sha256(("\n".join(ids) + "\n").encode()).hexdigest()
