#!/usr/bin/env python3
"""Entrypoint for the no-model 1536 MiB host-TSC feasibility probe."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import gha_m1c1_container_build_probe as base

AGENT = "evaluation.agents.dsh_harbor_adapter.tsc_1536_probe:DshHarborTsc1536FeasibilityProbe"

if __name__ == "__main__":
    base.SUBSTAGE_FORENSIC_AGENT = AGENT
    raise SystemExit(base.stage(Path.cwd().resolve()) if len(sys.argv) > 1 and sys.argv[1] == "stage" else base.probe(Path.cwd().resolve(), substage=True))
