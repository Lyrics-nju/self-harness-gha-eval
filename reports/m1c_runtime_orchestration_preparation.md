# Artifact V1 bounded orchestration preparation

Date: 2026-10-08. Required parent: `3852d4e3c15ca9d1937a9c4999cd40cd86821886`.
Local implementation and offline fixtures only. No external execution was authorized or performed.

## Storage semantics

The frozen task configuration remains 1 CPU, 2048 MiB memory and 10240 MiB storage.
Storage is `NOT_ENFORCED_BY_CURRENT_BACKEND`, not an enforced hard quota.
The accepted overall status is `TASK_RESOURCE_BASELINE_PRESERVED_WITH_STORAGE_GAP`;
`all_resource_limits_enforced` and `hard_quota_verified` remain false.

The gate binds original task-config bytes, exact frozen image/platform mapping,
Harbor 0.21.0 source hashes (including the entire environment implementation and
Docker templates), capability declarations and absence of storage writer support.
It requires actual Docker CPU/memory limits and matching cgroup v2 read-back.
Unknown capability, source drift, overrides, unexplained mounts, StorageOpt,
config or effective-limit conflicts prevent materialization. No quota is added.
The remaining evidence gap is real storage quota enforcement: deliberately absent.
Disk free space, artifact/staging size and disk-exhaustion log evidence are only
capacity diagnostics, never proof of a 10240 MiB quota.

## Fixed execution chain prepared, not executed

Dedicated manual workflow, no arbitrary dispatch inputs and no model secret access:

1. Download the exact previously qualified census artifact; verify its frozen map.
2. Verify explicit toolchain inputs and context; create one immutable builder candidate.
3. Read back actual image/Node/ABI/Corepack/pnpm identity and actual capacity.
4. Gate DSH dependency installation/build; recheck capacity immediately before build.
5. Build pinned DSH without inherited heap flags; save full stdout/stderr and resource diagnostics.
6. Package one conservative universal artifact **candidate**; independently verify
   archive/manifest/receipt, native inventory hashes and readelf dependency metadata.
7. Resolve only the fixed task via the pinned dataset. Pull only its immutable
   linux/amd64 platform digest. Use actual Harbor DockerEnvironment setup, not a
   substitute plain-Docker task, Agent, Trial executor or benchmark command.
8. Read back original task resource configuration, effective CPU/memory,
   backend storage gap, image, network and mount identity before materialization.
9. Materialize into a read-only mounted program-parent directory; verify both
   host and actual container-visible trees. Execute only the fixed no-model
   CLI/native probe from isolated scratch, with an empty credential environment.
10. Verify resources/program again, clean up owned containers/image, and independently
    scan SAFE CORE, bulk diagnostics and the program before any uploads.

Failure blocks the next handoff; no retry exists. Unsafe bulk is not uploaded.
SAFE CORE remains independently available for missing/bad program evidence, but
cannot report qualification success after scanner/integrity failure. Mock success
is always `MOCK_EXECUTION_ONLY`, never real-container qualification.

## External execution remains unproven

Registry/package availability, retained census artifact, final builder image ID,
actual runner CPU/memory/disk capacity, production DSH build, cgroup v2 baseline,
task mounts and native ABI/runtime behavior still require separately authorized
external execution. If any gate fails, stop without speculative correction.
One-task success will not prove universal compatibility or qualify all 24 tasks.

## Local verification

Targeted Artifact V1/identity/orchestration: 100/100.
All relevant M1C suites: 529/529. Skipped: 0.
Frozen Docker/Harbor/Normalizer/dataset regressions: 32/32.
Structured secret-scanner regressions: 12/12.
Publication manifest staging (137 files), strict secret scan, workflow YAML
(18 workflows), fixed JS probe syntax and diff checks: PASS.
Real Docker/build/native tests: NOT_RUN, not PASS.

## Changed files

- `.github/workflows/gha-m1c1-runtime-artifact.yml`
- `configs/m1c_runtime_backend_v1.json`
- `configs/m1c_runtime_prebuild_v1.json` (recomputed builder-helper context hash only)
- `scripts/m1c_runtime_orchestrator.py`
- `scripts/m1c_runtime_resources.py`
- `scripts/m1c_runtime_builder.py`
- `scripts/m1c_runtime_qualification.py`
- `evaluation/tests/test_m1c_runtime_orchestration.py`
- `evaluation/tests/test_m1c_runtime_artifact.py`
- `PUBLICATION_MANIFEST.txt`
- `reports/m1c_runtime_orchestration_preparation.md`

## Preserved research state

Production Adapter SHA: `8ef6389565309ba208557923cced1e619a8a1b25549353f9b5f13e2313ad6070`.
Pinned DSH: `b150a551b8d465e31e418e1b2eaf5e79bbb7d28e`.
Task: `terminal-bench/configure-git-webserver`, `PROVEN_ZERO / UNEXPOSED`.
Historical quarantines and exclusion SHA
`4791ea562b79392618c0da2dfd01ae7054267505124753d913c07e4a604e6e6b` unchanged.
Stable pool, historical mappings, task definitions and production Adapter unchanged.
Push=0; dispatch=0; actual DSH build=0; provider/DeepSeek requests=0;
live integration=0; Adapter frozen=no; M1D=no.
Prepared for separately authorized single no-model qualification; not build/native/live qualified.
