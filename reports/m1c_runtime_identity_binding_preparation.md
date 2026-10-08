# Artifact V1 pre-execution identity binding preparation

Date: 2026-10-08. Required parent: 78b6f94982ad97ac2c91cc8126b9309d46bd919b.
Local preparation only; no image/layer pull, builder creation, DSH install/build,
task execution, workflow dispatch, provider access or model execution occurred.

## Identity audit and correction

The parent Dockerfile performed DSH dependency installation/build while creating
the builder image. Its provenance recorded the BASE image as builder_image.
Thus there was no verified FINAL builder identity before DSH compilation.
The correction separates toolchain-image creation from DSH build. Final image
identity is deliberately BUILDER_IMAGE_NOT_YET_CREATED, not a fabricated digest.
Packing now requires independent image/capacity evidence plus successful build
receipt. Artifact provenance retains image identity and capacity evidence and
rejects inconsistent Node/ABI/N-API/libc/image observations. Fixture artifacts
were updated to the strengthened schema; no real Artifact V1 was produced.

Order prepared (offline validation functions, NOT an executed workflow):

PREBUILD_INPUT_IDENTITIES_PINNED -> BUILDER_IMAGE_IDENTITY_VERIFIED ->
BUILDER_CAPACITY_PREFLIGHT_PASS -> DSH_BUILD_PERMITTED ->
artifact receipt/manifest/archive verification -> original task/container
identity/resource validation -> TASK_CONTAINER_QUALIFICATION_PERMITTED.

No DSH compile command remains in the image Dockerfile. The packer does not
execute compilation. These functions do not constitute an implemented external
orchestrator: future execution must acquire real image/container read-back and
resource evidence, save it, and invoke the gates BEFORE compilation, not merely
provide caller-authored booleans or run gates retrospectively at packing time.
There is no artifact builder GHA workflow in this preparation.

## Trusted metadata frozen

All exact values and source URLs are in configs/m1c_runtime_prebuild_v1.json.
Only public manifest/checksum/package metadata was read; no image layers,
Node archive or npm package archives were downloaded or executed.

- Base: docker.io/library/python@sha256:297452d603034817c2a94bce91875a4c06fb0f7faefd4d2bd9fa22b393ef9574.
  Docker Hub OCI index descriptor selects linux/amd64. The fetched platform
  manifest bytes independently SHA256-match that digest. Config digest:
  sha256:d0305d03a42543c1a85755043645e45fc47049ad96b51224a8530c055401e88a.
  Official annotation: Python 3.11.13-bullseye, source revision
  14b61451ec7c172cf1d43d8e7859335459fcd344. Expected libc baseline 2.31;
  actual OS/libc/toolchain/ABI/N-API remain unobserved until image creation.
  This is a compatibility candidate, NOT a security/patch-freshness certification.
  Mutable discovery tag is not an execution identity or fallback.
- Node v24.0.0, official linux-x64 archive SHA256:
  59b8af617dccd7f9f68cc8451b2aee1e86d6bd5cb92cd51dd6216a31b707efd7.
  Source: https://nodejs.org/dist/v24.0.0/SHASUMS256.txt.
  Direct Windows metadata read hit TLS EOF; command-scoped metadata read
  succeeded. No installer/build was attempted.
- Corepack 0.33.0: exact npm tarball URL + registry SHA512 integrity frozen.
  Source: https://registry.npmjs.org/corepack/0.33.0.
- pnpm 11.7.0: exact npm tarball URL + registry SHA512 integrity frozen.
  Source: https://registry.npmjs.org/pnpm/11.7.0.
  Recipe verifies archive bytes, installs Corepack from the verified local
  archive, and uses Corepack's hash-qualified pnpm version. No npm replacement
  for DSH dependency installation is introduced.
- DSH: b150a551b8d465e31e418e1b2eaf5e79bbb7d28e.
  Frozen lockfile SHA256:
  6f20c268e76df1294c16f016ab10a7fa1271608b4db0f4fafe8f7c21ec90013e.
- Dockerfile byte SHA and context identity are in the prebuild config.
  Context scheme: canonical sorted path/identity map for the explicit files
  and three archives. Policy JSON is canonicalized excluding ONLY its derived
  context_sha256, avoiding self-hash recursion. Staged policy must equal frozen
  policy; undeclared files/symlinks are rejected. DSH source is not an image
  creation input; its Git/lock identity is separately checked before build.

The discarded buildpack-deps-only candidate lacked an explicit Python provision;
the Python image includes the existing buildpack-deps toolchain lineage. The
unavailable 3.11.14-bullseye discovery tag was not used or silently substituted
at execution. Metadata selection ended with the exact platform digest above.

## Resources: requested is not observed

BUILDER_REQUESTED_RESOURCES: 2 CPUs, 8 GiB container memory, no builder swap
(effective total memory+swap equals memory), 12 GiB minimum observed free disk,
2 GiB host available-memory reserve. These are bounded trial budgets/headroom
floors, NOT measured minimum requirements or peak estimates. CPU/memory/disk
must pass fresh read-back immediately before compilation in the same builder.
BUILDER_OBSERVED_RESOURCES, compilation peaks, layer/staging disk peak and
duration: NOT_MEASURED. Image ID also remains NOT_YET_CREATED.

Official standard ubuntu-24.04 public runner reference advertises 4 CPUs,
16 GB RAM, 14 GB SSD; private standard differs (2 CPUs/8 GB). Source:
https://docs.github.com/en/actions/reference/runners/github-hosted-runners.
Advertised disk is not free disk. Base layers, extracted archives, dependencies,
output tar and simultaneous staging can multiply disk use. The 12 GiB floor
may fail on a standard runner; it is not permission to clean system directories
or alter task limits. Future capacity snapshots need host CPUs/MemAvailable,
free bytes on the actual Docker/source/staging/output backing filesystem(s),
container inspect CPU/memory/swap and cgroup memory/events. Their independently
saved manifest SHA is measurement_id. No observation can be filled from the
requested values. Unsupported/read-back failure must stop before DSH build.

## Third-task binding

Only terminal-bench/configure-git-webserver, still PROVEN_ZERO / UNEXPOSED.
Byte-level task.toml SHA256 (no TOML canonicalization):
ebb40d72f689512cbd90d865d88ef966b6665ab215544f9247b898b7fa94751b.
Read from the retained frozen TB2.1 task source; no task file was changed.
Qualified census run 37751486266 task-image-map byte SHA256:
121788f925ce2d4e56e6da9aacda79c5663524f797fef41fa3b29b5997c7ecbe.
The validator hashes that census file and selects the exact task row; existing
strict pool/historical mapping loader remains unchanged. Original reference:
alexgshaw/configure-git-webserver:20251031. Platform digest:
sha256:9e48389b917fd4650dda1f64406bd7198bbf20dc1c6b0e5c4d81a3c16369f88c.
Values were programmatically extracted/cross-checked, not taken from chat text.

Original requested resources: 1 CPU, 2048 MiB memory, 10240 MiB storage.
Harbor 0.21.0 Docker backend declares CPU/memory limit capability, passes
effective CPUs/memory to Compose, and does not declare storage-limit support.
Task-file storage is not evidence of a 10 GiB filesystem quota. Original
effective swap, storage/default HostConfig fields and cgroup read-back are not
available in the retained fingerprint census. RESOURCE_ENVELOPE remains
UNRESOLVED; ORIGINAL_EFFECTIVE_RESOURCE_BASELINE_NOT_YET_BOUND blocks runtime
qualification. No guessed swap/default or new resource override was introduced.
Future qualification must bind independently observed original limits and
compare the actual container envelope, in addition to task hash/image identity.

## Scope and tests

Changed: dedicated builder Dockerfile, builder helper, provenance validator,
qualification task hash, new offline identity helper, two binding configs,
related fixture tests, publication manifest, this report. Production Adapter,
DSH, pool, mapping, census, four-image workflows, quarantines and formal splits
are unchanged. No extra artifact class or integration task was introduced.

Local validation: targeted Artifact/identity 80/80 PASS; complete related M1C
509/509 PASS (targeted tests are a subset, not additional trials); skipped 0.
Frozen evaluator direct runner: Docker 7/7, Harbor exception 8/8, Normalizer
v2 9/9, TB2.1 dataset policy 8/8 PASS (32 cases, four suite invocations).
Structured secret scanner regressions: 12/12 PASS. Publication secret scan:
PASS. Publication manifest: 131 existing unique files PASS. Workflow YAML:
17 parsed PASS. git diff --check: PASS. Real retained task-config/census
read-only cross-validation: PASS. Initial local fixture expectation/hash failures
were corrected before final successful runs; they were not external trials.
Secret scanner implementation/strictness remained unchanged.

## Readiness

Prebuild trusted metadata identities ready: yes (archives still need independent
byte verification when later downloaded under explicit execution authorization).
Ready for one bounded external no-model builder qualification: no; the external
image/resource read-back and before-build orchestration are not implemented by
this local validator preparation. Do not treat the post-build packer guard as
a substitute for the required pre-execution gate. Original task effective
resource baseline is independently still missing.
Actual DSH build: no. Native runtime qualified: no. Live ready: no.
Provider/DeepSeek requests: 0. Adapter frozen: no. M1D: no.
One local corrective commit only after all local checks; STOP BEFORE PUSH.
