# Immutable DSH runtime artifact V1 preparation

Scope: local fixtures and implementation only. No DSH build, task execution,
container pull, workflow dispatch, provider request, or publication is performed.

## Identities and execution blockers

Parent evaluation commit: `648f193a0920f7531b86512a907ecd7ff247dd95`.
DSH source: `b150a551b8d465e31e418e1b2eaf5e79bbb7d28e`.
Production Adapter SHA256 remains
`8ef6389565309ba208557923cced1e619a8a1b25549353f9b5f13e2313ad6070`.
Harbor remains 0.21.0. Qualified census 37751486266 is not rerun or altered.

Builder base image digest, exact Node version/archive checksum, Corepack version
and builder resource budget are `UNRESOLVED`. The execution gate rejects these
before dependency installation/build; a mutable base tag is not a fallback.
The base must be a generic pre-provisioned linux/amd64 build environment. Prefer
a glibc <=2.31 baseline; its name is not compatibility evidence. No task content
or credentials may enter the source/Node/tooling-only build context.

The original Harbor task-config hash and resource-envelope binding are also
unresolved. Runtime qualification fails closed until an independently verified
Harbor setup integration supplies actual container/image/resource/mount evidence.
The controller's Docker transport does not create a container or grant execution
authority. It reads actual image/resource/read-only mount identity, captures the
container-visible tree for independent verification, and accepts only fixed argv
with an empty credential environment. No new workflow/dispatch inputs are added.

## Components

- `gha/runtime-artifact-v1/Dockerfile`: one dedicated external builder definition.
- `scripts/m1c_runtime_builder.py`: frozen-input gate and conservative staging.
- `scripts/m1c_runtime_artifact.py`: deterministic manifest/receipt/archive,
  validation, safe offline materialization and mutation detection.
- `scripts/m1c_runtime_qualification.py`: fixed-task no-model controller.
- `scripts/m1c_runtime_no_model_probe.mjs`: CLI-adjacent profile/plugin resolution,
  node-pty/Koffi load, scratch PTY/FS, packaged ripgrep and Landlock probes;
  no Cordis provider instantiation or model/session boot.
- `evaluation/tests/test_m1c_runtime_artifact.py`: synthetic local regression.

The closure retains application output/assets, runtime workspace trees, vendor packages,
Landlock packages, installed node_modules (including conservative dev-dependency
superset), manifests, presets/bundles/assets and explicit pinned Node executable.
It keeps relative links and executable permissions. It excludes .git, build and
download caches, and rejects discovered credential/state paths rather than hiding
them. No package installer or network runs during packing/materialization.
No aggressive source/dependency pruning is claimed; actual build output packing
and native dependency completeness remain externally unqualified.

Archive member order, uid/gid/time/name metadata and JSON ordering are normalized.
`manifest.json` binds provenance, files/modes/links, ELF/.node inventory and explicit
NOT_RUN qualification states. `receipt.json` binds its hash and program.tar hash
outside the hashed archive. Receipt hash must be independently pinned by the
future execution record; a caller-supplied archive cannot self-authenticate.
Native ABI/shared-library/symbol inventory findings remain NOT_RUN, not PASS.

Extraction rejects traversal, undeclared/duplicate entries, hard links/devices,
link escapes/cycles/dangling targets and unsafe permissions. It verifies content
before atomic publication into a fresh destination and supports relocatable
relative pnpm links. Independent tree verification detects subsequent mutation.
This does not claim chmod is a root-proof immutable boundary.

## Future no-model setup boundary

Transfer occurs on the runner/Harbor setup side. Materialize locally, independently
verify the tree, then enforce a read-only program mount in the original immutable
task image without changing its CPU/memory/swap/storage envelope. Do not download
artifacts or install/build dependencies inside the task container. No bootstrap
network is allowed in the diagnostic container; future model-network semantics
remain a separate authorization and qualification.

The only task is `terminal-bench/configure-git-webserver`; exact references and
platform digest are selected from the hash-verified committed historical mapping
with frozen 24-task pool validation, not copied from chat. Actual Harbor setup
must independently read back identities/resources, expose no credential env,
and prove its read-only mount is the independently verified program bytes.
The transport must preserve scanned diagnostics on failures and independently
verify the remote program before/after. It must never serialize ambient env or
unscanned exception text. Container creation, model execution and benchmark task
commands are intentionally absent from this implementation.

The explicit artifact Node runs CLI help/version from scratch. The fixed probe
resolves headless profiles/plugins, exercises native dependencies and creates two
isolated scratch homes without a model session. CLI version alone is insufficient.
No global PATH, library path or heap flags are added to task execution.

Stop on identity/resource drift, native load/sandbox failure, missing runtime
assets, bootstrap dependency, unexpected write, evidence loss or safety rejection.
No fallback installation, automatic environment repair or new class selection.

## Scientific status

Fixtures prove archive/helper contracts, not DSH compilation or real native ABI
compatibility. There is one candidate design, zero built real artifacts, zero real
task-container qualifications, and zero qualified artifact classes. Artifact size,
build time, builder memory requirement and materialization cost remain UNKNOWN.
No real artifact or build success is inferred from synthetic provenance fixtures.

Production Adapter, stable pool, snapshot and historical quarantines are unchanged.
Third task remains PROVEN_ZERO / UNEXPOSED. Provider/DeepSeek requests = 0.
Formal 18-task cohort and fourth integration task are not selected.
Adapter frozen = no. Ready for live = no. M1D started = no.

## Local validation

Targeted fixture suite: 57/57 PASS. Existing relevant M1C suites: 429/429 PASS.
Combined final M1C discovery: 486/486 PASS, skipped = 0.
The combined authoritative run uses an isolated copy of the already installed
Harbor 0.21.0 interpreter and command-scoped HARBOR_PY; no persistent .pth change
is made to the original environment. No skipped tests count as PASS.
Frozen evaluator regressions retain their direct-script contracts: Docker 7/7,
Harbor exceptions 8/8, Normalizer v2 9/9, dataset policy 8/8.
Structured scanner regressions: 12/12 PASS, unchanged. Publication staging secret
scan PASS; publication manifest 126 entries PASS; existing workflow YAML 17/17
parse PASS; diagnostic JS syntax check PASS; git diff --check PASS.
Earlier system-Python discovery could not import Harbor; it is not counted as a
successful run. Initial missing-HARBOR_PY skips are superseded by the isolated run.

Next work requires separate authority to resolve/freeze external identities and
bind the Harbor setup transport, then build/verify one candidate and perform one
no-model original-container qualification. Do not push or dispatch this preparation.
