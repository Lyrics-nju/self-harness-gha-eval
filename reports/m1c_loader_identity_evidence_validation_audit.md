# M1C.1 loader identity evidence validation preparation

Preparation date: 2026-10-08. Parent: `335d41b69a3ee9c5d7552c59ee465de06331b6a9`.
Prior run: 34976954932, attempt 1, artifact 10400047108.

## Preserved scientific result

Historical snapshot/provenance passed; historical/current platform digests matched
24/24; within-run drift was zero; 24 unique digests, valid loader paths 24/24,
unresolved placeholders zero; pull/fingerprint/cleanup completed 24/24.
The workflow self-report is preserved unchanged. Its qualification is not accepted
scientifically: `COMPATIBILITY_NOT_YET_PROVEN` remains the research classification.
Corrective blocker:
`M1C_RUNTIME_FINGERPRINT_LOADER_IDENTITY_ERROR_TEXT_ACCEPTED_BLOCKER`.

## Exact historical control flow

The script executed:

```sh
loader_identity="$("$loader" --version 2>&1 | head -1 || true)"
emit dynamic_loader_identity "${loader_identity:-$na}"
```

For the Debian 11 image the loader argv was exactly
`["/lib64/ld-linux-x86-64.so.2", "--version"]`. Quoting kept the loader path and
option as separate arguments; this was not an argv splitting error.
The saved merged first line was:

```text
--version: error while loading shared libraries: --version: cannot open shared object file
```

The loader child's exit, independent stdout and independent stderr are
`NOT_AVAILABLE` in historical artifacts. They were never captured separately.
The shell pipeline used the last child's status (`head`), then `|| true` masked
pipeline failure. The outer fingerprint container exited zero, which is not
evidence that the loader child exited zero. No new loader invocation was run in
this preparation, and no historical child exit is fabricated.

Upstream glibc 2.31 `elf/rtld.c` parses recognized loader options and breaks on an
unrecognized argument, then loads it as the executable. `--version` is absent
from that parser. This establishes why the observed error names `--version` as
the file. The other 23 images had newer loader implementations and emitted
plausible release lines, but their independent child statuses were also lost.
Portability across the supported glibc versions was not guaranteed.

Source: https://raw.githubusercontent.com/bminor/glibc/glibc-2.31/elf/rtld.c
(option loop and executable loading in `dl_main`).

## Corrected identity contract

No loader-native version invocation remains. Path detection keeps the generic
readelf/PT_INTERP, ldd-interpreter, unique-existing-filesystem-candidate order.
`readlink -f -- <detected path>` captures exit/stdout/stderr separately. Only a
successful single absolute, placeholder-free realpath with empty stderr is
accepted. Failure produces unavailable binary identity and fails qualification.

The fingerprint container is created from the immutable platform digest, started
with the existing diagnostic shell, and retained after stopping. Controller
inspection validates its image config identity and child exit. The controller
uses `docker cp -L <same-container-id>:<resolved-realpath> loader.binary`.
Docker supports copying from stopped containers and `-L` follows source symlinks:
https://docs.docker.com/reference/cli/docker/container/cp/

The copied result must be a regular, non-symlink amd64 little-endian ELF shared
object. Python hashlib computes SHA256 over the complete file bytes on the host.
The byte file, copy command/exit/stdout/stderr, realpath probe, and hash are all
retained in the artifact lane. No in-image sha256sum is required. Container
cleanup is recorded before existing image cleanup. Every reached evidence file
remains subject to the independent secret scanner and complete SHA manifest.

Primary fields:
`dynamic_loader_path`, `dynamic_loader_realpath`, `dynamic_loader_sha256`,
`dynamic_loader_identity_method`, `loader_binary_identity_status`.
The compatibility alias `dynamic_loader_identity` is a `sha256:<hex>` value,
never subprocess diagnostic text.

Binary statuses: `LOADER_BINARY_IDENTITY_VALID`,
`LOADER_BINARY_IDENTITY_NOT_AVAILABLE`, or `LOADER_IDENTITY_PROBE_ERROR`.
A copied binary must pass the byte contract before identity becomes valid.

## Secondary metadata and keys

getconf GNU_LIBC_VERSION and ldd --version now preserve command, exit, full
stdout, full stderr and method-specific semantic validity. Nonzero results,
stderr diagnostics, missing commands, usage/error text or invalid formats cannot
be promoted into metadata. Valid getconf supplies `libc_version` separately.
Validated ldd output supplies secondary distribution release metadata, explicitly
not an exact loader identity. Missing release metadata is
`LOADER_RELEASE_METADATA_NOT_AVAILABLE`; it does not invalidate a valid binary
identity. The separate libc ABI evidence requirement remains unchanged.

Candidate keys carry loader SHA separately from libc ABI/version, architecture,
kernel/security contract and future artifact-provided Node contract. Exact hash
differences partition observed evidence; they do not establish incompatibility
or force separate final artifact classes. No actual DSH native compatibility is
claimed. Schemas advance to runtime_fingerprint_v2/artifact_class_selector_v2.

## Scope and next qualification

This preparation uses local fixtures and mocks only: no Docker census, registry
resolution, DSH, provider, Oracle, verifier or benchmark task execution.
Production Adapter, stable pool, exclusions, third task and historical snapshot
are unchanged. Third task remains PROVEN_ZERO / UNEXPOSED.

Recommend a narrower generic no-model identity qualification first, covering
Debian 11/12/13 and Ubuntu and exercising actual Docker stopped-container copy,
followed by a separately authorized full historical-gated 24-task census. Local
mocked Docker tests do not substitute for that external transport validation.
No push or dispatch is authorized by this preparation. Artifact-class design,
builder, live, Adapter freeze and M1D remain unavailable.

Local verification: loader/fingerprint targeted suites 129/129, complete relevant
M1C suites 366/366 with the Harbor interpreter and explicit HARBOR_PY (zero skips),
dataset policy 8/8, structured secret scanner 12/12, shell syntax, workflow YAML,
publication manifest coverage, source secret scan and git diff checks all pass.
