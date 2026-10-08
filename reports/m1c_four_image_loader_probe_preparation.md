# Four-image loader identity diagnostic preparation

Date: 2026-10-08. Parent: `0b1eb7dc406d27dc910176d6b9a927deddb9c581`.

## Independent entry point

Workflow: `.github/workflows/gha-m1c1-four-image-loader-probe.yml`.
Controller: `scripts/gha_m1c1_four_image_loader_probe.py --reports <new-directory>`.
The sole CLI option specifies output location. There are no task, image, digest,
heap, model or workflow-dispatch inputs. The workflow uses standard ubuntu-24.04.

Selection order is fixed: qemu-startup, model-extraction-relu-logits,
fix-code-vulnerability, configure-git-webserver, all under terminal-bench/.
The controller decompresses the frozen stable pool and reuses its exact SHA,
count and uniqueness validator. It loads the committed historical snapshot with
the existing provenance, full SHA and mapping SHA checks. Refs/digests are read
from that verified snapshot; none are recopied from conversation text. The
formal 24-task controller, classification, workflow and historical gate are
unchanged. These four diagnostic targets are not a new integration-task selection.

## Execution boundary and provenance

Sequentially inspect the exact `reference@historical-platform-digest` manifest,
verify its raw SHA and selected manifest identity, then reuse `fingerprint_one`.
There is no mutable-tag resolution or fallback. The shared helper pulls the
immutable platform digest with linux/amd64, inspects the config/architecture,
creates a container overriding image ENTRYPOINT with `/bin/sh` and replacing
image CMD with the controlled fingerprint script. It does not start task scripts.

Only that diagnostic shell is started. Its temporary capability checks are
existing fingerprint instrumentation; they are not benchmark task commands.
Docker metadata proves the diagnostic container stopped and its image config
matches the selected manifest. The loader realpath is resolved inside that same
container. `docker cp -L <container-id>:<realpath> loader.binary` then copies from
the stopped container. Hashing and ELF validation run in the controller.

The shared helper already checks regular ELF64 little-endian ET_DYN/EM_X86_64.
This diagnostic additionally checks the ELF header size, program-header table,
each segment's file bounds and at least one nonempty PT_LOAD. SHA256 covers the
complete copied file. A path, symlink text, empty/truncated file or error page
cannot provide identity. The source container ID, config digest, task/ref/digest,
loader path/realpath/SHA, command/exit/stdout/stderr and ELF validation are bound
in per-image structured records. Release metadata remains secondary; an explicit
NOT_AVAILABLE release can coexist with valid binary identity.

Each reached shared helper invocation cleans up its own diagnostic container and
image in finally. Both cleanup records must exist and succeed to qualify a row.
A cleanup error is reported as an independent infrastructure reason, including
when another execution error preceded it. No automatic cleanup retries occur.

## Four classifications

- FOUR_IMAGE_LOADER_IDENTITY_PROBE_PASS: all four immutable identities, bindings,
  binary validations, cleanup, artifact scanner and complete hash verification
  pass.
- FOUR_IMAGE_LOADER_IDENTITY_PROBE_FAIL: trusted evidence proves a loader path,
  copy, binary or ELF validation failure. Preserve its specific reason.
- FOUR_IMAGE_LOADER_IDENTITY_INFRASTRUCTURE_BLOCKER: registry, daemon, pull,
  container, disk/runner or diagnostic-cleanup failure.
- FOUR_IMAGE_LOADER_IDENTITY_EVIDENCE_INDETERMINATE: missing/malformed evidence,
  unbound copy source, hash mismatch, artifact safety/integrity failure or unknown
  evidence failure. Missing evidence never becomes PASS.

Failure stops further targets and preserves all reached evidence. Summary schema
is m1c_four_image_loader_identity_v1. Selection, registry channels, raw shell
channels, container metadata, copied ELF, identity probes, validation, cleanup
and summary enter a complete SHA256SUMS manifest. Controller scanner/hash gates
are followed by independent workflow scanner/hash gates. Upload occurs only when
the latter pass, even when diagnostic qualification failed. Four-image PASS never
sets task-runtime-census, DSH native compatibility or Adapter freeze flags.

## Local evidence versus external qualification

Read-only local Docker inventory did not contain the complete selected immutable
four-image set. No pull, container start or stopped-container copy was performed.
Actual four-image stopped-container verification: PENDING_EXTERNAL_QUALIFICATION.
Fixtures and mocked transport test the implementation, not actual Docker copy
behavior. External real-container claims require the separately authorized run.

Production Adapter, frozen pool, historical mapping and quarantines remain
unchanged. Historical run 34976954932 remains COMPATIBILITY_NOT_YET_PROVEN.
configure-git-webserver remains PROVEN_ZERO / UNEXPOSED. No formal cohort or new
integration task is selected. No DSH/provider/model/Oracle/verifier/task execution
occurs during this preparation. No push or dispatch occurs. Builder, live,
artifact classes, Adapter freeze and M1D remain unqualified.

## Local preparation gates

Targeted fingerprint/loader/four-image tests: 170/170 PASS.
All relevant M1C regression suites: 407/407 PASS; skipped tests: 0.
Dataset policy tests: 8/8 PASS. Public scanner regression tests: 12/12 PASS.
Public source secret scan and `git diff --check`: PASS.
Local fixture/mocked evidence includes complete manifest verification and
fail-closed scanner/hash paths; it is not external Docker qualification.
