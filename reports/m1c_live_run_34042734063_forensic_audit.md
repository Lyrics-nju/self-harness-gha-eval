# M1C.1 Live Run 34042734063 Forensic Audit

Date: 2026-09-07 (Asia/Shanghai)

This audit is read-only with respect to the immutable historical run. It does not
reinterpret the raw result, rerun the workflow, or assert that a provider request
did or did not occur.

## Immutable identity

- Repository: `Lyrics-nju/self-harness-gha-eval`
- Workflow run: `34042734063`, attempt `1`
- Job: `101512292141` (`live-smoke`)
- Commit: `84d8ca578de0ebdf0070c5184b3f749da0e7af16`
- Conclusion: `failure`
- Procedural classification: `M1C_LIVE_TRIAL_NOT_GREEN`
- Historical blocker: `M1C_LIVE_ARTIFACT_PRESERVATION_BLOCKER`
- Preserved masked job-log SHA256: `3ce50616971304110d728410d6f1bfb6c314a829102b19b6260d0bca49d70b57`

## Step evidence

The pre-model gate and live Harbor command steps completed successfully. The live
step ran from 15:37:07 through 15:40:57 UTC. `Normalize and classify live result`
then returned exit 1. `Prepare failure-safe sanitized artifacts` returned exit 1,
and the upload step was skipped. GitHub reports zero artifacts.

The complete masked log contains no live Harbor output because the controller
redirected it to runner-local `work/runtime/stdout.txt` and `stderr.txt`. It also
contains no normalization traceback: `summarize` deliberately returns 1 whenever
its compound GREEN predicate is false.

## Exact live contract

Working directory:

`/home/runner/work/self-harness-gha-eval/self-harness-gha-eval`

Harbor argv (the JSON `config=` value contains the frozen patch, credential
environment *name*, pinned DSH commit and 1800-second timeout):

```text
harbor run
  --dataset terminal-bench/terminal-bench-2-1@sha256:7d7bdc1cbedad549fc1140404bd4dc45e5fd0ea7c4186773687d177ad3a0699a
  --include-task-name terminal-bench/caffe-cifar-10
  --agent evaluation.agents.dsh_harbor_adapter.adapter:DshHarborAdapter
  --agent-kwarg config=<frozen-json>
  --model deepseek-v4-pro
  --env docker
  --n-concurrent 1
  --n-attempts 1
  --max-retries 0
  --job-name m1c1-live-single
  --jobs-dir <workspace>/work/jobs
  --yes
```

Harbor 0.21.0 constructs trial directories at
`<jobs-dir>/<job-name>/<task-name>__<dynamic-id>/`. A per-job aggregate
`result.json` is separate from the per-trial `result.json`. The controller sought
exactly one direct child directory and its `result.json`, which is consistent with
the Harbor 0.21.0 source contract. The historical dynamic ID and actual result
path are not recoverable after runner disposal.

An exit code 0 from `harbor run` means the Harbor job controller returned
successfully. It does not by itself prove the integration GREEN predicate or a
particular trial reward.

## Causal classifications

### Normalize/classify

Classification: `M1C_DERIVED_CLASSIFICATION_NON_GREEN_WITH_RAW_EVIDENCE_LOSS`.

The immediate cause is evidence-backed: `summarize()` returned 1 because its
compound `integration_green` predicate was false. The log has no Python traceback.
Because the raw job tree and generated summary were not preserved, it is no longer
possible to distinguish whether the predicate failed because the result was
absent/malformed, the verifier result was absent, the Normalizer did not produce
PASS/TASK_FAIL, or `exception_info` was present. No result-discovery race is shown
by the surviving evidence, and claiming one would be speculation.

### Artifact preparation

Classification: `M1C_ARTIFACT_SECRET_SCAN_REJECTION_WITH_UNPRESERVED_FINDINGS`.

The staging controller itself always returned 0. The shell captured the secret
scanner return code, generated `SHA256SUMS`, and then failed specifically at
`test "$scan_rc" -eq 0`. Scanner stdout/stderr had been redirected to
`reports/secret-scan.txt`, which was never uploaded, so the exact finding cannot
be reconstructed. The dependency was unsafe operationally: the only copy of the
scan diagnosis lived inside the ephemeral runner, and upload depended on scan
success.

These are two distinct blockers: derived classification was non-GREEN first, and
artifact preservation then independently failed.

## Exposure and session findings

- `PRE_MODEL_GATE_COMPLETED`: present.
- `MODEL_EXPOSURE_START`: present.
- AgentFactory and adapter initialization: PASS.
- Live Harbor command: exit 0.
- Provider request count: `NOT_AVAILABLE`.
- DeepSeek request count: `NOT_AVAILABLE`.
- DSH session ID/evidence: `NOT_AVAILABLE`.
- Harbor trial ID/result path: `NOT_AVAILABLE`.

No surviving evidence establishes an actual provider request, but absence of that
evidence is not evidence of zero requests. Corrected status:
`EXPOSURE_INDETERMINATE_AFTER_LIVE_ARTIFACT_LOSS`. The task is quarantined from
future D_mine, D_gate and D_sealed use without asserting actual exposure.

## Corrective architecture

The production controller now performs credential-value-redacted raw capture of
Harbor process streams and the complete Harbor job tree before parsing. Dynamic
trial discovery follows Harbor's actual job/trial contract. Normalization is a
separate derived stage and records parse failures. Artifact staging records every
expected item as PRESENT or ABSENT and always generates an integrity manifest;
optional missing evidence is not fatal. Existing DSH session/event files and
explicit request counters/request-start events are used as observational evidence.
No adapter behavior or instrumentation was changed.
