# M1C.1 run 34113571888 scanner forensics

Date: 2026-09-07

## Immutable run identity

- Workflow commit: `e93dff7f52a1da7860f1acb6ca54d6ae49bfa6ea`
- Run: `34113571888`, attempt `1`
- Task: `terminal-bench/chess-best-move`
- Procedural result: `M1C_LIVE_TRIAL_NOT_GREEN`
- Exposure: `EXPOSURE_INDETERMINATE_AFTER_LIVE_ARTIFACT_LOSS`

## Scanner finding

The masked GitHub log records the production command
`python3 scripts/public_secret_scan.py --artifact-mode artifact-stage` and return code `1`.
Its only emitted finding was:

`sanitized-trial-result.json    MODEL_OR_CLOUD_KEY_NAME`

At this commit that rule was a case-insensitive substring search for a fixed credential
identifier anywhere in a file. It did not parse key/value structure and did not inspect
whether the associated value was a frozen redaction sentinel. The finding category
therefore proves an identifier match, not credential-value exposure. Classification:
`M1C1_SECRET_SCANNER_IDENTIFIER_FALSE_POSITIVE`.

No actual candidate credential value, authorization value, bearer token, or private-key
content was printed by the masked log. Historical actual secret-value evidence: no.

## Independent normalize/classify failure

The live Harbor command returned success after approximately 3m28s and a sanitized
TrialResult existed. The subsequent `summarize` command returned `1`, but emitted no
classification fields or exception diagnostics to the GitHub log. Because artifact
upload was skipped, the runner-only `live-summary.json`, `post-live-decision.json`, raw
TrialResult, verifier fields, and Normalizer output cannot be recovered.

`NORMALIZE_FAILURE_CAUSE = NOT_RECOVERABLE`

It is not scientifically valid to infer TASK_FAIL, parsing failure, missing session
evidence, or another specific mechanism from the surviving log.

## Correction

The scanner now permits known sensitive identifiers only when their structured value is
null or an explicit safe sentinel. Non-redacted values fail closed. Text assignments,
authorization bearer values, known token formats, and private-key material remain blocked.
Diagnostics contain only rule ID, path, safe location/field metadata, candidate length,
and a truncated irreversible digest—never the candidate value.

Live evidence is split into an allowlisted scalar-only safe-core lane and a bulk sanitized
raw lane. Each lane is independently scanned and uploaded. Bulk rejection cannot prevent
safe-core upload, while the overall integration remains fail-closed.
