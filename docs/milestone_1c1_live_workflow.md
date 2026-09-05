# M1C.1 live integration workflow

This commit prepares, but does not execute, the single authorized live integration path. The preserved procedural classification is `M1C_LIVE_WORKFLOW_MISSING_BLOCKER`; this workflow is the bounded corrective artifact and does not reinterpret any earlier result.

The workflow is manually dispatched, fixes the only reachable task to `terminal-bench/caffe-cifar-10`, fixes Harbor to one attempt with zero retries, and injects the credential only into the live process step. Every identity, evaluator regression, materialization, isolation, adapter, dataset, runner, DSH commit, and profile check must finish before `PRE_MODEL_GATE_COMPLETED` can be written. The controller writes `MODEL_EXPOSURE_START` immediately before its sole Harbor subprocess call.

Artifacts are copied from an explicit safe-evidence list, model output is sanitized, the staged evidence is scanned before upload, and the always-run stage does not change the original step result. Reward 0 is acceptable only when the agent and verifier completed, a `TrialResult` exists, Normalizer v2 deterministically returns `TASK_FAIL`, and no exception or infrastructure failure is present.

After an authorized live run, private evidence retrieval must treat the task as permanently exposed if `MODEL_EXPOSURE_START` exists. Only then may the private repository create `configs/experiment_task_exclusions_v1.json` with classification `MODEL_EXPOSED_INTEGRATION_ONLY` and all three experiment eligibility fields set to false. This public preparation commit does not create that file.

The adapter may be frozen as `configs/dsh_harbor_adapter_v1.yaml` only after the live result is classified `M1C_LIVE_TRIAL_GREEN`. This preparation commit neither creates that freeze file nor begins M1D.
