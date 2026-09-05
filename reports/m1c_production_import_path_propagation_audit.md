# M1C.1 Production Import-Path Propagation Audit

Historical run `33975855965` at immutable commit `9d7ca31935a7edc2460d90e784a0be8a62698953` remains `M1C_LIVE_TRIAL_NOT_GREEN` / `M1C_LIVE_AGENT_IMPORT_PATH_BLOCKER`.

## Sanitized findings

- `ADAPTER_SOURCE_ROOT` present: **yes**, proven at the pre-model gate.
- Resolved value: the absolute GitHub Actions checkout root represented by `${{ github.workspace }}`.
- Absolute: **yes**.
- Equal to expected checkout: **yes**.
- `PYTHONPATH` contained the expected root in the Harbor CLI process: **UNKNOWN**.
- Harbor Python `sys.path` contained the expected root: **UNKNOWN**.

The workflow source constructed a child environment intended to prepend the checkout root to `PYTHONPATH`, but the preserved run artifacts contain neither a sanitized child-environment assertion nor a fresh Harbor interpreter `sys.path` capture. Source intent is not runtime proof. The terminal evidence only proves that Harbor 0.21.0 reached `Trial._init_agent` and `AgentFactory`, where `importlib.import_module` raised `No module named 'evaluation'`.

Therefore the exact reason transient `PYTHONPATH` failed is not proven. The correction registers the immutable public checkout root in the runtime-resolved Harbor interpreter's site-packages through a one-line, non-executable `.pth` file and verifies it from fresh isolated Harbor Python processes outside the checkout cwd.
