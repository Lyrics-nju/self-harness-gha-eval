# M1C.1 bounded Harbor interpreter correction

Historical commit `49a842b42e421af8002a76fc3f8f818858f927b7` and run `33893721013` remain classified as `M1C_ADAPTER_NO_MODEL_BLOCKER`.

The historical workflow installed Harbor 0.21.0 with pipx but consumed a hard-coded uv-tool interpreter path. The evidence-backed cause is `M1C1_HARBOR_INTERPRETER_PATH_ASSUMPTION_BUG`.

The correction retains `pipx install harbor==0.21.0`. It discovers `harbor` with `command -v`, resolves the executable symlink, selects the executable's sibling `python`, verifies that interpreter is executable, imports Harbor through it, checks package version 0.21.0, and verifies adapter registration. No pipx or uv filesystem prefix is assumed.

Seven regression cases cover pipx-like and uv-tool-like layouts, missing executable, missing interpreter, failed Harbor import, wrong Harbor version, and successful adapter registration.

Failure diagnostics are accumulated in a sanitized staging directory. An `if: always()` preparation step classifies the reached failure, runs the artifact-mode secret scan, and builds a SHA256 manifest. Upload also uses `always()` but is gated on the diagnostic secret scan, so prior failures remain failures and unsafe artifacts are not uploaded.

No evaluator semantics, benchmark content, Normalizer behavior, Harbor version, DSH commit, model profile, stable pool, or integration task is changed.

