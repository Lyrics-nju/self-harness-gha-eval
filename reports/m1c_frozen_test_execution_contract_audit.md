# M1C frozen evaluator test execution contract audit

## Authority and historical contract

Validated M1B workflows at frozen reference commit `d34a68000363b266f1af9ea52f4ec913917520e5` execute the regression files directly with the Ubuntu runner's system `python3`, under Bash `set -euo pipefail`, and pipe output to `tee`. The authoritative examples are `.github/workflows/gha-m1b19-acquisition.yml` and `.github/workflows/gha-tb21-multi-task.yml`.

The exit contract is fail-closed: direct script exit code 0 is required and `pipefail` propagates a nonzero Python exit through `tee`. For M1C, the corrected controller additionally requires the exact frozen terminal marker, so an empty or partial direct execution cannot pass.

| Logical test | Frozen/current path | Historical invocation | Required marker |
|---|---|---|---|
| Docker endpoint | `evaluation/tests/test_docker_endpoint_policy.py` | `python3 evaluation/tests/test_docker_endpoint_policy.py` | `DOCKER_ENDPOINT_POLICY=7/7 PASS` |
| Harbor exception | `evaluation/tests/test_harbor_exception_policy.py` | `python3 evaluation/tests/test_harbor_exception_policy.py` | `HARBOR_EXCEPTION_POLICY=8/8 PASS` |
| Normalizer v2 | `evaluation/tests/test_normalizer_v2_public.py` | `python3 evaluation/tests/test_normalizer_v2_public.py` | `NORMALIZER_V2=9/9 PASS` |
| TB2.1 dataset | `evaluation/tests/test_tb21_dataset_policy.py` | `python3 evaluation/tests/test_tb21_dataset_policy.py` | `TB21_DATASET_POLICY=8/8 PASS` |

## Immutability evidence

Frozen reference and current paths are identical. SHA256 values:

| Logical test | Frozen reference path | Current path | SHA256 | Equivalence |
|---|---|---|---|---|
| Docker endpoint | `d34a680: evaluation/tests/test_docker_endpoint_policy.py` | same path | `294235eb8d951ae3b258eed89930756071cc3a03ae28e9070aff92bb43ef8349` | PASS |
| Harbor exception | `d34a680: evaluation/tests/test_harbor_exception_policy.py` | same path | `dd7798b43ae87bd483ae4a7cfd528ec7d6061322c3fa647890369b01c4cf92f7` | PASS |
| Normalizer v2 | `d34a680: evaluation/tests/test_normalizer_v2_public.py` | same path | `1a6b83e839f1d678101e1f55526a767c3d9d586c4e83747b1e13d7bf1eddf473` | PASS |
| TB2.1 dataset | `d34a680: evaluation/tests/test_tb21_dataset_policy.py` | same path | `d7124ef90379ff0cc3b0fb9b233298b97d716433f8aee3c5a729f1cf53e39ea4` | PASS |

No evaluator assertion, expected count, or semantic implementation was modified.

## M1C mismatch and correction

The second M1C smoke routed these script-style modules through `python3 -m unittest`. Their import-time checks passed, but unittest discovered zero `TestCase` objects and returned exit code 5. Causal classification: `M1C1_FROZEN_EVALUATOR_TEST_INVOCATION_CONTRACT_BUG`.

The correction changes only invocation: a small controller launches every frozen file as a direct Python script, requires exit code 0, requires its exact frozen pass marker, and rejects unittest zero-test evidence. The frozen regression files remain byte-identical.

