# Full feasibility evidence policy

The full GitHub Actions feasibility run uses Docker endpoint policy tests and Harbor structured exception policy version 1.0.0. Each Harbor attempt is unique, has separate process streams, and emits structured evidence, Normalizer v2 output, a file manifest, and SHA-256 manifest. Text-only exception words are diagnostic evidence and never override a successful structured result.

The workflow performs exactly 5 preflight and 20 extended synthetic attempts and stops at the first genuine failure. If all qualification gates pass, it performs exactly one `portfolio-optimization` Oracle diagnostic attempt. A task-level non-PASS remains evidence; infrastructure ambiguity or failure fails closed.
