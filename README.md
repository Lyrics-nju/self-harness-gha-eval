# Self-Harness GitHub Actions evaluator feasibility

This public repository contains only a sanitized, no-model feasibility harness for a standard GitHub-hosted `ubuntu-24.04` runner. It evaluates native runner networking, Docker, Harbor 0.21.0, Outcome Normalizer v2 portability, Terminal-Bench 2.1 integrity, storage headroom, and one deterministic Oracle diagnostic.

The workflow is manual-dispatch only, has read-only repository permission, uses concurrency one and zero trial retries, and does not configure a model. A run does not authorize stable-pool acquisition.
