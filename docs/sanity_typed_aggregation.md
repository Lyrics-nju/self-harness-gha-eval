# Typed compact-sanity aggregation

Milestone 1B.17J converts the legacy compact-sanity CSV into structured JSON before aggregation. Boolean fields in the structured document are actual JSON booleans. The compatibility parser accepts only Python/JSON booleans, integers `0` and `1`, and the exact strings `false`, `true`, `0`, and `1`; every other representation is a parser error. Aggregation round-trips the structured JSON and rejects non-boolean fields rather than using Python string truthiness or arbitrary integer conversion.

This prospectively fixes the M1B.17I instrumentation defect without changing its historical commit, run, evidence, dataset, tasks, network operations, or experimental thresholds.
