# M1C.1 Legacy Negative Import-Test Isolation Audit

Historical run `34039332018` failed before the hard gate with causal classification `M1C1_LEGACY_NEGATIVE_IMPORT_TEST_ISOLATION_ORDER_BUG`.

## Exact failing tests

1. `evaluation/tests/test_m1c_live_invocation_edges.py::InvocationEdgeTests.test_05_wrong_import_path_fails_preflight`
   - Historical assertion: with fixture `PYTHONPATH` emptied, controller preflight returns 1 and records adapter/materialization failure.
   - Intended absence: the fixture checkout must not be importable through the process path.
   - Old assumption: removing transient `PYTHONPATH`, while running from the fixture root, represented absence of all authorized import wiring.
   - Site-packages assumption: no interpreter-level checkout registration existed.

2. `evaluation/tests/test_m1c_custom_agent_import_contract.py::CustomAgentImportContractTests.test_02_historical_nonrepo_import_failure_reproduced`
   - Historical assertion: from an unrelated temporary cwd with `PYTHONPATH` absent, AgentFactory import fails with `No module named 'evaluation'`.
   - Intended absence: neither cwd nor environment nor installed package exposes the repository namespace.
   - Old assumption: clearing `PYTHONPATH` was sufficient to remove source visibility.
   - Site-packages assumption: no interpreter-level checkout registration existed.

Both tests predate the production `.pth` wiring introduced by commit `0df5d60e9c3a04b1d45d8d08e0fa4fe1993a2462`. Their assertions remain correct when all authorized wiring is absent. Run `34039332018` installed the `.pth` first, so merely removing `PYTHONPATH` could not create the intended negative environment.

## Correction

The assertions are preserved unchanged. Both legacy suites now execute after Harbor interpreter resolution but before production `.pth` installation. The `.pth` is then installed and positively qualified in fresh processes before later pre-model stages. Negative tests never delete or mutate production wiring, eliminating cleanup risk and stale-state leakage.
