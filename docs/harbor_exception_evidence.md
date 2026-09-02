# Harbor 0.21.0 exception evidence policy

Policy version: 1.0.0.

Harbor's canonical trial record is `result.json`. In Harbor 0.21.0, `TrialResult.exception_info` is either `null` or an `ExceptionInfo` object containing exception type, message, traceback, and occurrence time. Harbor's retry queue treats `exception_info is None` as normal completion; its CLI prints a structured error when the field is populated and otherwise reports verifier rewards.

The diagnostic parser therefore distinguishes `NO_EXCEPTION`, `STRUCTURED_FATAL_EXCEPTION`, `STRUCTURED_NONFATAL_EXCEPTION`, `TEXT_ONLY_EXCEPTION_SIGNAL`, and `PARSER_AMBIGUOUS`. Free-text matching is retained only as a separate signal and is never authoritative for fatal infrastructure classification. Process exit, raw reward, structured status, three phase-network signals, artifact completeness, and synthetic assertions are recorded independently.

The prior implementation searched only the merged Harbor command log with a case-insensitive `Traceback|Exception|ERROR` expression. It did not inspect structured JSON or distinguish fatal, nonfatal, warning, empty, or handled text.
