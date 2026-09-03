# TB2.1 single-task Oracle probe

This workflow executes exactly one deterministic task: the C-locale lexical first ID from the M1B.17G identity-confirmed set, `terminal-bench/adaptive-rejection-sampler`. Harbor 0.21.0 resolves the immutable dataset digest before execution, then runs one Oracle attempt with Docker, concurrency one, and zero retries. No model argument or model credential is supplied.

Only deterministic summaries are uploaded. They record dataset identity, lifecycle timestamps/status, reward/result presence, disk and wall time, and zero API/model counters; raw environment variables and benchmark content are excluded.
