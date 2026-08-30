# Eval fixtures

All fixtures are synthetic and intentionally minimal. They test evidence states and false-positive controls, not whether the Swift snippets compile or whether Apple would approve an app.

`cases.json` drives `run_evals.py`. Every expectation has a stable rule ID and is counted as TP, TN, FP, FN, unknown, or blocked. Positive signal fixtures must be paired with negative controls when a detector could plausibly match comments, samples, generated files, or unrelated APIs.

Do not add proprietary source, real bundle identifiers, credentials, production endpoints, user records, Apple documentation copies, or real signing material.
