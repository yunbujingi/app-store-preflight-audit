# Reproducible evals and CI

Use `scripts/run_evals.py` with the repository's synthetic `evals/cases.json`. Never add proprietary app code, real account data, credentials, production endpoints, or copied Apple documentation to a fixture.

Each expectation has a stable `rule_id` and produces one of:

- `tp`: expected positive evidence was observed;
- `tn`: an explicitly absent finding remained absent;
- `fp`: a finding or signal appeared in a negative control;
- `fn`: expected evidence was missing or had the wrong state;
- `unknown`: the collector did not expose the required evidence path;
- `blocked`: the collector or prerequisite could not run.

Precision, recall, false-positive rate, and per-rule counts are descriptive quality metrics, not App Store approval probabilities. The default CI gate requires zero false positives, false negatives, and blocked expectations in bundled deterministic fixtures. Add a focused negative control whenever a broad pattern is introduced.

Use stable JSON for downstream logic, SARIF for code-scanning presentation, and JUnit for test dashboards. Preserve the distinctions between failure, unresolved, blocked, and not run.

For recurring projects, compare against a prior canonical JSON report. PR presentation should prioritize `triage.new` and `triage.changed`, show resolved findings separately, and keep unchanged findings available without repeating them as new noise. Read [baseline-and-suppression.md](baseline-and-suppression.md) before accepting an exception.
