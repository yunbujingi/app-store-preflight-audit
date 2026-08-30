# Baselines and suppressions

Use a prior stable report to separate new, changed, unchanged, and resolved findings. A baseline does not change evidence or severity.

A suppression is acceptable only for a reviewed false positive or explicitly accepted, time-bounded condition. Require:

- finding ID or exact stable fingerprint;
- justification;
- accountable owner;
- expiry date;
- Apple/source rule version.

Expired suppressions are active findings again. Keep suppressed findings in the canonical JSON for auditability, but exclude them from SARIF/JUnit failure noise and verdict calculation. Review broad finding-ID suppressions more carefully than exact-fingerprint suppressions because new evidence can otherwise inherit an old exception.

Never use suppression to convert unavailable evidence, a blocked runtime state, or a confirmed submission blocker into a pass.
