# Schema compatibility policy

Audit fragments, reports, and eval reports use an independent semantic schema version.

- Patch: clarifications and validator fixes with no observable shape change.
- Minor: additive optional fields or new enum values that tolerant readers can ignore.
- Major: removed/renamed fields, changed types, stricter required fields, or changed meaning.

The `0.2.0` assembler accepts `0.1.0` and `0.2.0` fragments and emits only `0.2.0`. Consumers must reject unsupported major versions rather than guessing. Preserve unknown `data` fields, but validate decision-bearing fields such as disposition, verification, severity, and layer.
