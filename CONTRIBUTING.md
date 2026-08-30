# Contributing

Contributions should improve observable audit behavior rather than add speculative checklist items.

## Before opening a pull request

1. Explain the false negative, false positive, unsafe behavior, or unsupported project shape being addressed.
2. Add or update a minimal synthetic fixture. Do not contribute proprietary projects, Apple SDK content, credentials, or personal data.
3. Run `python3 -m unittest discover -s tests -v`.
4. Run `python3 skill/app-store-preflight-audit/scripts/run_evals.py --cases evals/cases.json --output /tmp/evals.json` and explain any non-zero FP/FN/blocked result.
5. Build the Skill zip twice and confirm the archives are byte-identical.
6. Validate the skill with the bundled Codex `quick_validate.py` tool.
7. Update `CHANGELOG.md` and `COMPATIBILITY.md` when behavior or the report schema changes.

Policy changes must link to a current page on `developer.apple.com`, include the retrieval date, identify storefront or platform applicability, and avoid copying Apple documentation wholesale.

Update `references/policy-registry.json` only through a reviewable rule-level change: preserve the stable internal ID, update applicability and related checks/evals, recalculate the fingerprint with `validate_rule_registry.py`, and explain why the rule changed. A page hash alone is not sufficient evidence of a policy change.

Use the dedicated Issue forms for false positives, false negatives, Apple rule changes, and unsupported project shapes. Public attachments must be synthetic or fully redacted; never attach an original `.ipa`, `.xcarchive`, provisioning profile, App Store Connect export, or report containing private bundle IDs and paths.

Generated prose is not a stable test surface. Tests should assert evidence, states, safety boundaries, and schema invariants.

New static patterns require at least one positive fixture and one negative control. Never downgrade `INFERRED` or `UNRESOLVED` evidence merely to make the eval gate pass.
