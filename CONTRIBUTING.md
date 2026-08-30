# Contributing

Contributions should improve observable audit behavior rather than add speculative checklist items.

## Before opening a pull request

1. Explain the false negative, false positive, unsafe behavior, or unsupported project shape being addressed.
2. Add or update a minimal synthetic fixture. Do not contribute proprietary projects, Apple SDK content, credentials, or personal data.
3. Run `python3 -m unittest discover -s tests -v`.
4. Validate the skill with the bundled Codex `quick_validate.py` tool.
5. Update `CHANGELOG.md` when behavior or the report schema changes.

Policy changes must link to a current page on `developer.apple.com`, include the retrieval date, identify storefront or platform applicability, and avoid copying Apple documentation wholesale.

Generated prose is not a stable test surface. Tests should assert evidence, states, safety boundaries, and schema invariants.
