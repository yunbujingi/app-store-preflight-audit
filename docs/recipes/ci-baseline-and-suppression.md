# Recipe: CI baseline and suppression

[简体中文](ci-baseline-and-suppression.zh-CN.md) | [Understanding the report](../understanding-the-report.md)

Use a baseline to separate new or changed findings from known history. Use a suppression only for a reviewed false positive or an explicitly accepted, time-bounded condition. Neither mechanism changes the underlying evidence.

## Roles of the four interfaces

| Interface | Primary user | Responsibility |
| --- | --- | --- |
| CLI | Developers and CI | Deterministic collection, structured output, input/tool error exit status. |
| Codex Skill | Codex users | Select scope, orchestrate evidence, explain conclusions and missing coverage. |
| Python package | Integrators | Reuse scanner modules and parsers. |
| GitHub Actions | CI projects | Run commands, preserve artifacts, show baseline diffs, SARIF, and JUnit. |

CLI `--help` is the source of truth for arguments. Collector nonzero exit codes indicate execution or input problems. `assemble` writes the report and exits successfully even when the report verdict is `NO_GO`; CI must inspect canonical JSON or its chosen SARIF/JUnit integration instead of assuming exit code 0 means readiness.

## 1. Create a candidate report

```bash
mkdir -p /tmp/app-store-preflight

app-store-preflight-audit inventory \
  --root . \
  --output /tmp/app-store-preflight/inventory.json

app-store-preflight-audit privacy \
  --root . \
  --output /tmp/app-store-preflight/privacy.json

app-store-preflight-audit assemble \
  --input /tmp/app-store-preflight/inventory.json \
  --input /tmp/app-store-preflight/privacy.json \
  --json-output /tmp/app-store-preflight/audit.json \
  --markdown-output /tmp/app-store-preflight/audit.md \
  --sarif-output /tmp/app-store-preflight/audit.sarif \
  --junit-output /tmp/app-store-preflight/audit.xml
```

Review scope, revision, findings, and coverage. Only then promote `audit.json` to the project's baseline. A baseline may be stored in a protected private CI artifact or in the repository only after confirming it contains no private project metadata.

## 2. Compare a pull request with the baseline

```bash
app-store-preflight-audit assemble \
  --input /tmp/app-store-preflight/inventory.json \
  --input /tmp/app-store-preflight/privacy.json \
  --baseline ci/app-store-preflight-baseline.json \
  --suppressions ci/app-store-preflight-suppressions.json \
  --json-output /tmp/app-store-preflight/audit.json \
  --markdown-output /tmp/app-store-preflight/audit.md \
  --sarif-output /tmp/app-store-preflight/audit.sarif \
  --junit-output /tmp/app-store-preflight/audit.xml
```

Read these arrays in `triage`:

- `new`: finding IDs absent from the baseline;
- `changed`: same ID with a changed stable fingerprint;
- `unchanged`: same ID and fingerprint;
- `resolved`: baseline IDs no longer present;
- `suppressed`: still present and covered by a valid suppression;
- `expired_suppressions`: suppression no longer active.

A minimal verdict gate on GitHub-hosted runners can be explicit:

```bash
jq -e '([.fragments[].tool] | index("project_inventory")) != null and ([.fragments[].tool] | index("inspect_privacy_manifests")) != null' \
  /tmp/app-store-preflight/audit.json
jq -e '.verdict != "NO_GO"' /tmp/app-store-preflight/audit.json
```

The first command prevents an omitted collector from looking like a clean run; adjust the required tools to the job's declared scope. Choose a stricter project policy if desired, but document it. Do not fail solely because historical findings exist if the purpose of the baseline is to focus PR review on new risk. Always upload or retain JSON; SARIF/JUnit omit valid suppressions from failure noise, while canonical JSON preserves the original findings.

## 3. Create an accountable suppression

Start from [the synthetic suppression example](../../examples/suppressions.example.json):

```json
{
  "schema_version": "0.3.0",
  "suppressions": [
    {
      "finding_id": "EXACT-STABLE-FINDING-ID",
      "justification": "Confirmed generated-code false positive; tracked by issue 123.",
      "owner": "mobile-platform-team",
      "expires_at": "2026-12-31",
      "rule_version": "ASPA-RULE-ID@2026-08-31"
    }
  ]
}
```

Prefer an exact fingerprint when the exception applies only to one evidence shape. A broad finding-ID suppression can also suppress future evidence under that ID and therefore requires extra review.

Never suppress:

- a missing artifact, tool, authorization, or test state;
- `BLOCKED` or `NOT_RUN` merely to improve coverage;
- a confirmed security/privacy/submission blocker without a deliberate risk decision;
- a finding without owner, justification, expiry, and applicable source/rule version.

## 4. GitHub Actions expectations

- Pin third-party actions to full commit SHAs.
- Build/install the CLI in a clean job.
- Run the same commands documented in Quick Start.
- Preserve JSON, Markdown, SARIF, and JUnit as appropriate.
- Print the finding diff in the job summary.
- Keep real Archive, ASC export, credentials, and unsanitized reports out of public artifacts.
- Review suppression changes like code and require owners.

The repository CI smoke-tests the installed CLI against source and synthetic Archive paths so documentation command shapes fail before release if they drift.
