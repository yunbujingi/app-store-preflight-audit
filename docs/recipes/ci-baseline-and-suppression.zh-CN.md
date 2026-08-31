# Recipe：CI baseline 与 suppression

[English](ci-baseline-and-suppression.md) | [理解报告](../understanding-the-report.zh-CN.md)

Baseline 用于把新增或变化 finding 与已知历史分开。Suppression 只适用于经过审阅的 false positive，或明确接受且有期限的状态。两者都不会改变底层 evidence。

## 四种入口的职责

| 入口 | 主要用户 | 职责 |
| --- | --- | --- |
| CLI | 开发者与 CI | 确定性收集、结构化输出、输入/工具错误退出状态。 |
| Codex Skill | Codex 用户 | 选择 scope、组织 evidence、解释结论和 coverage 缺口。 |
| Python package | 工具集成方 | 复用 scanner module 和 parser。 |
| GitHub Actions | CI 项目 | 执行命令、保留 artifact、展示 baseline diff、SARIF 和 JUnit。 |

CLI 参数的唯一事实来源是 `--help`。Collector 非零 exit code 表示执行或输入问题。`assemble` 即使生成 `NO_GO` 报告也会成功写出文件并返回成功，因此 CI 必须检查 canonical JSON 或所选 SARIF/JUnit 集成，不能把 exit code 0 当成准备就绪。

## 1. 创建 candidate report

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

人工检查 scope、revision、finding 和 coverage，之后才能把 `audit.json` 提升为项目 baseline。Baseline 可以放在受保护的私有 CI artifact 中；只有确认不含私有项目 metadata 后才适合提交到 repository。

## 2. 将 pull request 与 baseline 比较

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

重点读取 `triage`：

- `new`：baseline 中没有的 finding ID；
- `changed`：ID 相同但 stable fingerprint 改变；
- `unchanged`：ID 和 fingerprint 都相同；
- `resolved`：baseline 中存在、当前已消失；
- `suppressed`：仍存在且命中有效 suppression；
- `expired_suppressions`：suppression 已过期。

GitHub-hosted runner 上可以使用显式的最小 verdict gate：

```bash
jq -e '([.fragments[].tool] | index("project_inventory")) != null and ([.fragments[].tool] | index("inspect_privacy_manifests")) != null' \
  /tmp/app-store-preflight/audit.json
jq -e '.verdict != "NO_GO"' /tmp/app-store-preflight/audit.json
```

第一条命令防止缺失 collector 被误看成干净运行；应根据 job 声明的 scope 调整必需 tool 列表。项目可以选择更严格策略，但必须写清楚。Baseline 的目的如果是让 PR 聚焦新增风险，就不应仅因历史 finding 仍存在而失败。始终保留 JSON；SARIF/JUnit 会从失败噪声中移除有效 suppression，但 canonical JSON 会保留原始 finding。

## 3. 创建可追责 suppression

从[合成 suppression 示例](../../examples/suppressions.example.json)开始：

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

如果例外只适用于某个具体 evidence shape，优先使用 exact fingerprint。宽泛的 finding-ID suppression 可能同时覆盖该 ID 的未来证据，需要额外审阅。

绝不能 suppression：

- 缺失 artifact、工具、授权或 test state；
- 仅为了提高 coverage 而隐藏 `BLOCKED` 或 `NOT_RUN`；
- 没有明确风险决定的 confirmed security/privacy/submission blocker；
- 缺少 owner、justification、expiry 和适用 source/rule version 的 finding。

## 4. GitHub Actions 要求

- 第三方 action pin 到完整 commit SHA；
- 在干净 job 中构建/安装 CLI；
- 执行 Quick Start 中相同的命令；
- 按需保留 JSON、Markdown、SARIF 和 JUnit；
- 在 job summary 中展示 finding diff；
- 真实 Archive、ASC export、credential 和未脱敏报告不能进入公开 artifact；
- suppression 变更按代码审查并要求 owner。

仓库 CI 会使用安装后的 CLI 对 source 和合成 Archive 路径做 smoke test，因此文档命令一旦与实现漂移，会在 Release 前失败。
