# App Store 上架前审计 / App Store Preflight Audit

[English](../README.md) | [简体中文](README.zh-CN.md)

这是一个非官方、证据驱动的 Codex Skill，用于在提交 Apple App Store 前审阅 Apple 平台 App。

最新已发布版本：`v0.3.0-beta`。

`v0.3.0-beta` 深化了 target/archive 真相层，谨慎引入 runtime evidence，提供独立 scanner CLI、可验证分发，以及严格 GET-only 的 App Store Connect inventory adapter。

它将审计拆为源码检查、隔离 Xcode 执行、Archive 检查、运行体验和 App Store Connect 验证。它输出机器可读证据和简明的人类报告，但不会把“构建成功”当成“Apple 一定会审核通过”。

> 本项目与 Apple Inc. 没有隶属、背书或赞助关系；不保证 App Store 审核通过，也不提供法律意见。

## 从这里开始

- 第一次使用：[十分钟快速开始](quick-start.zh-CN.md)
- 读懂结果：[理解审计报告](understanding-the-report.zh-CN.md)
- 审计最终产物：[Archive 和 IPA recipe](recipes/archive-and-ipa-audit.zh-CN.md)
- 接入 CI：[baseline 与 suppression recipe](recipes/ci-baseline-and-suppression.zh-CN.md)
- 使用 `--execute` 或公开证据前：[安全执行与公开证据](safe-execution-and-public-evidence.zh-CN.md)
- 输出示例：[合成 sample report](../examples/sample-report.md)

## 根据现有证据选择入口

| 输入 | 能证明什么 | 额外环境 |
| --- | --- | --- |
| 源码 repository | 产品信号、Privacy Manifest、target graph 线索、配置和 policy 风险。 | Python 3.9+；Xcode 可选。 |
| `.xcarchive` | 最终 archived bundle、Mach-O、framework、entitlement/signing metadata 和 packaged manifest。 | macOS/Xcode 可提高 binary 与 signing coverage。 |
| `.ipa` 或导出的 `.app` | 最接近提交物的 exported payload；按不可信输入读取，不启动二进制。 | Python 可跨平台；macOS 工具增加证据。 |
| Simulator screenshot/`.xcresult` | 指定 device/OS/locale/appearance matrix 的直接 runtime evidence。 | 专用 Simulator 和 test state；自动化保持 opt-in。 |
| App Store Connect export/API inventory | 比较 build、metadata、age rating、IAP/subscription、screenshot 和 privacy answer。 | 优先 export；API adapter 仅允许 allowlist GET。 |

只有源码就从 source 开始；验证打包真相时使用计划提交的精确 `.ipa` 或 `.xcarchive`。缺失证据不会被算作通过。CLI report 只覆盖传给 `assemble` 的 fragment，因此 CI 还必须确认每个预期 collector 都已运行。

## 三分钟安装

在可信 checkout 中执行：

```bash
python3 -m pip install --upgrade .
app-store-preflight-audit --version
```

接着按[快速开始](quick-start.zh-CN.md)执行经过测试的 source、Archive 或 GitHub Actions 路径。所有参数以 CLI `--help` 为唯一事实来源。

## 第一次使用 Codex Skill

先只读，再渐进增加证据：

```text
$app-store-preflight-audit

请先执行只读 source audit。
不要构建、运行脚本、启动 Simulator 或访问 App Store Connect。
输出 coverage、全部 BLOCKED 项以及下一步需要提供的 evidence。
```

已有最终产物时：

```text
对这个 .ipa 执行 Archive audit。
允许读取 Mach-O metadata、Info.plist、Privacy Manifest 和签名 metadata，
但不要执行其中的任何二进制，也不要修改签名状态。
```

## 使用方式与边界

| 使用方式 | 面向用户 | 职责 |
| --- | --- | --- |
| CLI | 开发者、CI | 确定性收集、结构化输出、输入/工具错误状态。 |
| Codex Skill | Codex 用户 | 选择模式、组织 evidence、解释 finding 和 coverage 缺口。 |
| Python package | 工具集成方 | 复用 scanner module 和 parser。 |
| GitHub Actions | CI 项目 | baseline diff、canonical JSON、SARIF、JUnit 保留与 gate。 |

本项目不保证 Apple 审核结果。默认 collector 不修改被审计 repository，也不执行 packaged binary。Xcode execution 默认 dry-run，并要求显式风险确认；Skill 内的 App Store Connect 永久只读。报告不能自动视为可公开——redaction 无法识别所有专有 identifier 或个人信息。

当前 beta 限制：复杂 Xcode project shape 可能保持 unresolved；真实 signing/runtime/ASC coverage 取决于提供的工具和 evidence；静态 symbol match 保持 inferred；Apple 规则和 storefront exception 必须在审计时核对。

## 社区验证

请分别使用 [False positive](../.github/ISSUE_TEMPLATE/false-positive.yml)、[False negative](../.github/ISSUE_TEMPLATE/false-negative.yml)、[Apple rule change](../.github/ISSUE_TEMPLATE/apple-rule-change.yml) 和 [New project shape](../.github/ISSUE_TEMPLATE/new-project-shape.yml) Issue 表单。公开 report 和 artifact 可能包含私有 metadata，只能提交 synthetic 或经人工确认完整脱敏的 evidence。

Skill packaging、checksum/provenance、安装和带 backup 升级命令见 [installation and packaging](../skill/app-store-preflight-audit/references/installation-and-packaging.md)。

## 开发与验证

```bash
python3 -m unittest discover -s tests -v
python3 skill/app-store-preflight-audit/scripts/run_evals.py \
  --cases evals/cases.json --output /tmp/app-store-preflight-evals.json
python3 /path/to/quick_validate.py skill/app-store-preflight-audit
```

测试仅使用 Python 标准库，不要求安装 Xcode。Xcode 相关执行受安全边界保护，默认只生成 dry-run 计划。

更多信息请查看[文档入口](quick-start.zh-CN.md)、[兼容策略](../COMPATIBILITY.md)、[免责声明](../DISCLAIMER.md)、[安全策略](../SECURITY.md)和[贡献指南](../CONTRIBUTING.md)。

## 结论边界

- 本项目与 Apple Inc. 无隶属或背书关系。
- 结果是提交准备度评估，不是 Apple 的审核决定。
- Apple 规则会变化，重要判断应在执行时核对 `developer.apple.com`。
- 本项目不提供法律意见，也不保证 App Store 审核通过。

## 许可证

Apache-2.0。Apple、App Store、Xcode、iOS、iPadOS、macOS、watchOS、tvOS 和 visionOS 是 Apple Inc. 的商标，本项目只作描述性使用。
