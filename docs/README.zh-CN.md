# App Store 上架前审计 / App Store Preflight Audit

[English](../README.md) | [简体中文](README.zh-CN.md)

这是一个非官方、证据驱动的 Codex Skill，用于在提交 Apple App Store 前审阅 Apple 平台 App。

最新已发布版本：`v0.1.0-beta`。当前开发目标：`v0.2.0-beta`。

它将审计拆为源码检查、隔离 Xcode 执行、Archive 检查、运行体验和 App Store Connect 验证。它输出机器可读证据和简明的人类报告，但不会把“构建成功”当成“Apple 一定会审核通过”。

> 本项目与 Apple Inc. 没有隶属、背书或赞助关系；不保证 App Store 审核通过，也不提供法律意见。

## 包含内容

- 采用渐进式 Skill 架构，只在适用时加载对应规则和流程 reference。
- 提供 source、build、archive 和 submission 审计模式，并显式记录覆盖状态。
- 分离 verification（验证状态）与 severity（严重度），避免把推断写成事实。
- 使用隔离输出目录执行 Xcode 命令，并比较执行前后的 Git 状态。
- 收集 Privacy Manifest 和 required-reason API 证据。
- 枚举 Archive 中的 App、Extension、Framework、Entitlement 和 Manifest。
- 在不执行 App 代码的前提下检查 Mach-O、动态依赖、签名和 bundle-local required-reason 声明。
- 输出稳定 JSON Schema、Markdown、SARIF 2.1.0 和 JUnit。
- 以 URL、时间、SHA-256、storefront 和 platform 记录 Apple 规则时效，不复制网页正文。
- 生成不修改 Simulator 的场景计划，并规范化直接运行观察。
- 提供可复现 fixtures、per-rule TP/TN/FP/FN 指标和零回归 CI gate。
- 提供确定性 Skill zip、checksum，以及 dry-run-first、禁止覆盖的安装器。

## 安装

先生成并检查确定性 zip 和 checksum：

```bash
python3 skill/app-store-preflight-audit/scripts/package_skill.py \
  --skill skill/app-store-preflight-audit --output /tmp/app-store-preflight-audit.zip \
  --checksum-output /tmp/app-store-preflight-audit.zip.sha256
python3 skill/app-store-preflight-audit/scripts/install_skill.py \
  --source /tmp/app-store-preflight-audit.zip --destination-root /path/to/skills
```

确认目标目录后再添加 `--install`；脚本不会覆盖已有 Skill。

## 调用示例

```text
$app-store-preflight-audit 对当前工程执行 source 模式上架前审计，不修改任何项目文件。
```

```text
$app-store-preflight-audit 对提供的 xcarchive 执行 Archive 级隐私、SDK、Bundle 和 Entitlement 审计。
```

除非另行获得明确授权，Skill 不会提交 build、修改 App Store Connect metadata、购买产品、重置 Simulator 或修复发现的问题。

## 开发与验证

```bash
python3 -m unittest discover -s tests -v
python3 skill/app-store-preflight-audit/scripts/run_evals.py \
  --cases evals/cases.json --output /tmp/app-store-preflight-evals.json
python3 /path/to/quick_validate.py skill/app-store-preflight-audit
```

测试仅使用 Python 标准库，不要求安装 Xcode。Xcode 相关执行受安全边界保护，默认只生成 dry-run 计划。

更多信息请查看[示例报告](../examples/sample-report.md)、[兼容策略](../COMPATIBILITY.md)、[免责声明](../DISCLAIMER.md)、[安全策略](../SECURITY.md)和[贡献指南](../CONTRIBUTING.md)。

## 结论边界

- 本项目与 Apple Inc. 无隶属或背书关系。
- 结果是提交准备度评估，不是 Apple 的审核决定。
- Apple 规则会变化，重要判断应在执行时核对 `developer.apple.com`。
- 本项目不提供法律意见，也不保证 App Store 审核通过。

## 许可证

Apache-2.0。Apple、App Store、Xcode、iOS、iPadOS、macOS、watchOS、tvOS 和 visionOS 是 Apple Inc. 的商标，本项目只作描述性使用。
