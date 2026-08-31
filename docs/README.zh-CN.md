# App Store 上架前审计 / App Store Preflight Audit

[English](../README.md) | [简体中文](README.zh-CN.md)

这是一个非官方、证据驱动的 Codex Skill，用于在提交 Apple App Store 前审阅 Apple 平台 App。

最新已发布版本：`v0.2.0-beta`。

当前 `codex/v0.3.0-beta` 开发目标：深化 target/archive 真相层、谨慎引入 runtime evidence、独立 scanner CLI、可验证分发，以及严格 GET-only 的 App Store Connect inventory adapter。

它将审计拆为源码检查、隔离 Xcode 执行、Archive 检查、运行体验和 App Store Connect 验证。它输出机器可读证据和简明的人类报告，但不会把“构建成功”当成“Apple 一定会审核通过”。

> 本项目与 Apple Inc. 没有隶属、背书或赞助关系；不保证 App Store 审核通过，也不提供法律意见。

## 包含内容

- 采用渐进式 Skill 架构，只在适用时加载对应规则和流程 reference。
- 提供 source、build、archive 和 submission 审计模式，并显式记录覆盖状态。
- 从 PBX phase、file-system synchronized group、workspace、SwiftPM/plugin、generated output、条件 XCConfig、可选 `xcodebuild` metadata 和 Link Map 建立稳定 target graph。
- 分离 verification（验证状态）与 severity（严重度），避免把推断写成事实。
- 使用隔离输出目录执行 Xcode 命令，并比较执行前后的 Git 状态。
- 收集 Privacy Manifest 和 required-reason API 证据。
- 支持 `.xcarchive`、导出 bundle 和受安全预算限制的 `.ipa` 检查。
- 在不执行 App 代码的前提下检查 Mach-O、动态依赖、签名和 bundle-local required-reason 声明。
- 检查 parent/child ID、App Clip/Watch/nested framework、版本、平台、规范化 Mach-O deployment/SDK、XCFramework slice、embedded profile、调试资源、static library 和语义化 Xcode Privacy Report 证据。
- 输出稳定 JSON Schema、Markdown、SARIF 2.1.0 和 JUnit。
- 使用稳定内部 ID、适用范围、fingerprint、review version 和关联 eval 建立 rule-level Apple 规则 registry。
- 只读导入 App Store Connect export，并提供固定 Apple origin、严格 GET-only、字段 allowlist 的 API inventory adapter；App Privacy answers 仍要求用户 export。
- 支持 baseline finding diff 和带 owner、理由、到期日、规则版本的 suppression；原始 finding 仍保留在 canonical JSON。
- 生成显式且不修改 Simulator 的矩阵、可审阅 XCTest plan，导入截图与 `xcresult`，并对敏感场景设置授权门槛。
- 提供可复现 fixtures、per-rule TP/TN/FP/FN 指标和零回归 CI gate。
- 将 scanner 发布为无依赖 Python package/CLI，并提供确定性 Skill zip、per-file provenance、checksum、可恢复升级与可选 minisign 验证。

## 安装

在 checkout 中用一条命令安装或升级独立 scanner：

```bash
python3 -m pip install --upgrade .
```

安装后可运行 `app-store-preflight-audit --version`。Release CLI 可用一条命令下载并验证不可变 tag 对应的 Skill：

```bash
app-store-preflight-audit install-release --repository OWNER/app-store-preflight-audit \
  --version v0.3.0-beta \
  --destination-root /path/to/skills
```

默认只验证和预览；新安装添加 `--install`，升级添加 `--install --upgrade`，旧版本会保留为带时间戳的 backup。

先生成并检查确定性 zip 和 checksum：

```bash
python3 skill/app-store-preflight-audit/scripts/package_skill.py \
  --skill skill/app-store-preflight-audit --output /tmp/app-store-preflight-audit.zip \
  --checksum-output /tmp/app-store-preflight-audit.zip.sha256 \
  --provenance-output /tmp/app-store-preflight-audit.provenance.json
python3 skill/app-store-preflight-audit/scripts/install_skill.py \
  --source /tmp/app-store-preflight-audit.zip \
  --checksum-file /tmp/app-store-preflight-audit.zip.sha256 \
  --destination-root /path/to/skills
```

确认目标目录后再添加 `--install`；已有 Skill 默认拒绝覆盖，只有显式 `--upgrade` 才会先保留带时间戳的 backup 再替换。

## 调用示例

```text
$app-store-preflight-audit 对当前工程执行 source 模式上架前审计，不修改任何项目文件。
```

```text
$app-store-preflight-audit 对提供的 xcarchive 执行 Archive 级隐私、SDK、Bundle 和 Entitlement 审计。
```

除非另行获得明确授权，Skill 不会提交 build、修改 App Store Connect metadata、购买产品、重置 Simulator 或修复发现的问题。

这个 beta 会交给社区验证。请分别通过 False positive、False negative、Apple rule change 和 New project shape Issue 表单反馈，并且只提交合成或完整脱敏的证据。

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
