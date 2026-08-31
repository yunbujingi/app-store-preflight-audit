# 快速开始：十分钟完成第一次审计

[English](quick-start.md) | [项目首页](README.zh-CN.md)

App Store Preflight Audit 是非官方的上架准备度扫描器。它不会提交 App、修改 App Store Connect，也不会预测 Apple 的审核决定。先使用侵入性最低的证据，再针对 finding 或 coverage 缺口补充更强证据。

## 安装与验证

要求 Python 3.9 或更高版本。只有 source audit 不需要 Xcode；读取 Xcode metadata、签名信息、执行构建或收集 Simulator evidence 时才需要 Xcode。

在可信 checkout 中执行：

```bash
python3 -m pip install --upgrade .
app-store-preflight-audit --version
```

以下示例只向 `/tmp/app-store-preflight` 写入结果，先创建一次目录：

```bash
mkdir -p /tmp/app-store-preflight
```

## 路径 A：只有源码

建议从这里开始。它读取 repository 文件和 Git metadata；不会构建、解析 package、执行脚本或启动 Simulator。

```bash
app-store-preflight-audit inventory \
  --root /path/to/repository \
  --output /tmp/app-store-preflight/inventory.json

app-store-preflight-audit privacy \
  --root /path/to/repository \
  --output /tmp/app-store-preflight/privacy.json

app-store-preflight-audit assemble \
  --input /tmp/app-store-preflight/inventory.json \
  --input /tmp/app-store-preflight/privacy.json \
  --json-output /tmp/app-store-preflight/audit.json \
  --markdown-output /tmp/app-store-preflight/audit.md
```

生成文件：

- `inventory.json`、`privacy.json`：collector fragment；
- `audit.json`：规范化结构报告；
- `audit.md`：供人阅读的报告。

当两个 collector fragment 和两份 report 都已生成，并且其中每个 check 都有 disposition 时，这次运行在声明的 source scope 内是完整的。Assembler 不会为未提供的 fragment 虚构 check：缺失的 Archive、runtime 或 App Store Connect layer 是这个 CLI report 的范围之外，不是通过。应在 Skill/人工审阅中把它们记录为 `NOT_RUN` 或 `BLOCKED`，并让 CI 断言预期 collector 列表。source-only 完整不等于已经完整证明上架准备度。

推荐 Skill prompt：

```text
$app-store-preflight-audit

请先执行只读 source audit。
不要构建、运行脚本、启动 Simulator 或访问 App Store Connect。
输出 coverage、全部 BLOCKED 项以及下一步需要提供的 evidence。
```

## 路径 B：已有 `.xcarchive`、`.ipa` 或导出的 `.app`

Archive evidence 更接近最终提交物，因为它包含最终 bundle、executable、Info.plist、embedded framework 和已打包 Privacy Manifest。

```bash
app-store-preflight-audit archive \
  --archive /path/to/App.ipa \
  --output /tmp/app-store-preflight/archive.json

app-store-preflight-audit assemble \
  --input /tmp/app-store-preflight/archive.json \
  --json-output /tmp/app-store-preflight/audit.json \
  --markdown-output /tmp/app-store-preflight/audit.md \
  --sarif-output /tmp/app-store-preflight/audit.sarif \
  --junit-output /tmp/app-store-preflight/audit.xml
```

默认 Archive 命令不会启动其中的二进制。在 macOS 上会使用可用的只读 binary metadata 工具；只有确定要使用本机签名工具时才添加 `--read-entitlements` 或 `--verify-signatures`。Privacy Report、Link Map 和证据限制见 [Archive/IPA recipe](recipes/archive-and-ipa-audit.zh-CN.md)。

推荐 Skill prompt：

```text
对这个 .ipa 执行 Archive audit。
允许读取 Mach-O metadata、Info.plist、Privacy Manifest 和签名 metadata，
但不要执行其中的任何二进制，也不要修改签名状态。
```

## 路径 C：准备接入 GitHub Actions

先在本地生成并人工检查一份稳定报告。只有确认它对应预期 revision 和 audit scope 后，才把它作为 CI baseline。之后使用 assembler 的 `--baseline` 和经审阅的 `--suppressions` 突出新增或变化 finding。

请继续阅读 [CI baseline 与 suppression recipe](recipes/ci-baseline-and-suppression.zh-CN.md)。CI 应保留 canonical JSON、SARIF 和 JUnit artifact，不能把 `BLOCKED` 静默当成 `PASS`。

## 下一步阅读

- [理解报告](understanding-the-report.zh-CN.md)：evidence、disposition、verdict 和 coverage。
- [安全执行与公开证据](safe-execution-and-public-evidence.zh-CN.md)：`--execute`、项目 hook、redaction 限制和 Issue 检查清单。
- [Archive 和 IPA 审计](recipes/archive-and-ipa-audit.zh-CN.md)：最终提交物证据。
- [CI baseline 与 suppression](recipes/ci-baseline-and-suppression.zh-CN.md)：减少重复噪声但不隐藏 finding。
- [合成示例报告](../examples/sample-report.md)。
