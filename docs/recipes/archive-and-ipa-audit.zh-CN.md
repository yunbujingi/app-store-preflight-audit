# Recipe：Archive 和 IPA 审计

[English](archive-and-ipa-audit.md) | [快速开始](../quick-start.zh-CN.md)

当你已经有准备分发的 `.xcarchive`、导出 `.app` 或 `.ipa` 时使用本 recipe。对于打包问题，Archive evidence 比源码推断更强，但仍不能证明 runtime 行为或 Apple 一定审核通过。

## 选择 artifact

| 输入 | 最适合验证 | 重要限制 |
| --- | --- | --- |
| `.xcarchive` | Xcode archived product、bundle、签名 metadata 和 archive context。 | 它可能不是之后真正上传的 export。 |
| `.ipa` | 最接近上传物的 exported payload。 | 缺少部分 archive context；ZIP 内容按不可信输入处理。 |
| 导出的 `.app` | 本地调查一个最终 app bundle。 | 可能缺少 export packaging 和 sibling product。 |
| 源码 repository | 解释来源和 target membership。 | 不能证明最终打包结果。 |

优先使用计划提交的精确 artifact，并记录它如何生成。不要把真实 artifact 附到公开 Issue。

## 基础只读审计

```bash
mkdir -p /tmp/app-store-preflight

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

读取 IPA 前，scanner 会检查 ZIP traversal、symlink、compression ratio、文件数和大小预算。它会解析 bundle、Info.plist、Privacy Manifest、Mach-O metadata、embedded framework/dylib、XCFramework container、版本、平台/deployment 信息和明显的 debug/test resource，但绝不会执行打包二进制。

## Entitlement 与 signature

在 macOS 上可以显式启用只读签名工具：

```bash
app-store-preflight-audit archive \
  --archive /path/to/App.xcarchive \
  --read-entitlements \
  --verify-signatures \
  --output /tmp/app-store-preflight/archive.json
```

`--read-entitlements` 使用 `codesign` display mode，并在可用时只读解码 profile。`--verify-signatures` 检查提供的 artifact，但不会导入证书、修改 profile 或重新签名。工具缺失或 fixture 未签名应形成 limitation/blocker，不能算通过。

Sanitized signing fixture 只用于可复现测试，只能验证比较逻辑，不能证明真实签名。

## Xcode Privacy Report

如果 Xcode 为这个精确 candidate 生成了 Privacy Report，可以导入：

```bash
app-store-preflight-audit archive \
  --archive /path/to/App.xcarchive \
  --privacy-report /path/to/PrivacyReport.json \
  --output /tmp/app-store-preflight/archive.json
```

Scanner 会规范化已知 report shape，并把 bundle identity、SDK name 和 required-reason category 与打包证据交叉验证。当 SDK aggregation 或 Xcode 视角能解决证据缺口时再提供 report；不能假设另一个 build 的 report 仍适用。未知 schema field 保持 `INFERRED` 或 `UNRESOLVED`。

## Target graph 与 Link Map

Archive 可以显示 final executable 中存在某个 symbol 或 library identity，但 static-library source ownership 需要 linker/project evidence。增加 target graph 和 Link Map fragment：

```bash
app-store-preflight-audit target-graph \
  --root /path/to/repository \
  --workspace App.xcworkspace \
  --configuration Release \
  --link-map /path/to/App-LinkMap-normal-arm64.txt \
  --output /tmp/app-store-preflight/target-graph.json

app-store-preflight-audit assemble \
  --input /tmp/app-store-preflight/archive.json \
  --input /tmp/app-store-preflight/target-graph.json \
  --json-output /tmp/app-store-preflight/audit.json \
  --markdown-output /tmp/app-store-preflight/audit.md
```

缺少 Link Map 时，linked static-library member 对 final executable 的归属保持 unresolved，scanner 不能只根据文件名猜测。

## 正确理解 symbol finding

Mach-O byte string 和 undefined symbol 是静态线索，可能来自 dead、unreachable、compatibility 或 wrapper code，因此使用 `INFERRED`。修改 Privacy Manifest 前必须确认可达性和真实目的；symbol match 不能替你选择 approved reason。

## 完成检查清单

- artifact 确实是计划提交的 build/export；
- inventory 包含所有 app、extension、App Clip、Watch product、framework 和 dylib；
- malformed packaged manifest 和 confirmed bundle/signing mismatch 已处理；
- 对 `NEEDS_VERIFY` symbol/SDK lead 有书面人工判断；
- 缺少 Link Map、签名工具、Privacy Report、runtime 或 App Store Connect evidence 时，报告明确显示 limitation，未静默当作 PASS；
- 公开前已经人工检查报告。
