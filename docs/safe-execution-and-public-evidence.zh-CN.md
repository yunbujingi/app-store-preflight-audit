# 安全执行与公开证据

[English](safe-execution-and-public-evidence.md) | [快速开始](quick-start.zh-CN.md)

本文面向实际使用者解释运行风险。[SECURITY.md](../SECURITY.md) 仍然是漏洞报告和 maintainer security policy。

## 默认 capability boundary

Source、privacy、Archive、本地 App Store Connect import、report assembly 和 runtime-plan generation 对被审计项目默认只读。它们可以向项目外的指定路径写入报告。Archive 检查绝不执行打包二进制。App Store Connect adapter 只发送 allowlist 中的 `GET` 请求，不能上传、修改、定价、提交或联系 App Review。

只读不等于“可以公开”，报告仍可能包含项目 metadata。

## `--execute` 会改变什么

`xcode` 命令默认只生成 dry-run plan，除非添加 `--execute`：

```bash
app-store-preflight-audit xcode \
  --root /path/to/repository \
  --project /path/to/repository/App.xcodeproj \
  --scheme App \
  --action build \
  --output-root /tmp/app-store-preflight-xcode \
  --evidence-output /tmp/app-store-preflight/xcode-plan.json
```

首先检查 capability/side-effect preview。真正执行还要求 `--acknowledge-execution-risk`。根据项目内容，可能还要分别确认：

- `--allow-run-scripts`；
- `--allow-build-hooks`：Swift Package plugin、custom build tool/rule 或 dependency hook；
- `--allow-dependency-resolution`：可能访问网络并改变 cache；
- `--allow-signing`：可能访问 signing identity 或 keychain-backed operation。

执行 Xcode build 可能运行 repository-controlled code。Run Script、Package Plugin、custom build tool、CocoaPods hook 或 dependency tool 可能访问网络、developer cache、当前进程可见 credential 或隔离 build 目录之外的路径。Runner 会隔离 build output 并比较执行前后 Git state，但不能 sandbox 任意项目代码的所有副作用。

不能只为了让 check 通过就添加 acknowledgement flag。应先检查 capability、使用可信 revision、减少 credential/network access，并优先在一次性 CI host 上运行。

## 其他显式工具访问

- `target-graph --use-xcodebuild` 会在禁止 automatic package resolution 的情况下运行 Xcode metadata command；它不构建 App，但仍会让 Xcode 读取项目。
- `archive --read-entitlements` 和 `archive --verify-signatures` 调用本机只读 signing metadata command。
- `runtime-plan --use-xcresulttool` 读取提供的 `.xcresult`；只生成 runtime plan 不会启动或修改 Simulator。
- StoreKit、permission 和 weak-network observation 要求明确授权和命名的专用 test state；工具不会自动创建这些状态。
- `asc-read` 只从环境变量读取预先生成的 JWT。绝不能把 token 写在命令行或报告中。

## Fragment 和 report 可能包含什么

根据输入证据，JSON、Markdown、SARIF、JUnit 可能包含：

- bundle identifier、product/target/scheme name 和相对文件名；
- SDK/framework/library name 和 dependency version；
- entitlement key 和已脱敏 value；
- App Store Connect app name、SKU、build/version inventory、age-rating answer、IAP/subscription metadata 和 screenshot filename；
- finding explanation、assumption、reviewer path detail 和 test-state description；
- 可关联多次报告的 hash 与 stable fingerprint；
- 导入的 screenshot 或 `xcresult` inventory。

原始 Archive、provisioning profile、screenshot、ASC export 和 runtime observation 可能比规范化报告包含更多敏感数据。

## Redaction 能保护什么、不能保护什么

自动 redaction 会替换已识别的 secret/token pattern 和常见绝对 user/temp path。Collector 优先输出相对路径或 path token，signing fixture 也会处理常见 team identifier。

Redaction 无法可靠识别：

- 专有 bundle ID、App/feature codename、server hostname 或 customer name；
- 自定义 credential format，或任意 binary/text field 中的 secret；
- screenshot 或 review note 中可见的个人信息；
- 从 filename、entitlement combination、IAP identifier 或 hash 推断出的敏感含义；
- custom integration 写入自由文本 evidence 的数据。

Redaction 只能降低意外泄露，不能替代人工检查。

## 公开 Issue 前检查清单

提交公开 False positive、False negative、Apple rule change 或 New project shape Issue 前：

- 尽量用最小 synthetic fixture 复现；
- 不要上传真实 `.ipa`、`.xcarchive`、`.app`、`.xcresult`、provisioning profile、certificate、App Store Connect export、JWT、screenshot 或完整 audit report；
- 把 bundle ID、team ID、product name、domain、account name、path、commit ID 和 review credential 替换为合成值；
- 删除与复现无关的 source code；
- 人工检查每个 JSON value、Markdown paragraph、SARIF property、JUnit message、filename 和 archive member；
- 确认 hash/fingerprint 可以公开，或使用 synthetic content 重新生成；
- 写明 tool version、schema version、platform/Xcode version、expected outcome、actual outcome，以及证据为何是合成或完整脱敏；
- credential exposure、code execution、traversal、unsafe archive handling 或 redaction bypass 应使用 private vulnerability reporting。

无法确定时，只描述 project shape 和 state transition，不上传原始 evidence。
