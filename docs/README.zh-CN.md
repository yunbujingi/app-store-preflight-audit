# App Store 上架前审计 Skill

这是一个非官方、证据驱动的 Codex Skill，用于在提交 Apple App Store 前审阅 Apple 平台 App。

它将审计拆为源码、隔离构建、Archive、运行体验和 App Store Connect 五层。缺少 Xcode、设备、签名、账号或后台访问时，相应检查会标记为 `NOT_RUN`、`NEEDS_VERIFY` 或 `BLOCKED`，不会伪装成通过。

## 安装

将 `skill/app-store-preflight-audit` 目录复制到 Codex skills 目录，或将该目录打包为兼容 Skill 上传器接受的 zip。

## 调用示例

```text
$app-store-preflight-audit 对当前工程执行 source 模式上架前审计，不修改任何项目文件。
```

```text
$app-store-preflight-audit 对提供的 xcarchive 执行 Archive 级隐私、SDK、Bundle 和 Entitlement 审计。
```

## 结论边界

- 本项目与 Apple Inc. 无隶属或背书关系。
- 结果是提交准备度评估，不是 Apple 的审核决定。
- Apple 规则会变化，重要判断应在执行时核对 `developer.apple.com`。
- 本项目不提供法律意见，也不保证 App Store 审核通过。
