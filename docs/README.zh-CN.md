# App Store 上架前审计 Skill

这是一个非官方、证据驱动的 Codex Skill，用于在提交 Apple App Store 前审阅 Apple 平台 App。

它将审计拆为源码、隔离构建、Archive、运行体验和 App Store Connect 五层。缺少 Xcode、设备、签名、账号或后台访问时，相应检查会标记为 `NOT_RUN`、`NEEDS_VERIFY` 或 `BLOCKED`，不会伪装成通过。

`v0.2.0-beta` 开发线增加 Mach-O/动态依赖/签名/Entitlement/Privacy Manifest 交叉证据、Apple 规则 hash 时效记录、Simulator 场景矩阵、SARIF/JUnit、可量化误报 eval，以及确定性安装包。

## 安装

先生成确定性 zip 和 checksum，再预览安装：

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

CI 可使用稳定 JSON、SARIF 2.1.0 和 JUnit。eval 会分别记录 TP、TN、FP、FN、unknown、blocked 和不可验证原因，这些指标只表示规则质量，不代表 Apple 通过概率。

## 结论边界

- 本项目与 Apple Inc. 无隶属或背书关系。
- 结果是提交准备度评估，不是 Apple 的审核决定。
- Apple 规则会变化，重要判断应在执行时核对 `developer.apple.com`。
- 本项目不提供法律意见，也不保证 App Store 审核通过。
