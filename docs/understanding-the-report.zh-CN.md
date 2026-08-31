# 理解审计报告

[English](understanding-the-report.md) | [快速开始](quick-start.zh-CN.md)

报告把三个问题分开表达：证据有多可靠、单项检查得出什么结论、所有检查合并后得到什么 preflight verdict。不要把它们压缩成一个简单的通过/失败信号。

## Evidence verification（证据验证状态）

| 状态 | 含义 | 示例 |
| --- | --- | --- |
| `CONFIRMED` | 在记录的 scope 内，有直接证据支持该陈述。 | 打包后的 Info.plist 包含某个 bundle ID。 |
| `INFERRED` | 证据是间接或启发式的，需要人工确认。 | Mach-O string 或 undefined symbol 暗示 required-reason API category。 |
| `UNRESOLVED` | 当前证据不能确定该陈述。 | target membership 依赖尚未解析的 Xcode 条件。 |

静态 symbol 或 byte evidence 不能证明代码实际可达、已经执行或用于某个具体目的。不能根据它自动选择 Privacy Manifest approved reason。

## Check disposition（检查结论）

| 结论 | 含义 | 上架解释 |
| --- | --- | --- |
| `PASS` | 在当前证据和 scope 内通过。 | 是正面结果，但不代表其他未测试层也通过。 |
| `FAIL` | 直接证据确认没有满足要求。 | 通常应在提交前解决并复验。 |
| `N/A` | 已确认该检查不适用。 | 仍应确认 applicability 判断本身可靠。 |
| `NOT_RUN` | 没有尝试执行该检查。 | 没有结果，不能算通过。 |
| `NEEDS_VERIFY` | 存在线索、歧义或未完成的交叉验证。 | 补充更强证据或做出有记录的人工判断。 |
| `BLOCKED` | 缺少所需工具、artifact、授权、测试状态或环境，无法执行。 | 它不是失败，但绝不能当作通过；应解除 blocker 或明确接受 coverage 缺口。 |

`PASS` 只表示“当前 evidence boundary 内的这个 check 通过”。例如源码中的 Privacy Manifest 解析可以通过，但 Archive 是否真正打包它仍然可能没有验证。

## Overall verdict（整体结论）

| 结论 | 含义 |
| --- | --- |
| `GO` | 在已审计 scope 内，没有仍然阻止继续的 active finding；仍必须阅读 coverage limitation。 |
| `CONDITIONAL_GO` | 只有在审阅所列条件、unresolved evidence 或较低严重度风险后才适合继续。 |
| `NO_GO` | 已有高影响证据表明，不应在未修复或未做出明确书面决定前提交。 |

任何 verdict 都不是 Apple 审核承诺。Apple 可能检查本项目未观察到的运行行为、metadata、policy applicability、账号状态、地区规则或 reviewer context。

## Coverage 不是“过审概率”

Coverage 表示各审计层中有多少 applicable check 获得了可解决的证据，不估算 App Review 通过概率。报告可能 source coverage 很高但 runtime coverage 为零；一个 confirmed blocker 也可能比很多低风险 PASS 更重要。

Canonical report 根据提供给 `assemble` 的 fragment 计算 coverage。如果某一层没有 fragment/check，该层可能不会出现在 `coverage` 中；缺席表示“不在这次 assembled scope 内”，绝不表示 `PASS` 或 100%。CI 应断言 `fragments` 中包含预期 collector name，Skill 或人工报告则应把预期但不可用的 check 记为 `NOT_RUN` 或 `BLOCKED`。

应分别阅读各层 coverage：

- source 和 target graph；
- build、unit test、UI test；
- Archive 和 signing；
- runtime 和 reviewer path；
- App Store Connect；
- 当前 policy/storefront applicability。

## Finding、baseline 与 suppression

Finding 同时包含 severity、disposition、verification、authority、evidence、assumption 和 remediation。重复运行 CI 时，报告还会区分 new、changed、unchanged、suppressed 和 resolved finding。

Suppression 不会把 finding 改写成 `PASS`。它记录经过审阅、有 owner、有期限的决定，在保留 canonical JSON 原始 finding 的同时减少选定的 CI 噪声和 verdict 影响。不能为了让 gate 变绿而 suppression 缺失 evidence 或 `BLOCKED` 状态。

## 公开报告前

Canonical JSON 可能包含 bundle identifier、文件名、SDK inventory、metadata value、finding detail 和 hash。Redaction 会降低明显 secret 和本机路径泄露，但无法理解所有项目专有标识。公开任何 fragment、report、screenshot、Archive 或 App Store Connect export 前，请遵循[安全执行与公开证据指南](safe-execution-and-public-evidence.zh-CN.md)。
