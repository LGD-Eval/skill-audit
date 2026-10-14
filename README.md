# Skill Audit · 技能审计

> 隶属：凡自治之物 · LGD 治理学（Lifecycle Governance Doctrine）· 创造术家族
> 角色：LGD-Eval 评测线 · 中立第三方
> 官方英文：Evidence-Gated AI Lifecycle Governance
> 许可证：Apache-2.0（代码）

## 是什么
AI 技能（Skill/MCP）安全审计工具 MVP：
- **manifest 扫描**：检测 SKILL.md / MCP manifest 中的异常指令
- **prompt 注入检测**：识别隐藏指令、投毒模式
- **引用完整性**：核对技能声明的来源与真实内容

## 为什么做
AI 自主加载技能时代，投毒攻击（prompt injection / manifest poisoning）是首要风险。
审计工具 = 评测号的核心技术能力，也是 LGD 门禁机制（Evidence-Gated）的工具化。

## 使用
- scanner.py：命令行扫描器（MVP，见 README 用法）
- 后续：规则库扩展、CI 集成、MCP 扫描

## 安全声明
- 工具仅用于防御性审计
- 报告须独立复验（不自查原则）