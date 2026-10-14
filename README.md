# Skill Audit — 技能安全审计

**Detecting prompt injection and poisoning in agent skill systems. / 检测智能体技能系统中的提示注入与投毒。**

This repository develops the LGD-Eval skill security audit toolchain: scanning skill manifests and prompts for injection, poisoning, and supply-chain risks in AI-accessible skill ecosystems.

本仓库开发 LGD-Eval 技能安全审计工具链：扫描技能 manifest 与提示词，检测 AI 技能生态中的注入、投毒与供应链风险。

## Why / 为什么需要

Agent skills are executable by AI with growing autonomy. A poisoned skill is a supply-chain attack on every agent that loads it. Independent, automated audit is the gate.

智能体技能正被日益自主的 AI 执行。一个被投毒的技能，就是对所有加载它的智能体的供应链攻击。独立、自动化的审计是门禁。

## Planned Capabilities / 规划能力

| English | 中文 | Status |
|---|---|---|
| **Manifest Scanner** — detect suspicious fields, hidden instructions, encoded payloads | **Manifest 扫描**——检测可疑字段、隐藏指令、编码载荷 | Planned / 规划中 |
| **Prompt Analyzer** — injection patterns, jailbreak, prompt-leak heuristics | **提示词分析**——注入模式、越狱、提示泄露启发式 | Planned / 规划中 |
| **Supply-Chain Check** — dependency & provenance verification | **供应链检查**——依赖与来源验证 | Planned / 规划中 |
| **Reputation Ledger** — community-reported skill risk registry | **声誉账本**——社区上报技能风险登记 | Planned / 规划中 |
| **CI Integration** — gate skills before release | **CI 集成**——发布前门禁 | Planned / 规划中 |

## Standards Alignment / 标准对齐

- Maps to Test Expert Manual **L4 (Security & Anti-Poisoning)** and **L10 (Notarization)**. / 对应测试专家手册 L4（安全与防投毒）与 L10（存证）。

## Status / 状态

- **MVP 已交付**：`scanner.py` 可运行（P0-P3 风险分级，P0 阻断退出码；含自引用检测防御）。本地实测通过。
- **PyPI 发布骨架已就绪**：`pyproject.toml` + GitHub Actions Trusted Publishing workflow（打 tag `v*` 自动发布）。

## Install / 安装（PyPI 发布后可用）

```bash
pip install lgd-skill-audit
skill-audit --target ./skills --json
```

或直接从仓库运行：

```bash
python scanner.py --target ./skills --json
```

- **Roadmap / 路线图阶段** — specification complete; implementation in progress. Contributions and security reviews welcome. / 规范已完成，实现推进中。欢迎贡献与安全评审。

---

*Audit before you trust. / 先审计，再信任。*

[← Back to LGD-Eval](https://github.com/LGD-Eval/LGD-Eval) · [Protocol](https://github.com/LGD-Eval/evaluation-protocol) · [Reports](https://github.com/LGD-Eval/evaluation-reports) · [Evidence](https://github.com/LGD-Eval/evaluation-evidence)