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

## lgd-skill-lint — SKILL.md 六维质量分（G-06，2026-10-19 新增）

对标 **Glama TDQS**（https://glama.ai/mcp/methodology）的 SKILL.md 质量评分器，评测号自营（规划 v3.0 P0-3，批次 B 免批准）：

| 维度 | 权重 | 检查对象 |
|---|---|---|
| Purpose Clarity | 25% | description 是否含动作动词+对象（"做什么"明确） |
| Usage Guidelines | 20% | 「何时用 / 何时不用 / 用法」是否结构化 |
| Behavioral Transparency | 20% | 副作用 / 边界 / 输入输出 / 不可逆动作是否披露 |
| Parameter/Field Semantics | 15% | agentskills.io 六规范字段（name/description/version/license/allowed-tools/platforms） |
| Conciseness & Structure | 10% | description ≤300 字符（上下文预算=会话 2%） |
| Contextual Completeness | 10% | platforms/tags/触发词/dependencies 声明 |

集合级得分 = **60% × 均值 + 40% × 最小值**（对齐 Glama server-level TDQS——单个差技能会拉低整仓）。

```bash
python skill_lint.py --target ./skills --json        # 逐技能六维分 + 集合分
python skill_lint.py --target ./skills --badges out --commit-sha <sha>   # 徽章绑定 commit SHA
python skill_lint.py --self-test                     # 内置断言
```

- **徽章绑定 commit SHA**：`--badges` 生成带 sha 的 SVG + `commit-sha.txt`；每次新 commit CI 重扫重发，旧徽章自动失效（G-06 "新 commit 自动重扫失效"）。
- **CI 门槛**：`.github/workflows/skill-lint.yml` 每次 push/PR 重跑 self-test + fixtures 质量门槛（70 分，"构建不过即不可见"）。
- **注册表重扫接口**：113→187 条技能注册表（理论号 lgd-skills-index）接 `skill-lint` CI 重扫，因三号隔离纪律（评测号不写理论号仓）留待 Steven 批准后由理论号侧接入（批次 D / 集中检查点 2026-10-22）。

- **Roadmap / 路线图阶段** — specification complete; implementation in progress. Contributions and security reviews welcome. / 规范已完成，实现推进中。欢迎贡献与安全评审。

---

*Audit before you trust. / 先审计，再信任。*

[← Back to LGD-Eval](https://github.com/LGD-Eval/LGD-Eval) · [Protocol](https://github.com/LGD-Eval/evaluation-protocol) · [Reports](https://github.com/LGD-Eval/evaluation-reports) · [Evidence](https://github.com/LGD-Eval/evaluation-evidence)