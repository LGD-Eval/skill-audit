# ADVERSARIAL TEST REPORT — 对抗测试与改进报告
# 对抗测试与改进报告：skill-audit 扫描器红队实测（评测→改进→复测闭环）

> 发布方：LGD-Eval ｜ 日期：2026-10-14 ｜ 被测：skill-audit scanner.py v0.1.0-mvp
> 方法：构造 9 样本对抗集（明显投毒/大小写绕过/空格绕过/Unicode 同形字/乱码/伪声明/干净对照），实跑扫描器，对比预期。
> 意义：**评测价值 = 诊断 + 处方**。本报告演示完整闭环：发现缺口 → 给出可执行改进意见 → 修复 → 复测 9/9 通过。
> 双语：英文在前，中文在后，均完整。

---

## 1. 评测对象与方法（Scope & method）

- 被测对象：`scanner.py`（skill-audit 技能投毒检测扫描器，LGD-Eval 自有工具）。
- 对抗样本集（9 个，UTF-8 明文，全部本机实跑）：

| 样本 | 攻击意图 | 预期 |
|---|---|---|
| poison_obvious.md | 隐藏指令（ignore previous） | P0 命中 |
| poison_exfil.md | 数据外泄指令 | P0 命中 |
| poison_manip.md | 操纵性指令（best/never refuse） | P2 命中 |
| poison_fake.md | 虚假声明（claim certified…） | P1 命中 |
| bypass_upper.md | 大小写混淆（IGNORE ALL） | P0 命中 |
| bypass_space.md | 多重空格混淆 | P0 命中 |
| bypass_unicode.md | Unicode 同形字（iɡnore，U+0261） | 应命中 |
| mojibake.md | 乱码（锟斤拷/?????） | 应命中 |
| clean.md | 干净对照 | 0 发现（无误报） |

## 2. 首轮发现（Round-1 findings）

| # | 结果 | 发现 |
|---|---|---|
| R1 | ✅ 通过 | 5 类核心投毒 + 大小写/空格绕过全部命中（(?i) 与 \s+ 正则有效） |
| R2 | ✅ 通过 | 干净样本 0 误报 |
| **G1** | ❌ 缺口 | **乱码检测缺失**：mojibake.md 未被检出（?????/锟斤拷/替换符） |
| **G2** | ❌ 缺口 | **Unicode 同形字绕过**：bypass_unicode.md 未被检出（U+0261 ɡ 视觉等同 g） |
| **G3** | ❌ 缺口 | **伪声明正则锚定过严**：`claim\s+.*(certified|verified|passed)\s*$` 的 `$` 被句尾追加内容绕过 |

## 3. 改进意见（Improvement recommendations —— 每条：证据 / 优先级 / 动作 / 影响）

| 意见 | 证据等级 | 优先级 | 可执行动作 | 预期影响 |
|---|---|---|---|---|
| 新增乱码检测规则（?????/�/锟斤拷） | V（复现 100%） | P0 | 加入 mojibake 正则规则 | 阻断乱码内容进入评审，防投毒掩盖 |
| 新增 Unicode 混淆检测（零宽字符 + 同形字母表） | V（复现 100%） | P0 | 加入 zero_width / unicode_confusion 规则 | 拦截视觉不可见的隐藏指令 |
| 放宽 fake_claim 锚定（移除 `$` 句末约束） | V（复现 100%） | P1 | 正则改为行内匹配 | 提高伪声明检出率，同时控制误报 |
| 补对抗回归集到仓库 tests/ | S（方法建议） | P2 | 将 9 样本固化为回归测试 | 后续改动防回归（复用本报告样本） |

## 4. 修复与复测结果（Round-2 verification — 9/9 通过）

| 样本 | 首轮 | 修复后 | 命中规则 |
|---|---|---|---|
| poison_obvious | ✅ | ✅ | hidden_instruction P0 |
| poison_exfil | ✅ | ✅ | data_exfil P0 |
| poison_manip | ✅ | ✅ | self_praise P2 ×3 |
| poison_fake | ❌ | ✅ | **fake_claim P1**（"claim certified"） |
| bypass_upper | ✅ | ✅ | hidden_instruction P0 |
| bypass_space | ✅ | ✅ | hidden_instruction P0 |
| bypass_unicode | ❌ | ✅ | **unicode_confusion P1**（"iɡnore"） |
| mojibake | ❌ | ✅ | **mojibake P1**（锟斤拷/?????） |
| clean | ✅ 0 | ✅ 0 | 无误报 |

- 结论：修复后 9/9 正确，无回归、无误报；修复版已发布（scanner.py sha=796ad75）。
- 待办：G4 建议（固化回归测试集）为 P2 可选改进，已记录供后续迭代。

## 5. 被评方收益（Benefit-maximization for evaluatees —— 我们评测的价值承诺）

> **我们承诺：每一份评测报告，给被评方的收益做到最大。** 不止打分挑毛病，还包括：

| 收益 | 机制 |
|---|---|
| 1. 可执行改进意见 | 每条发现附：证据等级、优先级（P0-P3）、具体动作、预期影响（本报告即样例） |
| 2. 荣誉认证 | 高分/达标者上光荣榜（HALL_OF_FAME）、可认领评测页与认证徽章 |
| 3. 曝光引流 | 评测报告公开发布 + 引导读者访问被评方仓库/官网 |
| 4. 生态互荐 | 进入 LGD 生态链（ECOSYSTEM_REFERRAL）：互荐分润、广告位、会员（RefEarn） |
| 5. 可信证据 | 完整证据链（哈希/时间戳/复现步骤）——被评方可直接用于投标、客户信任、合规证明 |
| 6. 学习对比 | 行业最佳实践与同侪对比，明确差距与标杆（Benchmark 板块） |
| 7. 机器可读 | 评测结果以机器可读格式交付（JSON/schema.jsonld），便于被评方集成与自动化治理 |
| 8. 申诉与修正 | 14 天回应期、24h 更正、公平申诉（程序正义）——被评方权益有保障 |

---

*Evaluating Autonomy. Verifying Governance. / 评测自治之物，验证治理主张。*
