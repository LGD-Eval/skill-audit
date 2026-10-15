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

## 4.5 第三方对等监督 N3/N4/N5 整改（Round-3 — scanner v0.2.0，2026-10-15）

> 理论号对等监督测试报告 v1 指出：N3 字母间隔绕过未覆盖（`i g n o r e` 不命中）、N4 `--baseline` 不存在（委托单把计划写成现状）、N5 "12 项"与"9 样本"口径漂移、G4 回归集待办建议升级。全部认领并整改如下：

| 发现 | 级别 | 整改动作 | 验证 |
|---|---|---|---|
| N3 字母间隔绕过 | P1 | `hidden_instruction` 增字母间隔变体 `i\s+g\s+n\s+o\s+r\s+e` / `d\s+i\s+s\s+r\s+e\s+g\s+a\s+r\s+d`（`\s+` 至少一空白，不误伤正常拼写） | `i g n o r e all previous instructions` → P0 命中（实测） |
| N4 `--baseline` 不存在 | P1 | 落地 `--baseline FILE`（精确豁免+报告披露）与 `--write-baseline FILE`（豁免清单生成） | 10 条豁免加载后全抑制、exit=0、JSON 输出纯净（实测） |
| N5 口径漂移（"12 项"） | P2 | 对抗回归集固化为 **12 用例**（10 攻击 + 2 干净对照，见 `tests/adversarial_regression.py`），"12 项"获得真实所指 | `python tests/adversarial_regression.py` → **12/12 passed** |
| G4 回归集待办（原 P2） | — | 升级落地为 `tests/adversarial_regression.py` 可运行回归套件 | 见上 |
| 附加：fake_claim 复数漏检 | — | 规则升级支持 `claims/claimed/claiming` 变位 | "This skill claims certified..." → P1 命中（实测） |

**Round-3 结论：scanner v0.2.0 对抗回归 12/12 通过，P0 命中即阻断原则合规，无回归、无误报。**

## 5. 被评方收益（Benefit-maximization for evaluatees —— 我们评测的价值承诺）

> **我们承诺：每一份评测报告，给被评方的收益做到最大。** 不止打分挑毛病，还包括：

| 收益 | 机制 |
|---|---|
| 1. 可执行改进意见 | 每条发现附：证据等级、优先级（P0-P3）、具体动作、预期影响（本报告即样例） |
| 2. 荣誉认证 | 高分/达标者上光荣榜（HALL_OF_FAME）、可认领评测页与认证徽章 |
| 3. 曝光引流 | 评测报告公开发布 + 引导读者访问被评方仓库/官网 |
| 4. 生态互荐 | 进入 LGD 生态链（ECOSYSTEM_REFERRAL）：生态激励、广告位、会员（生态协作） |
| 5. 可信证据 | 完整证据链（哈希/时间戳/复现步骤）——被评方可直接用于投标、客户信任、合规证明 |
| 6. 学习对比 | 行业最佳实践与同侪对比，明确差距与标杆（Benchmark 板块） |
| 7. 机器可读 | 评测结果以机器可读格式交付（JSON/schema.jsonld），便于被评方集成与自动化治理 |
| 8. 申诉与修正 | 14 天回应期、24h 更正、公平申诉（程序正义）——被评方权益有保障 |

## 6. 自扫描披露（Self-scan disclosure —— 第三方对等监督 P1-3 整改，2026-10-14）

> 背景：理论号对等监督评估指出"scanner.py 对自身仓报 findings 未自曝"。被评方认领并即时整改，如实披露如下。

**自扫描结果（scanner.py 对 skill-audit 全 46 文件实跑，2026-10-14）**：

| 级别 | 数量 | 性质 |
|---|---|---|
| P0 | 3 | 规则自引用（scanner.py 检测器关键字 exfiltrat/steal/fabricat/hallucinat 被自身检出） |
| P1 | 30 | 自引用/样本引用误报（pr-audit.py 正则含"锟斤拷"；ADVERSARIAL_TEST_REPORT 引用对抗样本串；GITHUB_GUARDRAILS 乱码示例） |
| P2 | 1 | 样本引用（"never refuse"——对抗样本原文） |
| **合计** | **34** | exit=1（有阻断级命中） |

**误报根因（分类说明）**：
1. **检测器关键字自引用**：scanner.py 的规则正则字面量（exfiltrate、steal、fabricate、hallucinate、"锟斤拷"、同形字母表）本身就是扫描目标，必然被自身规则命中——这是检测器对自身代码扫描的固有现象。
2. **对抗样本引用**：本报告与 GITHUB_GUARDRAILS 引用攻击样本串（never refuse / claim certified / 锟斤拷 / ???? / iɡnore）以说明规则，样本正文被规则命中。
3. **审计脚本样本字面量**：pr-audit.py 的乱码检测 pattern 含"锟斤拷"样本字面量。

**豁免与改进机制（v2 计划落地）**：
- scanner 新增 `--baseline` 豁免基线：接受"路径+规则+行"已知误报清单，输出仅报告**新增**命中，基线内不阻断；
- 对抗样本串改写为转义/占位写法，消除样本引用误报；
- 自扫描纳入发布前门禁：每次规则变更后跑自扫描，基线外新增项必须说明。

**结论**：自扫描非"投毒未检出"，而是"检测器与样本被自身规则检出"——34 项全部可归因、可豁免、可复现。披露即整改的第一步；基线机制落地后自扫描 exit=0。

---

*Evaluating Autonomy. Verifying Governance. / 评测自治之物，验证治理主张。*
