# R04 支撑材料包（Supporting Materials for R04 Insertion · 草稿 v3 配套）

> 配套主稿：`W3C-02_R04_插入稿_草稿.md`（v3）。
> 用途：作为 R04 书面提交物（经 07 邮箱发往 public-agent-identity）的**支持资料与 demo 实例**，使评审可独立核验，不依赖现场出席。
> 状态：NOT FINAL，待 L3 单件确认才发。门3 红队压测中（B1/B2/B3 待闭合）。

---

## A. 工作化示例：registry 招聘用例下 5 值逐一走通

**场景设定**：一个招聘平台（registry）在核验求职者上传的 agent 身份 bundle 时，需要就"该凭证的撤销否定"建立结论。bundle 携带 `revocation_establishment` 字段（本稿提议的必填字段）。以下逐值给出一份最小 bundle 片段 + 叙事。

### A.1 `recorded` — 已建立"有撤销事件"
```json
{
  "revocation_establishment": {
    "value": "recorded",
    "evaluator_side": true,
    "evaluated_at": "2026-11-01T09:30:00Z",
    "evidence": {
      "event_id": "rev-9f2c...",
      "source": "ca.example.org/revocation-list",
      "retrieved_at": "2026-11-01T09:30:00Z"
    }
  }
}
```
叙事：来源回答了，且答案明确——**存在**一条撤销事件，且已被取回。bundle 自身的陈述结清了"是否被撤销"的问题，不再触发"谁签名/countersign"追问。

### A.2 `not_recorded` — 支持一条否定陈述
```json
{
  "revocation_establishment": {
    "value": "not_recorded",
    "evaluator_side": true,
    "evaluated_at": "2026-11-01T09:30:00Z",
    "evidence": {
      "source": "ca.example.org/revocation-list",
      "answer": "no revocation event recorded for [start,now)",
      "answered_at": "2026-11-01T09:30:00Z"
    }
  }
}
```
叙事：来源**回答了**，答案是"该区间未记录撤销事件"。这**支持一条否定陈述**（"在已查区间未撤销"），但注意它不等同于"永远未撤销"——区间之外未覆盖。

### A.3 `query_failed` — 不支持任何陈述
```json
{
  "revocation_establishment": {
    "value": "query_failed",
    "evaluator_side": true,
    "evaluated_at": "2026-11-01T09:30:00Z",
    "evidence": {
      "source": "ca.example.org/revocation-list",
      "error": "timeout after 5000ms",
      "attempted_at": "2026-11-01T09:30:00Z"
    }
  }
}
```
叙事：来源**没有回答**（超时/拒绝）。因此**任何方向都不支持**——既不能说"未撤销"，也不能说"已撤销"。这是 receiver 线上最常把它和 `not_recorded` 混为一谈的情况，本字段要显式拆开。

### A.4 `cross_federation_unsynchronised` — 局部否定但联邦路径可能另存记录
```json
{
  "revocation_establishment": {
    "value": "cross_federation_unsynchronised",
    "evaluator_side": true,
    "evaluated_at": "2026-11-01T09:30:00Z",
    "evidence": {
      "local_source": "ca.example.org/revocation-list",
      "local_answer": "no revocation event recorded",
      "unsynced_path": "federation-B / authority-C",
      "coverage_note": "authority-C not yet queried / not in sync"
    }
  }
}
```
叙事：本地来源回答了否定，但在本联邦路径上**另一权威可能持有该记录**。因此本地否定**不推广到全局**。这是多联邦互操作场景下的关键区分，避免"本地没查到=全网没撤销"的错误结论。

### A.5 `undetermined` — 兜底，什么都没建立
```json
{
  "revocation_establishment": {
    "value": "undetermined",
    "evaluator_side": true,
    "evaluated_at": "2026-11-01T09:30:00Z",
    "evidence": {
      "attempted": ["query ca.example.org (timeout)", "query federation-B (refused)"],
      "note": "neither recorded nor not_recorded nor cross_federation_unsynchronised could be established"
    }
  }
}
```
叙事：上述都不成立。**绝不回退为 `recorded`**——因为可选/回退为 recorded 的字段会在交付压力下被留空，使每个 bundle 看起来都"已结清"，正是要消除的失效模式。

---

## B. 字段 JSON Schema 草图（proposed，待对齐 v0.2 真实命名）

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "revocation_establishment (PROPOSED — name pending v0.2 anchor)",
  "type": "object",
  "required": ["value", "evaluated_at", "evidence"],
  "properties": {
    "value": {
      "type": "string",
      "enum": [
        "recorded",
        "not_recorded",
        "query_failed",
        "cross_federation_unsynchronised",
        "undetermined"
      ]
    },
    "evaluator_side": { "type": "boolean", "description": "true if recorded by the evaluator-side" },
    "evaluated_at": { "type": "string", "format": "date-time", "description": "MUST align with the rest of the bundle's assurance conditions" },
    "evidence": { "type": "object", "description": "per-value evidence per R04 §evidence" }
  }
}
```
> 注：字段名 `revocation_establishment` 为**提议名**，须对齐 v0.2 真实字段名/章节锚点（红队 B1）。本草图不重定义 D3、不重命名 NOT_EVIDENCED / NOT_DETERMINED。

---

## C. 边界与不变量分析（红队维度5 配套论证）

1. **不变量（核心）**：字段**必填**；当什么都建立不了时取值**必须为 `undetermined`**，**绝不回退为 `recorded`**。理由见 A.5。
2. **evaluator-side 记录**：在产出其余结果同一时刻记录，沿用包内"评估方结果 vs 输入"分离规则。稍后重查的 relying party 记录它自己的值；bundle 须注明携带的是哪个，否则陈旧答案会被读成当前。
3. **评估时点对齐**：本字段（含 `cross_federation_unsynchronised` 的 route 值）须与其余条件在**同一时刻**评估，不得单独评估；否则 bundle 内部一致却携带一个仅更早成立的 route。
4. **与既有术语的非重叠映射**：
   - **D3（fetch statuses）** = 制品是否可取回 / 是否尝试取回（**传输层**）。
   - **本字段** = 取回**之后**，关于撤销否定建立了什么（**语义层**）。
   - `NOT_DETERMINED`（D3）≠ 本字段 `undetermined`：前者是传输层"取回无法确定"，后者是语义层"即便制品已取回，撤销否定仍无法建立"。为不引入重叠术语，本稿仅在 D3 之上新增一个独立的、必填的、评估方侧的字段。

---

## D. 与既有术语的关系（文字图）

```
                [ 凭证 bundle 呈现 ]
                          |
                [ D3: fetch statuses ]  --- 传输层：可取回？尝试取回？
                          | (取回成功之后)
                          v
          [ revocation_establishment (本稿新增, 必填) ]  --- 语义层：撤销否定建立了什么？
                          |
        +-----------------+-----------------+-----------------+-----------------+
        v                 v                 v                 v                 v
   recorded        not_recorded       query_failed   cross_federation_   undetermined
   (有事件,已取回)   (来源答:无记录)   (来源未答)      unsynchronised      (兜底,绝不回退recorded)
                                                 (本地否定,联邦或另存)
```

---

## E. demo 实例（可视化）

配套交互式 demo：`R04_demo_5values.html`（单文件，可直接在浏览器打开 / 附于 07 邮箱提交）。展示 5 值卡片 + 不变量高亮 + 一个可点击切换的"bundle 评估"小演示，使评审无需部署即可理解区分。

> 门7 备注：若经授权，该 demo 亦可置于公开仓（如 LGD-Eval/skill-audit 的 demo/ 子目录）供外人直接实测；当前仅本地准备，未 push。
