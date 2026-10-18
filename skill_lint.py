#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lgd-skill-lint v1.0.0 — SKILL.md 六维质量分（对标 Glama TDQS，LGD-Eval 评测线）

Six-dimension quality scorer for SKILL.md, mapped from Glama TDQS:
  Purpose Clarity 25% | Usage Guidelines 20% | Behavioral Transparency 20%
  Parameter/Field Semantics 15% | Conciseness & Structure 10% | Contextual Completeness 10%
  (source: https://glama.ai/mcp/methodology; weights from Glama server score pages)

Design contract (G-06, 规划 v3.0 P0-3):
  - 每个技能 SKILL.md 输出六维 1-5 分 + 加权总分(0-100)
  - 集合级得分 = 60% * 均值 + 40% * 最小值（对齐 Glama server-level TDQS，单个差技能会拉低整仓分）
  - 徽章绑定 commit SHA：--badges 输出带 sha 的 SVG，commit 变化 -> CI 重扫 -> 旧徽章自动失效
  - 新 commit 自动重扫：CI workflow 每次 push/PR 重跑（skill-lint.yml）

Usage / 用法:
    python skill_lint.py --target <skills_dir>            # 表格输出
    python skill_lint.py --target <skills_dir> --json     # JSON 输出
    python skill_lint.py --target <skills_dir> --badges <out_dir> --commit-sha <sha>   # 生成徽章
    python skill_lint.py --self-test                      # 内置断言（无需目标目录）

Exit: 0=通过；1=存在总分<60 或集合级<70（默认门槛，可 --threshold 覆盖）。
"""
import argparse
import json
import os
import re
import sys

VERSION = "1.0.0"

# --- TDQS 维度与权重 ---
DIMS = [
    ("purpose",      "Purpose Clarity",       0.25),
    ("usage",        "Usage Guidelines",      0.20),
    ("behavioral",   "Behavioral Transparency", 0.20),
    ("fields",       "Parameter/Field Semantics", 0.15),
    ("conciseness",  "Conciseness & Structure", 0.10),
    ("context",      "Contextual Completeness", 0.10),
]

REQUIRED_FIELDS = ["name", "description", "version", "license", "allowed-tools", "platforms"]

ACTION_VERBS = [
    "生成", "检测", "校验", "验证", "压缩", "瘦身", "创建", "构建", "转换", "翻译", "分析",
    "提取", "管理", "优化", "自动", "扫描", "路由", "审计", "审查", "拆分", "合并", "排序",
    "统计", "盘点", "比较", "对比", "评估", "评分", "推荐", "规划", "起草", "解析", "识别",
    "追踪", "监控", "清理", "恢复", "同步", "导出", "导入", "归档", "加密", "解密", "签发",
    "核验", "核查", "分解", "跑批", "复跑", "升级", "适配", "拦截", "防护", "守卫", "断言",
    "生成报告", "输出", "返回", "保存", "报告",
    "generate", "creates", "detect", "validate", "verify", "compress", "slim", "build",
    "convert", "translate", "analyze", "extract", "manage", "optimize", "auto", "scan",
    "route", "audit", "review", "split", "merge", "sort", "stats", "count", "compare",
    "score", "recommend", "plan", "draft", "parse", "recognize", "track", "monitor",
    "clean", "restore", "sync", "export", "import", "archive", "encrypt", "decrypt",
    "issue", "verify", "check", "enforce", "guard", "protect", "block", "returns", "report",
]

WHEN_HEADERS = ["何时用", "何时不用", "## 用法", "## Usage", "when to use", "when not to use", "如何使用", "怎么用"]
BEHAVIOR_MARKERS = [
    "副作用", "注意", "警告", "风险", "限制", "边界", "不可逆", "不会", "不适用", "仅限",
    "输入", "输出", "返回", "结果", "幂等", "example", "示例", "举例",
    "side effect", "warning", "note", "limit", "boundary", "idempotent", "returns", "output",
    "does not", "do not", "read-only", "read only", "requires", "需要", "依赖",
]
TRIGGER_MARKERS = ["当用户", "当.*说", "触发词", "trigger", "when the user", "use it when"]

FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---", re.S)
FIELD_RE = re.compile(r"^([A-Za-z0-9_-]+):\s*(.*)$", re.M)


def parse_frontmatter(text):
    m = FRONTMATTER_RE.match(text)
    if not m:
        return {}
    fields = {}
    for k, v in FIELD_RE.findall(m.group(1)):
        fields[k] = v.strip().strip('"').strip("'")
    return fields


def clamp(v, lo=1.0, hi=5.0):
    return max(lo, min(hi, v))


def score_purpose(fields, body):
    desc = fields.get("description", "")
    if not desc or len(desc) < 10:
        return 1.0, "no meaningful description"
    has_verb = any(v in desc.lower() for v in ACTION_VERBS)
    if has_verb and len(desc) >= 30:
        return 5.0, "action verb + object present"
    if has_verb:
        return 4.0, "action verb present but thin"
    return 3.0, "nominal description, no action verb"


def score_usage(fields, body):
    low = body.lower()
    has_when = any(h.lower() in low for h in ["何时用", "when to use", "## 用法", "## usage"])
    has_whennot = any(h.lower() in low for h in ["何时不用", "when not to use"])
    if has_when and has_whennot:
        return 5.0, "when-to-use + when-not-to-use sections"
    if has_when:
        return 4.0, "when-to-use section present"
    if "read_when" in fields or "用法" in body or "usage" in low:
        return 3.0, "usage implied (frontmatter or body)"
    return 2.0, "no structured usage guidance"


def score_behavioral(fields, body):
    low = body.lower()
    hits = [m for m in BEHAVIOR_MARKERS if m.lower() in low]
    if len(hits) >= 3:
        return 5.0, "side-effects/boundaries disclosed"
    if len(hits) == 2:
        return 4.0, "partial behavior disclosure"
    if len(hits) == 1:
        return 3.0, "one behavior marker"
    return 2.0, "behavior implicit"


def score_fields(fields):
    present = [f for f in REQUIRED_FIELDS if fields.get(f)]
    missing = len(REQUIRED_FIELDS) - len(present)
    if missing == 0:
        return 5.0, "all 6 spec fields present"
    if missing == 1:
        return 4.0, "missing 1 spec field"
    if missing == 2:
        return 3.0, "missing 2 spec fields"
    if missing == 3:
        return 2.0, "missing 3 spec fields"
    return 1.0, "spec fields largely absent"


def score_conciseness(fields):
    desc = fields.get("description", "")
    n = len(desc)
    if n == 0:
        return 1.0, "no description"
    if n <= 300:
        return 5.0, "desc <=300 chars"
    if n <= 400:
        return 4.0, "desc 301-400 chars"
    if n <= 500:
        return 3.0, "desc 401-500 chars"
    if n <= 700:
        return 2.0, "desc 501-700 chars"
    return 1.0, "desc >700 chars"


def score_context(fields, body):
    have = 0
    if fields.get("platforms"):
        have += 1
    if fields.get("tags") or fields.get("read_when"):
        have += 1
    if any(re.search(p, body) for p in TRIGGER_MARKERS):
        have += 1
    if fields.get("metadata") or "dependencies" in body.lower() or fields.get("dependencies"):
        have += 1
    if have == 4:
        return 5.0, "platforms+tags+triggers+deps declared"
    return 3.0 + (have - 2) if have >= 2 else (1.0 + have), \
        "context items present: %d/4" % have


def score_skill(skill_dir):
    md = os.path.join(skill_dir, "SKILL.md")
    name = os.path.basename(skill_dir)
    if not os.path.exists(md):
        return {"skill": name, "error": "SKILL.md missing", "total": 0.0, "dims": {}}
    text = open(md, encoding="utf-8", errors="replace").read()
    fields = parse_frontmatter(text)
    body = text[len(FRONTMATTER_RE.match(text).group(0)):] if FRONTMATTER_RE.match(text) else text
    dims = {
        "purpose":     score_purpose(fields, body),
        "usage":       score_usage(fields, body),
        "behavioral":  score_behavioral(fields, body),
        "fields":      score_fields(fields),
        "conciseness": score_conciseness(fields),
        "context":     score_context(fields, body),
    }
    total = sum(dims[k][0] * w for k, _, w in DIMS) / 5.0 * 100.0
    return {
        "skill": name,
        "error": None,
        "total": round(total, 1),
        "dims": {k: {"score": round(v[0], 1), "note": v[1]} for k, v in dims.items()},
    }


def scan(root):
    out = []
    if not os.path.isdir(root):
        return None
    # target 指向单个技能目录时直接评分
    if os.path.exists(os.path.join(root, "SKILL.md")):
        return [score_skill(root)]
    for entry in sorted(os.listdir(root)):
        p = os.path.join(root, entry)
        if os.path.isdir(p):
            out.append(score_skill(p))
    return out


def aggregate(results):
    valid = [r for r in results if not r.get("error")]
    if not valid:
        return {"mean": 0.0, "min": 0.0, "score": 0.0, "n": 0}
    mean = sum(r["total"] for r in valid) / len(valid)
    mn = min(r["total"] for r in valid)
    return {"mean": round(mean, 1), "min": round(mn, 1),
            "score": round(0.6 * mean + 0.4 * mn, 1), "n": len(valid)}


def badge_svg(total, label, sha):
    color = "brightgreen" if total >= 90 else ("green" if total >= 80 else
            ("yellowgreen" if total >= 70 else ("orange" if total >= 60 else "red")))
    w, h = 260, 22
    return ('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d">'
            '<rect width="100%%" height="100%%" fill="#555"/>'
            '<text x="8" y="15" fill="#fff" font-family="monospace" font-size="11">%s</text>'
            '<rect x="150" width="110" height="100%%" fill="%s"/>'
            '<text x="156" y="15" fill="#fff" font-family="monospace" font-size="11">%s%%</text>'
            '<text x="8" y="20" fill="#ccc" font-family="monospace" font-size="8">sha %s</text>'
            '</svg>' % (w, h, label, color, total, sha[:8]))


def main():
    ap = argparse.ArgumentParser(description="lgd-skill-lint: SKILL.md 六维质量分")
    ap.add_argument("--target", help="skills/ root dir")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--badges", help="output dir for badge SVGs")
    ap.add_argument("--commit-sha", default="", help="commit SHA to bind badges")
    ap.add_argument("--threshold", type=float, default=70.0, help="collection min score (default 70)")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        ok = self_test()
        sys.exit(0 if ok else 1)

    if not args.target:
        ap.error("--target or --self-test required")
    results = scan(args.target)
    if results is None:
        print("error: target dir not found", file=sys.stderr)
        sys.exit(2)
    agg = aggregate(results)
    for r in results:
        if r.get("error"):
            continue
        dims = r["dims"]
        if args.json:
            continue
        print("%-28s total=%5.1f  purpose=%s usage=%s behavioral=%s fields=%s concise=%s context=%s"
              % (r["skill"], r["total"], dims["purpose"]["score"], dims["usage"]["score"],
                 dims["behavioral"]["score"], dims["fields"]["score"],
                 dims["conciseness"]["score"], dims["context"]["score"]))
    print("--- collection: mean=%s min=%s score=%s n=%s (60%%mean+40%%min, threshold=%s)"
          % (agg["mean"], agg["min"], agg["score"], agg["n"], args.threshold))

    if args.badges:
        os.makedirs(args.badges, exist_ok=True)
        out = os.path.join(args.badges, "lgd-skill-lint.svg")
        with open(out, "w", encoding="utf-8") as f:
            f.write(badge_svg(agg["score"], "lgd-skill-lint", args.commit_sha or "HEAD"))
        with open(os.path.join(args.badges, "commit-sha.txt"), "w", encoding="utf-8") as f:
            f.write(args.commit_sha or "HEAD")
        print("badges written to %s (bound sha=%s)" % (args.badges, args.commit_sha or "HEAD"))

    if args.json:
        print(json.dumps({"version": VERSION, "aggregate": agg, "skills": results},
                         ensure_ascii=False, indent=1))
    sys.exit(0 if (agg["n"] > 0 and agg["score"] >= args.threshold) else 1)


def self_test():
    """内置断言：构造已知分样本验证规则端到端。"""
    import tempfile
    import shutil
    good = """---
name: sample-good
description: 生成月度账单报告并自动发送邮件，支持批量任务与失败重试。当用户说「帮我出账单」时使用。触发词：账单、月报。
version: 1.0.0
license: MIT
allowed-tools: Read, Write
platforms: [windows, macos, linux]
tags: [报表, 自动化]
read_when:
  - 用户要求生成账单
---
# Sample

## 何时用
用户要求出账单时。

## 何时不用
仅查询历史、不需要生成新文件时。

## 用法
运行脚本并检查输出目录。注意：会覆盖同名文件（不可逆），请先备份。
"""
    bad = """---
name: sample-bad
---
"""
    tf = tempfile.mkdtemp()
    try:
        okdir = os.path.join(tf, "g"); os.makedirs(okdir)
        baddir = os.path.join(tf, "b"); os.makedirs(baddir)
        with open(os.path.join(okdir, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write(good)
        with open(os.path.join(baddir, "SKILL.md"), "w", encoding="utf-8") as f:
            f.write(bad)
        res = scan(tf)
        by = {r["skill"]: r for r in res}
        assert by["g"]["total"] >= 90, "good sample should score >=90, got %s" % by["g"]["total"]
        assert by["b"]["total"] < 60, "bad sample should score <60, got %s" % by["b"]["total"]
        print("self-test OK: good=%s bad=%s" % (by["g"]["total"], by["b"]["total"]))
        return True
    finally:
        shutil.rmtree(tf, ignore_errors=True)


if __name__ == "__main__":
    main()
