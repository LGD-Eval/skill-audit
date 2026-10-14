#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Skill Audit MVP - manifest/prompt 投毒检测扫描器 (LGD-Eval 评测线)

用法:
    python scanner.py --target <path> [--rules <dir>]

输出: JSON 扫描结果（风险分级 P0-P3，P0=阻断）
原则: 防御性审计；结论须独立复验（不自查原则）。
"""
import argparse
import hashlib
import json
import os
import re
import sys

RISK_LEVELS = ("P0", "P1", "P2", "P3")

# 默认投毒检测规则（正则；MVP 基线，规则库可扩展）
DEFAULT_RULES = {
    "hidden_instruction": {
        # 正常拼写 + 字母间隔绕过（N3 修复 2026-10-15）：\s+ 要求至少一个空白，
        # 只命中 "i g n o r e" / "d i s r e g a r d" 形式，不误伤正常拼写。
        "pattern": re.compile(r"(?i)((?:ignore|disregard|i\s+g\s+n\s+o\s+r\s+e|d\s+i\s+s\s+r\s+e\s+g\s+a\s+r\s+d)\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|context))"),
        "level": "P0",
        "reason": "隐藏指令：要求忽略先前指令（典型投毒模式；含字母间隔绕过变体）",
    },
    "data_exfil": {
        "pattern": re.compile(r"(?i)(exfiltrat|steal|send\s+(user\s+)?data|upload\s+to\s+https?://)"),
        "level": "P0",
        "reason": "数据外泄指令",
    },
    "unauthorized_action": {
        "pattern": re.compile(r"(?i)(delete|rm\s+-rf|drop\s+table|format\s+disk|shutdown)"),
        "level": "P1",
        "reason": "危险动作指令",
    },
    "self_praise": {
        "pattern": re.compile(r"(?i)(you\s+are\s+(the\s+)?best|always\s+agree|never\s+refuse|do\s+not\s+tell\s+the\s+user)"),
        "level": "P2",
        "reason": "操纵性指令（过度顺从/禁止告知）",
    },
    "fake_claim": {
        # 2026-10-15 升级：支持 claims/claimed/claiming 变位（N3 回归发现复数形式漏检）
        "pattern": re.compile(r"(?i)(claim(s|ed|ing)?\s+.*(certified|verified|passed)|fabricat|hallucinat)"),
        "level": "P1",
        "reason": "虚假声明/伪造证据指令（含 claims/claimed 变位）",
    },
    # 对抗测试（ADVERSARIAL_TEST_REPORT 2026-10-14）新增：
    "mojibake": {
        "pattern": re.compile(r"\?\?\?\?\?|\ufffd|锟斤拷"),
        "level": "P1",
        "reason": "乱码/编码损坏：可能掩盖投毒内容或破坏可信度",
    },
    "zero_width": {
        "pattern": re.compile(r"[\u200b\u200c\u200d\ufeff]"),
        "level": "P1",
        "reason": "零宽字符隐藏指令：视觉不可见，常用于绕过",
    },
    "unicode_confusion": {
        "pattern": re.compile(r"(?i)([a-z]*[ɡаеос][a-z]*|i\s*ɡ\s*n\s*o\s*r\s*e|d\s*i\s*s\s*r\s*e\s*g\s*a\s*r\s*d)"),
        "level": "P1",
        "reason": "Unicode 同形字混淆：视觉近似 ASCII 的异体字母（对抗绕过）",
    },
}


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_file(path: str, rules: dict) -> list:
    findings = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        return [{"file": path, "level": "P3", "rule": "io_error", "reason": str(e)}]
    for name, rule in rules.items():
        for m in rule["pattern"].finditer(text):
            findings.append({
                "file": path,
                "level": rule["level"],
                "rule": name,
                "reason": rule["reason"],
                "match": m.group(0)[:120],
                "line": text.count("\n", 0, m.start()) + 1,
            })
    return findings


def collect_targets(target: str) -> list:
    if os.path.isfile(target):
        return [target]
    out = []
    for root, _dirs, files in os.walk(target):
        for f in files:
            if f.endswith((".md", ".txt", ".yaml", ".yml", ".json", ".py", ".sh")):
                out.append(os.path.join(root, f))
    return out


def load_baseline(path: str) -> list:
    """Load baseline exemptions（加载豁免基线：已登记发现的精确豁免清单）. JSON 形如
    {"tool": "skill-audit", "version": "...", "exemptions": [{"file":..., "rule":..., "line":..., "match":...}]}.
    任何豁免都在报告中披露（可追溯）。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        ex = data.get("exemptions", [])
        if not isinstance(ex, list):
            return []
        return [tuple(e.get(k, "") for k in ("file", "rule", "line", "match")) for e in ex]
    except Exception:
        return []


def main() -> int:
    ap = argparse.ArgumentParser(description="Skill Audit - 技能投毒检测扫描器 (v0.2.0)")
    ap.add_argument("--target", required=True, help="要扫描的文件或目录")
    ap.add_argument("--rules", default=None, help="自定义规则 Python 文件（可选）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--baseline", default=None,
                    help="豁免基线 JSON（已登记发现的精确豁免；加载后这些发现被抑制并在报告中披露）")
    ap.add_argument("--write-baseline", default=None,
                    help="把本次全部发现写入基线 JSON 文件（自扫豁免清单生成；基线变更后必须重扫并重生成）")
    args = ap.parse_args()

    rules = DEFAULT_RULES
    if args.rules:
        import importlib.util
        spec = importlib.util.spec_from_file_location("user_rules", args.rules)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        rules = getattr(mod, "RULES", DEFAULT_RULES)

    findings = []
    for f in collect_targets(args.target):
        findings.extend(scan_file(f, rules))

    baseline_exemptions = []
    if args.baseline:
        baseline_exemptions = load_baseline(args.baseline)
        keys = {tuple(e[:2]) + (str(e[2]), e[3][:120]) for e in baseline_exemptions}
        kept, suppressed = [], 0
        for f in findings:
            k = (f["file"].replace("\\", "/"), f["rule"], str(f["line"]), f["match"][:120])
            if k in keys:
                suppressed += 1
            else:
                kept.append(f)
        findings = kept
        msg = "baseline %s loaded: %d exemption(s), %d suppressed" % (args.baseline, len(baseline_exemptions), suppressed)
        if args.json:
            sys.stderr.write(msg + "\n")
        else:
            print(msg)

    if args.write_baseline:
        payload = {
            "tool": "skill-audit", "version": "0.2.0", "generated": __import__("datetime").datetime.now().isoformat(),
            "note": "自扫豁免清单：任何豁免均需在审计报告中披露；基线变更后必须重扫并重生成。",
            "exemptions": [{"file": f["file"].replace("\\", "/"), "rule": f["rule"],
                            "line": f["line"], "match": f["match"][:120]} for f in findings],
        }
        with open(args.write_baseline, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        print("baseline written to %s (%d exemptions)" % (args.write_baseline, len(payload["exemptions"])))

    summary = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    for f in findings:
        summary[f["level"]] = summary.get(f["level"], 0) + 1

    result = {
        "tool": "skill-audit",
        "version": "0.2.0",
        "target": args.target,
        "sha256_targets": {f: sha256_of(f) for f in collect_targets(args.target)},
        "baseline": {"loaded": args.baseline, "exemptions": len(baseline_exemptions)},
        "summary": summary,
        "findings": findings,
    }

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"Skill Audit 扫描完成: {len(findings)} 条发现")
        for k, v in summary.items():
            print(f"  {k}: {v}")
        for f in findings:
            print(f"  [{f['level']}] {f['rule']} @ {f['file']}:{f['line']} - {f['reason']}")
    # 退出码：P0 发现即阻断
    return 1 if summary.get("P0", 0) > 0 else 0


if __name__ == "__main__":
    sys.exit(main())