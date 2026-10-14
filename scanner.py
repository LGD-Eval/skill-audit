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
        "pattern": re.compile(r"(?i)(ignore|disregard)\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|context)"),
        "level": "P0",
        "reason": "隐藏指令：要求忽略先前指令（典型投毒模式）",
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
        "pattern": re.compile(r"(?i)(claim\s+.*(certified|verified|passed)\s*$|fabricat|hallucinat)"),
        "level": "P1",
        "reason": "虚假声明/伪造证据指令",
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


def main() -> int:
    ap = argparse.ArgumentParser(description="Skill Audit - 技能投毒检测扫描器 (MVP)")
    ap.add_argument("--target", required=True, help="要扫描的文件或目录")
    ap.add_argument("--rules", default=None, help="自定义规则 Python 文件（可选）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
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

    summary = {"P0": 0, "P1": 0, "P2": 0, "P3": 0}
    for f in findings:
        summary[f["level"]] = summary.get(f["level"], 0) + 1

    result = {
        "tool": "skill-audit",
        "version": "0.1.0-mvp",
        "target": args.target,
        "sha256_targets": {f: sha256_of(f) for f in collect_targets(args.target)},
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