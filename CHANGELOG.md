# Skill Audit Scanner Changelog / 变更记录

## v0.3.0 (2026-10-15)
- Rules / 规则: 40 rules across 10+ packs (was 9 rules in v0.2.0)
- Patterns / 模式: 100 detection patterns (was ~20)
- Coverage / 覆盖: OWASP LLM Top 10 2025 (LLM01-LLM10) + OWASP Agentic AI Threat Landscape 2026 (A01-A12)
- New packs / 新增包: spoof (identity/impersonation A07), license (certification forgery LLM09),
  encoding-obfuscation (base64 / URL-encoded / zero-width / HTML-entity)
- Features / 特性: --self-test built-in (16 samples, positive + negative), SARIF 2.1.0 output,
  --baseline exemption, --write-baseline, multi-format scan (md/txt/yaml/json/py/sh/js/ts/html/xml/toml/lock)
- Principle / 原则: defensive audit only; conclusions require independent re-verification

## v0.2.0
- 9 rule packs: hidden_instruction / data_exfil / unauthorized_action / self_praise / fake_claim / mojibake / zero_width / unicode_confusion
