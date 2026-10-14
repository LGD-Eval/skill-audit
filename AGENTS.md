# AGENTS.md（写给 AI 协作代理）

## 本仓是什么
AI 技能安全审计工具（manifest/prompt 投毒检测）。

## 怎么跑
python scanner.py --target <dir-or-file>
预期：输出扫描结果与风险分级（P0-P3）

## 你能帮什么
- 增加检测规则：rules/ 下新增规则文件
- 复放测试：运行 scanner.py 验证
- 报告漏洞：开 Issue（附样例）

## 验收标准
- 新规则须附测试样例
- 改动后 scanner.py 全量回归通过
- 不采信自查：审计结论由独立方复验