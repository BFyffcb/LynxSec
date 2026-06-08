---
name: security-audit
description: |
  LynxSec 安全审计基线。OWASP Top 10 (2021) 漏洞分类 + CVSS 3.1 评分 + 误报过滤规则。
  触发词：安全审计、漏洞分析、误报过滤、CVSS评分、OWASP、攻击链。
framework: OWASP Top 10 (2021)
version: "2.0"
topics:
  - web-security
  - owasp-top10
  - cvss-scoring
  - false-positive-filtering
  - attack-chain-analysis
  - vulnerability-assessment
agent: auditor
license: MIT
---

# LynxSec 安全审计 Skill

## 核心使命

作为审计Agent的分析基线，对情报Agent和渗透Agent的上游产出进行：
1. 误报过滤 —— 按排除规则表逐条筛查
2. OWASP 分类 —— 将确认漏洞归入 A01-A10
3. CVSS 3.1 评分 —— 计算漏洞严重度
4. 攻击链串联 —— 评估多漏洞组合利用风险

---

## 审计工作流

### 第一步：加载上游产出

读取 `state/recon_status.json` 和 `state/pentest_status.json` 中的 outputs 路径，收集所有 `*_analysis.json` 文件。

### 第二步：误报过滤

读取 [references/false-positive-rules.md](references/false-positive-rules.md)，对每个发现按排除规则表逐条匹配。
任一排除条件命中 → 归入 `false_positives`，记录排除原因。

### 第三步：OWASP 分类

读取 [references/owasp-top10.md](references/owasp-top10.md)，将确认漏洞归入对应的 A01-A10 分类。

### 第四步：CVSS 评分

读取 [references/cvss-scoring.md](references/cvss-scoring.md)，对每个确认漏洞计算：
- 攻击向量 (AV)
- 攻击复杂度 (AC)
- 权限要求 (PR)
- 用户交互 (UI)
- 范围 (S)
- 机密性/完整性/可用性影响 (C/I/A)
输出 CVSS 向量字符串和分数。

### 第五步：攻击链串联

若存在 ≥2 个确认漏洞，评估是否可串联利用：
```
漏洞A (初始入口) → 漏洞B (权限提升) → 漏洞C (数据窃取)
```
给出组合后的总体影响评估。

### 第六步：输出审计报告

以 JSON 格式输出，包含：
- `confirmed_vulnerabilities`: 确认漏洞列表（含 OWASP 分类 + CVSS 评分 + 修复建议）
- `false_positives`: 误报列表（含排除原因）
- `attack_chains`: 攻击链列表
- `risk_summary`: 整体风险评估
- `recommendations`: 按优先级排序的修复建议

---

## Resources

- [references/owasp-top10.md](references/owasp-top10.md) — OWASP Top 10 (2021) 分类 checklist
- [references/cvss-scoring.md](references/cvss-scoring.md) — CVSS 3.1 评分标准
- [references/false-positive-rules.md](references/false-positive-rules.md) — 误报排除规则表
