# CVSS 3.1 评分标准

## 评分维度

### 基础指标

| 指标 | 可选值 |
|------|--------|
| 攻击向量 (AV) | N:网络 / A:相邻 / L:本地 / P:物理 |
| 攻击复杂度 (AC) | L:低 / H:高 |
| 权限要求 (PR) | N:无 / L:低 / H:高 |
| 用户交互 (UI) | N:无 / R:需要 |
| 范围 (S) | U:不变 / C:改变 |
| 机密性影响 (C) | N:无 / L:低 / H:高 |
| 完整性影响 (I) | N:无 / L:低 / H:高 |
| 可用性影响 (A) | N:无 / L:低 / H:高 |

### 严重度等级

| 分数范围 | 等级 | 标签 |
|----------|------|------|
| 9.0 - 10.0 | Critical | `critical` |
| 7.0 - 8.9 | High | `high` |
| 4.0 - 6.9 | Medium | `medium` |
| 0.1 - 3.9 | Low | `low` |
| 0.0 | None | `info` |

## 常见漏洞 CVSS 参考值

| 漏洞类型 | 典型 AV | 典型分数 |
|----------|---------|----------|
| SQL 注入（无认证） | N | 9.8 |
| 存储型 XSS | N | 6.1 |
| 反射型 XSS | N | 6.1 |
| 命令注入 | N | 9.8 |
| 弱口令（可爆破） | N | 7.5 |
| HTTP 安全头缺失 | N | 4.3 |
| 信息泄露（低敏） | N | 3.7 |
| SSRF（可访问内部） | N | 8.6 |

## 评分公式

Base Score 由以下公式计算：

**影响子分数 (ISC):**
```
ISC = 1 - ((1 - C) * (1 - I) * (1 - A))
```

**基础分数:**
- 若 Scope = Unchanged:
  `Base = RoundUp(min(ISC + Exploitability, 10))`
- 若 Scope = Changed:
  `Base = RoundUp(min(1.08 * (ISC + Exploitability), 10))`

**Exploitability:**
```
Exploitability = 8.22 * AV * AC * PR * UI
```
