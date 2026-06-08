# OWASP Top 10 (2021) Checklist

## A01: Broken Access Control（失效的访问控制）

- [ ] 所有 API 端点有授权检查
- [ ] 无 IDOR（不安全的直接对象引用）漏洞
- [ ] 基于角色的访问控制（RBAC）已执行
- [ ] CORS 配置不是 `*`
- [ ] 目录遍历攻击（../）已防护

## A02: Cryptographic Failures（加密失败）

- [ ] 密钥/密码走环境变量，不硬编码
- [ ] HTTPS 强制执行（HSTS 头）
- [ ] Cookie 设置 Secure / HttpOnly / SameSite
- [ ] 使用强加密算法（AES-256-GCM / RSA-2048+）
- [ ] 无弱哈希（MD5/SHA1）用于密码存储

## A03: Injection（注入）

- [ ] SQL: 参数化查询（Prepared Statements）
- [ ] OS Command: 不拼接用户输入到系统命令
- [ ] LDAP / XPath / NoSQL: 同样做参数化
- [ ] 输入验证: 格式/长度/类型
- [ ] 输出编码: HTML/JS/URL context-aware

## A04: Insecure Design（不安全的设计）

- [ ] 威胁建模已完成
- [ ] 安全架构已审查
- [ ] 速率限制（rate limiting）生效
- [ ] 批量操作有确认步骤

## A05: Security Misconfiguration（安全配置错误）

- [ ] 默认凭据已删除
- [ ] 错误消息不暴露内部信息
- [ ] Debug 模式已禁用
- [ ] HTTP 安全头完整: CSP / X-Frame-Options / X-Content-Type-Options / Strict-Transport-Security
- [ ] 不必要的 HTTP 方法（PUT/DELETE/TRACE）已禁用

## A06: Vulnerable Components（易受攻击的组件）

- [ ] 依赖项已审计（npm audit / pip audit）
- [ ] 没有已知 CVE 的组件
- [ ] 第三方库是最新版本
- [ ] 不再维护的组件已替换

## A07: Auth Failures（认证失败）

- [ ] 强密码策略
- [ ] 会话管理安全（httpOnly cookie / 过期机制）
- [ ] 多因素认证（MFA）可用
- [ ] 登录失败有锁定机制（防暴力破解）
- [ ] 密码重置流程安全（token 一次性有效）

## A08: Data Integrity（数据完整性）

- [ ] 输入已验证（类型/范围/格式）
- [ ] 关键数据有完整性校验
- [ ] 反序列化攻击已防护（不接受用户提供的序列化对象）
- [ ] CI/CD 流水线有完整性检查

## A09: Logging Failures（日志失败）

- [ ] 安全事件已记录（登录/失败/权限变更）
- [ ] 日志不含敏感信息（密码/Token/个人信息）
- [ ] 日志有时间戳 + 用户标识
- [ ] 日志至少保留 6 个月（等保要求）

## A10: SSRF（服务端请求伪造）

- [ ] 外部请求有 URL 白名单
- [ ] 不接受用户提供的任意 URL
- [ ] 内部地址（127.0.0.1 / 10.x / 192.168.x）已过滤
- [ ] DNS 重绑定攻击已防护
