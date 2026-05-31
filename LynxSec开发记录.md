# LynxSec 开发记录
**项目：LynxSec — 专精白帽安全的AI智能体**
**日期：2026-05-31**

---

## 项目概述

LynxSec是一个多Agent白帽安全AI智能体，核心定位：会用工具的AI，而不只是工具本身。区别于ClaudeSec（纯Shell工具集），LynxSec能自主决策、调用工具、分析漏洞、生成报告。

5个Agent协作，文件+Bridge通信模式，三层架构（ui/core/infra），LLM厂商无关。

---

## 阶段一：架构设计v1.0 → v1.1

### v1.0 初始设计
- 7层架构：入口层 → 会话层 → 核心层 → 能力层 → 执行层 → 状态层 → 模型层
- 5个Agent：dispatcher / recon / pentest / auditor / reporter
- 双版本报告：人话版（普通开发者）+ 技术版（专业安全人员）
- 安全边界：未授权拒绝渗透、授权记录存SQLite、工具Docker沙箱执行

### v1.1 修订（4项）
1. 目录结构：skills/ memory/ 归入 infra/
2. 依赖链修正：ui → core → infra → llm
3. 补全Agent通信协议（文件+Bridge，6种JSON文件，四态枚举）
4. 授权验证归入 dispatcher.py 入口

   后续修订：state/ outputs/ 标注为运行时目录，不在版本控制中

### 产出
- 架构设计.md v1.1（13KB）
- README.md
- config.env.example
- .gitignore / LICENSE

---

## 阶段二：核心五件套开发

### infra/llm.py（4KB）
模型统一接口，兼容任意OpenAI格式API（DeepSeek / 千问 / GPT）。
- `LLM` 类，`chat(system_prompt, user_message) → str`
- 配置从 config.env 读取，零硬编码
- HTTP错误+网络错误全捕获，含超时120s

### infra/tools.py（6KB）
安全工具统一调用层。
- `ToolResult` Pydantic模型（纪律C2：禁裸dict）
- `run_tool(tool_name, args) → ToolResult`
- WSL2自动适配：Windows宿主→wsl前缀，WSL内→直接调用
- code码分类：0成功/1参数错误/2工具缺失/3超时/4命令失败/5解析失败

### core/dispatcher.py（30KB）
调度中枢。核心设计：
- 状态机：IDLE → AUTH_CHECK → DISPATCHING → MONITORING → COMPLETE
- 步骤间LLM决策（_llm_decide_next），不是死板流水线
- 超时300s后询问用户retry/skip/abort
- pipeline.json中断恢复
- v1.2：_wait_for_agent() 新增result字段判定，解决working→idle无法区分完成/空转
- v1.3：code字段支持

### core/recon.py（17KB）
情报Agent。LLM规划nmap/subfinder/whatweb调用顺序，通过tools.py统一执行。
- v1.3：_run_tool() 下沉到 infra/tools.py
- v1.4：dry-run模拟模式

### core/pentest.py（17KB）
渗透Agent。auth.json硬闸——未授权直接blocked。
- sqlmap限制 --batch --level=1 --risk=1（不深度注入）
- 禁止 --os-shell / --os-cmd / --file-read / --file-write
- hydra限制 -t 4 线程

### core/auditor.py（13KB）
审计Agent。纯LLM推理，不调用任何工具。
- 误报过滤、攻击链串联、CVSS 3.1评分
- 读取上游recon/pentest的analysis.json

### core/reporter.py（15KB）
报告Agent。双版本输出到 outputs/reports/。
- 人话版：三段式（问题是什么/为什么会这样/怎么修）+ 代码示例
- 技术版：CVE编号/CVSS向量/攻击向量/POC/修复方案

### start_lynxsec.py（16KB）
一键启动脚本，6个检查阶段：
1. config.env 完整性检查
2. 安全工具链预飞检查（nmap/whatweb/subfinder/sqlmap/hydra）
3. DVWA (localhost:80) 可达性
4. 旧状态文件清理（防幽灵任务）
5. 4个Agent并行启动（0.5s stagger）
6. 轮询status.json等待全部就绪
7. 交互模式 → dispatcher.run()
8. 退出清理

支持 --dry-run 模拟模式（通过环境变量 LYNXSEC_DRY_RUN=1 下沉到子进程）。

---

## 设计决策汇总

| 决策 | 内容 | 理由 |
|------|------|------|
| 通信方式 | 文件+Bridge（JSON） | 复用指挥台19阶段经验，可观测性强 |
| 去掉callback.json | dispatcher直接轮询status文件 | 架构5.5已定义完成信号，不引入第二套机制 |
| Agent内部循环 | 轮询command.json（2s间隔） | task_id去重防重复执行 |
| 工具执行 | 全部通过infra/tools.py | 统一封装、统一日志、统一错误码 |
| 终态判定 | status + result + code 三字段 | 解决working→idle歧义，区分子状态 |
| 权限模型 | 双层（slim prompt行为边界 + settings.json工具权限） | 继承指挥台方案 |
| 干跑模式 | 环境变量 LYNXSEC_DRY_RUN=1 | 轻量，不改代码结构 |
| 模拟数据 | 与真实返回完全同形 | 防止dispatcher/auditor/reporter被异构数据背刺 |

---

## 遇到的问题与解决

### 问题1：DeepSeek base_url
原因：初版 config.env.example 填了 `https://api.deepseek.com/v1`
解决：DeepSeek 官方文档明确使用 `https://api.deepseek.com`（不带/v1），已修正

### 问题2：working→idle 终态歧义
原因：Agent完成任务回idle和空转回idle无法区分
解决：status.json 新增 result 字段（success/failed/skipped/blocked）和 code 字段（0-5）

### 问题3：PowerShell编码冲突
原因：直接在PowerShell命令行传Python代码，中文和引号被PS解析器截断
解决：改为 @' ... '@ | Set-Content 先写临时文件再 python 执行

### 问题4：Git推送权限
原因：本机Git凭据为 ByNamsizsoft，无 BFyffcb/LynxSec 写入权限
解决：临时使用 token URL 推送，推完立即清除 token

---

## 纪律审查

对全部8个Python文件进行自动化纪律检查，逐条对照CLAUDE.md的32条规则：

| 纪律 | 结果 | 说明 |
|------|------|------|
| R3 零空catch | ✓ 通过 | 0个裸except，0个无日志catch |
| R4 零硬编码 | ✓ 通过 | 0处硬编码密钥/Token，全部走config.env |
| C1 类型标注 | ✓ 通过 | 所有函数有完整参数+返回类型（3个误报已人工确认，签名跨行） |
| A1 三层结构 | ✓ 通过 | ui/ core/ infra/ 分层清晰 |
| A2 单向依赖 | ✓ 通过 | core→infra→llm，无反向依赖 |
| C2 Pydantic | ✓ 通过 | ToolResult用Pydantic v2 |
| C3 异常处理 | ✓ 通过 | 所有except含日志 |
| C4 环境变量 | ✓ 通过 | 敏感信息走config.env |
| C5 导入规范 | ✓ 通过 | 标准库→第三方→本地模块 |
| R6 零擅自重构 | ✓ 通过 | 未改无关代码 |

结论：32条纪律零违规。

---

## 项目状态

| 指标 | 数值 |
|------|------|
| 核心文件 | 8个（5 Agent + 2 infra + 1启动脚本） |
| 总代码量 | ~110KB |
| Python行数 | ~2,810 |
| 语法检查 | 全部通过 |
| Git提交 | 6次 |
| 纪律违规 | 0 |

下一步：DVWA端到端联调（Stage1流程测试 → Stage2授权测试 → Stage3中断恢复）。

---

## 变更记录

| 版本 | 日期 | 内容 |
|------|------|------|
| v1.0 | 2026-05-31 | 初始开发记录 |
