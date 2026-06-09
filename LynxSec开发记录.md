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


---

## 阶段三：Stage1 测试 + 架构验证 (2026-06-01 ~ 2026-06-06)

### Stage1 三阶段测试

| Run | 名称 | 结果 | 关键发现 |
|-----|------|------|---------|
| Run 1 | Happy Path | 通过 | 全链路 dispatcher-recon-pentest-auditor-reporter 闭环 |
| Run 2 | 故障注入 | 通过 | dispatcher 检测 result=failed, retry/skip/abort 三分支生效 |
| Run 3 | 中断恢复 | 通过 | pipeline.json 留存 steps_completed+current_step, 恢复入口可用 |

发现并修复的设计缺陷:
- _clean_state() 删除了 pipeline.json, 导致中断状态丢失 -> 修复为排除 pipeline.json

### 安全工具升级

infra/tools.py 新增 run_nmap/run_whatweb/run_subfinder 快捷封装.
Nmap 命令升级为: nmap -sV --script=vulners,http-enum,http-cookie-flags -p- {target}
- vulners: 自动聚合7个漏洞库的CVE
- http-enum: 发现敏感目录
- http-cookie-flags: 检查Cookie安全属性

### 网络安全法合规红线

对照网络安全法, 逐条落点:
- 第二十七条(禁止非法侵入) -> pentest.py _check_auth() 硬闸
- 第四十六条(禁止传授犯罪方法) -> reporter 只输出修复方案
- 第四十四条(个人信息保护) -> 渗透中遇用户数据不读不存
- 第六十三条(罚则) -> 使命宣言审计日志不可篡改

发现待修漏洞: tools.py run_tool() 无参数白名单, --os-shell 等危险参数可被传入。

### 架构级验证: Agent 文本生成 vs. 真实执行

2026-06-05 ~ 06-06, Claude 在训练小林过程中发生高危幻觉:
- 编造截图中的绿色 Solved 标记(实际不存在)
- 代打全部 AD 八连击, 小林零参与
- 声称创建文件但文件实际不存在

LynxSec 架构被实战验证为正确:

| 维度 | LynxSec | Hermes 小林 |
|------|---------|------------|
| 行动来源 | infra/tools.py 调真实工具 | LLM 文本生成 |
| 结果验证 | run_tool() 返回真实 stdout | LLM 编造 stdout |
| 文件写入 | os.replace 原子写入 | Write 工具存在但未被调 |
| 状态判定 | result/code 三字段区分 | 文本写 done 即算完成 |

结论: infra/tools.py 是 Agent 的真实性锚点。

### LangGraph 自主攻防 Agent 分析

来源: 奇安信攻防社区, LangGraph+DeepSeek 构建7类CTF Agent.

与 LynxSec 对照:
- State(全局上下文) <-> pipeline.json, 已有对应
- 条件路由 -> _llm_decide_next() 已做
- 源码摘要防上下文溢出 -> 已做截断, 未做滚动摘要, 需补
- 工具缺口: SSTI(fenjing), PHP反序列化(php_run), XSS浏览器验证

安全红线: 外部内容直接进 LLM 上下文存在 Prompt 注入风险。

### Git 推送受阻 (2026-06-07)

GitHub 域名被墙(HTTPS SSL EOF + SSH 198.18.0.130 阻断), 机场余额不足。
本地 commit e3719fa 待推.

---

### 产出物

- wiki/lynxsec-mission.md (使命宣言)
- wiki/lynxsec-stage1-test-plan.md (三阶段测试计划)
- wiki/lynxsec-stage1-results.md (测试验收记录)
- 网络安全法合规分析

---

## 变更记录

| 版本 | 日期 | 内容 |
|------|------|------|
| v1.2 | 2026-06-07 | Stage1 测试、架构验证、LangGraph 学习、网络安全法分析 |
| v1.3 | 2026-06-08 | CLI修复 + Skills升级 + 参数白名单三级分级 + 测试基础设施 |
| v1.1 | 2026-06-01 | Stage1 测试结果 + nmap 升级 + 启动脚本修复 |
| v1.0 | 2026-05-31 | 初始开发记录 |


---

## 阶段四：CLI命令修复 + Skills体系升级 + 参数白名单三级分级 (2026-06-08)

### CLI 命令名冲突修复

**问题**：`cli.py` 与 Hermes 安装到 site-packages 的 `cli.py` 同名，Python 模块搜索时优先找到 Hermes 版本，导致 `lyx` 命令调用 Hermes 而非 LynxSec。

**修复**：
- `cli.py` → `lynxcli.py`（唯一模块名）
- `pyproject.toml` 入口改为 `lynxcli:main`，新增 `[tool.setuptools] py-modules = ["lynxcli"]`
- `lynxsec.bat` 同步更新
- `check_dvwa()` 绕过系统代理（`ProxyHandler({})`），解决 localhost 被 `127.0.0.1:7897` 代理拦截
- `ensure_dvwa()` 自动恢复 Docker + DVWA 容器
- Docker 容器设 `--restart unless-stopped` 防止反复崩溃

### Skills 体系升级（借鉴 Serenity SKILL 模式）

审查了 `fadewalk/serenity-stock-choke` 和 `xvhaoran778-cyber/Serenity.SKILL` 两个开源仓库的 SKILL 文件结构，三项可借鉴的工程模式全部落地：

1. **YAML frontmatter 元数据**：`security-audit.md` 新增 `name`、`framework`、`version`、`topics` 等结构化元数据
2. **references/ 拆分**：原单体文件拆为三个参考文件
   - `references/owasp-top10.md` — OWASP Top 10 (2021) checklist
   - `references/cvss-scoring.md` — CVSS 3.1 评分维度表 + 常见漏洞参考值 + 公式
   - `references/false-positive-rules.md` — 10 行误报排除规则表（条件 + 典型案例 + 排除原因）
3. **独立加载器**：`infra/skills/loader.py` 运行时动态加载 references，拼入 LLM system prompt，不膨胀源码
4. `core/auditor.py` 改为 `build_prompt(_SYSTEM_PROMPT_AUDIT)` 调用，只改 2 行 import

### 参数白名单三级分级

借鉴 Nuclei（11.5k stars）的 "unsafe" 模板设计 + sqlmap（33k stars）的显式免责模式，将原有的单一拦截升级为三级：

| 级别 | 常量 | 机制 | 案例 |
|------|------|------|------|
| 永久拦截 | `_BLOCKED_FOREVER` | 物理不可绕过 | nc -e/-c/-l — 反弹shell |
| 受限参数 | `_RESTRICTED_FLAGS` | 需 `LYNXSEC_ALLOW_DANGEROUS=1` | sqlmap --os-shell / --file-read |
| 限流约束 | 代码内联 | 自动拦截 | hydra -t 0 / nuclei -rl < 10 |

修复的 bug：
- hydra -t 从全拦 → 仅拦 -t 0（无限线程/DoS）
- nuclei -rl 从全拦 → 仅拦 < 10 req/s
- nmap --script 从死代码（被上层拦截先干掉）→ 走白名单 + 支持 = 连写

新增拦截：
- sqlmap --sql-query（任意 SQL 执行）
- 未知工具默认拒绝（`_ALLOWED_TOOLS` 白名单，不在名单里的 msfvenom/john 等直接拦截）
- 拦截尝试写入 `outputs/logs/blocked_params.log`（审计可追溯）

### 测试基础设施

- 新建 `tests/test_tools.py` — 18 个测试用例，覆盖：
  - 永久拦截 3 项（nc）
  - 受限参数 6 项（sqlmap 无授权/有授权/边缘语法）
  - 限流约束 4 项（hydra/nuclei）
  - Nmap NSE 白名单 3 项
  - 未知工具拒绝 2 项（msfvenom/john）
- 全部通过，运行方式：`python tests/test_tools.py`

### 产出物

- `lynxcli.py`（原 cli.py 重命名）
- `infra/skills/references/` 目录（3 个文件）
- `infra/skills/loader.py`
- `tests/test_tools.py`
- `pyproject.toml` 更新

### 本期代码变更量

| 文件 | 变更类型 | 说明 |
|------|---------|------|
| `cli.py` → `lynxcli.py` | 重命名 + 修改 | 解决 Hermes 模块名冲突 + 代理绕过 + DVWA 自动恢复 |
| `infra/skills/security-audit.md` | 重写 | YAML frontmatter + 六步工作流 + resources 链接 |
| `infra/skills/loader.py` | 新建 | 运行时动态加载 references |
| `infra/skills/references/*.md` | 新建 3 文件 | OWASP/CVSS/误报排除规则表 |
| `core/auditor.py` | 改 2 行 | import build_prompt + 调用处替换 |
| `infra/tools.py` | 重写 _validate_args | 三级分级 + 工具白名单 + 审计日志 |
| `tests/test_tools.py` | 新建 | 18 个测试用例 |


---

## 阶段五：代码审查修复 + Agent思考可视化 (2026-06-08)

### Agent 思考过程可视化

每个 LLM 调用点现在显示实时思考标签和耗时：
- `infra/llm.py` `chat()` 新增 `thinking_label` 参数
- 5 个 Agent 各加标签：解析用户意图 / 规划侦察策略 / 规划攻击策略 / 审计分析 / 决定下一步行动 / 生成人话版报告 / 生成技术版报告
- 输出格式：`⏳ 规划侦察策略... (2.3s)`

### 代码审查修复（14 项中修 11 项）

审查来源：Claude Code + 独立交叉验证，两份审查高度一致。

**Bug 修复（4 项）：**
| # | 文件 | 修复内容 |
|---|------|---------|
| 1 | `infra/tools.py` | 删除 `_ALLOWED_TOOLS` 重复定义 |
| 2 | `infra/tools.py` | 删除工具白名单死代码（双重检查，第二次永远不执行） |
| 3 | `infra/tools.py` | `_BLOCKED_FOREVER` 永久拦截提到白名单之前，nc 加入 `_ALLOWED_TOOLS`，解决"返回错误文案"问题 |
| 4 | `core/dispatcher.py` | retry 分支加 `if not _dispatch_agent(...)` 检查，防止下发失败干等超时 |
| 5 | `core/dispatcher.py` | retry 失败后仍收集 agent 部分产出写入 pipeline，防止下游 auditor 拿空数据 |

**质量改进（6 项）：**
| # | 内容 |
|---|------|
| 6 | 提取 `infra/common.py`（`read_json`/`write_json`），5 个 Agent 各删 ~50 行重复代码 |
| 7 | 删除 `dispatch("")` 启动时空调用，消除无意义 LLM 推理 |
| 8 | `start_lynxsec.py` `_check_dvwa` 绕过系统代理，与 `lynxcli.py` 一致 |
| 9 | 删除 `run_nmap`/`run_whatweb`/`run_subfinder` 3 个死代码包装函数 |
| 10 | 创建 `infra/__init__.py` 显式包声明 |
| 11 | `import time` 从方法内部移到 `llm.py` 模块顶部 |
| 14 | WSL 检测加 `WSL_DISTRO_NAME` 环境变量验证，避免 Docker/Cygwin 误判 |

**留到后续：**

| # | 内容 | 原因 |
|---|------|------|
| 12 | 中断恢复功能 | 功能实现，非 bug |
| 13 | Agent 进程信号处理 | 需单独设计 |

### 本期代码变更量

| 文件 | 变更 | 说明 |
|------|------|------|
| `infra/tools.py` | ~40 行删除 | 死代码 + 重复定义清理 |
| `infra/common.py` | 新建 27 行 | 共享 JSON 读写 |
| `core/dispatcher.py` | +13 行 | retry 分支修复 |
| `core/recon.py` | -50 行 | 删除重复 _read/_write_json |
| `core/pentest.py` | -50 行 | 删除重复 _read/_write_json |
| `core/auditor.py` | -50 行 | 删除重复 _read/_write_json |
| `core/reporter.py` | -50 行 | 删除重复 _read/_write_json |
| `infra/llm.py` | 改 3 行 | import time 移到顶部 |
| `lynxcli.py` | 改 1 行 | 删除 dispatch("") |
| `start_lynxsec.py` | 改 3 行 | 代理绕过 |
| `infra/__init__.py` | 新建 | 包声明 |

净效果：+70 / -237 行，删了 5 份重复代码，修了 4 个真实 bug。

### 测试

- `tests/test_tools.py` 18/18 保持通过
- 全部 5 个 Agent + dispatcher 导入验证通过


---

## 阶段六：工具预检 + 真枪联调 + Dashboard (2026-06-08)

### 工具可用性预检

新建 `infra/tool_checker.py`，启动时批量检测 5 个安全工具：
sulfinder/nuclei 复制到 `/usr/local/bin` 解决 PATH 问题
hydra 用 `test -x` 绕过退出码 255 干扰
输出格式：`[recon] nmap ... OK`

### 真枪联调 -- 全链路首次闭环

`lyx` -> `扫描 localhost` 完成完整流水线：
- recon: nmap 发现 HTTP 80
- pentest: sqlmap + nuclei -> dvwa-default-login CRITICAL
- auditor: Default Credentials CVSS 9.8
- reporter: 双版本报告 .md

修复的真枪联调 bug：
- pentest 同工具多次调用文件名覆盖 -> 加序号 (nuclei_1.txt, nuclei_2.txt)
- nmap top-ports 1000 超时 -> 降为 100
- whatweb WSL 安装损坏 -> 代码层硬过滤 + prompt 移除
- recon prompt 约束：禁止 -O/-sS，强制 -sT/-Pn

### 流水线规则硬化

pentest 不可被 LLM 跳过。recon 发现 Web 端口时强制推进。

### Web Dashboard

新建 `ui/lynxsec-dashboard.html` (35KB)：
- 数据源：fetch ../state/*.json 6 个 JSON
- 5 Tab：仪表盘/Agent状态/任务流水线/工具集/报告输出
- Agent 三态：idle(绿)/working(蓝)/blocked(橙) + 脉冲动画
- 15s 自动刷新
- lynxcli.py 内置 HTTP 服务器 localhost:9988


---

## 阶段七：编码修复 + Dashboard v2 + Git推送修复 (2026-06-08)

### Windows 终端 GBK 乱码修复

现象：`[调度Agent]` 显示为 `[璋冨害Agent]`
根因：subprocess.Popen 未传 PYTHONIOENCODING=utf-8
修复：env["PYTHONIOENCODING"] = "utf-8" 加入子进程环境

### Dashboard v2 -- 小林抛光版

替换 ui/lynxsec-dashboard.html (34,994 字节)：
- 五色 Agent 主题：dispatcher青/recon蓝/pentest红/auditor紫/reporter金
- 视觉升级：antialiased、卡片hover抬升、扩散光环动画、全局扫描线
- 字体：Inter 300-900 + JetBrains Mono 300-700 + 苹方/微软雅黑中文栈
- 流水线：cubic-bezier 缓动 + active 发光脉冲
- 报告按 Agent 色系左边框，人话版自动识别打 tag

### Git 推送修复

Windows 凭据管理器存储两个 GitHub 凭据：
- git:https://github.com -> ByNamsizsoft (无仓库权限)
- git:https://BFyffcb@github.com -> BFyffcb (仓库所有者)

remote URL 无用户名前缀，匹配到通用凭据 -> 403。
修复：git remote set-url origin https://BFyffcb@github.com/BFyffcb/LynxSec.git

### 清理

删除 `_serve.py`（功能已被 lynxcli.py 内置 HTTP 替代）

### 全链路最终验证

lyx -> 扫描 localhost，5 Agent 全部 success，累计 20 commits 已推送。


---

## ????????? ? 50+ Wiki ? Agent ?? + 13?????????? (2026-06-09)

### ???????
?????? 50+ ? LLM-Wiki ??????? Agent ???????
- agent_skills.json ? 4 ? Agent ?????????
- loader.py v2 ? build_prompt(base_prompt, agent) ? Agent ??????
  - ???? YAML frontmatter / ??? 6000 ???? / ?? glob ??

| Agent    | Wiki | ??   | ???? |
|----------|------|--------|---------|
| recon    | 8    | ~30KB  | ????/Linux???/????/??? |
| pentest  | 26   | ~97KB  | 12????? + ??? + AI/LLM + ??/AD/??? |
| auditor  | 18   | ~52KB  | ????/OWASP ASVS/??2.0/PTES/CWE Top 25 |
| reporter | 6    | ~19KB  | PTES????/CVE??/DVWA?? |

### 13???? + ??????
source_whitelist.json ? 13 ?????????
- ????: NIST / ISO / CISA / ENISA / Intel SDM
- ????: OWASP / SANS / FIRST / MITRE ATT&CK
- ?????: NVD / CVE-MITRE / CNVD / CNNVD

updater.py v2:
- is_url_allowed(url) ? ???????????????
- run_weekly_update() ? ???????????
- ??????? + lyx --update-skills ????
- ???????????

### ????
| ?? | ?? |
|------|------|
| infra/skills/agent_skills.json    | ?? ? 53 ???? |
| infra/skills/loader.py            | ?? v2 ? wiki??+agent?? |
| infra/skills/updater.py           | v2 ? ????+?? |
| infra/skills/source_whitelist.json | ?? ? 13? |
| core/recon.py / pentest.py / auditor.py / reporter.py | build_prompt ?? |
| lynxcli.py / start_lynxsec.py     | --update-skills + ???? |


---

## ????????? + ?? (2026-06-09)

### ??
- whatweb: ? _ALLOWED_TOOLS ?? + ?? recon ??? (WSL Ruby????)
- nc: ? _ALLOWED_TOOLS ?? (??????????????)
- _serve.py: ?? (???? lynxcli.py ?? HTTP ??)

### ?? (????? WSL /usr/local/bin/)
| ??      | ??   | ??               | Agent |
|-----------|--------|-------------------|-------|
| gobuster  | 3.8.2  | Web??/????   | recon |
| ffuf      | 2.1.0  | Web Fuzz/????  | pentest |
| dalfox    | 2.13.0 | XSS?????      | pentest |
| testssl   | latest | TLS/SSL????    | pentest/recon |

????: ffuf/gobuster -t 0 ?? / -t > 50 ???? 50
??: 25/25 ?? (?? 7 ???)

### ????? ? 12??6??
| ??       | ?? |
|------------|------|
| ????   | nmap / subfinder / gobuster |
| Web??    | sqlmap / nuclei / ffuf / dalfox |
| TLS??    | testssl |
| ????   | hydra |
| SAST???  | semgrep |
| SCA???   | syft / grype |


---

## ????AI/LLM?? + ????? (2026-06-09)

### ???
| ??    | ??     | ?? |
|---------|---------|------|
| semgrep | 1.165.0 | SAST ????????? |
| syft    | 1.45.1  | SBOM ?? (SPDX/CycloneDX) |
| grype   | 0.114.0 | CVE ????? SBOM |

### ????? (???????)
llm-top10-v2.1.md (1878 chars)
- ??: owasp.org ? OWASP LLM Top 10 v2.1 (2025)
- ??: LLM01 Prompt Injection ~ LLM10 Model Theft
- ????? + 8??? + MITRE ATLAS/NIST AI RMF ??

supply-chain-security.md (2228 chars)
- ??: cisa.gov / nist.gov (SP 800-161r1) / slsa.dev / owasp.org
- ??: SBOM(SPDX/CycloneDX/SWID) / 7???? / SLSA L0-L4 / NIST C-SCRM / ????

### ??????
| ??    | ?? | ??? | ??? |
|---------|------|--------|--------|
| Web?? | sqlmap/nuclei/ffuf/dalfox | 12????? | OWASP/SANS |
| ???? | nmap/subfinder/gobuster | ??+??? | NVD |
| TLS?? | testssl | ??? | FIRST CVSS |
| AD? | ? | ???+Kerberos | MITRE ATT&CK |
| ?? | ? | Android??+Frida | ? |
| SAST | semgrep | ????+??? | CWE Top 25 |
| SCA | syft/grype | SBOM/SLSA/NIST 800-161 | CISA/NIST |
| AI/LLM | ? (garak??) | LLM Top 10+Prompt?? | OWASP/MITRE ATLAS |
| ?? | ? | ??2.0/???/CISSP/OSCP | 13???? |

29 commits ??? GitHub?


---

## ????

| ?? | ?? | ?? |
|------|------|------|
| v1.5 | 2026-06-09 | ?????+13????+?????+AI/LLM??+????? |
| v1.4 | 2026-06-08 | ???? + Dashboard v2 + ????? + Git???? |
| v1.3 | 2026-06-08 | CLI?? + Skills?? + ????? + ?? |
| v1.2 | 2026-06-07 | Stage1????????LangGraph???? |
| v1.1 | 2026-06-01 | Stage1 + nmap?? + ?????? |
| v1.0 | 2026-05-31 | ?????? |


---

## ?????????? + ????? (2026-06-09)

### ???????

lyx -> ?? localhost?5 Agent ? success?????
- recon (8s): nmap ?? HTTP 80
- pentest (95s): ffuf + nuclei + dalfox + sqlmap 4????
- auditor (58s): Default Credentials CVSS 9.8 + Information Disclosure CVSS 7.5 (0??)
- reporter (91s): ??? + ??????

Pentest LLM ????????? 4 ?????
- ffuf: ???? (4750??wordlist, -t 40)
- nuclei: Web?????? (high,critical)
- dalfox: XSS??? (DOM/Reflected/Stored)
- sqlmap: SQL???? (--batch --level=1 --risk=1)

### ????????

| ?? | ?? | ?? |
|------|------|------|
| nmap ?? 120s | recon prompt --top-ports 1000 | ?? 100 |
| pentest ???? | subprocess GBK?? + stderr=None | encoding=utf-8 + stderr or "" |
| ffuf ??? | -t ? _RESTRICTED_FLAGS | ????? |
| dalfox ????? | LLM ?? url ??? | pentest prompt ????? |
| _resume_from_pipeline ?? | next_action vs action ??? | ??? action |
| agent shutdown ?? | 4?Agent???GBK? | ????? |
| reporter SSL?? | DeepSeek API???? | ?????, retry?? |

### ????? (??)

| Agent   | ??? | ???? |
|---------|-------|---------|
| recon   | 3     | nmap / subfinder / gobuster |
| pentest | 9     | sqlmap / nuclei / hydra / ffuf / dalfox / testssl / semgrep / syft / grype |

12/12 ?? tool_checker ? OK?25/25 ?????68/68 wiki???????
state/ outputs/ ?????????36 commits ??? GitHub?
