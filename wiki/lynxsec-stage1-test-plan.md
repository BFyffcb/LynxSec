# LynxSec Stage 1 Dry-Run 测试计划

**版本：v0.1 MVP | 日期：2026-05-31**
**测试模式：python start_lynxsec.py --dry-run（模拟模式，不调真实工具）**

---

## 测试目标

验证全链路流程闭环：dispatcher → recon → pentest → auditor → reporter → 报告落盘。

三个 Run 全部通过 = LynxSec v0.1 MVP 可运行。

---

## 前置条件

- [x] `config.env` 已配置 LLM 密钥
- [x] DVWA 可达（`http://localhost:80` 返回 HTTP 200）
- [x] 所有 Agent 语法检查通过
- [x] dry-run 模拟数据已在 4 个 Agent 中补入

---

## Run 1：Happy Path（全链路正常流转）

**输入：**
```
LynxSec> 扫描本地 DVWA，检查 Web 漏洞
```

**期望结果：**

| 步骤 | Agent | 期望 |
|------|-------|------|
| 1 | dispatcher | 解析意图，授权校验通过（或跳过） |
| 2 | recon | result=success, code=0, 返回端口80 Apache指纹 |
| 3 | dispatcher | _llm_decide_next() 决策进入 pentest |
| 4 | pentest | result=success, code=0, 返回 SQLi critical 漏洞 |
| 5 | dispatcher | 决策进入 auditor |
| 6 | auditor | result=success, code=0, 1个确认漏洞 0个误报 |
| 7 | dispatcher | 决策进入 reporter |
| 8 | reporter | result=success, code=0, 双版本报告落盘 |

**验证点：**
- `state/pipeline.json` 中 status=completed, steps_completed 含全部4个Agent
- `outputs/reports/` 下存在人话版和技术版 Markdown 文件
- `outputs/evidence/` 下有 analysis.json 文件
- 终态各 Agent status.json 中 result=success, code=0

**通过标准：** dispacher 输出报告路径，报告文件可打开阅读。

---

## Run 2：故障注入（Agent 失败分支验证）

**操作方法：**
1. 编辑 `core/recon.py`，在 dry-run 代码块中将 `_write_done_status(task_id, [mock_path], "success", code=0)` 改为 `_write_done_status(task_id, [], "failed", code=4)`
2. 保存后重新运行 `python start_lynxsec.py --dry-run`

**输入：**
```
LynxSec> 扫描本地 DVWA
```

**期望结果：**

| 步骤 | Agent | 期望 |
|------|-------|------|
| 1 | dispatcher | 解析意图 |
| 2 | recon | result=failed, code=4 |
| 3 | dispatcher | 检测到 failed → 询问用户 retry/skip/abort |

**验证点：**
- 终端显示 "recon 报告执行失败"
- 弹出 retry/skip/abort 选项
- 选择 skip → dispatcher 跳过 recon 继续执行后续 Agent（或终止取决于决策逻辑）
- 选择 retry → 重新下发 recon 任务
- 选择 abort → 流水线 halted

**通过标准：** 三个选项各自产生预期行为，无崩溃。

**恢复操作：** 测试完成后将 recon.py 改回 `result="success"`。

---

## Run 3：中断恢复（pipeline.json 断点续跑）

**操作方法：**
1. 启动 `python start_lynxsec.py --dry-run`
2. 输入任务后，在 dispatcher 等待某个 Agent 完成期间（看到 "等待 xx 完成..." 字样），按 `Ctrl+C`
3. 确认进程已终止
4. 检查 `state/pipeline.json` 是否留存（status=running, current_step 指向中断点）
5. 重新运行 `python start_lynxsec.py --dry-run`

**输入（第二次启动后）：**
```
LynxSec> 扫描本地 DVWA
```

**期望结果：**

| 步骤 | 期望 |
|------|------|
| 1 | 启动脚本检测到 pipeline.json 存在且 status=running |
| 2 | dispatcher 提示 "发现未完成的任务"，显示已完成步骤 |
| 3 | 询问 "是否从中断点继续？" |
| 4 | 选择 y → 从断点继续执行 |

**验证点：**
- pipeline.json 中 steps_completed 包含中断前已完成的 Agent
- 不会重复执行已完成的步骤
- 最终 pipeline.json status=completed

**通过标准：** 中断恢复不重做已完成步骤，最终完成全链路。

> [UNCERTAIN] dispatcher.py 中断恢复逻辑目前标注为 TODO（v1.2），实际是否可用取决于 LLM 决策能否跳过已完成步骤。当前为概念验证。

---

## 测试记录

| Run | 日期 | 结果 | 备注 |
|-----|------|------|------|
| 1 | — | ⬜ 未执行 | |
| 2 | — | ⬜ 未执行 | |
| 3 | — | ⬜ 未执行 | |

---

## 判定

- [ ] Run 1 通过
- [ ] Run 2 通过
- [ ] Run 3 通过

**三项全部打勾 → LynxSec v0.1 MVP 可运行 ✅**
