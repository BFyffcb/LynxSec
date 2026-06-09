"""
core/reporter.py — LynxSec 报告Agent

职责：
  1. 轮询 state/report_command.json，等待 dispatcher 下发任务
  2. 读取上游全部产出（recon + pentest + audit）
  3. 用 LLM 生成两份报告：
     人话版（面向普通开发者）— 通俗语言，代码级修复建议
     技术版（面向专业安全人员）— CVE编号、CVSS评分、攻击链、POC
  4. 输出 Markdown 文件到 outputs/reports/

双版本设计：
  人话版：[HIGH]风险 -> 影响解释 -> 怎么修（代码示例）
  技术版：CVE | CVSS | 攻击向量 | POC | 修复方案

依赖链：core/reporter.py → infra/llm.py
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone, timedelta

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from infra.llm import LLM  # type: ignore[import-untyped]
from infra.common import read_json as _read_json, write_json as _write_json  # type: ignore[import-untyped]
from infra.skills.loader import build_prompt

# ============================================================
# 常量
# ============================================================

_STATE_DIR = os.path.join(_PROJECT_ROOT, "state")
_AGENT_NAME = "reporter"
_POLL_INTERVAL_SECONDS: float = 2.0
_CST = timezone(timedelta(hours=8))
_REPORTS_DIR = os.path.join(_PROJECT_ROOT, "outputs", "reports")
_EVIDENCE_DIR = os.path.join(_PROJECT_ROOT, "outputs", "evidence")


def _now_iso() -> str:
    return datetime.now(_CST).isoformat()



# ============================================================
# 状态管理
# ============================================================

def _command_path() -> str:
    return os.path.join(_STATE_DIR, f"{_AGENT_NAME}_command.json")


def _status_path() -> str:
    return os.path.join(_STATE_DIR, f"{_AGENT_NAME}_status.json")


def _write_initial_status() -> None:
    _write_json(_status_path(), {
        "agent": _AGENT_NAME,
        "status": "idle",
        "result": "",
        "code": 0,
        "current_task": None,
        "outputs": [],
        "updated_at": _now_iso(),
    })
    print(f"[报告Agent] 已就绪，等待调度指令...")


def _write_working_status(task_id: str) -> None:
    _write_json(_status_path(), {
        "agent": _AGENT_NAME,
        "status": "working",
        "result": "",
        "code": 0,
        "current_task": task_id,
        "outputs": [],
        "updated_at": _now_iso(),
    })


def _write_done_status(task_id: str, outputs: list, result: str, code: int = 0) -> None:
    _write_json(_status_path(), {
        "agent": _AGENT_NAME,
        "status": "idle",
        "result": result,
        "code": code,
        "current_task": task_id,
        "outputs": outputs,
        "updated_at": _now_iso(),
    })


# ============================================================
# 收集全流程产出
# ============================================================

def _collect_all_outputs() -> dict:
    """收集 recon + pentest + auditor 三份分析结果。

    从 state/ 文件中读取 outputs 路径，加载对应的 *_analysis.json 和 *_audit.json。
    """
    all_data: dict = {"recon": None, "pentest": None, "auditor": None}

    for agent_name in ["recon", "pentest"]:
        status = _read_json(os.path.join(_STATE_DIR, f"{agent_name}_status.json"))
        if status:
            for p in status.get("outputs", []):
                if p.endswith("_analysis.json") and os.path.isfile(p):
                    all_data[agent_name] = _read_json(p)
                    break

    # auditor 产出
    audit_status = _read_json(os.path.join(_STATE_DIR, "auditor_status.json"))
    if audit_status:
        for p in audit_status.get("outputs", []):
            if p.endswith("_audit.json") and os.path.isfile(p):
                all_data["auditor"] = _read_json(p)
                break

    return all_data


# ============================================================
# 人话版报告（LLM 生成）
# ============================================================

_SYSTEM_PROMPT_HUMAN = """你是 LynxSec 的安全报告撰写专家，专门为**没有安全背景的普通开发者**写报告。

要求：
  1. 用通俗易懂的语言，避免专业术语（或解释了再读）
  2. 每个问题用 "[HIGH] / [MED] / [LOW]" 前缀开头
  3. 三个部分：【问题是什么】【为什么会这样】【怎么修】
  4. 修复方案给出具体代码示例
  5. 最后给一个简短的"你应该优先处理的事"

输出格式（Markdown）：

## [SEC] 安全检测结果

### [HIGH] 发现 X 个高危漏洞

#### 1. [漏洞名称]
【问题是什么】
（一句话说清楚，用比喻更好理解）

【为什么会这样】
（用日常场景举例说明原因）

【怎么修】
（粘贴修复代码，标明在第几行）

```python
# 修复前（第23行）
old_code
# 修复后
new_code
```

---

### [MED] 发现 X 个中危问题
（同样的三段式）

### [LOW] 发现 X 个低危提示
（同样的三段式）

---
## [PRI] 优先处理清单
- [ ] 第一件事
- [ ] 第二件事

直接输出 Markdown，不需要 JSON 包装。"""


def _generate_human_report(llm: LLM, all_data: dict, target: str) -> str:
    """LLM 生成人话版报告。"""
    # 构造上下文 — 把审计结果（如果有）作为主要输入
    auditor_data = all_data.get("auditor", {}) or {}

    context_parts: list[str] = [
        f"检测目标: {target}",
        f"检测时间: {_now_iso()}",
        "",
        "## 审计结果（漏洞已过误报过滤）",
        json.dumps(auditor_data, ensure_ascii=False, indent=2),
        "",
        "## 附录：原始侦察数据",
    ]
    if all_data.get("recon"):
        context_parts.append(json.dumps(all_data["recon"], ensure_ascii=False, indent=2))

    context = "\n".join(context_parts)

    print("[报告Agent] 正在生成人话版报告...")
    report = llm.chat(build_prompt(_SYSTEM_PROMPT_HUMAN, "reporter"), context, thinking_label="生成人话版报告")
    return report


# ============================================================
# 技术版报告（LLM 生成）
# ============================================================

_SYSTEM_PROMPT_TECH = """你是 LynxSec 的安全报告撰写专家，专门为**专业安全人员**写技术报告。

要求：
  1. 每个漏洞包含：CVE编号（如有）、CVSS 3.1 向量和分数、攻击向量、POC、修复方案
  2. 如果有攻击链，完整串联描述
  3. 附录包含端口开放清单、服务版本、指纹识别结果
  4. 使用 Markdown 格式

输出格式（Markdown）：

## [TECH] 渗透测试技术报告

| 字段 | 内容 |
|------|------|
| 目标 | xxxx |
| 检测时间 | xxxx |
| 漏洞总数 | X (高危Y / 中危Z / 低危W) |

---

### 1. CVE-XXXX-XXXXX | CVSS 9.8 CRITICAL
**漏洞类型**：SQL 注入
**攻击向量**：POST /api/login → username 参数
**前提条件**：无需认证
**POC**：
```http
POST /api/login HTTP/1.1
username=' OR 1=1--
```

**CVSS 3.1 向量**：CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

**修复方案**：使用参数化查询

```python
# 修复示例
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
```

---

### 攻击链分析
（如果有的话）

### 附录
- 开放端口
- 服务版本
- 子域名

直接输出 Markdown，不需要 JSON 包装。"""


def _generate_tech_report(llm: LLM, all_data: dict, target: str) -> str:
    """LLM 生成技术版报告。"""
    auditor_data = all_data.get("auditor", {}) or {}
    recon_data = all_data.get("recon", {}) or {}
    pentest_data = all_data.get("pentest", {}) or {}

    context_parts: list[str] = [
        f"检测目标: {target}",
        f"检测时间: {_now_iso()}",
        "",
        "## 审计结果（已过滤误报）",
        json.dumps(auditor_data, ensure_ascii=False, indent=2),
        "",
        "## 情报侦察结果",
        json.dumps(recon_data, ensure_ascii=False, indent=2),
        "",
        "## 渗透测试结果",
        json.dumps(pentest_data, ensure_ascii=False, indent=2),
    ]
    context = "\n".join(context_parts)

    print("[报告Agent] 正在生成技术版报告...")
    report = llm.chat(build_prompt(_SYSTEM_PROMPT_TECH, "reporter"), context, thinking_label="生成技术版报告")
    return report


# ============================================================
# 单次任务
# ============================================================

def run_once(command: dict) -> str:
    task_id: str = command.get("task_id", "unknown")
    target: str = command.get("target", "")

    print(f"\n{'=' * 60}")
    print(f"[报告Agent] 收到任务: {task_id}")
    print(f"  目标: {target}")
    print(f"{'=' * 60}")

    _write_working_status(task_id)

    # --- dry-run 模拟模式 ---
    if os.getenv("LYNXSEC_DRY_RUN") == "1":
        print("[报告Agent] 模拟模式 — 生成预设双版本报告")
        os.makedirs(_REPORTS_DIR, exist_ok=True)
        safe_t = task_id.replace("/", "_").replace("\\", "_")
        safe_target = target.replace("/", "_").replace("\\", "_").replace(":", "_")

        human = "## [SEC] 安全检测结果\n\n### [HIGH] 发现 1 个高危漏洞\n\n#### 1. SQL 注入漏洞\n【问题是什么】你的网站登录接口可以被攻击者注入恶意SQL代码。\n【为什么会这样】代码直接把用户输入拼进了SQL查询。\n【怎么修】使用参数化查询。\n```python\ncursor.execute(\"SELECT * FROM users WHERE username = ?\", (username,))\n```\n\n## [PRI] 优先处理清单\n- [ ] 修复 SQL 注入\n\n*本报告由 LynxSec 自动生成（模拟模式）*"

        tech = f"## [TECH] 渗透测试技术报告\n\n| 字段 | 内容 |\n|------|------|\n| 目标 | {target} |\n| 检测时间 | {_now_iso()} |\n| 漏洞总数 | 1 (高危1) |\n\n### 1. SQL Injection | CVSS 9.8 CRITICAL\n**攻击向量**：GET /vulnerabilities/sqli/?id=1\n**POC**：`' OR 1=1--`\n**CVSS 3.1 向量**：CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n**修复方案**：参数化查询\n\n*本报告由 LynxSec 自动生成（模拟模式）*"

        human_path = os.path.join(_REPORTS_DIR, f"{safe_t}_{safe_target}_人话版.md")
        tech_path = os.path.join(_REPORTS_DIR, f"{safe_t}_{safe_target}_技术版.md")

        with open(human_path, "w", encoding="utf-8") as f:
            f.write(human)
        with open(tech_path, "w", encoding="utf-8") as f:
            f.write(tech)

        output_paths = [human_path, tech_path]
        _write_done_status(task_id, output_paths, "success", code=0)
        print(f"[报告Agent] 模拟报告已生成：")
        for p in output_paths:
            print(f"  {p}")
        return "success"

    try:
        llm = LLM()
    except RuntimeError as e:
        print(f"[报告Agent] LLM 初始化失败: {e}")
        _write_done_status(task_id, [], "failed", code=1)
        return "failed"

    # 收集全流程产出
    all_data = _collect_all_outputs()

    # 生成双版本报告
    human_report = _generate_human_report(llm, all_data, target)
    tech_report = _generate_tech_report(llm, all_data, target)

    # 写入文件
    os.makedirs(_REPORTS_DIR, exist_ok=True)
    safe_task = task_id.replace("/", "_").replace("\\", "_")
    safe_target = target.replace("/", "_").replace("\\", "_").replace(":", "_")

    human_path = os.path.join(_REPORTS_DIR, f"{safe_task}_{safe_target}_人话版.md")
    tech_path = os.path.join(_REPORTS_DIR, f"{safe_task}_{safe_target}_技术版.md")

    try:
        with open(human_path, "w", encoding="utf-8") as f:
            f.write(human_report)
    except OSError as e:
        print(f"[LOG] 写入人话版报告失败: {human_path} — {e}")
        human_path = ""

    try:
        with open(tech_path, "w", encoding="utf-8") as f:
            f.write(tech_report)
    except OSError as e:
        print(f"[LOG] 写入技术版报告失败: {tech_path} — {e}")
        tech_path = ""

    output_paths = [p for p in [human_path, tech_path] if p]

    if not output_paths:
        _write_done_status(task_id, [], "failed", code=5)  # 5=解析/写入失败
        return "failed"

    _write_done_status(task_id, output_paths, "success", code=0)

    print(f"[报告Agent] 报告生成完成：")
    for p in output_paths:
        print(f"  {p}")

    return "success"


# ============================================================
# 主轮询
# ============================================================

def poll_loop() -> None:
    _write_initial_status()
    last_seen_task_id: str | None = None

    while True:
        command_data = _read_json(_command_path())
        if command_data is None:
            time.sleep(_POLL_INTERVAL_SECONDS)
            continue
        # check shutdown signal
        if command_data.get("action") == "shutdown":
            print("[报告Agent] 收到 shutdown 信号，正在退出...")
            break

        current_task_id: str | None = command_data.get("task_id")
        if current_task_id is not None and current_task_id == last_seen_task_id:
            time.sleep(_POLL_INTERVAL_SECONDS)
            continue

        if current_task_id is not None:
            print(f"\n[报告Agent] 发现新任务: {current_task_id}")
            result = run_once(command_data)
            last_seen_task_id = current_task_id
            print(f"[报告Agent] {result}，等待下一个任务...")

        time.sleep(_POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    print("=" * 60)
    print("  LynxSec 报告Agent — 双版本安全报告")
    print("=" * 60)
    print("  按 Ctrl+C 停止\n")
    try:
        poll_loop()
    except KeyboardInterrupt:
        _write_done_status("shutdown", [], "failed", code=1)
        print("\n[reporter] 已退出。")
