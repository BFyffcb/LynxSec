"""
core/recon.py — LynxSec 情报Agent

职责：
  1. 轮询 state/recon_command.json，等待 dispatcher 下发任务
  2. 用 LLM 分析指令，规划信息收集策略
  3. 调用 infra/tools.py 统一工具封装执行侦察
  4. 将扫描结果结构化写入 state/recon_status.json
  5. 通过 result + code 字段明确报告终态

工具执行由 infra/tools.py 统一封装（纪律 A2：core→infra 单向依赖）。
recon.py 只做编排与结果汇总，不直接调用 subprocess。

status.json 终态字段（v1.3）：
  - result: "success" | "failed" | "skipped" | "blocked"
  - code:   0=成功 / 1=参数错误 / 2=工具缺失 / 3=超时 / 4=命令失败 / 5=解析失败

依赖链：core/recon.py → infra/llm.py, infra/tools.py
"""

from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone, timedelta

# ============================================================
# 第0步：把项目根目录加进 Python 搜索路径
# ============================================================
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from infra.llm import LLM           # type: ignore[import-untyped]
from infra.tools import run_tool     # type: ignore[import-untyped]
from infra.common import read_json as _read_json, write_json as _write_json  # type: ignore[import-untyped]

# ============================================================
# 常量配置
# ============================================================

_STATE_DIR = os.path.join(_PROJECT_ROOT, "state")
_AGENT_NAME = "recon"
_POLL_INTERVAL_SECONDS: float = 2.0
_CST = timezone(timedelta(hours=8))
_OUTPUTS_DIR = os.path.join(_PROJECT_ROOT, "outputs", "evidence")


# ============================================================
# 辅助函数
# ============================================================

def _now_iso() -> str:
    """当前北京时间 ISO 格式。"""
    return datetime.now(_CST).isoformat()



# ============================================================
# 状态文件管理
# ============================================================

def _command_path() -> str:
    return os.path.join(_STATE_DIR, f"{_AGENT_NAME}_command.json")


def _status_path() -> str:
    return os.path.join(_STATE_DIR, f"{_AGENT_NAME}_status.json")


def _write_initial_status() -> None:
    """启动时写入初始状态。"""
    _write_json(_status_path(), {
        "agent": _AGENT_NAME,
        "status": "idle",
        "result": "",
        "code": 0,
        "current_task": None,
        "outputs": [],
        "updated_at": _now_iso(),
    })
    print(f"[情报Agent] 已就绪，等待调度指令...")


def _write_working_status(task_id: str) -> None:
    """标记工作中。"""
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
    """标记任务完成。

    result: "success" | "failed" | "skipped" | "blocked"
    code:   0=成功 / 1=参数错误 / 2=工具缺失 / 3=超时 / 4=命令失败 / 5=解析失败
    """
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
# 情报收集策略（LLM 驱动）
# ============================================================

_SYSTEM_PROMPT_PLAN = """你是 LynxSec 的情报收集规划器。基于以下任务目标，规划需要按顺序执行的安全工具。

重要约束（必须遵守）：
- nmap 扫描端头使用 --top-ports 1000 或 -p 80,443,8080,8443，禁止使用 -p- 或 -p 1-65535
- nmap 必须使用 -sT（TCP connect，无需root）和 -Pn（跳过ping，Docker/WSL环境必需）
- 禁止使用 -O 参数（OS指纹扫描需要 root 权限）
- subfinder 仅用于外部域名（如 example.com），不要对 localhost/IP 地址使用
- 默认 each tool timeout 120s，扫描本地 localhost 时用 -p 80 就够了

你会收到 dispatcher 下发的侦察指令（包含目标和参数）。
你需要规划要运行哪些工具，以及每个工具的参数。

可用工具：
  - nmap:     端口扫描 / 服务版本检测
  - subfinder: 子域名发现（仅对域名有效，IP 跳过）（仅当目标有 HTTP 服务时）

规则：
  1. 如果目标是域名，先 subfinder 再 nmap
  2. 如果目标是 IP，只 nmap（subfinder 不适用）
  3. nmap 默认扫描 1-1000 端口，如果 dispatcher 指定了端口范围则使用指定的
  4. 如果 nmap 发现 Web 端口（80/443/8080/8443），追加 whatweb
  5. 输出一个 JSON 对象，格式如下：

{
  "tools": [
    {"tool": "nmap", "args": ["-sV", "-p", "1-1000", "目标"], "reason": "端口扫描"},
    {"tool": "subfinder", "args": ["-d", "目标域名"], "reason": "子域名发现"}
  ],
  "summary": "简短说明这次侦察计划"
}

如果 dispatcher 指令的 skip_pentest 为 true（仅被动分析），工具列表可以为空。

只返回 JSON，不要任何其他文字。"""


def _plan_tools(llm: LLM, command: dict) -> list[dict]:
    """用 LLM 规划工具清单。"""
    context = json.dumps(command, ensure_ascii=False, indent=2)

    print("[情报Agent] 正在分析任务，规划侦察策略...")
    raw_reply = llm.chat(_SYSTEM_PROMPT_PLAN, context, thinking_label="规划侦察策略")

    cleaned = raw_reply.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        cleaned = "\n".join(lines[1:])
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3].strip()

    try:
        plan = json.loads(cleaned)
    except json.JSONDecodeError as e:
        print(f"[LOG] LLM 规划解析失败: {e}，使用默认 nmap 扫描")
        plan = {
            "tools": [
                {
                    "tool": "nmap",
                    "args": ["-sV", "-p", "1-1000", command.get("target", "")],
                    "reason": "默认端口扫描（LLM 解析降级）",
                }
            ],
            "summary": "默认侦察策略",
        }

    tools: list[dict] = plan.get("tools", [])
    print(f"[情报Agent] 规划完成，共 {len(tools)} 个工具任务")
    for t in tools:
        print(f"  - {t.get('tool')}: {t.get('reason', '')}")
    return tools


# ============================================================
# 结果汇总（LLM 驱动）
# ============================================================

_SYSTEM_PROMPT_SUMMARIZE = """你是 LynxSec 的情报分析器。

你会收到一堆安全工具的原始输出（nmap、subfinder、whatweb 等）。
请将结果整理成一个结构化的 JSON 总结，供下游的渗透Agent和审计Agent使用。

JSON 格式：
{
  "findings": [
    {
      "type": "open_port",
      "detail": "端口 80/tcp - HTTP (nginx 1.18.0)",
      "severity": "info"
    }
  ],
  "summary": "3 个开放端口：80(HTTP), 443(HTTPS), 22(SSH)。发现 2 个子域名。",
  "recommendation": "建议对 80 和 443 端口进行 Web 漏洞检测。"
}

只返回 JSON，不要任何其他文字。"""


def _summarize_results(llm: LLM, tool_results: list[dict], target: str) -> dict:
    """用 LLM 整理工具输出为结构化分析。"""
    if not tool_results:
        return {
            "findings": [],
            "summary": "无工具输出（可能是仅被动分析模式）",
            "recommendation": "无需渗透",
        }

    context_parts: list[str] = [f"目标: {target}\n"]
    for r in tool_results:
        tool = r.get("tool", "unknown")
        success = r.get("success", False)
        stdout = r.get("stdout", "")
        stderr = r.get("stderr", "")
        max_len = 3000
        stdout_s = stdout[:max_len] + ("..." if len(stdout) > max_len else "")
        stderr_s = stderr[:500] + ("..." if len(stderr) > 500 else "")
        context_parts.append(
            f"=== {tool} (success={success}) ===\n"
            f"STDOUT:\n{stdout_s}\n"
            f"STDERR:\n{stderr_s}\n"
        )

    context = "\n".join(context_parts)
    print("[情报Agent] 正在分析扫描结果...")
    raw_reply = llm.chat(_SYSTEM_PROMPT_SUMMARIZE, context, thinking_label="分析侦察结果")

    cleaned = raw_reply.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        cleaned = "\n".join(lines[1:])
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3].strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError as e:
        print(f"[LOG] LLM 结果解析失败: {e}，返回降级摘要")
        return {
            "findings": [],
            "summary": f"扫描完成（LLM 解析失败，共 {len(tool_results)} 个工具输出）",
            "recommendation": "请手动查看 outputs/evidence/ 目录下的原始结果",
        }


# ============================================================
# 单次任务处理
# ============================================================

def run_once(command: dict) -> str:
    """处理单次侦察任务。

    流程：
      1. 标记 working
      2. LLM 规划工具
      3. 通过 infra/tools.py 依次执行工具
      4. 保存原始结果到 outputs/evidence/
      5. LLM 汇总分析
      6. 写入 status.json（idle + result + code）
    """
    os.makedirs(_OUTPUTS_DIR, exist_ok=True)

    task_id: str = command.get("task_id", "unknown")
    target: str = command.get("target", "")
    params: dict = command.get("params", {})

    print(f"\n{'=' * 60}")
    print(f"[情报Agent] 收到任务: {task_id}")
    print(f"  目标: {target}")
    print(f"  参数: {json.dumps(params, ensure_ascii=False)}")
    print(f"{'=' * 60}")

    _write_working_status(task_id)

    # --- dry-run 模拟模式 ---
    if os.getenv("LYNXSEC_DRY_RUN") == "1":
        print("[情报Agent] 模拟模式 — 返回预设侦察数据")
        mock_summary = {
            "findings": [
                {"type": "open_port", "detail": "端口 80/tcp - HTTP (Apache/2.4.54)", "severity": "info"},
                {"type": "tech_stack", "detail": "Apache/2.4.54, PHP/7.4.33", "severity": "info"},
            ],
            "summary": "1 个开放端口：80(HTTP/Apache)。未发现子域名。",
            "recommendation": "建议对 80 端口进行 Web 漏洞检测。",
        }
        safe_t = task_id.replace("/", "_").replace("\\", "_")
        mock_path = os.path.join(_OUTPUTS_DIR, f"{safe_t}_analysis.json")
        _write_json(mock_path, mock_summary)
        _write_done_status(task_id, [mock_path], "success", code=0)
        return "success"

    # --- LLM 初始化 ---
    try:
        llm = LLM()
    except RuntimeError as e:
        print(f"[情报Agent] LLM 初始化失败: {e}")
        _write_done_status(task_id, [], "failed", code=1)
        return "failed"

    # --- 规划工具 ---
    tools_plan = _plan_tools(llm, command)

    if not tools_plan:
        print("[情报Agent] 无需执行工具（仅被动分析或无适用工具）。")
        _write_done_status(task_id, [], "skipped", code=0)
        return "skipped"

    # --- 执行工具（通过 infra/tools.py） ---
    output_paths: list[str] = []
    all_success: bool = True

    for plan_item in tools_plan:
        tool_name = plan_item.get("tool", "")
        args = plan_item.get("args", [])

        # 统一通过 tools.py 调用，返回 ToolResult（Pydantic 模型）
        tool_result = run_tool(tool_name, args)

        # 保存原始结果到 evidence/
        safe_task = task_id.replace("/", "_").replace("\\", "_")
        output_filename = f"{safe_task}_{tool_name}.txt"
        output_path = os.path.join(_OUTPUTS_DIR, output_filename)

        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(f"工具: {tool_name}\n")
                f.write(f"命令: {' '.join(tool_result.cmd)}\n")
                f.write(f"成功: {tool_result.success}\n")
                f.write(f"code: {tool_result.code}\n")
                f.write(f"{'=' * 60}\n")
                f.write(tool_result.stdout)
                if tool_result.stderr:
                    f.write(f"\n{'=' * 60}\nSTDERR:\n")
                    f.write(tool_result.stderr)
        except OSError as e:
            print(f"[LOG] 保存结果文件失败: {output_path} — {e}")

        if os.path.isfile(output_path):
            output_paths.append(output_path)

        if not tool_result.success:
            all_success = False
            print(f"  [情报Agent] ✗ {tool_name} 执行失败 (code={tool_result.code}):")
            print(f"    {tool_result.stderr[:300]}")

    # --- 汇总分析 ---
    summary_results: list[dict] = []
    for plan_item in tools_plan:
        t_name = plan_item.get("tool", "")
        safe_t = task_id.replace("/", "_").replace("\\", "_")
        op = os.path.join(_OUTPUTS_DIR, f"{safe_t}_{t_name}.txt")
        stdout_c = ""
        if os.path.isfile(op):
            try:
                with open(op, "r", encoding="utf-8") as f:
                    stdout_c = f.read()
            except OSError:
                pass
        summary_results.append({
            "tool": t_name,
            "success": os.path.isfile(op),
            "stdout": stdout_c,
            "stderr": "",
        })

    analysis = _summarize_results(llm, summary_results, target)

    analysis_filename = f"{safe_task}_analysis.json"
    analysis_path = os.path.join(_OUTPUTS_DIR, analysis_filename)
    _write_json(analysis_path, analysis)
    output_paths.append(analysis_path)

    # --- 写入终态 ---
    result_kind = "success" if all_success else "failed"
    final_code = 0 if all_success else 4  # 4=命令失败/部分失败
    _write_done_status(task_id, output_paths, result_kind, code=final_code)

    print(f"[情报Agent] 任务完成 (result={result_kind}, code={final_code})")
    for p in output_paths:
        print(f"    {p}")

    return result_kind


# ============================================================
# 主轮询循环
# ============================================================

def poll_loop() -> None:
    """主循环：轮询 recon_command.json，task_id 去重防重复执行。"""
    _write_initial_status()

    last_seen_task_id: str | None = None

    while True:
        command_data = _read_json(_command_path())

        if command_data is None:
            time.sleep(_POLL_INTERVAL_SECONDS)
            continue

        current_task_id: str | None = command_data.get("task_id")

        if current_task_id is not None and current_task_id == last_seen_task_id:
            time.sleep(_POLL_INTERVAL_SECONDS)
            continue

        if current_task_id is not None:
            print(f"\n[情报Agent] 发现新任务: {current_task_id}")
            result = run_once(command_data)
            last_seen_task_id = current_task_id

            status = "success" if result == "success" else result
            print(f"[情报Agent] {status}，等待下一个任务...")

        time.sleep(_POLL_INTERVAL_SECONDS)


# ============================================================
# 直接运行入口
# ============================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  LynxSec 情报Agent — 信息收集与侦察")
    print("=" * 60)
    print(f"  轮询间隔: {_POLL_INTERVAL_SECONDS}s")
    print(f"  指令文件: {_command_path()}")
    print(f"  状态文件: {_status_path()}")
    print(f"  产出目录: {_OUTPUTS_DIR}")
    print()
    print("  等待 dispatcher 下发任务...")
    print("  按 Ctrl+C 停止")
    print()

    try:
        poll_loop()
    except KeyboardInterrupt:
        print("\n[情报Agent] 收到停止信号，正在退出...")
        status = _read_json(_status_path())
        if status and status.get("status") == "working":
            current_task = status.get("current_task", "unknown")
            _write_done_status(current_task, status.get("outputs", []), "failed", code=1)
            print("[情报Agent] 已标记当前任务为 failed（被中断）")
        print("[情报Agent] 已退出。")
