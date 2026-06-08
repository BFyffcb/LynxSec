"""
core/dispatcher.py — LynxSec 调度Agent

职责：
  1. 接收用户的安全检测请求
  2. 校验目标授权（未授权拒绝渗透）
  3. 用 LLM 分析意图，拆解任务链
  4. 按流水线顺序调度其他 Agent：
     情报 → 渗透 → 审计 → 报告
  5. 每步之间由 LLM 决策是否继续
  6. 全流程记录到 pipeline.json，支持中断恢复

通信方式：
  通过 state/ 目录下的 JSON 文件与其他 Agent 通信。
  Agent 完成后轮询其 *_status.json 判断是否完成。

依赖链：core/dispatcher.py → infra/llm.py
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone, timedelta

# ============================================================
# 第0步：把项目根目录加进 Python 搜索路径
# ============================================================
# 这样 import infra.llm 才能找到文件
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from infra.llm import LLM  # type: ignore[import-untyped]
from infra.common import read_json as _read_json, write_json as _write_json  # type: ignore[import-untyped]

# ============================================================
# 常量配置
# ============================================================

# state/ 目录的绝对路径（运行时状态，不在版本控制中）
_STATE_DIR = os.path.join(_PROJECT_ROOT, "state")

# 流水线中各 Agent 的顺序（dispatcher 自己不在此列）
_PIPELINE_ORDER: list[str] = ["recon", "pentest", "auditor", "reporter"]

# 轮询间隔：每次检查 Agent 状态文件后等待的秒数
_POLL_INTERVAL_SECONDS: float = 2.0

# 超时：等待单个 Agent 完成的最长秒数
_AGENT_TIMEOUT_SECONDS: int = 300

# 流水线记录文件路径
_PIPELINE_PATH = os.path.join(_STATE_DIR, "pipeline.json")

# 授权记录文件路径
_AUTH_PATH = os.path.join(_STATE_DIR, "auth.json")

# 北京时间时区
_CST = timezone(timedelta(hours=8))


# ============================================================
# 辅助函数
# ============================================================

def _now_iso() -> str:
    """返回当前北京时间的 ISO 格式字符串。

    示例: "2026-05-31T22:05:00+08:00"
    """
    return datetime.now(_CST).isoformat()


def _agent_command_path(agent: str) -> str:
    """返回某个 Agent 的指令文件路径。

    例如 agent="recon" → ".../state/recon_command.json"
    """
    return os.path.join(_STATE_DIR, f"{agent}_command.json")


def _agent_status_path(agent: str) -> str:
    """返回某个 Agent 的状态文件路径。

    例如 agent="recon" → ".../state/recon_status.json"
    """
    return os.path.join(_STATE_DIR, f"{agent}_status.json")




def _ensure_state_dir() -> None:
    """确保 state/ 目录存在。首次启动时创建。"""
    os.makedirs(_STATE_DIR, exist_ok=True)


# ============================================================
# 授权校验
# ============================================================

def _authorize(target: str, scan_scope: str) -> bool:
    """入口授权校验。

    在所有操作之前执行。要求用户确认拥有目标测试授权。
    确认后写入 state/auth.json 持久化记录。

    参数:
        target:     目标地址（IP 或域名）
        scan_scope: 扫描范围描述（如 "端口扫描 + Web漏洞检测"）

    返回:
        True 表示授权通过，False 表示用户拒绝。
    """
    print()
    print("+" + "-" * 50 + "+")
    print("|  LynxSec 授权声明" + " " * 33 + "|")
    print(f"|  目标: {target:<44}" + "|")
    print(f"|  范围: {scan_scope:<44}" + "|")
    print("|  我确认拥有该目标的测试授权" + " " * 23 + "|")
    print("+" + "-" * 50 + "+")

    try:
        answer = input("  [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\n[调度Agent] 授权取消。")
        return False

    if answer != "y":
        print("[调度Agent] 未获得授权，操作取消。")
        return False

    # 写入授权记录
    auth_record: dict = {
        "target": target,
        "scope": scan_scope,
        "authorized": True,
        "timestamp": _now_iso(),
    }
    _write_json(_AUTH_PATH, auth_record)
    print(f"[调度Agent] 授权已确认，记录保存至 state/auth.json\n")
    return True


# ============================================================
# 意图解析（LLM 驱动）
# ============================================================

_SYSTEM_PROMPT_INTENT = """你是 LynxSec 的安全调度分析器。

用户会输入一个安全检测请求。请分析并返回一个 JSON 对象。

JSON 格式（严格按此）：
{
  "target": "目标IP或域名",
  "scan_scope": "简短描述扫描范围",
  "steps": ["recon", "pentest", "auditor", "reporter"],
  "recon_instruction": "给情报Agent的具体指令，包含要扫描的端口范围等",
  "skip_pentest": false
}

规则：
- target: 从用户输入中提取目标。如果用户没指定，填 "UNKNOWN"。
- scan_scope: 一句话描述这次要检测什么。
- steps: 固定顺序 [recon, pentest, auditor, reporter]。
- recon_instruction: 自然语言指令，告诉情报Agent该做什么。
- skip_pentest: 如果用户明确说"只看信息不攻击"，填 true；否则 false。

只返回 JSON，不要任何其他文字。"""


def _parse_intent(llm: LLM, user_input: str) -> dict:
    """用 LLM 解析用户的自然语言请求。

    参数:
        llm:        LLM 实例
        user_input: 用户输入的原文本

    返回:
        包含 target, scan_scope, steps, recon_instruction, skip_pentest 的字典。
    """
    print("[调度Agent] 正在分析你的需求...")
    raw_reply = llm.chat(_SYSTEM_PROMPT_INTENT, user_input, thinking_label="解析用户意图")

    # LLM 可能返回带 markdown 代码块包装的 JSON，先清理
    # 去掉 ```json 和 ``` 包装
    cleaned = raw_reply.strip()
    if cleaned.startswith("```"):
        # 找到第一行换行后的内容
        lines = cleaned.split("\n")
        cleaned = "\n".join(lines[1:])  # 跳过 ```json 或 ```
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3].strip()

    try:
        intent = json.loads(cleaned)
    except json.JSONDecodeError as e:
        print(f"[调度Agent] LLM 返回格式异常，使用默认解析。错误: {e}")
        # 降级策略：用最简单的假设
        intent = {
            "target": user_input.strip(),
            "scan_scope": "安全扫描",
            "steps": ["recon", "pentest", "auditor", "reporter"],
            "recon_instruction": f"对目标 {user_input.strip()} 进行全面的信息收集",
            "skip_pentest": False,
        }

    return intent


# ============================================================
# 流水线管理
# ============================================================

def _init_pipeline(task_id: str, intent: dict) -> dict:
    """初始化 pipeline.json，记录任务全貌。

    参数:
        task_id: 本次任务的唯一 ID
        intent:  解析后的意图字典

    返回:
        pipeline 字典。
    """
    pipeline: dict = {
        "task_id": task_id,
        "target": intent.get("target", ""),
        "scan_scope": intent.get("scan_scope", ""),
        "created_at": _now_iso(),
        "status": "running",  # running | completed | halted
        "steps_completed": [],
        "current_step": None,
        "outputs": {},
    }
    _write_json(_PIPELINE_PATH, pipeline)
    return pipeline


def _update_pipeline(
    task_id: str,
    step_name: str | None = None,
    status: str | None = None,
    step_completed: str | None = None,
    outputs_update: dict | None = None,
) -> None:
    """更新 pipeline.json 中的进度。

    参数:
        task_id:         任务 ID
        step_name:       当前正在执行的步骤名
        status:          流水线整体状态
        step_completed:  标记某个步骤完成（追加到 steps_completed）
        outputs_update:  追加 Agent 产出
    """
    pipeline = _read_json(_PIPELINE_PATH) or {}

    # 确保 task_id 一致（防止读到旧流水线）
    if pipeline.get("task_id") != task_id:
        return

    if step_name is not None:
        pipeline["current_step"] = step_name
    if status is not None:
        pipeline["status"] = status
    if step_completed is not None:
        completed: list = pipeline.get("steps_completed", [])
        if step_completed not in completed:
            completed.append(step_completed)
        pipeline["steps_completed"] = completed
    if outputs_update is not None:
        existing_outputs: dict = pipeline.get("outputs", {})
        existing_outputs.update(outputs_update)
        pipeline["outputs"] = existing_outputs

    _write_json(_PIPELINE_PATH, pipeline)


def _check_existing_pipeline() -> dict | None:
    """启动时检查是否有未完成的流水线任务。

    返回:
        如果有未完成的任务，返回 pipeline 字典；否则返回 None。
    """
    pipeline = _read_json(_PIPELINE_PATH)
    if pipeline is None:
        return None
    if pipeline.get("status") == "running":
        return pipeline
    return None


# ============================================================
# Agent 调度核心
# ============================================================

def _dispatch_agent(agent: str, task_id: str, action: str, target: str, params: dict | None = None) -> bool:
    """向某个 Agent 下发任务（写入 command 文件）。

    参数:
        agent:    Agent 名称（recon / pentest / auditor / reporter）
        task_id:  任务 ID
        action:   动作描述（如 "port_scan"、"sql_injection_test"）
        target:   目标地址
        params:   额外参数

    返回:
        True 表示下发成功，False 表示失败。
    """
    command: dict = {
        "task_id": task_id,
        "action": action,
        "target": target,
        "params": params or {},
        "sender": "dispatcher",
        "created_at": _now_iso(),
    }
    path = _agent_command_path(agent)
    ok = _write_json(path, command)
    if ok:
        print(f"  [调度Agent] → 已下发任务到 {agent}（{action}）")
    else:
        print(f"  [调度Agent] [FAIL] 下发任务到 {agent} 失败！")
    return ok


def _wait_for_agent(agent: str, last_task_id: str, timeout: int = _AGENT_TIMEOUT_SECONDS) -> str | None:
    """轮询等待某个 Agent 完成任务。

    轮询逻辑：
      - 每 _POLL_INTERVAL_SECONDS 秒读取一次 {agent}_status.json
      - 检测 status 字段：working → 继续等；idle → 检查 result 字段判定终态
      - result 字段（v1.2 新增）：
        "success" → 任务完成
        "failed"  → 任务执行失败
        "skipped" → Agent 判定无需执行
        "blocked" → 工具/权限受阻
      - 超时后返回 None

    参数:
        agent:          Agent 名称
        last_task_id:   期望 Agent 处理的 task_id
        timeout:        超时秒数

    返回:
        "done"    — Agent 正常完成（result=success）
        "failed"  — Agent 执行失败（result=failed）
        "skipped" — Agent 判定跳过（result=skipped）
        "blocked" — Agent 报告阻塞（status=blocked 或 result=blocked）
        None      — 超时

    纪律 R1：超时和阻塞都会打印日志，不静默。
    纪律 R5：不依赖单一 status 字段判定终态，必须结合 result 字段。
    """
    status_path = _agent_status_path(agent)
    elapsed: float = 0.0

    print(f"  [调度Agent] 等待 {agent} 完成（最长 {timeout} 秒）...", end="", flush=True)

    while elapsed < timeout:
        time.sleep(_POLL_INTERVAL_SECONDS)
        elapsed += _POLL_INTERVAL_SECONDS

        status_data = _read_json(status_path)
        if status_data is None:
            continue  # 文件还没被 Agent 创建，继续等

        current_status: str = status_data.get("status", "")
        result_field: str = status_data.get("result", "")  # v1.2 新增
        current_task: str | None = status_data.get("current_task")

        # Agent 正在工作中
        if current_status == "working":
            print(".", end="", flush=True)
            continue

        # Agent 进入终态 — 必须同时检查 status 和 result
        if current_status in ("idle", "blocked"):
            if current_task == last_task_id or current_task is None:
                print(f" {current_status}")
                # 优先用 result 字段判定；向后兼容（老版本 Agent 可能没有 result）
                if result_field == "success":
                    return "done"
                elif result_field == "failed":
                    return "failed"
                elif result_field == "skipped":
                    return "skipped"
                elif result_field == "blocked" or current_status == "blocked":
                    return "blocked"
                else:
                    # 向后兼容：老版本没有 result 字段，idle 视为 done
                    print(f"  [LOG] {agent} 未提供 result 字段（可能是旧版Agent），按 done 处理")
                    return "done"

    # 超时
    print(f" 超时")
    print(f"[LOG] {agent} 任务超时 ({timeout}s)，task_id={last_task_id}")
    return None


def _read_agent_output(agent: str) -> dict:
    """读取某个 Agent 的产出（从其 status 文件中提取）。

    返回:
        outputs 列表和 updated_at 时间戳。
    """
    status_data = _read_json(_agent_status_path(agent))
    if status_data is None:
        return {"outputs": [], "updated_at": _now_iso(), "result": "unknown"}
    return {
        "outputs": status_data.get("outputs", []),
        "updated_at": status_data.get("updated_at", _now_iso()),
        "status": status_data.get("status", "unknown"),
        "result": status_data.get("result", "unknown"),
    }


# ============================================================
# LLM 决策系统
# ============================================================

_SYSTEM_PROMPT_DECIDE = """你是 LynxSec 的安全调度决策器。

你会收到上一步 Agent 的扫描结果，然后决定下一步如何行动。

规则：
1. 如果 recon 返回了 Web 端口（80/443/8080等），必须把端口信息传给 pentest
2. 如果 recon 没有发现 Web 端口，pentest 跳过（但仍需告诉 dispatcher "跳过"）
3. pentest 的结果必须完整传给 auditor（包含漏洞详情、URL、参数）
4. auditor 的结果必须完整传给 reporter
5. 输出一个 JSON 对象：

{
  "next_action": "port_scan" 或其他动作名,
  "target": "目标地址",
  "params": {"ports": "80,443", "url": "http://..."}  (每步需要的参数),
  "reason": "一句话说明为什么要这步"
}

只返回 JSON，不要任何其他文字。"""


def _llm_decide_next(llm: LLM, agent_name: str, agent_output: dict, intent: dict, completed: list[str]) -> dict:
    """由 LLM 决定当前 Agent 完成后下一步做什么。

    参数:
        llm:          LLM 实例
        agent_name:   刚完成的 Agent 名称
        agent_output: 刚完成的 Agent 产出
        intent:       最初的用户意图
        completed:    已完成的步骤列表

    返回:
        LLM 的决策 JSON（包含 next_action, target, params, reason）
    """
    # 构建决策上下文
    context: str = f"""上一步完成: {agent_name}
    已完成的步骤: {completed}
    用户原始目标: {intent.get('target', '')}
    扫描范围: {intent.get('scan_scope', '')}

    {agent_name} 的产出:
    {json.dumps(agent_output, ensure_ascii=False, indent=2)}
    """
    raw_reply = llm.chat(_SYSTEM_PROMPT_DECIDE, context, thinking_label="决定下一步行动")

    # 清理 markdown 包装
    cleaned = raw_reply.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        cleaned = "\n".join(lines[1:])
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3].strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        print(f"[调度Agent] LLM 决策返回格式异常，使用默认参数。")
        return {
            "next_action": "continue",
            "target": intent.get("target", ""),
            "params": {},
            "reason": "LLM 解析失败，使用默认参数继续流水线",
        }


# ============================================================
# 命令行交互
# ============================================================

def _ask_blocked_action(agent: str) -> str:
    """当某个 Agent 阻塞时，询问用户如何处理。

    返回: "retry" / "skip" / "abort"
    """
    print()
    print(f"[调度Agent] {agent} 报告阻塞，可能的原因：")
    print("  - 目标不可达")
    print("  - 工具执行失败")
    print("  - 权限不足")
    print()
    while True:
        try:
            choice = input("  如何处理？ (r)etry重试 / (s)kip跳过 / (a)bort终止 [s]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return "abort"

        if choice in ("", "s", "skip"):
            return "skip"
        if choice in ("r", "retry"):
            return "retry"
        if choice in ("a", "abort"):
            return "abort"
        print("  请输入 r / s / a")


# ============================================================
# 主流程
# ============================================================

def run(user_input: str) -> str | None:
    """dispatcher 的主入口。

    完整流程：
      1. 初始化 state/ 目录
      2. 检查未完成流水线（中断恢复）
      3. LLM 解析用户意图
      4. 授权校验
      5. 初始化流水线
      6. 按步骤调度：recon → pentest → auditor → reporter
      7. 每步完成后由 LLM 决策下一步参数
      8. 全部完成后输出报告路径

    参数:
        user_input: 用户的自然语言请求

    返回:
        报告文件路径（成功时）；None（失败或用户取消时）。
    """
    _ensure_state_dir()

    # ----------------------------------------------------------
    # 第1步：检查中断恢复
    # ----------------------------------------------------------
    existing = _check_existing_pipeline()
    if existing is not None:
        print(f"[调度Agent] 发现未完成的任务: {existing.get('task_id')}")
        print(f"  目标: {existing.get('target')}")
        print(f"  已完成步骤: {existing.get('steps_completed')}")
        try:
            resume = input("  是否从中断点继续？ [Y/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            resume = "n"
        if resume in ("", "y"):
            # TODO: 中断恢复逻辑（v1.2）
            print("[调度Agent] 中断恢复功能开发中，将新建任务。")
        # 不管选什么，都进入新任务流程

    # ----------------------------------------------------------
    # 第2步：初始化 LLM
    # ----------------------------------------------------------
    print("[调度Agent] 正在连接 LLM...")
    try:
        llm = LLM()
    except RuntimeError as e:
        print(f"\n[FAIL] 启动失败: {e}")
        return None

    # ----------------------------------------------------------
    # 第3步：解析意图
    # ----------------------------------------------------------
    intent = _parse_intent(llm, user_input)
    target: str = intent.get("target", "")
    scan_scope: str = intent.get("scan_scope", "安全扫描")
    skip_pentest: bool = intent.get("skip_pentest", False)

    print(f"  目标: {target}")
    print(f"  范围: {scan_scope}")

    # ----------------------------------------------------------
    # 第4步：授权校验
    # ----------------------------------------------------------
    if not skip_pentest and target != "UNKNOWN":
        # 只有涉及渗透检测且目标明确时才需要授权
        if not _authorize(target, scan_scope):
            return None
    else:
        print("[调度Agent] 仅被动分析模式，跳过授权校验。\n")

    # ----------------------------------------------------------
    # 第5步：初始化流水线
    # ----------------------------------------------------------
    task_id: str = f"task-{datetime.now(_CST).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    _init_pipeline(task_id, intent)
    print(f"[调度Agent] 任务 ID: {task_id}")
    print(f"[调度Agent] 流水线: 情报 → 渗透 → 审计 → 报告")
    print()

    # ----------------------------------------------------------
    # 第6步：按顺序驱动流水线
    # ----------------------------------------------------------
    completed_steps: list[str] = []

    # recon 是一定执行的
    agents_to_run: list[str] = ["recon"]
    if not skip_pentest:
        agents_to_run.append("pentest")
    agents_to_run.extend(["auditor", "reporter"])

    for agent in agents_to_run:
        _update_pipeline(task_id, step_name=agent)

        # --- 6a. 由 LLM 决定这一步做什么 ---
        # 第一步 (recon) 使用 intent 中的指令
        if agent == "recon":
            action = "reconnaissance"
            step_target = target
            step_params: dict = {
                "instruction": intent.get("recon_instruction", f"对 {target} 进行全面信息收集"),
            }
        else:
            # 后续步骤：读取前一步产出，让 LLM 决策
            prev_agent = completed_steps[-1] if completed_steps else "recon"
            prev_output = _read_agent_output(prev_agent)
            print(f"[调度Agent] 分析 {prev_agent} 的结果，决定 {agent} 的行动...")
            decision = _llm_decide_next(llm, prev_agent, prev_output, intent, completed_steps)
            action = decision.get("next_action", "continue")
            step_target = decision.get("target", target)
            step_params = decision.get("params", {})
            print(f"  决策: {decision.get('reason', '继续流水线')}")

        # --- 6b. 下发任务 ---
        ok = _dispatch_agent(agent, task_id, action, step_target, step_params)
        if not ok:
            print(f"[调度Agent] [FAIL] 无法下发任务到 {agent}，流水线终止。")
            _update_pipeline(task_id, status="halted")
            return None

        # --- 6c. 等待 Agent 完成 ---
        result = _wait_for_agent(agent, task_id)

        # --- 6d. 处理 Agent 结果 ---
        # result 可能值: "done" / "failed" / "skipped" / "blocked" / None(超时)
        if result == "failed":
            # Agent 执行失败（如工具报错、目标不可达）
            print(f"[调度Agent] {agent} 报告执行失败，检查产出详情。")
            user_choice = _ask_blocked_action(agent)
            if user_choice == "abort":
                _update_pipeline(task_id, status="halted")
                return None
            elif user_choice == "retry":
                if not _dispatch_agent(agent, task_id, action, step_target, step_params):
                    print(f"[调度Agent] 重试下发失败，跳过 {agent}。")
                    _update_pipeline(task_id, step_completed=agent)
                    completed_steps.append(agent)
                    continue
                retry_result = _wait_for_agent(agent, task_id)
                if retry_result != "done":
                    print(f"[调度Agent] {agent} 重试仍未成功，跳过。")
                    _update_pipeline(task_id, step_completed=agent)
                    completed_steps.append(agent)
                    agent_output = _read_agent_output(agent)
                    if agent_output:
                        _update_pipeline(task_id, outputs_update={agent: agent_output})
                    continue
            else:
                print(f"[调度Agent] 跳过 {agent}（失败后跳过）。")
                _update_pipeline(task_id, step_completed=agent)
                completed_steps.append(agent)
                continue
        elif result == "skipped":
            # Agent 判定无需执行（如 recon 没发现 Web 端口，pentest 跳过）
            print(f"[调度Agent] {agent} 判定无需执行，跳过。")
            _update_pipeline(task_id, step_completed=agent)
            completed_steps.append(agent)
            continue
        elif result == "blocked":
            # Agent 报告阻塞 — 询问用户
            user_choice = _ask_blocked_action(agent)
            if user_choice == "abort":
                print("[调度Agent] 用户终止流水线。")
                _update_pipeline(task_id, status="halted")
                return None
            else:
                print(f"[调度Agent] 跳过 {agent}（遇阻跳过）。")
                _update_pipeline(task_id, step_completed=agent)
                completed_steps.append(agent)
                continue

        elif result is None:
            # 超时 — 询问用户
            print(f"[调度Agent] {agent} 超时 ({_AGENT_TIMEOUT_SECONDS}s)。")
            user_choice = _ask_blocked_action(agent)
            if user_choice == "abort":
                _update_pipeline(task_id, status="halted")
                return None
            else:
                print(f"[调度Agent] 跳过 {agent}（超时）。")
                _update_pipeline(task_id, step_completed=agent)
                completed_steps.append(agent)
                continue

        # --- 6e. 记录产出 ---
        agent_output = _read_agent_output(agent)
        print(f"  [调度Agent] [OK] {agent} 完成")
        if agent_output.get("outputs"):
            for item in agent_output["outputs"]:
                print(f"    产出: {item}")

        # 保存产出到 pipeline
        _update_pipeline(
            task_id,
            step_completed=agent,
            outputs_update={agent: agent_output},
        )
        completed_steps.append(agent)

    # ----------------------------------------------------------
    # 第7步：任务完成
    # ----------------------------------------------------------
    _update_pipeline(task_id, status="completed")

    # 尝试找到报告文件
    report_output = _read_agent_output("reporter")
    report_paths = report_output.get("outputs", [])

    print()
    print("=" * 60)
    print("  扫描完成！")
    print(f"  任务 ID: {task_id}")
    if report_paths:
        for p in report_paths:
            print(f"  报告: {p}")
    else:
        outputs_dir = os.path.join(_PROJECT_ROOT, "outputs", "reports")
        print(f"  报告目录: {outputs_dir}")
    print("=" * 60)

    return report_paths[0] if report_paths else None


# ============================================================
# 直接运行入口
# ============================================================
# python core/dispatcher.py 时执行

if __name__ == "__main__":
    # 如果你直接运行这个文件，就会进入交互模式
    print("=" * 60)
    print("  LynxSec 调度Agent — 白帽安全AI智能体")
    print("=" * 60)
    print()
    print("示例请求：")
    print('  "扫描 192.168.1.100，检查是否有Web漏洞"')
    print('  "帮我看看 example.com 的安全性"')
    print('  "对 10.0.0.1 做信息收集，不要攻击"')
    print()

    try:
        user_msg = input("请输入你的安全检测需求: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n再见。")
        sys.exit(0)

    if not user_msg:
        print("未输入任何内容。")
        sys.exit(0)

    result = run(user_msg)
    if result:
        print(f"\n最终报告: {result}")
    else:
        print("\n任务未完成。")
