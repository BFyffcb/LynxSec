"""
core/auditor.py — LynxSec 审计Agent

职责：
  1. 轮询 state/audit_command.json，等待 dispatcher 下发任务
  2. 读取上游产出（recon + pentest 的 analysis.json）
  3. 用 LLM 进行：误报过滤、攻击链串联、CVSS 评分、影响评估
  4. 无权调用任何外部工具（纯推理分析）
  5. 写入 state/audit_status.json

这是流水线中唯一不接触工具层（infra/tools.py）的 Agent。
所有分析由 LLM 推理完成。

依赖链：core/auditor.py → infra/llm.py
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
from infra.skills.loader import build_prompt  # type: ignore[import-untyped]

# ============================================================
# 常量
# ============================================================

_STATE_DIR = os.path.join(_PROJECT_ROOT, "state")
_AGENT_NAME = "auditor"
_POLL_INTERVAL_SECONDS: float = 2.0
_CST = timezone(timedelta(hours=8))
_OUTPUTS_DIR = os.path.join(_PROJECT_ROOT, "outputs", "evidence")


def _now_iso() -> str:
    return datetime.now(_CST).isoformat()


def _read_json(filepath: str) -> dict | None:
    if not os.path.isfile(filepath):
        return None
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        if content.startswith("\ufeff"):
            content = content[1:]
        return json.loads(content)
    except (json.JSONDecodeError, OSError) as e:
        print(f"[LOG] 读取 JSON 失败: {filepath} — {e}")
        return None


def _write_json(filepath: str, data: dict) -> bool:
    tmp_path = filepath + ".tmp" + str(os.getpid())
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, filepath)
        return True
    except OSError as e:
        print(f"[LOG] 写入 JSON 失败: {filepath} — {e}")
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return False


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
    print(f"[审计Agent] 已就绪，等待调度指令...")


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
# 收集上游产出
# ============================================================

def _collect_upstream_outputs() -> dict:
    """从 state/ 和 outputs/evidence/ 目录收集上游 Agent 的产出。

    读取：
      - recon_status.json 中的 outputs 路径
      - pentest_status.json 中的 outputs 路径
      - 对应的 *_analysis.json 文件内容

    返回:
        包含上游所有分析结果的字典。
    """
    upstream: dict = {"recon": None, "pentest": None}

    # 尝试读取 recon 产出
    recon_status = _read_json(os.path.join(_STATE_DIR, "recon_status.json"))
    if recon_status:
        recon_outputs = recon_status.get("outputs", [])
        # 找 *_analysis.json
        for p in recon_outputs:
            if p.endswith("_analysis.json") and os.path.isfile(p):
                upstream["recon"] = _read_json(p)
                break

    # 尝试读取 pentest 产出
    pentest_status = _read_json(os.path.join(_STATE_DIR, "pentest_status.json"))
    if pentest_status:
        pentest_outputs = pentest_status.get("outputs", [])
        for p in pentest_outputs:
            if p.endswith("_analysis.json") and os.path.isfile(p):
                upstream["pentest"] = _read_json(p)
                break

    return upstream


# ============================================================
# 审计分析（LLM 驱动）
# ============================================================

_SYSTEM_PROMPT_AUDIT = """你是 LynxSec 的资深安全审计专家。

你会收到：
  - 情报Agent 的侦察结果（开放端口、服务版本、子域名）
  - 渗透Agent 的漏洞发现（SQLi、XSS、弱口令等）

请进行以下分析，输出 JSON：

1. 误报过滤：逐条检查每个漏洞，判断是否为误报
2. 影响评估：对每个确认漏洞评估影响范围（单系统/局域网/全网）
3. 攻击链串联：把多个漏洞串联起来，看攻击者能否组合利用扩大危害
4. CVSS 3.1 评分：对每个确认漏洞给出 CVSS 向量和分数

输出 JSON 格式：
{
  "confirmed_vulnerabilities": [
    {
      "type": "SQL Injection",
      "cve": "N/A 或 CVE-XXXX-XXXXX",
      "cvss_score": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "severity": "critical",
      "description": "登录接口存在SQL注入，无需认证即可利用",
      "impact": "数据库完全泄露，可能波及所有用户数据",
      "remediation": "使用参数化查询替代字符串拼接"
    }
  ],
  "false_positives": [
    {"finding": "xxx", "reason": "误报原因"}
  ],
  "attack_chains": [
    {
      "name": "攻击链名称",
      "steps": ["步骤1", "步骤2"],
      "total_impact": "组合后的总体影响评估"
    }
  ],
  "risk_summary": "整体风险评估：2个critical + 1个medium，建议立即修复",
  "recommendations": ["优先修复SQL注入", "启用HTTP安全头"]
}

只返回 JSON。"""


def _audit(llm: LLM, upstream: dict, command: dict) -> dict:
    """LLM 驱动的审计分析。"""
    context_parts: list[str] = [
        f"任务目标: {command.get('target', '未知')}",
        "",
        "=== 情报Agent 侦察结果 ===",
        json.dumps(upstream.get("recon"), ensure_ascii=False, indent=2) if upstream.get("recon") else "（无侦察数据）",
        "",
        "=== 渗透Agent 漏洞发现 ===",
        json.dumps(upstream.get("pentest"), ensure_ascii=False, indent=2) if upstream.get("pentest") else "（无渗透数据）",
    ]
    context = "\n".join(context_parts)

    print("[审计Agent] 正在分析漏洞、过滤误报、评估影响...")
    raw_reply = llm.chat(build_prompt(_SYSTEM_PROMPT_AUDIT), context)

    cleaned = raw_reply.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        cleaned = "\n".join(lines[1:])
        if cleaned.endswith("```"):
            cleaned = cleaned[:-3].strip()

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        print("[LOG] LLM 审计解析失败")
        return {
            "confirmed_vulnerabilities": [],
            "false_positives": [],
            "attack_chains": [],
            "risk_summary": "审计分析失败（LLM 输出解析错误）",
            "recommendations": ["请手动查看原始扫描结果"],
        }


# ============================================================
# 单次任务
# ============================================================

def run_once(command: dict) -> str:
    task_id: str = command.get("task_id", "unknown")
    target: str = command.get("target", "")

    print(f"\n{'=' * 60}")
    print(f"[审计Agent] 收到任务: {task_id}")
    print(f"  目标: {target}")
    print(f"{'=' * 60}")

    _write_working_status(task_id)

    # --- dry-run 模拟模式 ---
    if os.getenv("LYNXSEC_DRY_RUN") == "1":
        print("[审计Agent] 模拟模式 — 返回预设审计数据")
        mock_audit = {
            "confirmed_vulnerabilities": [
                {
                    "type": "SQL Injection",
                    "cve": "N/A",
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "severity": "critical",
                    "description": "登录接口存在 SQL 注入，无需认证即可利用",
                    "impact": "数据库完全泄露，可能波及所有用户数据",
                    "remediation": "使用参数化查询替代字符串拼接",
                }
            ],
            "false_positives": [],
            "attack_chains": [
                {
                    "name": "SQLi 数据泄露链",
                    "steps": ["SQL注入获取数据库凭据", "读取敏感表", "凭据可用于横向移动"],
                    "total_impact": "单个 SQLi 可导致数据库完全泄露",
                }
            ],
            "risk_summary": "整体风险评估：1 个 critical 漏洞，建议立即修复",
            "recommendations": ["立即修复 SQL 注入漏洞，使用参数化查询"],
        }
        os.makedirs(_OUTPUTS_DIR, exist_ok=True)
        safe_t = task_id.replace("/", "_").replace("\\", "_")
        audit_path = os.path.join(_OUTPUTS_DIR, f"{safe_t}_audit.json")
        _write_json(audit_path, mock_audit)
        _write_done_status(task_id, [audit_path], "success", code=0)
        return "success"

    try:
        llm = LLM()
    except RuntimeError as e:
        print(f"[审计Agent] LLM 初始化失败: {e}")
        _write_done_status(task_id, [], "failed", code=1)
        return "failed"

    # 收集上游产出
    upstream = _collect_upstream_outputs()

    # LLM 审计
    audit_result = _audit(llm, upstream, command)

    # 保存审计结果
    os.makedirs(_OUTPUTS_DIR, exist_ok=True)
    safe_task = task_id.replace("/", "_").replace("\\", "_")
    audit_path = os.path.join(_OUTPUTS_DIR, f"{safe_task}_audit.json")
    _write_json(audit_path, audit_result)

    confirmed = audit_result.get("confirmed_vulnerabilities", [])
    vuln_count = len(confirmed)
    print(f"[审计Agent] 审计完成：{vuln_count} 个确认漏洞，"
          f"{len(audit_result.get('false_positives', []))} 个误报")

    for v in confirmed:
        print(f"  - {v.get('type')}: CVSS {v.get('cvss_score', '?')} ({v.get('severity')})")

    _write_done_status(task_id, [audit_path], "success", code=0)

    print(f"[审计Agent] 任务完成")
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

        current_task_id: str | None = command_data.get("task_id")
        if current_task_id is not None and current_task_id == last_seen_task_id:
            time.sleep(_POLL_INTERVAL_SECONDS)
            continue

        if current_task_id is not None:
            print(f"\n[审计Agent] 发现新任务: {current_task_id}")
            result = run_once(command_data)
            last_seen_task_id = current_task_id
            print(f"[审计Agent] {result}，等待下一个任务...")

        time.sleep(_POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    print("=" * 60)
    print("  LynxSec 审计Agent — 误报过滤与CVSS评分")
    print("=" * 60)
    print("  按 Ctrl+C 停止\n")
    try:
        poll_loop()
    except KeyboardInterrupt:
        _write_done_status("shutdown", [], "failed", code=1)
        print("\n[auditor] 已退出。")
