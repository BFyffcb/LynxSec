"""infra/tool_checker.py — 工具可用性预检系统

启动时扫描所有已注册工具的 PATH + fallback 路径可用性，
写入 state/tools_available.json。每个 Agent 在规划阶段读取此文件，
从 LLM prompt 中动态排除不可用工具。

企业级设计：工具缺失不影响链路，自动降级。
"""

from __future__ import annotations

import json
import os
import subprocess


# ============================================================
# 工具注册表 — 唯一真相来源
# ============================================================

AGENT_TOOLS: dict[str, list[dict]] = {
    "recon": [
        {"name": "nmap",      "check_cmd": "nmap --version",      "desc": "端口扫描 / 服务版本检测"},
        {"name": "subfinder", "check_cmd": "subfinder -version",  "desc": "子域名发现", "fallback_paths": ["/root/go/bin/subfinder"]},
    ],
    "pentest": [
        {"name": "sqlmap",    "check_cmd": "sqlmap --version",    "desc": "SQL 注入自动检测与验证"},
        {"name": "nuclei",    "check_cmd": "nuclei -version",     "desc": "Web 漏洞模板扫描", "fallback_paths": ["/root/go/bin/nuclei"]},
        {"name": "hydra",     "check_cmd": "hydra -h",            "desc": "弱口令爆破"},
    ],
}


def _check_tool_in_wsl(name: str, check_cmd: str, fallback_paths: list[str] | None = None) -> bool:
    """在 WSL 中执行 check_cmd，返回工具是否可用。

    Go 工具安装在 /root/go/bin，wsl -u root 不会 source bashrc，
    所以需要检查 fallback_paths。
    """
    is_wsl_inside = os.path.isfile("/proc/version")
    if is_wsl_inside:
        try:
            result = subprocess.run(check_cmd.split(), capture_output=True, timeout=10)
            if result.returncode == 0:
                return True
        except Exception:
            pass
        if fallback_paths:
            for fp in fallback_paths:
                if os.path.isfile(fp):
                    return True
        return False
    else:
        try:
            result = subprocess.run(
                ["wsl", "-u", "root"] + check_cmd.split(),
                capture_output=True, timeout=15,
            )
            if result.returncode == 0:
                return True
        except Exception:
            pass
        if fallback_paths:
            for fp in fallback_paths:
                try:
                    r = subprocess.run(
                        ["wsl", "-u", "root", "test", "-x", fp],
                        capture_output=True, timeout=5,
                    )
                    if r.returncode == 0:
                        return True
                except Exception:
                    pass
        return False


def scan_all_tools(project_root: str) -> dict:
    """扫描所有注册工具的可用性，写入 state/tools_available.json。

    返回:
        {"recon": {"nmap": True, ...}, "pentest": {...}, "checked_at": "..."}
    """
    from datetime import datetime, timezone, timedelta

    result: dict = {}
    for agent, tools in AGENT_TOOLS.items():
        result[agent] = {}
        for tool in tools:
            name = tool["name"]
            available = _check_tool_in_wsl(name, tool["check_cmd"], tool.get("fallback_paths"))
            result[agent][name] = available
            status = "[green]OK[/green]" if available else "[red]MISSING[/red]"
            print(f"  [{agent}] {name:12s} ... {status}")

    result["checked_at"] = datetime.now(timezone(timedelta(hours=8))).isoformat()

    state_dir = os.path.join(project_root, "state")
    os.makedirs(state_dir, exist_ok=True)
    tools_path = os.path.join(state_dir, "tools_available.json")
    with open(tools_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    return result


def get_available_tools(project_root: str, agent: str) -> list[str]:
    """读取缓存的工具可用性，返回可用工具名列表。"""
    tools_path = os.path.join(project_root, "state", "tools_available.json")
    if not os.path.isfile(tools_path):
        data = scan_all_tools(project_root)
    else:
        with open(tools_path, "r", encoding="utf-8") as f:
            data = json.loads(f.read())
    agent_tools = data.get(agent, {})
    return [name for name, available in agent_tools.items() if available]
