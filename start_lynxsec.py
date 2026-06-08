#!/usr/bin/env python3
"""
start_lynxsec.py — LynxSec 一键启动脚本

职责：
  1. 启动前环境检查（config.env / 工具链 / DVWA）
  2. 清理旧状态文件，防止幽灵任务
  3. 并行启动 4 个后台 Agent 进程
  4. 进入交互模式 → dispatcher.run()

模式：
  python start_lynxsec.py             正常模式
  python start_lynxsec.py --dry-run   模拟模式（不调真实工具，用于流程测试）

三层对接：
  start_lynxsec.py → core/dispatcher.py → core/* → infra/*
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from glob import glob
from urllib.request import ProxyHandler, Request, build_opener, urlopen
from urllib.error import URLError

# ============================================================
# 配置
# ============================================================

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
_CORE_DIR = os.path.join(_PROJECT_ROOT, "core")
_STATE_DIR = os.path.join(_PROJECT_ROOT, "state")
_OUTPUTS_DIR = os.path.join(_PROJECT_ROOT, "outputs")
_DVWA_URL = "http://localhost:80"

# 需要启动的后台 Agent（dispatcher 是交互入口，不在此列）
_AGENTS: list[str] = ["recon", "pentest", "auditor", "reporter"]

# 必需的安全工具清单（名称 → 检查命令）
_REQUIRED_TOOLS: dict[str, list[str]] = {
    "nmap":      ["nmap", "--version"],
    "whatweb":   ["whatweb", "--version"],
    "subfinder": ["subfinder", "-version"],
    "sqlmap":    ["sqlmap", "--version"],
    "hydra":     ["hydra", "-h"],
}

# 启动时清理的目录/文件模式
_CLEAN_PATTERNS: list[str] = [
    os.path.join(_STATE_DIR, "*.json"),
    os.path.join(_OUTPUTS_DIR, "temp", "*"),
]


# ============================================================
# 第1步：检查 config.env
# ============================================================

def _check_config() -> bool:
    """检查 config.env 是否存在且包含必要配置。

    返回:
        True 表示配置完整，False 表示缺失。
    """
    config_path = os.path.join(_PROJECT_ROOT, "config.env")

    if not os.path.isfile(config_path):
        example_path = os.path.join(_PROJECT_ROOT, "config.env.example")
        print("[启动检查] ? 未找到 config.env 文件！")
        print(f"  请从 {example_path} 复制一份：")
        print(f"    cp {example_path} {config_path}")
        print(f"  然后编辑 {config_path} 填入你的 API Key")
        return False

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()
    except OSError as e:
        print(f"[启动检查] ? 无法读取 config.env: {e}")
        return False

    checks: dict[str, str] = {
        "LLM_BASE_URL": "LLM_BASE_URL=",
        "LLM_API_KEY":  "LLM_API_KEY=",
        "LLM_MODEL":    "LLM_MODEL=",
    }

    all_ok = True
    for name, prefix in checks.items():
        if prefix not in content:
            print(f"[启动检查] ? config.env 缺少 {name}")
            all_ok = False
        else:
            line_start = content.find(prefix)
            line_end = content.find("\n", line_start)
            if line_end == -1:
                line_end = len(content)
            value = content[line_start + len(prefix):line_end].strip()
            if not value or "your_" in value.lower() or "xxx" in value.lower():
                print(f"[启动检查] ? {name} 未填写（当前值: {value[:20]}...）")
                all_ok = False

    if all_ok:
        print(f"[启动检查] ? config.env 配置完整")
    return all_ok


# ============================================================
# 第2步：检查 DVWA
# ============================================================

def _check_dvwa() -> bool:
    """检查 DVWA 靶场是否可访问。"""
    print(f"[启动检查] 检测 DVWA ({_DVWA_URL}) ...", end=" ", flush=True)

    try:
        handler = ProxyHandler({})
        opener = build_opener(handler)
        with opener.open(_DVWA_URL, timeout=5) as response:
            print(f"? HTTP {response.status}")
            return True
    except URLError:
        print(f"? 无法连接")
        print(f"  请先启动 DVWA 靶场：")
        print(f"    cd 你的DVWA目录 && docker-compose up -d")
        return False


# ============================================================
# 第3步：检查安全工具链（预飞检查 preflight）
# ============================================================

def _check_tools() -> bool:
    """启动前检查必需的安全工具是否可用。

    工具通过 wsl 调用（匹配 infra/tools.py 的 WSL2 适配逻辑）。
    缺失工具只报 warning，不阻断启动——用户可能只想测流程。

    返回:
        True 表示全部工具可用，False 表示有缺失。
    """
    print("[启动检查] 检测安全工具链 ...")

    # 检测执行环境：WSL内还是Windows宿主
    is_wsl_inside = os.path.isfile("/proc/version")
    prefix = [] if is_wsl_inside else ["wsl"]

    missing: list[str] = []

    for tool_name, check_cmd in _REQUIRED_TOOLS.items():
        full_cmd = prefix + check_cmd
        try:
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0:
                # 取第一行输出作为版本信息
                version_line = (result.stdout or result.stderr or "").split("\n")[0].strip()
                print(f"  ? {tool_name}: {version_line[:60]}")
            else:
                print(f"  ? {tool_name}: 命令返回非零 (exit={result.returncode})")
                missing.append(tool_name)
        except FileNotFoundError:
            print(f"  ? {tool_name}: 未安装或不在 PATH 中")
            missing.append(tool_name)
        except subprocess.TimeoutExpired:
            print(f"  ? {tool_name}: 检查超时")
            missing.append(tool_name)

    if missing:
        print(f"\n  缺少/异常的工具 ({len(missing)}): {', '.join(missing)}")
        print(f"  这些工具在对应 Agent 执行时会失败，但不影响流程测试。")
        try:
            answer = input("  是否继续？ [Y/n]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        if answer in ("n", "no"):
            return False

    print(f"[启动检查] ? 工具链检查完成")
    return True


# ============================================================
# 第4步：清理旧状态文件
# ============================================================

def _clean_state() -> None:
    """启动时清理旧的运行时状态文件。

    如果不清理，上次运行的残留状态（如 *_status.json 中的 "working"、
    pipeline.json 中的 "running"）会导致：
      - 幽灵任务（Agent 看到旧 task_id 不执行新任务）
      - pipeline 恢复把已完成任务重新执行
      - status=working 导致 dispatcher 误判 Agent 正在忙

    清理范围：
      - state/*.json（命令、状态、授权、流水线）
      - outputs/temp/*（临时文件）
      不清理 outputs/reports/ 和 outputs/evidence/（历史产出有价值）
    """
    print("[启动检查] 清理旧状态文件 ...")

    cleaned_count = 0

    # 清理 state/ 下的 JSON 文件
    if os.path.isdir(_STATE_DIR):
        for filename in os.listdir(_STATE_DIR):
            if filename.endswith(".json"):
                if filename == "pipeline.json":
                    continue
                filepath = os.path.join(_STATE_DIR, filename)
                try:
                    os.remove(filepath)
                    cleaned_count += 1
                except OSError as e:
                    print(f"  Warning cannot delete {filepath}: {e}")

    # 清理 outputs/temp/
    temp_dir = os.path.join(_OUTPUTS_DIR, "temp")
    if os.path.isdir(temp_dir):
        for item in os.listdir(temp_dir):
            itempath = os.path.join(temp_dir, item)
            try:
                if os.path.isfile(itempath):
                    os.remove(itempath)
                elif os.path.isdir(itempath):
                    shutil.rmtree(itempath)
                cleaned_count += 1
            except OSError as e:
                print(f"  ? 无法删除 {itempath}: {e}")

    print(f"[启动检查] ? 已清理 {cleaned_count} 个旧文件")


# ============================================================
# 第5步：启动后台 Agent
# ============================================================

def _start_agent_process(agent_name: str, dry_run: bool) -> subprocess.Popen | None:
    """启动一个后台 Agent 进程。

    如果 dry_run=True，通过环境变量 LYNXSEC_DRY_RUN=1 告知 Agent
    使用模拟数据，不调用真实工具。

    参数:
        agent_name: Agent 文件名（不含 .py）
        dry_run:    是否为模拟模式

    返回:
        Popen 对象（成功时），None（失败时）。
    """
    agent_script = os.path.join(_CORE_DIR, f"{agent_name}.py")

    if not os.path.isfile(agent_script):
        print(f"  ? {agent_name}.py 不存在: {agent_script}")
        return None

    # 构建环境变量（继承当前环境 + dry-run 标记）
    env = os.environ.copy()
    if dry_run:
        env["LYNXSEC_DRY_RUN"] = "1"

    try:
        proc = subprocess.Popen(
            [sys.executable, agent_script],
            cwd=_PROJECT_ROOT,
            env=env,
        )
        mode_label = " [模拟模式]" if dry_run else ""
        print(f"  ? {agent_name} 已启动{mode_label} (PID={proc.pid})")
        return proc
    except OSError as e:
        print(f"  ? {agent_name} 启动失败: {e}")
        return None


def _start_all_agents(dry_run: bool) -> list[subprocess.Popen]:
    """并行启动所有后台 Agent。"""
    mode = "模拟模式" if dry_run else "正常模式"
    print(f"\n[启动检查] 启动后台 Agent ({mode}) ...")
    processes: list[subprocess.Popen] = []

    for agent in _AGENTS:
        proc = _start_agent_process(agent, dry_run)
        if proc is not None:
            processes.append(proc)
        time.sleep(0.5)

    print(f"[启动检查] {len(processes)}/{len(_AGENTS)} 个 Agent 已启动")
    return processes


# ============================================================
# 第6步：等待 Agent 就绪
# ============================================================

def _wait_agents_ready(timeout: int = 30) -> bool:
    """等待所有 Agent 写入初始 status.json。"""
    print("[启动检查] 等待 Agent 就绪 ...", end="", flush=True)

    expected = set(_AGENTS)
    ready: set[str] = set()
    elapsed: float = 0.0

    while elapsed < timeout:
        time.sleep(1.0)
        elapsed += 1.0

        for agent in expected - ready:
            status_path = os.path.join(_STATE_DIR, f"{agent}_status.json")
            if not os.path.isfile(status_path):
                continue
            try:
                with open(status_path, "r", encoding="utf-8") as f:
                    data = json.loads(f.read())
                if data.get("status") == "idle":
                    ready.add(agent)
            except (json.JSONDecodeError, OSError):
                continue

        if len(ready) == len(expected):
            print(" ? 全部就绪")
            return True

        print(".", end="", flush=True)

    print(f" 超时 ({timeout}s)")
    still_waiting = expected - ready
    print(f"  未就绪的 Agent: {', '.join(still_waiting)}")
    return False


# ============================================================
# 第7步：交互模式
# ============================================================

def _interactive_loop(dry_run: bool) -> None:
    """交互主循环。"""
    try:
        from core.dispatcher import run as dispatch  # type: ignore[import-untyped]
    except ImportError as e:
        print(f"? 无法导入 dispatcher: {e}")
        return

    mode_label = " [模拟模式 — 不调用真实工具]" if dry_run else ""
    print()
    print("=" * 60)
    print(f"  ?? LynxSec 已就绪 — 专精白帽安全的AI智能体{mode_label}")
    print("=" * 60)
    print()
    print("  输入你的安全检测需求，例如：")
    print('    "扫描 http://localhost:80，检查 Web 漏洞"')
    print('    "对 localhost 做安全检测"')
    print('    "帮我看一下 http://localhost:80 有没有 SQL 注入"')
    print()
    print("  输入 quit 退出")
    print()

    task_count = 0

    while True:
        try:
            user_input = input("LynxSec> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n再见。")
            break

        if not user_input:
            continue

        if user_input.lower() in ("quit", "exit", "q"):
            print("再见。")
            break

        task_count += 1
        print(f"\n[任务 #{task_count}] 正在处理...")
        print("-" * 40)

        try:
            result = dispatch(user_input)
        except Exception as e:
            print(f"[错误] dispatcher 执行异常: {e}")
            continue

        if result:
            print(f"\n[任务 #{task_count}] ? 完成")
            print(f"  报告路径: {result}")
        else:
            print(f"\n[任务 #{task_count}] ? 未完成（可能被取消或遇到错误）")

        print("-" * 40)


# ============================================================
# 清理
# ============================================================

def _cleanup(processes: list[subprocess.Popen]) -> None:
    """退出时停止所有后台 Agent 进程。

    TODO: v1.2 — 目前用 terminate() 杀进程，后续可改为
    向各 Agent 的 command.json 写入 {"action": "shutdown"} 优雅退出。
    """
    print("\n[清理] 正在停止后台 Agent ...")
    for proc in processes:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            print(f"  ? PID {proc.pid} 已停止")
    print("[清理] 完成")


# ============================================================
# 主入口
# ============================================================

def main() -> None:
    """启动脚本主流程。

    支持参数：
      --dry-run    模拟模式，Agent 不调用真实工具
    """
    dry_run = "--dry-run" in sys.argv

    print("=" * 60)
    print("  LynxSec 启动脚本")
    if dry_run:
        print("  模式: 模拟 (不调用真实工具)")
    print("=" * 60)

    # --- 1. 环境检查 ---
    if not _check_config():
        sys.exit(1)

    # --- 2. 工具链检查 ---
    if not dry_run:
        # 正常模式检查工具；模拟模式跳过（不需要真实工具）
        if not _check_tools():
            print("已取消。")
            sys.exit(0)
    else:
        print("[启动检查] 模拟模式 — 跳过工具链检查")

    # --- 3. DVWA 检查 ---
    if not _check_dvwa():
        print()
        print("提示：如果你暂时没有 DVWA 环境，可以继续启动，")
        print("但扫描 http://localhost:80 时会失败。")
        try:
            answer = input("是否继续？ [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        if answer != "y":
            print("已取消。")
            sys.exit(0)

    # --- 4. 清理旧状态 ---
    _clean_state()

    # --- 5. 确保 state/ 目录存在 ---
    os.makedirs(_STATE_DIR, exist_ok=True)

    # --- 6. 设置 dry-run 环境变量（子进程继承） ---
    if dry_run:
        os.environ["LYNXSEC_DRY_RUN"] = "1"

    # --- 7. 启动后台 Agent ---
    processes = _start_all_agents(dry_run)
    if not processes:
        print("? 没有任何 Agent 成功启动，无法继续。")
        sys.exit(1)

    # --- 8. 等待就绪 ---
    all_ready = _wait_agents_ready(timeout=30)
    if not all_ready:
        print()
        print("=" * 60)
        print("  [WARN] 部分 Agent 未能就绪！")
        print("  未启动的 Agent 将无法接收任务，可能导致流水线中断。")
        print("=" * 60)
        try:
            answer = input("  是否继续启动？ [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        if answer not in ("y", "yes"):
            print("已取消。")
            _cleanup(processes)
            sys.exit(1)
        print("  继续（部分 Agent 不可用）...")

    # --- 9. 交互模式 ---
    try:
        _interactive_loop(dry_run)
    finally:
        _cleanup(processes)


if __name__ == "__main__":
    main()
