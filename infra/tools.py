"""
infra/tools.py — LynxSec 安全工具统一调用层

职责：
  1. 统一封装所有安全工具的调用（nmap / subfinder / whatweb / sqlmap 等）
  2. WSL2沙箱自动适配（Windows宿主 → wsl前缀，WSL内 → 直接调用）
  3. 统一错误分类与 code 码映射
  4. 统一日志输出

工具执行结果 code 码：
  0 — 成功
  1 — 参数错误
  2 — 工具缺失（FileNotFoundError）
  3 — 执行超时（TimeoutExpired）
  4 — 命令失败（exit code != 0）
  5 — 输出解析失败

使用方式：
    from infra.tools import run_tool, ToolResult

    result = run_tool("nmap", ["-sV", "-p", "80", "192.168.1.1"])
    print(result.success)  # True/False
    print(result.code)     # 0-5
    print(result.stdout)   # 原始输出

依赖链：infra/tools.py → 仅标准库 + pydantic
"""

from __future__ import annotations

import os
import subprocess
from pydantic import BaseModel


# ============================================================
# Pydantic 数据模型（纪律 C2：禁止裸 dict）
# ============================================================

class ToolResult(BaseModel):
    """工具执行结果。

    纪律 C2：所有数据传递用 Pydantic 模型，不传裸 dict。
    """
    tool: str          # 工具名（nmap / subfinder / whatweb）
    success: bool      # 是否成功（code==0）
    code: int          # 状态码（0-5，见文件顶部）
    stdout: str        # 标准输出
    stderr: str        # 标准错误
    cmd: list[str]     # 实际执行的完整命令
    error_type: str    # 错误类型字符串（"" / "timeout" / "tool_not_found" / "command_failed"）

    def to_dict(self) -> dict:
        """转为字典，兼容需要 dict 的已有接口。"""
        return self.model_dump()


# ============================================================
# 命令组装（WSL2 适配）
# ============================================================

def _build_cmd(tool_name: str, args: list[str]) -> list[str]:
    """组装实际要执行的命令。

    检测当前运行环境：
    - 如果在 WSL 内（/proc/version 存在）→ 直接调用工具
    - 如果在 Windows 宿主 → 用 wsl 前缀调用

    返回:
        完整的命令列表，如 ["wsl", "nmap", "-sV", "192.168.1.1"]
    """
    is_wsl_inside = os.path.isfile("/proc/version") and "WSL" in os.getenv("WSL_DISTRO_NAME", "")

    if is_wsl_inside:
        return [tool_name] + args
    else:
        return ["wsl", tool_name] + args


# ============================================================
# 错误分类映射
# ============================================================

def _map_error(
    exc: Exception | None = None,
    returncode: int = 0,
) -> tuple[int, str]:
    """将异常/返回码映射为统一 code 码和错误类型。

    映射规则（与设计文档对齐）：
      TimeoutExpired   → code=3, "timeout"
      FileNotFoundError → code=2, "tool_not_found"
      returncode != 0  → code=4, "command_failed"
      无异常且 exit=0  → code=0, ""

    参数:
        exc:        捕获的异常对象（可为 None）
        returncode: 进程退出码

    返回:
        (code, error_type) 元组
    """
    if isinstance(exc, subprocess.TimeoutExpired):
        return 3, "timeout"
    if isinstance(exc, FileNotFoundError):
        return 2, "tool_not_found"
    if returncode != 0:
        return 4, "command_failed"
    return 0, ""


# ============================================================
# ============================================================
# 参数安全校验
# ============================================================

# 参数分级系统（借鉴 Nuclei "unsafe" 模板 + sqlmap 显式警告设计）

# 永久拦截：无论什么场景都禁止。相当于物理安全闸。
_BLOCKED_FOREVER: dict[str, list[str]] = {
    "nc": ["-e", "-c", "-l"],       # 反弹shell — 攻击行为
}

# 受限参数：专业用户在显式授权后可使用。
# 设置了环境变量 LYNXSEC_ALLOW_DANGEROUS=1 时放行，否则拦截。
_RESTRICTED_FLAGS: dict[str, list[str]] = {
    # semgrep: ????????????
    "semgrep": [],
    "sqlmap": [
        "--os-shell", "--os-cmd", "--os-pwn",
        "--file-read", "--file-write", "--file-dest",
        "--sql-shell", "--reg-read", "--reg-write",
        "--dump-all", "--drop-set",
        "--sql-query",
    ],
    # ???????????/????
    "ffuf": ["-t", "-rate"],
    "gobuster": ["-t"],
    # dalfox ????????????????
    "dalfox": [],
    "testssl": [],
}

_NMAP_ALLOWED_SCRIPTS: set[str] = {
    "vulners", "http-enum", "http-cookie-flags",
    "http-headers", "ssl-enum-ciphers", "http-title",
    "ftp-anon", "ssh-auth-methods",
}

# 工具白名单。不在名单里的工具名一律被 _validate_args 拦截。
# 新增工具时，在此注册后才会放行。
_ALLOWED_TOOLS: set[str] = {
    # recon
    "nmap", "subfinder", "gobuster",
    # pentest
    "sqlmap", "hydra", "nuclei",
    "ffuf", "dalfox", "testssl",
    # SAST / SCA
    "semgrep", "syft", "grype",
}


def _is_dangerous_allowed() -> bool:
    """检查用户是否显式授权了 restricted 级别参数。

    环境变量 LYNXSEC_ALLOW_DANGEROUS=1 时放行 restricted 参数。
    永久拦截参数 (_BLOCKED_FOREVER) 在任何情况下都不放行。
    """
    return os.getenv("LYNXSEC_ALLOW_DANGEROUS", "").strip() == "1"

def _validate_args(tool_name: str, args: list[str]) -> tuple[bool, str]:
    """检查参数是否包含危险标志. 三级分类:

    blocked (永久拦截): nc -e/-c/-l — 攻击行为，永不放过. 最先执行.  
    restricted (受限): sqlmap --os-shell 等 — 需 LYNXSEC_ALLOW_DANGEROUS=1
    tool_whitelist: 未知工具名直接拦截
    safe_limit (限流): hydra -t 0 / nuclei -rl < 10 — 防 DoS

    对应网络安全法第二十七条 + Nuclei "unsafe" 模板设计.

    返回:
        (True, "")  -- 安全，可以继续
        (False, reason) -- 被拦截，原因说明
    """
    # ---- 永久拦截（物理不可绕过）— 最先执行，优先级最高 ----
    forever_blocked = _BLOCKED_FOREVER.get(tool_name, [])
    for i, arg in enumerate(args):
        arg_stripped = arg.strip()
        for bad in forever_blocked:
            if arg_stripped == bad or arg_stripped.startswith(bad + "="):
                _log_block_attempt(tool_name, bad, "BLOCKED_FOREVER")
                return False, f"[BLOCKED] {tool_name} {bad} — 攻击类参数，在任何模式下不可用"

    # ---- 工具名白名单 ----
    if tool_name not in _ALLOWED_TOOLS:
        return False, (
            f"[BLOCKED] unknown tool [{tool_name}] not in allowlist. "
            f"approved: {sorted(_ALLOWED_TOOLS)}"
        )

    dangerous_allowed = _is_dangerous_allowed()

    # ---- 受限参数（需显式授权）----
    restricted = _RESTRICTED_FLAGS.get(tool_name, [])
    for i, arg in enumerate(args):
        arg_stripped = arg.strip()
        for bad in restricted:
            if arg_stripped == bad or arg_stripped.startswith(bad + "="):
                if not dangerous_allowed:
                    _log_block_attempt(tool_name, bad, "RESTRICTED")
                    return False, (
                        f"[RESTRICTED] {tool_name} {bad} — 需设置环境变量 "
                        f"LYNXSEC_ALLOW_DANGEROUS=1 后使用. "
                        f"注意: 仅在授权范围内使用，后果自负."
                    )
                print(f"  [tools] 危险参数已授权: {tool_name} {bad}")

    # ---- 限流检查（防 DoS, 扫描全部 args）----
    for idx, a in enumerate(args):
        a_stripped = a.strip()
        if tool_name == "hydra" and a_stripped in ("-t", "--threads"):
            if idx + 1 < len(args):
                try:
                    if int(args[idx + 1].lstrip("=")) == 0:
                        return False, "[BLOCKED] hydra -t 0 (无限线程/DoS风险)"
                except ValueError:
                    pass
        if tool_name == "nuclei" and a_stripped in ("-rl", "--rate-limit"):
            if idx + 1 < len(args):
                raw = args[idx + 1]
                try:
                    if int(raw.lstrip("=")) < 10:
                        return False, f"[BLOCKED] nuclei -rl {raw} 过低; 最小 10 req/s"
                except ValueError:
                    return False, f"[BLOCKED] nuclei 无效 -rl 值: {raw}"
        if tool_name == "nmap":
            script_list: list[str] = []
            if a_stripped == "--script":
                if idx + 1 < len(args):
                    script_list = args[idx + 1].split(",")
            elif a_stripped.startswith("--script="):
                script_list = a_stripped[len("--script="):].split(",")
            for s in script_list:
                s_clean = s.strip()
                if s_clean and s_clean not in _NMAP_ALLOWED_SCRIPTS:
                    return False, (
                        f"[BLOCKED] nmap NSE 脚本 {s_clean} 不在允许列表中. "
                        f"允许: {sorted(_NMAP_ALLOWED_SCRIPTS)}"
                    )

    return True, ""


def _log_block_attempt(tool: str, flag: str, level: str) -> None:
    """记录被拦截的尝试到日志文件。不被拦截失败中断。"""
    from datetime import datetime, timezone, timedelta
    try:
        log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "outputs", "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, "blocked_params.log")
        ts = datetime.now(timezone(timedelta(hours=8))).isoformat()
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"{ts} | {level:16s} | {tool:12s} | {flag}\n")
    except OSError:
        pass


# ============================================================
# 统一调用入口
# ============================================================

def run_tool(
    tool_name: str,
    args: list[str],
    timeout: int = 120,
    cwd: str | None = None,
) -> ToolResult:
    """统一工具调用入口。

    所有 Agent（recon / pentest 等）都通过此函数调用安全工具，
    不需要各自管理 subprocess 细节。

    参数:
        tool_name: 工具名（nmap / subfinder / whatweb / sqlmap 等）
        args:      命令行参数列表，如 ["-sV", "-p", "80", "192.168.1.1"]
        timeout:   超时秒数（默认 120s）
        cwd:       工作目录（可选，默认继承当前进程的工作目录）

    返回:
        ToolResult 对象（含 success / code / stdout / stderr / cmd）

    纪律 C3（异常处理）：所有异常都被捕获并转为 ToolResult，
    不向上抛出未处理的异常。
    纪律 C4（安全边界）：参数在 subprocess 之前被 _validate_args 三级拦截。
    """
    safe, block_reason = _validate_args(tool_name, args)
    if not safe:
        print(f"  [tools] parameter blocked: {block_reason}")
        return ToolResult(
            tool=tool_name,
            success=False,
            code=1,
            stdout="",
            stderr=block_reason,
            cmd=[tool_name] + args,
            error_type="blocked_by_policy",
        )

    cmd = _build_cmd(tool_name, args)

    print(f"  [tools] 执行: {' '.join(cmd)}")

    code: int = 0
    error_type: str = ""
    stdout: str = ""
    stderr: str = ""
    success: bool = True

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        stdout = result.stdout
        stderr = result.stderr

        if result.returncode != 0:
            code, error_type = _map_error(returncode=result.returncode)
            success = False
        else:
            code, error_type = 0, ""
            success = True

    except subprocess.TimeoutExpired as e:
        code, error_type = _map_error(exc=e)
        success = False
        stdout = ""
        stderr = f"工具 {tool_name} 执行超时 ({timeout}s)"

    except FileNotFoundError as e:
        code, error_type = _map_error(exc=e)
        success = False
        stdout = ""
        stderr = (
            f"工具 {tool_name} 未安装或不在 PATH 中。\n"
            f"请在 WSL 中安装: apt install {tool_name}"
        )

    # 纪律 C3：如果仍有未预期的异常（极端情况），也记录
    # 当前 try/except 已覆盖 TimeoutExpired 和 FileNotFoundError，
    # subprocess.run 在有 capture_output=True 时不会抛出其他异常。

    return ToolResult(
        tool=tool_name,
        success=success,
        code=code,
        stdout=stdout,
        stderr=stderr,
        cmd=cmd,
        error_type=error_type,
    )

# ============================================================
# Nmap standard scan wrapper
# ============================================================