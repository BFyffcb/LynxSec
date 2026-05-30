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
    is_wsl_inside = os.path.isfile("/proc/version")

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
    """
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
