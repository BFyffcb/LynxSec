"""tests/test_tools.py — _validate_args 参数白名单测试"""

from __future__ import annotations

import os
import sys

# 让测试能 import infra.tools
_PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT not in sys.path:
    sys.path.insert(0, _PROJECT)

from infra.tools import _validate_args


def _reset() -> None:
    """每个测试前重置环境变量."""
    os.environ.pop("LYNXSEC_ALLOW_DANGEROUS", None)


# ============================================================
# BLOCKED_FOREVER — 永久拦截（物理不可绕过）
# ============================================================

def test_nc_e_blocked() -> None:
    _reset()
    ok, reason = _validate_args("nc", ["-e", "/bin/sh", "target", "4444"])
    assert not ok, f"nc -e should be blocked: {reason}"

def test_nc_l_blocked() -> None:
    _reset()
    ok, reason = _validate_args("nc", ["-l", "-p", "4444"])
    assert not ok, f"nc -l should be blocked: {reason}"

def test_nc_c_blocked() -> None:
    _reset()
    ok, reason = _validate_args("nc", ["-c", "/bin/sh"])
    assert not ok, f"nc -c should be blocked: {reason}"


# ============================================================
# RESTRICTED — 受限参数（需 LYNXSEC_ALLOW_DANGEROUS=1）
# ============================================================

def test_sqlmap_osshell_blocked_no_auth() -> None:
    _reset()
    ok, reason = _validate_args("sqlmap", ["-u", "target", "--os-shell"])
    assert not ok, f"--os-shell without auth should be blocked: {reason}"

def test_sqlmap_sqlquery_blocked_no_auth() -> None:
    _reset()
    ok, reason = _validate_args("sqlmap", ["--sql-query", "SELECT 1"])
    assert not ok, f"--sql-query without auth should be blocked: {reason}"

def test_sqlmap_dumpall_blocked_no_auth() -> None:
    _reset()
    ok, reason = _validate_args("sqlmap", ["--dump-all"])
    assert not ok, f"--dump-all without auth should be blocked: {reason}"

def test_sqlmap_osshell_allowed_with_auth() -> None:
    _reset()
    os.environ["LYNXSEC_ALLOW_DANGEROUS"] = "1"
    ok, reason = _validate_args("sqlmap", ["-u", "target", "--os-shell"])
    assert ok, f"--os-shell with auth should be allowed: {reason}"

def test_sqlmap_filewrite_allowed_equals_syntax() -> None:
    """--file-write=path 带等号写法也应被正确处理."""
    _reset()
    os.environ["LYNXSEC_ALLOW_DANGEROUS"] = "1"
    ok, reason = _validate_args("sqlmap", ["--file-write=/tmp/x", "-u", "t"])
    assert ok, f"--file-write=path with auth should be allowed: {reason}"

def test_sqlmap_normal_allowed() -> None:
    _reset()
    ok, reason = _validate_args("sqlmap", ["--batch", "-u", "http://target"])
    assert ok, f"normal sqlmap should be allowed: {reason}"


# ============================================================
# 限流约束 — 防 DoS
# ============================================================

def test_hydra_t0_blocked() -> None:
    _reset()
    ok, reason = _validate_args("hydra", ["-t", "0", "target"])
    assert not ok, f"hydra -t 0 should be blocked: {reason}"

def test_hydra_t4_allowed() -> None:
    _reset()
    ok, reason = _validate_args("hydra", ["-t", "4", "target"])
    assert ok, f"hydra -t 4 should be allowed: {reason}"

def test_nuclei_rl5_blocked() -> None:
    _reset()
    ok, reason = _validate_args("nuclei", ["-rl", "5", "-u", "target"])
    assert not ok, f"nuclei -rl 5 should be blocked: {reason}"

def test_nuclei_rl50_allowed() -> None:
    _reset()
    ok, reason = _validate_args("nuclei", ["-rl", "50", "-u", "target"])
    assert ok, f"nuclei -rl 50 should be allowed: {reason}"


# ============================================================
# Nmap NSE 白名单
# ============================================================

def test_nmap_vulners_allowed() -> None:
    _reset()
    ok, reason = _validate_args("nmap", ["--script=vulners", "-p-", "target"])
    assert ok, f"nmap --script=vulners should be allowed: {reason}"

def test_nmap_vulners_space_allowed() -> None:
    """--script vulners 空格分隔也应生效."""
    _reset()
    ok, reason = _validate_args("nmap", ["--script", "vulners", "-p-", "target"])
    assert ok, f"nmap --script vulners should be allowed: {reason}"

def test_nmap_smb_blocked() -> None:
    _reset()
    ok, reason = _validate_args("nmap", ["--script=smb-vuln-ms17-010", "target"])
    assert not ok, f"nmap malicious script should be blocked: {reason}"


# ============================================================
# 缺口1修复 — 未知工具默认拒绝
# ============================================================

def test_unknown_tool_blocked() -> None:
    """不在工具注册表里的工具名应被拦截."""
    _reset()
    ok, reason = _validate_args("msfvenom", ["-p", "windows/shell_reverse_tcp"])
    assert not ok, f"unknown tool should be blocked: {reason}"

def test_unknown_tool_blocked_john() -> None:
    _reset()
    ok, reason = _validate_args("john", ["--wordlist=rockyou.txt", "hash.txt"])
    assert not ok, f"unknown tool john should be blocked: {reason}"


# ============================================================
# 快捷运行入口
# ============================================================


def test_gobuster_allowed() -> None:
    _reset()
    ok, reason = _validate_args("gobuster", ["dir", "-u", "http://localhost", "-w", "common.txt"])
    assert ok, f"gobuster should be allowed: {reason}"

def test_ffuf_allowed() -> None:
    _reset()
    ok, reason = _validate_args("ffuf", ["-u", "http://localhost/FUZZ", "-w", "wordlist.txt"])
    assert ok, f"ffuf should be allowed: {reason}"

def test_dalfox_allowed() -> None:
    _reset()
    ok, reason = _validate_args("dalfox", ["http://localhost"])
    assert ok, f"dalfox should be allowed: {reason}"

def test_testssl_allowed() -> None:
    _reset()
    ok, reason = _validate_args("testssl", ["localhost"])
    assert ok, f"testssl should be allowed: {reason}"

def test_whatweb_blocked() -> None:
    _reset()
    ok, reason = _validate_args("whatweb", ["localhost"])
    assert not ok, f"whatweb should be blocked as unknown tool: {reason}"

def test_ffuf_t0_blocked() -> None:
    _reset()
    ok, reason = _validate_args("ffuf", ["-u", "http://t/FUZZ", "-w", "w.txt", "-t", "0"])
    assert not ok, f"ffuf -t 0 should be blocked: {reason}"

def test_gobuster_t0_blocked() -> None:
    _reset()
    ok, reason = _validate_args("gobuster", ["dir", "-u", "http://t", "-w", "w.txt", "-t", "0"])
    assert not ok, f"gobuster -t 0 should be blocked: {reason}"

if __name__ == "__main__":
    import traceback
    passed = 0
    failed = 0
    tests = [
        ("nc -e blocked", test_nc_e_blocked),
        ("nc -l blocked", test_nc_l_blocked),
        ("nc -c blocked", test_nc_c_blocked),
        ("sqlmap --os-shell blocked (no auth)", test_sqlmap_osshell_blocked_no_auth),
        ("sqlmap --sql-query blocked (no auth)", test_sqlmap_sqlquery_blocked_no_auth),
        ("sqlmap --dump-all blocked (no auth)", test_sqlmap_dumpall_blocked_no_auth),
        ("sqlmap --os-shell allowed (auth)", test_sqlmap_osshell_allowed_with_auth),
        ("sqlmap --file-write=path allowed (auth)", test_sqlmap_filewrite_allowed_equals_syntax),
        ("sqlmap normal allowed", test_sqlmap_normal_allowed),
        ("hydra -t 0 blocked", test_hydra_t0_blocked),
        ("hydra -t 4 allowed", test_hydra_t4_allowed),
        ("nuclei -rl 5 blocked", test_nuclei_rl5_blocked),
        ("nuclei -rl 50 allowed", test_nuclei_rl50_allowed),
        ("nmap --script=vulners allowed", test_nmap_vulners_allowed),
        ("nmap --script vulners allowed", test_nmap_vulners_space_allowed),
        ("nmap SMB script blocked", test_nmap_smb_blocked),
        ("unknown tool msfvenom blocked", test_unknown_tool_blocked),
        ("unknown tool john blocked", test_unknown_tool_blocked_john),
        ("gobuster dir allowed", test_gobuster_allowed),
        ("ffuf fuzz allowed", test_ffuf_allowed),
        ("dalfox XSS allowed", test_dalfox_allowed),
        ("testssl audit allowed", test_testssl_allowed),
        ("whatweb removed blocked", test_whatweb_blocked),
        ("ffuf -t 0 blocked", test_ffuf_t0_blocked),
        ("gobuster -t 0 blocked", test_gobuster_t0_blocked),
    ]
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS: {name}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL: {name} — {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR: {name} — {e}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed}/{passed+failed} passed")
