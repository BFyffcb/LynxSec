"""infra/tool_checker.py - batch tool scan at startup."""

import json, os, subprocess
from datetime import datetime, timezone, timedelta

_CST = timezone(timedelta(hours=8))

AGENT_TOOLS = {
    "recon": [
        {"name": "nmap", "check": "command -v nmap"},
        {"name": "subfinder", "check": "test -x /root/go/bin/subfinder || test -x /usr/local/bin/subfinder || command -v subfinder"},
        {"name": "gobuster", "check": "test -x /usr/local/bin/gobuster || command -v gobuster"},
    ],
    "pentest": [
        {"name": "sqlmap", "check": "command -v sqlmap"},
        {"name": "nuclei", "check": "test -x /root/go/bin/nuclei || test -x /usr/local/bin/nuclei || command -v nuclei"},
        {"name": "hydra", "check": "test -x /usr/bin/hydra"},
        {"name": "ffuf", "check": "test -x /usr/local/bin/ffuf || command -v ffuf"},
        {"name": "dalfox", "check": "test -x /usr/local/bin/dalfox || command -v dalfox"},
        {"name": "testssl", "check": "test -x /usr/local/bin/testssl || command -v testssl"},
    ],
}

def scan_all_tools(project_root):
    lines = []
    for agent, tools in AGENT_TOOLS.items():
        for t in tools:
            lines.append(f'echo "{agent}:{t["name"]}:$({t["check"]} >/dev/null 2>&1 && echo OK || echo MISSING)"')
    script = "; ".join(lines)

    is_wsl = os.path.isfile("/proc/version")
    try:
        if is_wsl:
            r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30)
        else:
            r = subprocess.run(["wsl", "-u", "root", "bash", "-c", script], capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return _all_timeout()

    parsed = {}
    for line in r.stdout.strip().split("\n"):
        if ":" not in line: continue
        a, n, s = line.split(":", 2)
        parsed.setdefault(a, {})[n] = (s.strip() == "OK")

    for agent, tools in AGENT_TOOLS.items():
        parsed.setdefault(agent, {})
        for t in tools:
            n = t["name"]
            ok = parsed[agent].get(n, False)
            print(f"  [{agent}] {n:12s} ... {'OK' if ok else 'MISSING'}")

    parsed["checked_at"] = datetime.now(_CST).isoformat()
    d = os.path.join(project_root, "state")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "tools_available.json"), "w") as f:
        json.dump(parsed, f, ensure_ascii=False, indent=2)
    return parsed

def _all_timeout():
    parsed = {}
    for agent, tools in AGENT_TOOLS.items():
        parsed[agent] = {t["name"]: False for t in tools}
        for t in tools:
            print(f"  [{agent}] {t['name']:12s} ... TIMEOUT")
    parsed["checked_at"] = datetime.now(_CST).isoformat()
    return parsed

def get_available_tools(project_root, agent):
    p = os.path.join(project_root, "state", "tools_available.json")
    if not os.path.isfile(p):
        data = scan_all_tools(project_root)
    else:
        with open(p) as f:
            data = json.load(f)
    return [n for n, ok in data.get(agent, {}).items() if ok]
