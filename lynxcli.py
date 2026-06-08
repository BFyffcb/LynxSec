"""cli.py -- LynxSec CLI. Claude Code style + Rich terminal."""

from __future__ import annotations
import json, os, subprocess, sys, time
from urllib.request import Request, urlopen
from urllib.error import URLError
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
CORE = os.path.join(ROOT, "core")
STATE = os.path.join(ROOT, "state")
DVWA = "http://localhost:80"
AGENTS = ["recon", "pentest", "auditor", "reporter"]
COLORS = {"recon":"green","pentest":"red","auditor":"blue","reporter":"yellow","dispatcher":"cyan"}
TAGS = {"recon":"[渚﹀療]","pentest":"[娓楅€廬","auditor":"[瀹¤]","reporter":"[鎶ュ憡]","dispatcher":"[璋冨害]"}

def tag(a):
    c = COLORS.get(a,"white"); t = TAGS.get(a,a)
    return f"[{c}]{t}[/{c}]"

def check_config():
    p = os.path.join(ROOT, "config.env")
    if not os.path.isfile(p): return False
    with open(p, encoding="utf-8") as f:
        return "LLM_API_KEY=" in f.read() and "your_" not in f.read()

def check_dvwa():
    """Check if DVWA is reachable, bypassing system proxy for localhost."""
    try:
        import urllib.request
        handler = urllib.request.ProxyHandler({})
        opener = urllib.request.build_opener(handler)
        with opener.open(DVWA, timeout=5) as r2:
            return r2.status in (200, 302, 403)
    except Exception:
        return False

def _auto_start_dvwa():
    """Try to start Docker + DVWA container inside WSL."""
    import subprocess as _sp
    try:
        _sp.run(["wsl", "-u", "root", "service", "docker", "start"],
                capture_output=True, timeout=10)
        _sp.run(["wsl", "-u", "root", "docker", "start", "dvwa"],
                capture_output=True, timeout=15)
        return check_dvwa()
    except Exception:
        return False

def ensure_dvwa():
    """Check DVWA, auto-recover if possible."""
    if check_dvwa():
        return True
    console.print("[yellow]DVWA offline. Trying auto-recovery...[/yellow]")
    if _auto_start_dvwa():
        console.print("[green]DVWA recovered![/green]")
        return True
    return False

def clean_state():
    if os.path.isdir(STATE):
        for fn in os.listdir(STATE):
            if fn.endswith(".json") and fn != "pipeline.json":
                try: os.remove(os.path.join(STATE, fn))
                except OSError: pass

def start_agents(dry):
    env = os.environ.copy()
    if dry: env["LYNXSEC_DRY_RUN"] = "1"
    procs = []
    for a in AGENTS:
        s = os.path.join(CORE, f"{a}.py")
        if os.path.isfile(s):
            try:
                p = subprocess.Popen([sys.executable, s], cwd=ROOT, env=env)
                procs.append(p); time.sleep(0.3)
            except OSError: pass
    return procs

def wait_agents(t=25):
    exp = set(AGENTS); ready = set(); t0 = time.time()
    while time.time() - t0 < t:
        time.sleep(0.8)
        for a in exp - ready:
            sp = os.path.join(STATE, f"{a}_status.json")
            if os.path.isfile(sp):
                try:
                    with open(sp, encoding="utf-8") as f:
                        d = json.loads(f.read())
                    if d.get("status") == "idle": ready.add(a)
                except (json.JSONDecodeError, OSError): pass
        if len(ready) == len(exp): return True
    return False

def cleanup(procs):
    for p in procs:
        if p.poll() is None:
            p.terminate()
            try: p.wait(timeout=3)
            except subprocess.TimeoutExpired: p.kill()

def show_banner(dry):
    lines = [f"[bold cyan]  LynxSec[/bold cyan] [dim]v0.2 - ---  [/dim]"]
    if dry: lines.append("[dim italic]  dry-run mode[/dim italic]")
    dv = "[green]DVWA: ready[/green]" if check_dvwa() else "[red]DVWA: offline[/red]"
    lines.append(f"  {dv} | deepseek-v4-pro")
    console.print(Panel("\n".join(lines), border_style="cyan"))

def show_agents():
    table = Table.grid(padding=(0, 2))
    table.add_column(); table.add_column()
    for a in AGENTS:
        sp = os.path.join(STATE, f"{a}_status.json")
        st = "[dim]?[/dim]"
        if os.path.isfile(sp):
            try:
                with open(sp, encoding="utf-8") as f:
                    d = json.loads(f.read())
                s = d.get("status","?")
                st = {"idle":"[dim]idle[/dim]","working":"[green]working[/green]","blocked":"[red]blocked[/red]"}.get(s, f"[dim]{s}[/dim]")
            except: pass
        table.add_row(f"  {tag(a)}", st)
    console.print(table)

def show_result(path):
    if not path or not os.path.isfile(path):
        console.print(Panel("[yellow]not completed[/yellow]", border_style="yellow"))
        return
    with open(path, encoding="utf-8") as f:
        txt = f.read()
    lines = txt.split("\n")
    preview = "\n".join(lines[:20])
    if len(lines) > 20: preview += f"\n[dim]... ({len(lines)} lines)[/dim]"
    console.print(Panel(preview, title=os.path.basename(path), border_style="green"))

def interactive(dry):
    from core.dispatcher import run as dispatch
    show_banner(dry)

    try:
        console.print(f"  {tag('dispatcher')} [dim]connecting...[/dim]")
        dispatch("")
    except: pass

    console.print("\n[dim]  Type a request or /help.  /quit to exit.[/dim]\n")
    task_count = 0

    while True:
        try:
            raw = console.input("[bold cyan]lynx[/bold cyan][bold white] > [/bold white]")
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]bye.[/dim]"); break

        cmd = raw.strip()
        if not cmd: continue

        if cmd.startswith("/"):
            parts = cmd[1:].split(maxsplit=1)
            act = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""

            if act in ("q","quit","exit"):
                console.print("[dim]bye.[/dim]"); break
            elif act in ("h","help"):
                console.print("  [bold]/scan <target>[/bold]  scan a target")
                console.print("  [bold]/agents[/bold]        show agent status")
                console.print("  [bold]/quit[/bold]          exit")
                continue
            elif act in ("a","agents"):
                show_agents(); continue
            elif act in ("s","scan"):
                cmd = f"scan {arg}"
            else:
                console.print(f"[red]unknown: /{act}[/red]"); continue

        task_count += 1
        console.print(f"\n[dim]#{task_count}[/dim] [bold]{cmd}[/bold]\n")

        try:
            result = dispatch(cmd)
        except Exception as e:
            console.print(f"[red]error: {e}[/red]"); continue

        if result:
            console.print(f"\n  {tag('reporter')} [green]done[/green]")
            show_result(result)
        else:
            console.print(f"\n  {tag('dispatcher')} [yellow]not completed[/yellow]")
        show_agents()

def main():
    dry = "--dry-run" in sys.argv

    if not check_config():
        console.print("[red]config.env missing or incomplete.[/red]")
        sys.exit(1)

    if not ensure_dvwa():
        console.print("[yellow]DVWA offline. continue? [y/N] [/yellow]", end="")
        try:
            if input().strip().lower() != "y": sys.exit(0)
        except: sys.exit(0)

    clean_state()
    os.makedirs(STATE, exist_ok=True)

    if dry: os.environ["LYNXSEC_DRY_RUN"] = "1"

    procs = start_agents(dry)
    if not procs:
        console.print("[red]no agents started.[/red]"); sys.exit(1)

    wait_agents()

    try:
        interactive(dry)
    finally:
        cleanup(procs)

if __name__ == "__main__":
    main()




