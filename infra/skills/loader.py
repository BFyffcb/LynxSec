"""skill ??????? v2 ? ?? wiki ???? agent ???

auditor ?? references/ ???????
recon / pentest / reporter ?? agent_skills.json ???? wiki ????
"""

from __future__ import annotations
import os
import json as _json
from fnmatch import fnmatch


def _ref_dir() -> str:
    """?? references/ ???????"""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "references")


def _wiki_dir() -> str:
    """LLM Wiki root dir: env LYNXSEC_WIKI_DIR > ~/.workbuddy > local references/"""
    env = os.getenv("LYNXSEC_WIKI_DIR", "")
    if env and os.path.isdir(env):
        return env
    home = os.path.expanduser("~")
    default = os.path.join(home, ".workbuddy", "wiki-knowledge", "wiki")
    if os.path.isdir(default):
        return default
    return _ref_dir()


def _skills_config() -> dict:
    """?? agent_skills.json ?????"""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_skills.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return _json.load(f)
    except (OSError, _json.JSONDecodeError):
        return {}


def load_ref(filename: str) -> str:
    """???? reference ???????????"""
    path = os.path.join(_ref_dir(), filename)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def load_wiki_file(filename: str) -> str:
    """???? wiki ??????? glob ???????????"""
    wdir = _wiki_dir()
    if "*" in filename or "?" in filename:
        # Glob match: pick first match
        try:
            for entry in os.listdir(wdir):
                if fnmatch(entry, filename) and entry.endswith(".md"):
                    filename = entry
                    break
        except OSError:
            return ""
    path = os.path.join(wdir, filename)
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        # Skip YAML frontmatter for cleaner context
        if text.startswith("---"):
            idx = text.find("---", 3)
            if idx != -1:
                text = text[idx + 3:].strip()
        return text
    except OSError:
        return ""


def build_prompt(base_prompt: str, agent: str = "auditor") -> str:
    """?? references + wiki ??? base prompt?

    Args:
        base_prompt: ?? system prompt
        agent: ?? agent ? (auditor/recon/pentest/reporter)

    Returns:
        ???????? system prompt
    """
    config = _skills_config()
    agent_cfg = config.get(agent, {})

    blocks = []

    # 1. Local references (for auditor)
    local_refs = agent_cfg.get("local_refs", [])
    for filename in local_refs:
        text = load_ref(filename)
        if text:
            label = filename.replace(".md", "").replace("-", " ").title()
            blocks.append(f"### {label}\n{text}")

    # 2. Wiki knowledge files
    wiki_files = agent_cfg.get("wiki_files", [])
    if wiki_files:
        wiki_blocks = []
        for filename in wiki_files:
            text = load_wiki_file(filename)
            if text:
                # Trim to 6000 chars to avoid context overflow
                if len(text) > 6000:
                    text = text[:6000] + "\n\n... (truncated)"
                wiki_blocks.append(text)
        if wiki_blocks:
            blocks.append("### Wiki ???\n" + "\n\n---\n\n".join(wiki_blocks))

    if not blocks:
        return base_prompt

    return base_prompt + "\n\n---\n\n## ????\n" + "\n".join(blocks)

def validate_skills(verbose: bool = True) -> dict[str, list[str]]:
    """Validate all wiki and reference files referenced in agent_skills.json.

    Args:
        verbose: If True, print warnings for missing files.

    Returns:
        {agent_name: [missing_file_list]} dict. Empty dict if all files present.
    """
    import json as _json
    config = _skills_config()
    missing: dict[str, list[str]] = {}
    for agent, cfg in config.items():
        if agent.startswith("_"):
            continue
        lost: list[str] = []
        for fname in cfg.get("wiki_files", []):
            full = os.path.join(_wiki_dir(), fname)
            if not os.path.isfile(full):
                lost.append(f"[wiki] {fname}")
        for fname in cfg.get("local_refs", []):
            full = os.path.join(_ref_dir(), fname)
            if not os.path.isfile(full):
                lost.append(f"[refs] {fname}")
        if lost:
            missing[agent] = lost
    if verbose and missing:
        print("  [skills] WARNING: some knowledge files missing:")
        for agent, files in missing.items():
            for f in files:
                print(f"    [{agent}] {f}")
        print("  [skills] Set LYNXSEC_WIKI_DIR env var or restore wiki files.")
    return missing
