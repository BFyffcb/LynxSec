"""infra/skills/updater.py v2 ? 13???? + ???????

?????
  - ???lyx ?????, ???? + ??7???????
  - ???lyx --update-skills ???????????

??????source_whitelist.json ?? 13 ??????
  ?? URL ??????????????? fetch?
"""

from __future__ import annotations
import os
import json
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timezone, timedelta

_CST = timezone(timedelta(hours=8))
_SEVEN_DAYS = 7 * 24 * 3600
_MONDAY = 0  # Monday is 0 in Python's weekday()


def _skills_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def _whitelist_path() -> str:
    return os.path.join(_skills_dir(), "source_whitelist.json")


def _config_path() -> str:
    return os.path.join(_skills_dir(), "agent_skills.json")


def _output_dir() -> str:
    d = os.path.join(os.path.dirname(_skills_dir()), "..", "outputs", "skills_feed")
    os.makedirs(d, exist_ok=True)
    return os.path.abspath(d)


# ---- ??????? ----

def _load_whitelist() -> dict:
    """?? source_whitelist.json????????."""
    try:
        with open(_whitelist_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _get_allowed_domains() -> set[str]:
    """?????????????."""
    wl = _load_whitelist()
    domains = set()
    for src in wl.get("sources", []):
        d = src.get("domain", "").strip()
        if d:
            domains.add(d)
    return domains


def is_url_allowed(url: str) -> bool:
    """?? URL ??????????.

    Args:
        url: ?? URL (https://nvd.nist.gov/...)

    Returns:
        True ?????????.
    """
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
    except Exception:
        return False

    if not hostname:
        return False

    allowed = _get_allowed_domains()
    # ?????hostname ??? .domain ??????? domain
    for domain in allowed:
        if hostname == domain or hostname.endswith("." + domain):
            return True
    return False


def _find_source_by_url(url: str) -> dict | None:
    """?? URL ?????????."""
    wl = _load_whitelist()
    for src in wl.get("sources", []):
        for fetch_url in src.get("fetch_urls", []):
            if fetch_url == url:
                return src
    return None


# ---- ???? ----

def _is_monday() -> bool:
    """????????."""
    return datetime.now(_CST).weekday() == _MONDAY


def check_update_needed(force: bool = False) -> bool:
    """????????.

    Args:
        force: True ?????/???????? True

    Returns:
        True ?????????.
    """
    if force:
        return True

    # ???????
    if not _is_monday():
        return False

    # ?? 7 ???
    try:
        with open(_config_path(), "r", encoding="utf-8") as f:
            config = json.load(f)
    except (OSError, json.JSONDecodeError):
        return True

    meta = config.get("_meta", {})
    last = meta.get("last_updated", "")
    if not last:
        return True

    try:
        last_dt = datetime.fromisoformat(last)
        now = datetime.now(_CST)
        return (now - last_dt).total_seconds() > _SEVEN_DAYS
    except (ValueError, TypeError):
        return True


def mark_updated() -> None:
    """????????."""
    try:
        with open(_config_path(), "r", encoding="utf-8") as f:
            config = json.load(f)
    except (OSError, json.JSONDecodeError):
        return
    config.setdefault("_meta", {})["last_updated"] = datetime.now(_CST).isoformat()
    config["_meta"]["version"] = config["_meta"].get("version", 0) + 1
    with open(_config_path(), "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)


def _fetch_url(url: str, timeout: int = 30) -> str | None:
    """??????? URL ????.

    Args:
        url: ????? URL
        timeout: ????

    Returns:
        ???? (??) ? None (??).
    """
    if not is_url_allowed(url):
        print(f"  [BLOCKED] {url} ? ???? 13 ?????")
        return None

    src = _find_source_by_url(url)
    src_id = src["id"] if src else "unknown"
    print(f"  [{src_id}] fetching {url} ...", end=" ")

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "LynxSec/2.0 (Security Research)"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
        print(f"OK ({len(data)} bytes)")
        # Store in outputs/skills_feed/
        fname = f"{src_id}_{datetime.now(_CST).strftime('%Y%m%d')}.txt"
        out_path = os.path.join(_output_dir(), fname)
        with open(out_path, "wb") as f:
            f.write(data)
        return data.decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        print(f"FAIL ({e.reason})")
        return None
    except Exception as e:
        print(f"FAIL ({e})")
        return None


def run_weekly_update(dry: bool = False) -> dict[str, bool]:
    """??????????????? URL ????.

    Args:
        dry: True ?????????????

    Returns:
        {source_id: success} ??.
    """
    wl = _load_whitelist()
    sources = wl.get("sources", [])
    if not sources:
        print("[updater] ?????")
        return {}

    print(f"[updater] 13 ???????? ({'dry-run' if dry else 'live'})")
    results = {}

    for src in sources:
        sid = src["id"]
        strategy = src.get("update_strategy", "version_check")
        fetch_urls = src.get("fetch_urls", [])
        domain = src.get("domain", "")

        if not is_url_allowed(f"https://{domain}"):
            print(f"  [{sid}] BLOCKED ? ????????, ??")
            results[sid] = False
            continue

        if dry:
            print(f"  [{sid}] {strategy}: {fetch_urls[0] if fetch_urls else 'N/A'} (dry)")
            results[sid] = True  # dry-run assumes success
            continue

        if strategy == "daily_feed" and fetch_urls:
            # ????? URL ????
            content = _fetch_url(fetch_urls[0])
            results[sid] = content is not None
        elif fetch_urls:
            # version_check: just verify reachability
            content = _fetch_url(fetch_urls[0])
            results[sid] = content is not None
        else:
            print(f"  [{sid}] no URLs configured")
            results[sid] = False

    ok = sum(1 for v in results.values() if v)
    print(f"[updater] {ok}/{len(results)} ?????")
    return results


# ---- CLI ?? ----

def print_update_status() -> None:
    """??????."""
    if _is_monday():
        if check_update_needed():
            print("  [skills] ????????????????: lyx --update-skills")
        else:
            print("  [skills] ????? (?????)")
    else:
        print("  [skills] ??????: ??")
        if check_update_needed(force=True):
            print("  [skills] ????: lyx --update-skills")
