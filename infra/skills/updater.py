"""infra/skills/updater.py ? ????????????

?????
  - ???lyx ????? agent_skills.json ? last_updated ???
          ??? 7 ??????????
  - ???lyx --update-skills ????

???????? trusted-sources.md ????
  - OWASP Top 10: https://owasp.org/www-project-top-ten/
  - CWE Top 25: https://cwe.mitre.org/top25/
  - CVE NVD: https://nvd.nist.gov/
  - CNNVD: https://www.cnnvd.org.cn/
  - PTES: http://www.pentest-standard.org/
"""

from __future__ import annotations
import os
import json
import time
from datetime import datetime, timezone, timedelta

_CST = timezone(timedelta(hours=8))
_SEVEN_DAYS = 7 * 24 * 3600


def _skills_config_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "agent_skills.json")


def check_update_needed() -> bool:
    """???????????????? 7 ???

    Returns:
        True ??????
    """
    path = _skills_config_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except (OSError, json.JSONDecodeError):
        return False

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
    """????????????????"""
    path = _skills_config_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except (OSError, json.JSONDecodeError):
        return

    config.setdefault("_meta", {})["last_updated"] = datetime.now(_CST).isoformat()
    config["_meta"]["version"] = config["_meta"].get("version", 0) + 1

    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)


def print_update_status() -> None:
    """???????"""
    if check_update_needed():
        print("  [skills] ????? 7 ?????????: lyx --update-skills")
    else:
        print("  [skills] ????? (7??)")
