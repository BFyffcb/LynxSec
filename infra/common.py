"""infra/common.py — 所有 Agent 共享的基础函数。

提取自 5 个 Agent 中完全相同的 _read_json / _write_json 实现。
"""

from __future__ import annotations

import json
import os


def read_json(filepath: str) -> dict | None:
    """读取 JSON 文件，支持 BOM 头，失败返回 None。"""
    if not os.path.isfile(filepath):
        return None
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        if content.startswith("\ufeff"):
            content = content[1:]
        return json.loads(content)
    except (json.JSONDecodeError, OSError):
        return None


def write_json(filepath: str, data: dict) -> bool:
    """原子写入 JSON 文件（先写 .tmp，再 os.replace）。"""
    tmp_path = filepath + ".tmp" + str(os.getpid())
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, filepath)
        return True
    except OSError:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        return False
