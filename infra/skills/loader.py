"""skill 引用文件加载器 — 借鉴 Serenity SKILL 的 references/ 模式。

auditor.py 通过此模块在运行时加载 references/*.md，拼入 LLM system prompt。
"""

from __future__ import annotations
import os


def _ref_dir() -> str:
    """返回 references/ 目录绝对路径。"""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "references")


def load_ref(filename: str) -> str:
    """读取单个 reference 文件，失败返空字符串。"""
    path = os.path.join(_ref_dir(), filename)
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def build_prompt(base_prompt: str) -> str:
    """拼接所有 references 到 base prompt 后面，生成完整 system prompt。

    Args:
        base_prompt: auditor.py 的 _SYSTEM_PROMPT_AUDIT 原始内容

    Returns:
        包含 references 知识的完整 prompt
    """
    refs = [
        ("false-positive-rules.md", "误报排除规则表"),
        ("owasp-top10.md", "OWASP Top 10 (2021) Checklist"),
        ("cvss-scoring.md", "CVSS 3.1 评分标准"),
    ]
    rules_blocks: list[str] = []
    for filename, label in refs:
        text = load_ref(filename)
        if text:
            rules_blocks.append(f"### {label}\n{text}")

    if not rules_blocks:
        return base_prompt

    return base_prompt + "\n\n---\n\n## 审计参考知识\n" + "\n".join(rules_blocks)
