"""infra/llm.py — LynxSec 模型统一接口

兼容任意 OpenAI 格式 API（DeepSeek / 千问 / GPT 等）。
从 config.env 读取配置，不绑定任何厂商。
"""

import json
import os
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from dotenv import load_dotenv


def _find_config() -> str | None:
    """在项目根目录查找 config.env 文件"""
    candidates = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.env"),
        os.path.join(os.getcwd(), "config.env"),
    ]
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


class LLM:
    """LLM 调用封装。

    使用方式:
        llm = LLM()
        reply = llm.chat("你是一个安全专家", "分析这个扫描结果...")

    配置来源: 项目根目录 config.env 文件
        LLM_BASE_URL=https://api.deepseek.com
        LLM_API_KEY=你的Key
        LLM_MODEL=deepseek-v4-pro
    """

    def __init__(self) -> None:
        config_path = _find_config()
        if config_path:
            load_dotenv(config_path)

        self.base_url: str = os.getenv("LLM_BASE_URL", "").rstrip("/")
        self.api_key: str = os.getenv("LLM_API_KEY", "")
        self.model: str = os.getenv("LLM_MODEL", "deepseek-v4-pro")
        self.max_tokens: int = int(os.getenv("LLM_MAX_TOKENS", "4096"))
        self.temperature: float = float(os.getenv("LLM_TEMPERATURE", "0.1"))

        if not self.base_url or not self.api_key:
            raise RuntimeError(
                "[LLM] 配置缺失！请确保 config.env 文件中设置了：\n"
                "  LLM_BASE_URL=xxx\n"
                "  LLM_API_KEY=xxx\n"
                "  LLM_MODEL=xxx"
            )

    def chat(self, system_prompt: str, user_message: str,
             thinking_label: str = "") -> str:
        """发送一次对话请求，返回模型的文本回复。

        参数:
            system_prompt:  系统提示词（定义角色、输出格式等）
            user_message:   用户消息（具体的任务内容）
            thinking_label: 思考标签，非空时输出 "⏳ {label}..." 和耗时

        返回:
            str: 模型的回复文本

        异常:
            RuntimeError: API 调用失败时抛出（带详细错误信息）
        """
        if thinking_label:
            import time as _time
            _start = _time.time()
            print(f"  ⏳ {thinking_label}...", end="", flush=True)

        url = f"{self.base_url}/chat/completions"

        body: dict = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
        }

        data = json.dumps(body).encode("utf-8")

        headers: dict[str, str] = {
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Bearer {self.api_key}",
        }

        request = Request(url, data=data, headers=headers, method="POST")

        try:
            with urlopen(request, timeout=120) as response:
                result: dict = json.loads(response.read().decode("utf-8"))
        except HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"[LLM] API 请求失败 (HTTP {e.code})\n"
                f"  地址: {url}\n"
                f"  详情: {error_body[:500]}"
            ) from e
        except URLError as e:
            raise RuntimeError(
                f"[LLM] 网络请求失败\n"
                f"  地址: {url}\n"
                f"  原因: {e.reason}"
            ) from e

        choices: list = result.get("choices", [])
        if not choices:
            snippet = json.dumps(result, ensure_ascii=False)[:500]
            raise RuntimeError(f"[LLM] API 返回了空的 choices 列表\n响应: {snippet}")

        content: str = choices[0].get("message", {}).get("content", "")
        if not content:
            snippet = json.dumps(result, ensure_ascii=False)[:500]
            raise RuntimeError(f"[LLM] API 返回了空的 content\n响应: {snippet}")

        if thinking_label:
            _elapsed = _time.time() - _start
            print(f" (dim {_elapsed:.1f}s)")

        return content
