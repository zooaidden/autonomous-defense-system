from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from urllib import error, request

logger = logging.getLogger(__name__)


class LLMClient(ABC):
    @abstractmethod
    def generate(self, *, system_prompt: str, user_prompt: str) -> str:
        raise NotImplementedError


class MockLLMClient(LLMClient):
    def generate(self, *, system_prompt: str, user_prompt: str) -> str:
        # 可控输出，保证本地 demo 稳定可复现
        return f"MOCK_RESPONSE::{system_prompt[:20]}::{user_prompt[:60]}"


class HttpChatCompletionLLMClient(LLMClient):
    """OpenAI 兼容 ``/chat/completions``（硅基流动 / DeepSeek / OpenAI / 兼容网关）。"""

    def __init__(self) -> None:
        self._api_key = (
            os.environ.get("AGENT_BRAIN_LLM_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or ""
        ).strip()
        self._base = (
            os.environ.get("AGENT_BRAIN_LLM_BASE_URL")
            or os.environ.get("OPENAI_BASE_URL")
            or "https://api.openai.com/v1"
        ).rstrip("/")
        self._model = (
            os.environ.get("AGENT_BRAIN_LLM_MODEL")
            or os.environ.get("OPENAI_MODEL")
            or "gpt-4o-mini"
        )
        try:
            self._timeout = float(os.environ.get("AGENT_BRAIN_LLM_TIMEOUT_SECONDS", "120"))
        except ValueError:
            self._timeout = 120.0

    @property
    def model(self) -> str:
        return self._model

    def generate(self, *, system_prompt: str, user_prompt: str) -> str:
        if not self._api_key:
            raise RuntimeError(
                "HttpChatCompletionLLMClient: set AGENT_BRAIN_LLM_API_KEY or OPENAI_API_KEY"
            )
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": float(os.environ.get("AGENT_BRAIN_LLM_TEMPERATURE", "0.2")),
        }
        body = json.dumps(payload).encode("utf-8")
        url = f"{self._base}/chat/completions"
        req = request.Request(
            url=url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read().decode("utf-8")
        except error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")[:2000]
            logger.error("LLM HTTPError %s: %s", e.code, detail)
            raise RuntimeError(f"LLM HTTP {e.code}: {detail}") from e
        except error.URLError as e:
            logger.error("LLM URLError: %s", e.reason)
            raise RuntimeError(f"LLM network error: {e.reason}") from e

        data = json.loads(raw)
        choices = data.get("choices") or []
        if not choices:
            raise RuntimeError(f"LLM response missing choices: {raw[:800]}")
        msg = choices[0].get("message") or {}
        content = msg.get("content")
        if content is None:
            raise RuntimeError(f"LLM response missing message.content: {raw[:800]}")
        return str(content).strip()


def create_default_llm_client() -> LLMClient:
    """若配置了 ``AGENT_BRAIN_LLM_API_KEY`` 或 ``OPENAI_API_KEY`` 则走真实 HTTP LLM，否则 Mock。"""
    key = (
        os.environ.get("AGENT_BRAIN_LLM_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or ""
    ).strip()
    if key:
        logger.info(
            "Using HttpChatCompletionLLMClient model=%s base=%s",
            os.environ.get("AGENT_BRAIN_LLM_MODEL") or os.environ.get("OPENAI_MODEL") or "gpt-4o-mini",
            (os.environ.get("AGENT_BRAIN_LLM_BASE_URL") or os.environ.get("OPENAI_BASE_URL") or "https://api.openai.com/v1"),
        )
        return HttpChatCompletionLLMClient()
    logger.info("No AGENT_BRAIN_LLM_API_KEY / OPENAI_API_KEY — using MockLLMClient")
    return MockLLMClient()
