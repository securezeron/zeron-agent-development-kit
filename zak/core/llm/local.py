"""
ZAK LLM — Local Ollama provider.

No external SDK required — uses Python's built-in urllib.request.
Ollama must be running at OLLAMA_BASE_URL (default: http://localhost:11434).

Suitable for:
    - Air-gapped enterprise deployments
    - Development / testing without API keys
    - On-premise security data isolation

Recommended models for security agents:
    - llama3.1:70b   (best quality, high resource)
    - llama3.1:8b    (fast, moderate quality)
    - mixtral:8x7b   (good function calling)
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from zak.core.llm.base import LLMClient, LLMResponse, ToolCall


class OllamaClient(LLMClient):
    """Local Ollama provider — zero extra dependencies."""

    def __init__(
        self,
        model: str | None = None,
        base_url: str | None = None,
    ) -> None:
        self.model = model or os.getenv("LLM_MODEL", "llama3.1:8b")
        self.base_url = (
            base_url
            or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        ).rstrip("/")

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> LLMResponse:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }
        if tools:
            payload["tools"] = tools

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=data,
            method="POST",
        )
        req.add_header("Content-Type", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=180) as resp:
                result = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise ConnectionError(
                f"Could not connect to Ollama at {self.base_url}. "
                "Make sure Ollama is running: https://ollama.com"
            ) from exc

        message = result.get("message", {})
        content_text: str | None = message.get("content") or None

        tool_calls: list[ToolCall] = []
        for tc in message.get("tool_calls", []):
            fn = tc.get("function", {})
            args = fn.get("arguments", {})
            # Ollama may return arguments as a JSON string
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            tool_calls.append(
                ToolCall(
                    id=tc.get("id", fn.get("name", "")),
                    name=fn.get("name", ""),
                    arguments=args,
                )
            )

        finish_reason = "tool_calls" if tool_calls else "stop"

        return LLMResponse(
            content=content_text,
            tool_calls=tool_calls,
            finish_reason=finish_reason,
            usage={
                "prompt_tokens": result.get("prompt_eval_count", 0),
                "completion_tokens": result.get("eval_count", 0),
                "total_tokens": result.get("prompt_eval_count", 0)
                + result.get("eval_count", 0),
            },
        )
