"""
ZAK LLM — OpenAI / Azure OpenAI provider.

Requires: pip install "zin-adk[llm]" or openai>=1.30

Supported models: gpt-4o, gpt-4o-mini, gpt-4-turbo, gpt-3.5-turbo
Azure: set LLM_PROVIDER=openai and AZURE_OPENAI_API_KEY + AZURE_OPENAI_ENDPOINT
"""

from __future__ import annotations

import json
import os
from typing import Any

from zak.core.llm.base import LLMClient, LLMResponse, ToolCall


class OpenAIClient(LLMClient):
    """OpenAI / Azure OpenAI provider implementation."""

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
    ) -> None:
        self.model = model or os.getenv("LLM_MODEL", "gpt-4o")
        self.api_key = api_key or os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY")

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> LLMResponse:
        try:
            import openai
        except ImportError as exc:
            raise ImportError(
                "openai package is required. Install with: pip install 'zin-adk[llm]'"
            ) from exc

        client = openai.OpenAI(api_key=self.api_key)

        kwargs: dict[str, Any] = dict(
            model=self.model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        response = client.chat.completions.create(**kwargs)
        choice = response.choices[0]

        tool_calls: list[ToolCall] = []
        if choice.message.tool_calls:
            for tc in choice.message.tool_calls:
                tool_calls.append(
                    ToolCall(
                        id=tc.id,
                        name=tc.function.name,
                        arguments=json.loads(tc.function.arguments or "{}"),
                    )
                )

        finish_reason = choice.finish_reason or "stop"
        if tool_calls and finish_reason == "tool_calls":
            finish_reason = "tool_calls"

        return LLMResponse(
            content=choice.message.content,
            tool_calls=tool_calls,
            finish_reason=finish_reason,
            usage={
                "prompt_tokens": response.usage.prompt_tokens if response.usage else 0,
                "completion_tokens": response.usage.completion_tokens if response.usage else 0,
                "total_tokens": response.usage.total_tokens if response.usage else 0,
            },
        )
