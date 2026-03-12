"""
ZAK LLM — Anthropic Claude provider.

Requires: pip install "zin-adk[llm]" or anthropic>=0.28

Supported models: claude-opus-4-5, claude-sonnet-4-5, claude-haiku-3-5
"""

from __future__ import annotations

import os
from typing import Any

from zak.core.llm.base import LLMClient, LLMResponse, ToolCall


class AnthropicClient(LLMClient):
    """Anthropic Claude provider implementation."""

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
    ) -> None:
        self.model = model or os.getenv("LLM_MODEL", "claude-opus-4-5")
        self.api_key = api_key or os.getenv("LLM_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
        self.base_url = base_url
        self._client: Any = None

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> LLMResponse:
        try:
            import anthropic
        except ImportError as exc:
            raise ImportError(
                "anthropic package is required. Install with: pip install 'zin-adk[llm]'"
            ) from exc

        import httpx
        if self._client is None:
            http_client = httpx.Client(verify=False)
            kwargs: dict[str, Any] = {"api_key": self.api_key, "http_client": http_client}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            self._client = anthropic.Anthropic(**kwargs)
        client = self._client

        # Separate system message from conversation history
        system_content: str | None = None
        conv_messages: list[dict[str, Any]] = []
        for msg in messages:
            if msg.get("role") == "system":
                system_content = msg.get("content", "")
            elif msg.get("role") == "tool":
                # Translate OpenAI "tool" role back to Anthropic tool_result block
                # We need to attach this to a 'user' message as per Anthropic API
                tool_msg = {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": msg.get("tool_call_id", ""),
                            "content": msg.get("content", "")
                        }
                    ]
                }
                conv_messages.append(tool_msg)
            elif msg.get("role") == "assistant" and "tool_calls" in msg:
                # Format assistant sending a tool call
                content_blocks: list[dict[str, Any]] = []
                if msg.get("content"):
                    content_blocks.append({"type": "text", "text": msg.get("content")})
                
                for tc in msg.get("tool_calls", []):
                    import json
                    args_str = tc.get("function", {}).get("arguments", "{}")
                    try:
                        args = json.loads(args_str)
                    except json.JSONDecodeError:
                        args = {}
                    
                    content_blocks.append({
                        "type": "tool_use",
                        "id": tc.get("id", ""),
                        "name": tc.get("function", {}).get("name", ""),
                        "input": args
                    })
                
                conv_messages.append({
                    "role": "assistant",
                    "content": content_blocks
                })
            else:
                conv_messages.append(msg)

        # Convert OpenAI tool schema to Anthropic format
        anthropic_tools: list[dict[str, Any]] = []
        for t in tools:
            if t.get("type") == "function":
                fn = t["function"]
                anthropic_tools.append(
                    {
                        "name": fn["name"],
                        "description": fn.get("description", ""),
                        "input_schema": fn.get(
                            "parameters",
                            {"type": "object", "properties": {}},
                        ),
                    }
                )

        kwargs: dict[str, Any] = dict(
            model=self.model,
            messages=conv_messages,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        if system_content:
            kwargs["system"] = system_content
        if anthropic_tools:
            kwargs["tools"] = anthropic_tools

        response = client.messages.create(**kwargs)

        content_text: str | None = None
        tool_calls: list[ToolCall] = []

        for block in response.content:
            if block.type == "text":
                content_text = block.text
            elif block.type == "tool_use":
                tool_calls.append(
                    ToolCall(
                        id=block.id,
                        name=block.name,
                        arguments=dict(block.input) if block.input else {},
                    )
                )

        finish_reason = "stop"
        if response.stop_reason == "tool_use":
            finish_reason = "tool_calls"
        elif response.stop_reason == "max_tokens":
            finish_reason = "max_tokens"

        return LLMResponse(
            content=content_text,
            tool_calls=tool_calls,
            finish_reason=finish_reason,
            usage={
                "prompt_tokens": response.usage.input_tokens,
                "completion_tokens": response.usage.output_tokens,
                "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
            },
        )
