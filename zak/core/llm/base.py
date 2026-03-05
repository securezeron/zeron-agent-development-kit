"""
ZAK LLM Base — Abstract LLMClient interface and shared response types.

All provider implementations must implement LLMClient.chat() and return
an LLMResponse. This keeps agents decoupled from any specific LLM SDK.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCall:
    """A single tool call issued by the LLM."""
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class LLMResponse:
    """Unified response from any LLM provider."""
    content: str | None          # Text content (None if pure tool call response)
    tool_calls: list[ToolCall]   # Tool calls requested by the LLM
    finish_reason: str           # "stop" | "tool_calls" | "max_tokens" | "error"
    usage: dict[str, int] = field(default_factory=dict)  # prompt/completion/total tokens


class LLMClient(abc.ABC):
    """
    Abstract LLM client interface.

    All providers (OpenAI, Anthropic, Google, Ollama) implement this interface
    so agents are not coupled to any specific SDK.
    """

    @abc.abstractmethod
    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> LLMResponse:
        """
        Send a chat request to the LLM.

        Args:
            messages:    Conversation history in OpenAI message format.
            tools:       List of tool schemas in OpenAI function-call format.
            max_tokens:  Maximum tokens in the response.
            temperature: Sampling temperature (0.0 = deterministic, 1.0 = creative).

        Returns:
            LLMResponse with content, tool_calls, finish_reason, and usage stats.
        """
        ...
