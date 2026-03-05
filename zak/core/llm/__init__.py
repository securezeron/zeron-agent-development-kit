"""
ZAK Core LLM — Provider-agnostic LLM client abstraction.

Usage:
    from zak.core.llm import get_llm_client

    client = get_llm_client()   # reads LLM_PROVIDER / LLM_MODEL / LLM_API_KEY from env
    response = client.chat(messages, tools)
"""

from zak.core.llm.base import LLMClient, LLMResponse, ToolCall
from zak.core.llm.registry import get_llm_client

__all__ = ["LLMClient", "LLMResponse", "ToolCall", "get_llm_client"]
