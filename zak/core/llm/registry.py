"""
ZAK LLM Registry — Provider factory.

Reads LLM_PROVIDER, LLM_MODEL, LLM_API_KEY from environment variables and
returns the appropriate LLMClient implementation.

Supported providers:
    openai     — OpenAI GPT-4o, GPT-4-turbo, etc.  (requires openai>=1.30)
    anthropic  — Anthropic Claude models            (requires anthropic>=0.28)
    google     — Google Gemini models               (requires google-generativeai>=0.7)
    local      — Local Ollama deployment            (no extra dependencies)
"""

from __future__ import annotations

import os

from zak.core.llm.base import LLMClient


def get_llm_client(
    provider: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
) -> LLMClient:
    """
    Return an LLMClient for the requested provider.

    Falls back to environment variables:
        LLM_PROVIDER — openai | anthropic | google | local (default: openai)
        LLM_MODEL    — model name (provider-specific default if unset)
        LLM_API_KEY  — API key (provider-specific env var if unset)

    Raises:
        ValueError: If the provider is unsupported.
        ImportError: If the required SDK is not installed.
    """
    env_provider = os.getenv("LLM_PROVIDER")
    resolved_provider = env_provider or provider or "openai"

    if resolved_provider == "openai":
        from zak.core.llm.openai_client import OpenAIClient
        return OpenAIClient(model=model, api_key=api_key)

    if resolved_provider == "anthropic":
        from zak.core.llm.anthropic_client import AnthropicClient
        return AnthropicClient(model=model, api_key=api_key)

    if resolved_provider == "google":
        from zak.core.llm.google_client import GoogleClient
        return GoogleClient(model=model, api_key=api_key)

    if resolved_provider == "local":
        from zak.core.llm.local import OllamaClient
        return OllamaClient(model=model, base_url=base_url)

    if resolved_provider == "mock":
        from zak.core.llm.mock_client import MockLLMClient
        return MockLLMClient(model=model, api_key=api_key)

    raise ValueError(
        f"Unsupported LLM provider: '{resolved_provider}'. "
        "Supported: openai, anthropic, google, local"
    )
