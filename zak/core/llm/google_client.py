"""
ZAK LLM — Google Gemini provider.

Requires: pip install "zin-adk[llm]" or google-generativeai>=0.7

Supported models: gemini-1.5-pro, gemini-1.5-flash, gemini-2.0-flash
"""

from __future__ import annotations

import os
from typing import Any

from zak.core.llm.base import LLMClient, LLMResponse, ToolCall


class GoogleClient(LLMClient):
    """Google Gemini provider implementation."""

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
    ) -> None:
        self.model = model or os.getenv("LLM_MODEL", "gemini-1.5-pro")
        self.api_key = api_key or os.getenv("LLM_API_KEY") or os.getenv("GOOGLE_API_KEY")

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> LLMResponse:
        try:
            import google.generativeai as genai
        except ImportError as exc:
            raise ImportError(
                "google-generativeai package is required. "
                "Install with: pip install 'zin-adk[llm]'"
            ) from exc

        genai.configure(api_key=self.api_key)

        # Build Gemini function declarations from OpenAI schema
        gemini_tools = []
        for t in tools:
            if t.get("type") == "function":
                fn = t["function"]
                gemini_tools.append(
                    genai.protos.Tool(
                        function_declarations=[
                            genai.protos.FunctionDeclaration(
                                name=fn["name"],
                                description=fn.get("description", ""),
                                parameters=_openai_params_to_gemini(
                                    fn.get("parameters", {})
                                ),
                            )
                        ]
                    )
                )

        model = genai.GenerativeModel(
            model_name=self.model,
            generation_config=genai.GenerationConfig(
                temperature=temperature,
                max_output_tokens=max_tokens,
            ),
            tools=gemini_tools or None,
        )

        # Convert messages to Gemini chat history format
        system_text = ""
        gemini_history = []
        for msg in messages:
            role = msg.get("role")
            content = msg.get("content", "")
            if role == "system":
                system_text = content
            elif role == "user":
                gemini_history.append({"role": "user", "parts": [content]})
            elif role == "assistant":
                gemini_history.append({"role": "model", "parts": [content or ""]})

        # Prepend system text to first user message if present
        if system_text and gemini_history and gemini_history[0]["role"] == "user":
            gemini_history[0]["parts"] = [
                f"{system_text}\n\n{gemini_history[0]['parts'][0]}"
            ]

        chat = model.start_chat(history=gemini_history[:-1] if len(gemini_history) > 1 else [])
        last_message = gemini_history[-1]["parts"][0] if gemini_history else ""
        response = chat.send_message(last_message)

        tool_calls: list[ToolCall] = []
        content_text: str | None = None

        for part in response.parts:
            if hasattr(part, "function_call") and part.function_call.name:
                fc = part.function_call
                tool_calls.append(
                    ToolCall(
                        id=fc.name,
                        name=fc.name,
                        arguments=dict(fc.args),
                    )
                )
            elif hasattr(part, "text") and part.text:
                content_text = part.text

        finish_reason = "tool_calls" if tool_calls else "stop"
        usage = {}
        if hasattr(response, "usage_metadata"):
            um = response.usage_metadata
            usage = {
                "prompt_tokens": getattr(um, "prompt_token_count", 0),
                "completion_tokens": getattr(um, "candidates_token_count", 0),
                "total_tokens": getattr(um, "total_token_count", 0),
            }

        return LLMResponse(
            content=content_text,
            tool_calls=tool_calls,
            finish_reason=finish_reason,
            usage=usage,
        )


def _openai_params_to_gemini(params: dict[str, Any]) -> Any:
    """Convert OpenAI parameters schema to Gemini Schema format."""
    try:
        import google.generativeai.protos as protos

        props = {}
        for name, prop in params.get("properties", {}).items():
            type_map = {
                "string": protos.Type.STRING,
                "integer": protos.Type.INTEGER,
                "number": protos.Type.NUMBER,
                "boolean": protos.Type.BOOLEAN,
                "array": protos.Type.ARRAY,
                "object": protos.Type.OBJECT,
            }
            props[name] = protos.Schema(
                type=type_map.get(prop.get("type", "string"), protos.Type.STRING),
                description=prop.get("description", ""),
            )

        return protos.Schema(
            type=protos.Type.OBJECT,
            properties=props,
            required=params.get("required", []),
        )
    except Exception:
        return None
