"""
ZAK LLM — Mock provider for demonstrations and testing.
"""

from __future__ import annotations

import json
from typing import Any
from zak.core.llm.base import LLMClient, LLMResponse, ToolCall

class MockLLMClient(LLMClient):
    """Mock LLM provider that simulates a DPDP audit or generic responses."""

    def __init__(self, model: str | None = None, api_key: str | None = None) -> None:
        self.model = model or "mock-model"

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int = 4096,
        temperature: float = 0.2,
    ) -> LLMResponse:
        # Check if we are in the DPDP flow
        last_message = messages[-1]["content"] if messages else ""
        
        # Step 1: LLM decides to fetch content
        if "fetch_website_content" in str(tools) and not any(m.get("role") == "tool" for m in messages):
            # Extract URL if possible or just use a generic one
            target_url = "https://www.snaplogic.com/privacy-policy"
            return LLMResponse(
                content="I need to examine the privacy policy to assess DPDP compliance. I will fetch the content now.",
                tool_calls=[
                    ToolCall(
                        id="call_" + json.dumps(target_url)[:10],
                        name="fetch_website_content",
                        arguments={"url": target_url}
                    )
                ],
                finish_reason="tool_calls",
                usage={"total_tokens": 100}
            )

        # Step 2: Tool result is in messages, now provide the "analysis"
        if any(m.get("role") == "tool" for m in messages):
            analysis = """
### DPDP COMPLIANCE AUDIT REPORT: SNAPLOGIC
**Target:** https://www.snaplogic.com/privacy-policy
**Status:** Partially Compliant

#### 1. Notice: COMPLIANT
SnapLogic provides a detailed Privacy Policy that explicitly lists categories of personal data collected, including contact information and usage data. The purpose (service delivery, marketing) is clearly stated.

#### 2. Consent: PARTIALLY COMPLIANT
The website uses a cookie banner for consent, but the granularity of "specific and informed" consent for different processing activities (like cross-border transfer) under DPDP Sec 6 could be clearer.

#### 3. Individual Rights: COMPLIANT
The policy mentions rights to access, correction, and deletion. Users can contact `privacy@snaplogic.com` to exercise these rights.

#### 4. Withdrawal: COMPLIANT
The policy states that users can withdraw consent at any time by contacting the privacy team or using opt-out links.

#### 5. Grievance Redressal: NON-COMPLIANT
While a privacy email is provided, there is no explicit mention of an India-based Grievance Officer or DPO as expected for entities processing Indian data subjects' data under DPDP.

#### 6. Minor's Data: NON-COMPLIANT
The policy states the services are not for children but does not detail a verifiable parental consent mechanism for Indian minors (under 18).

**Overall Score: 72/100**
**Remediation:**
1. Appoint and name an India-specific Grievance Officer.
2. Implement verifiable parental consent for users in India.
"""
            return LLMResponse(
                content=analysis,
                tool_calls=[],
                finish_reason="stop",
                usage={"total_tokens": 500}
            )

        # Default fallback
        return LLMResponse(
            content="I am a mock agent. I have received your request and I am ready to assist.",
            tool_calls=[],
            finish_reason="stop",
            usage={"total_tokens": 50}
        )
