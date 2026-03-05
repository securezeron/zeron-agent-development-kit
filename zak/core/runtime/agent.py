"""
ZAK Runtime — BaseAgent, AgentContext, AgentResult.

All security agents in ZAK inherit from BaseAgent and receive an AgentContext
at execution time. Results are always wrapped in AgentResult.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from zak.core.dsl.schema import AgentDSL


@dataclass
class AgentContext:
    """
    Runtime context injected into every agent execution.

    Carries tenant identity, trace ID, and the validated DSL for the agent.
    This is the single source of truth for 'who is running, under which tenant,
    with what permissions'.
    """
    tenant_id: str
    trace_id: str
    dsl: AgentDSL
    environment: str = "staging"
    metadata: dict[str, Any] = field(default_factory=dict)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def agent_id(self) -> str:
        return self.dsl.agent.id


@dataclass
class AgentResult:
    """Typed result envelope returned by every agent execution."""
    success: bool
    agent_id: str
    tenant_id: str
    trace_id: str
    output: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    duration_ms: float = 0.0
    completed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def ok(
        cls,
        context: AgentContext,
        output: dict[str, Any],
        duration_ms: float = 0.0,
    ) -> AgentResult:
        return cls(
            success=True,
            agent_id=context.agent_id,
            tenant_id=context.tenant_id,
            trace_id=context.trace_id,
            output=output,
            duration_ms=duration_ms,
        )

    @classmethod
    def fail(
        cls,
        context: AgentContext,
        errors: list[str],
        duration_ms: float = 0.0,
    ) -> AgentResult:
        return cls(
            success=False,
            agent_id=context.agent_id,
            tenant_id=context.tenant_id,
            trace_id=context.trace_id,
            errors=errors,
            duration_ms=duration_ms,
        )


class BaseAgent(abc.ABC):
    """
    Abstract base class for all ZAK security agents.

    Every agent must implement:
    - execute(context) → AgentResult

    Optionally override:
    - pre_run(context)  — setup / validation before main execution
    - post_run(context, result) — cleanup / result enrichment
    """

    @property
    def name(self) -> str:
        return self.__class__.__name__

    def pre_run(self, context: AgentContext) -> None:
        """Optional hook called before execute(). Override for setup logic."""
        pass

    @abc.abstractmethod
    def execute(self, context: AgentContext) -> AgentResult:
        """
        Core agent logic. Must be implemented by every concrete agent.

        Args:
            context: Runtime context with tenant, trace ID, and DSL.

        Returns:
            AgentResult with success status and typed output.
        """

    def post_run(self, context: AgentContext, result: AgentResult) -> None:
        """Optional hook called after execute(). Override for cleanup logic."""
        pass
