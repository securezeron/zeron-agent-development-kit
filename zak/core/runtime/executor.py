"""
ZAK AgentExecutor — orchestrates the full agent lifecycle:
  pre_run → ([policy check] → execute) → post_run → audit

The executor is the only place where policy enforcement and audit emission happen.
Agents themselves are never responsible for these cross-cutting concerns.
"""

from __future__ import annotations

import time

from zak.core.audit.events import (
    AgentCompletedEvent,
    AgentFailedEvent,
    AgentStartedEvent,
    AuditEventType,
    PolicyBlockedEvent,
)
from zak.core.audit.logger import AuditLogger
from zak.core.policy.engine import PolicyDecision, PolicyEngine
from zak.core.runtime.agent import AgentContext, AgentResult, BaseAgent
from zak.tenants.context import TenantContext, TenantRegistry


class AgentExecutor:
    """
    Executes an agent within a tenant-scoped context.

    Flow:
      1. Emit agent.started audit event
      2. Call agent.pre_run()
      3. Evaluate pre-execution policy
      4. Call agent.execute()
      5. Call agent.post_run()
      6. Emit agent.completed or agent.failed audit event

    Usage:
        executor = AgentExecutor()
        result = executor.run(my_agent, context)
    """

    def __init__(self) -> None:
        self._policy = PolicyEngine()

    def run(self, agent: BaseAgent, context: AgentContext) -> AgentResult:
        """Execute `agent` within `context`, enforcing policy and emitting audit events."""
        # Block deactivated tenants before any work or audit
        registry = TenantRegistry.get()
        if registry.exists(context.tenant_id):
            tenant_ctx = TenantContext(
                tenant_id=context.tenant_id,
                trace_id=context.trace_id,
                environment=context.environment,
            )
            tenant_ctx.assert_active(registry)

        logger = AuditLogger(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            trace_id=context.trace_id,
        )

        logger.emit(AgentStartedEvent(
            agent_id=context.agent_id,
            tenant_id=context.tenant_id,
            trace_id=context.trace_id,
            payload={"domain": context.dsl.agent.domain.value, "version": context.dsl.agent.version},
        ))

        start = time.monotonic()

        try:
            # Pre-run hook
            agent.pre_run(context)

            # Pre-execution policy evaluation
            policy_check = self._policy.evaluate(
                dsl=context.dsl,
                action="agent_execute",
                environment=context.environment,
            )
            if not policy_check.allowed:
                logger.emit(PolicyBlockedEvent(
                    agent_id=context.agent_id,
                    tenant_id=context.tenant_id,
                    trace_id=context.trace_id,
                    action="agent_execute",
                    reason=policy_check.reason,
                ))
                duration_ms = (time.monotonic() - start) * 1000
                return AgentResult.fail(context, errors=[f"Policy denied: {policy_check.reason}"], duration_ms=duration_ms)

            # Main execution
            result = agent.execute(context)
            result.duration_ms = (time.monotonic() - start) * 1000

            # Post-run hook
            agent.post_run(context, result)

            if result.success:
                logger.emit(AgentCompletedEvent(
                    agent_id=context.agent_id,
                    tenant_id=context.tenant_id,
                    trace_id=context.trace_id,
                    success=True,
                    duration_ms=result.duration_ms,
                ))
            else:
                logger.emit(AgentFailedEvent(
                    agent_id=context.agent_id,
                    tenant_id=context.tenant_id,
                    trace_id=context.trace_id,
                    error="; ".join(result.errors),
                ))

            return result

        except Exception as exc:
            duration_ms = (time.monotonic() - start) * 1000
            logger.emit(AgentFailedEvent(
                agent_id=context.agent_id,
                tenant_id=context.tenant_id,
                trace_id=context.trace_id,
                error=str(exc),
            ))
            return AgentResult.fail(context, errors=[str(exc)], duration_ms=duration_ms)

    def check_action(
        self, context: AgentContext, action: str, environment: str | None = None
    ) -> PolicyDecision:
        """
        Mid-execution policy check for a specific action (callable from within agents).

        Agents should call this before performing sensitive operations.
        """
        logger = AuditLogger(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            trace_id=context.trace_id,
        )
        decision = self._policy.evaluate(
            dsl=context.dsl,
            action=action,
            environment=environment or context.environment,
        )
        if decision.allowed:
            logger.log_raw(AuditEventType.POLICY_ALLOWED, action=action)
        else:
            logger.emit(PolicyBlockedEvent(
                agent_id=context.agent_id,
                tenant_id=context.tenant_id,
                trace_id=context.trace_id,
                action=action,
                reason=decision.reason,
            ))
        return decision
