"""
ZAK Policy Engine — pure-Python in-process policy enforcement.

Evaluates agent actions against a set of rules derived from the AgentDSL boundaries
and safety config. No external OPA dependency in Phase 1.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from zak.core.dsl.schema import AgentDSL, AutonomyLevel, Domain, RiskBudget


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str

    @classmethod
    def permit(cls, reason: str = "Action permitted by policy") -> PolicyDecision:
        return cls(allowed=True, reason=reason)

    @classmethod
    def deny(cls, reason: str) -> PolicyDecision:
        return cls(allowed=False, reason=reason)


class PolicyEngine:
    """
    Evaluates whether an action is permitted for a given agent in a tenant context.

    Rules applied in order (first deny wins):
    1. Explicit deny-list check
    2. Explicit allow-list check (if allow-list is non-empty)
    3. Autonomy level constraints
    4. Risk budget constraints
    5. Environment scope constraints
    6. Offensive agent safety constraints
    """

    def evaluate(
        self,
        dsl: AgentDSL,
        action: str,
        environment: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """
        Evaluate whether `action` is permitted under `dsl` constraints.

        Args:
            dsl:         The agent's parsed DSL definition.
            action:      Identifier of the action being requested.
            environment: Environment the action targets (e.g. 'production').
            metadata:    Optional additional context (unused in Phase 1, reserved for OPA).

        Returns:
            PolicyDecision with allowed=True/False and a human-readable reason.
        """
        boundaries = dsl.boundaries

        # Rule 1 — Explicit deny-list (always wins)
        if action in boundaries.denied_actions:
            return PolicyDecision.deny(
                f"Action '{action}' is explicitly denied by agent boundaries."
            )

        # Rule 2 — Explicit allow-list (if defined, action must be in it)
        if boundaries.allowed_actions and action not in boundaries.allowed_actions:
            return PolicyDecision.deny(
                f"Action '{action}' is not in the agent's allow-list. "
                f"Allowed: {boundaries.allowed_actions}"
            )

        # Rule 3 — Observe-only agents cannot write/mutate anything
        if dsl.reasoning.autonomy_level == AutonomyLevel.OBSERVE:
            mutating_verbs = ("write", "delete", "update", "create", "modify", "execute")
            if any(action.lower().startswith(v) for v in mutating_verbs):
                return PolicyDecision.deny(
                    f"Action '{action}' is a mutating operation. "
                    "Agents with autonomy_level 'observe' are read-only."
                )

        # Rule 4 — Risk budget: high-budget actions require sufficient risk budget
        high_risk_actions = ("execute_exploit", "deploy_payload", "modify_production")
        if action in high_risk_actions and boundaries.risk_budget == RiskBudget.LOW:
            return PolicyDecision.deny(
                f"Action '{action}' requires at least risk_budget: medium. "
                f"Current budget: {boundaries.risk_budget.value}"
            )

        # Rule 5 — Environment scope
        if environment and boundaries.environment_scope:
            if environment not in boundaries.environment_scope:
                return PolicyDecision.deny(
                    f"Environment '{environment}' is not in scope for this agent. "
                    f"Allowed environments: {boundaries.environment_scope}"
                )

        # Rule 6 — Offensive agents: production access denied unless explicitly scoped
        if dsl.agent.domain == Domain.RED_TEAM:
            if environment == "production" and "production" not in boundaries.environment_scope:
                return PolicyDecision.deny(
                    "Red team agents are not permitted to target production "
                    "unless 'production' is explicitly in environment_scope."
                )

        return PolicyDecision.permit()

    def check_approval_gate(self, dsl: AgentDSL, action: str) -> bool:
        """Returns True if `action` requires human approval before execution."""
        return action in dsl.boundaries.approval_gates
