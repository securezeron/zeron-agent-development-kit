"""
ZAK Agent Registry — decorator-based agent registration and domain discovery.

Design:
- @register_agent(domain) marks a BaseAgent subclass as the handler for a domain
- AgentRegistry is a singleton that holds all registrations
- AgentExecutor uses it to automatically resolve the right class for a DSL domain

Usage:
    from zak.core.runtime.registry import register_agent, AgentRegistry

    @register_agent(domain="risk_quant")
    class MyRiskAgent(BaseAgent):
        def execute(self, context): ...

    # Later — resolve agent class for a domain:
    cls = AgentRegistry.get().resolve("risk_quant")
    agent = cls()
"""

from __future__ import annotations

import inspect
import threading
from typing import TYPE_CHECKING, Any

from zak.core.edition import Edition, EditionError, get_edition

if TYPE_CHECKING:
    pass


class AgentRegistration:
    """Metadata for a single registered agent class."""

    def __init__(
        self,
        domain: str,
        agent_class: type,
        description: str = "",
        version: str = "1.0.0",
        edition: str = "enterprise",
    ) -> None:
        self.domain = domain
        self.agent_class = agent_class
        self.description = description or (inspect.getdoc(agent_class) or "").split("\n")[0]
        self.version = version
        self.edition = edition
        self.module = agent_class.__module__
        self.class_name = agent_class.__name__

    def __repr__(self) -> str:
        return f"<AgentRegistration domain={self.domain!r} class={self.class_name!r} edition={self.edition!r}>"


class _AgentRegistry:
    """
    Singleton agent registry. Holds all @register_agent registrations.

    Do not instantiate directly — use AgentRegistry.get().
    """

    def __init__(self) -> None:
        self._registry: dict[str, list[AgentRegistration]] = {}

    def register(
        self,
        domain: str,
        agent_class: type,
        description: str = "",
        version: str = "1.0.0",
        edition: str = "enterprise",
        override: bool = False,
    ) -> AgentRegistration:
        """
        Register an agent class under a domain.

        Args:
            domain:       Security domain (e.g. 'risk_quant', 'red_team').
            agent_class:  The BaseAgent subclass to register.
            description:  Optional description (defaults to class docstring first line).
            version:      Agent version string.
            edition:      'open-source' or 'enterprise' (default: 'enterprise').
            override:     If True, replaces the primary agent for this domain.
                          If False, the new registration is added as an alternative.

        Returns:
            The created AgentRegistration.
        """
        reg = AgentRegistration(
            domain=domain,
            agent_class=agent_class,
            description=description,
            version=version,
            edition=edition,
        )
        if domain not in self._registry:
            self._registry[domain] = []

        if override:
            self._registry[domain].insert(0, reg)
        else:
            self._registry[domain].append(reg)

        return reg

    def resolve(self, domain: str) -> type:
        """
        Return the primary agent class registered for a domain.

        Raises:
            KeyError:       If no agent is registered for the domain.
            EditionError:   If the agent requires enterprise edition and the current
                            edition is open-source.
        """
        entries = self._registry.get(domain)
        if not entries:
            raise KeyError(
                f"No agent registered for domain '{domain}'. "
                f"Available domains: {list(self._registry.keys())}"
            )
        reg = entries[0]
        if reg.edition == "enterprise" and get_edition() != Edition.ENTERPRISE:
            raise EditionError(
                f"Agent '{domain}' is available in the enterprise edition only. "
                f"Set ZAK_EDITION=enterprise to unlock all 22 agents."
            )
        return reg.agent_class

    def resolve_all(self, domain: str) -> list[AgentRegistration]:
        """Return all registrations for a domain (primary first)."""
        return list(self._registry.get(domain, []))

    def all_domains(self) -> list[str]:
        """Return a sorted list of domains accessible in the current edition."""
        current = get_edition()
        return sorted(
            domain
            for domain, regs in self._registry.items()
            if regs and (current == Edition.ENTERPRISE or regs[0].edition == "open-source")
        )

    def all_registrations(self) -> list[AgentRegistration]:
        """Return a flat list of registrations accessible in the current edition."""
        current = get_edition()
        return [
            reg
            for regs in self._registry.values()
            for reg in regs
            if current == Edition.ENTERPRISE or reg.edition == "open-source"
        ]

    def all_registrations_unfiltered(self) -> list[AgentRegistration]:
        """Return all registrations regardless of edition (for internal/admin use)."""
        return [reg for regs in self._registry.values() for reg in regs]

    def is_registered(self, domain: str) -> bool:
        return domain in self._registry and bool(self._registry[domain])

    def unregister(self, domain: str, agent_class: type | None = None) -> None:
        """
        Remove a registration.

        If agent_class is None, removes all registrations for the domain.
        If agent_class is specified, removes only that class from the domain.
        """
        if domain not in self._registry:
            return
        if agent_class is None:
            del self._registry[domain]
        else:
            self._registry[domain] = [
                r for r in self._registry[domain] if r.agent_class is not agent_class
            ]
            if not self._registry[domain]:
                del self._registry[domain]

    def clear(self) -> None:
        """Clear all registrations. Primarily for use in tests."""
        self._registry.clear()

    def summary(self) -> str:
        """Return a human-readable summary of all registrations."""
        if not self._registry:
            return "No agents registered."
        lines = ["Registered agents:"]
        for domain in self.all_domains():
            regs = self._registry[domain]
            primary = regs[0]
            extras = f" (+{len(regs) - 1} alternatives)" if len(regs) > 1 else ""
            lines.append(f"  {domain:<20} → {primary.class_name}{extras}")
        return "\n".join(lines)


# Global singleton
_registry_instance: _AgentRegistry | None = None
_registry_lock = threading.Lock()


class AgentRegistry:
    """
    Public access point for the global agent registry.

    Usage:
        AgentRegistry.get().resolve("risk_quant")
        AgentRegistry.get().all_domains()
    """

    @staticmethod
    def get() -> _AgentRegistry:
        global _registry_instance
        if _registry_instance is None:
            with _registry_lock:
                if _registry_instance is None:
                    _registry_instance = _AgentRegistry()
        return _registry_instance


def register_agent(
    domain: str,
    *,
    description: str = "",
    version: str = "1.0.0",
    edition: str = "enterprise",
    override: bool = False,
) -> Any:
    """
    Class decorator that registers a BaseAgent subclass with the global AgentRegistry.

    Args:
        domain:      The security domain this agent handles (must match AgentDSL.agent.domain).
        description: Human-readable description (defaults to class docstring).
        version:     Agent version string.
        edition:     'open-source' (available to all) or 'enterprise' (default, gated).
        override:    If True, this agent becomes the primary for the domain,
                     displacing any previously registered primary.

    Example:
        @register_agent(domain="risk_quant", edition="open-source")
        class MyRiskAgent(BaseAgent):
            def execute(self, context: AgentContext) -> AgentResult:
                ...
    """
    def decorator(cls: type) -> type:
        AgentRegistry.get().register(
            domain=domain,
            agent_class=cls,
            description=description,
            version=version,
            edition=edition,
            override=override,
        )
        # Attach metadata to the class itself for introspection
        cls._zak_domain = domain
        cls._zak_version = version
        cls._zak_edition = edition
        return cls

    return decorator
