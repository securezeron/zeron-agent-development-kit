"""
Tests for the AgentRegistry and @register_agent decorator.
"""

import pytest

from zak.core.runtime.agent import AgentContext, AgentResult, BaseAgent
from zak.core.runtime.registry import AgentRegistry, register_agent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fresh_registry():
    """Return a cleared global registry for test isolation."""
    AgentRegistry.get().clear()
    return AgentRegistry.get()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAgentRegistry:
    def setup_method(self):
        # Each test starts with a clean registry
        AgentRegistry.get().clear()

    def test_register_and_resolve(self):
        reg = fresh_registry()

        @register_agent(domain="test_domain", edition="open-source")
        class TestAgent(BaseAgent):
            def execute(self, context: AgentContext) -> AgentResult:
                return AgentResult.ok(context, output={})

        resolved = reg.resolve("test_domain")
        assert resolved is TestAgent

    def test_decorator_attaches_metadata(self):
        @register_agent(domain="meta_domain", version="2.0.0", edition="open-source")
        class MetaAgent(BaseAgent):
            def execute(self, context: AgentContext) -> AgentResult:
                return AgentResult.ok(context, output={})

        assert MetaAgent._zak_domain == "meta_domain"
        assert MetaAgent._zak_version == "2.0.0"

    def test_resolve_unknown_domain_raises(self):
        reg = fresh_registry()
        with pytest.raises(KeyError, match="no_such_domain"):
            reg.resolve("no_such_domain")

    def test_is_registered_returns_false_for_missing(self):
        reg = fresh_registry()
        assert reg.is_registered("ghost_domain") is False

    def test_is_registered_returns_true_after_registration(self):
        reg = fresh_registry()

        @register_agent(domain="present_domain", edition="open-source")
        class PresentAgent(BaseAgent):
            def execute(self, context: AgentContext) -> AgentResult:
                return AgentResult.ok(context, output={})

        assert reg.is_registered("present_domain") is True

    def test_multiple_registrations_primary_first(self):
        reg = fresh_registry()

        @register_agent(domain="multi_domain", edition="open-source")
        class AgentA(BaseAgent):
            def execute(self, context: AgentContext) -> AgentResult:
                return AgentResult.ok(context, output={})

        @register_agent(domain="multi_domain", edition="open-source")
        class AgentB(BaseAgent):
            def execute(self, context: AgentContext) -> AgentResult:
                return AgentResult.ok(context, output={})

        # Primary is still AgentA (registered first)
        assert reg.resolve("multi_domain") is AgentA
        assert len(reg.resolve_all("multi_domain")) == 2

    def test_override_replaces_primary(self):
        reg = fresh_registry()

        @register_agent(domain="override_domain", edition="open-source")
        class OriginalAgent(BaseAgent):
            def execute(self, context: AgentContext) -> AgentResult:
                return AgentResult.ok(context, output={})

        @register_agent(domain="override_domain", override=True, edition="open-source")
        class NewPrimaryAgent(BaseAgent):
            def execute(self, context: AgentContext) -> AgentResult:
                return AgentResult.ok(context, output={})

        assert reg.resolve("override_domain") is NewPrimaryAgent

    def test_unregister_single_class(self):
        reg = fresh_registry()

        @register_agent(domain="unregister_domain", edition="open-source")
        class ToRemove(BaseAgent):
            def execute(self, context: AgentContext) -> AgentResult:
                return AgentResult.ok(context, output={})

        reg.unregister("unregister_domain", agent_class=ToRemove)
        assert not reg.is_registered("unregister_domain")

    def test_all_domains_sorted(self):
        reg = fresh_registry()

        @register_agent(domain="zzz_domain", edition="open-source")
        class ZAgent(BaseAgent):
            def execute(self, context: AgentContext) -> AgentResult:
                return AgentResult.ok(context, output={})

        @register_agent(domain="aaa_domain", edition="open-source")
        class AAgent(BaseAgent):
            def execute(self, context: AgentContext) -> AgentResult:
                return AgentResult.ok(context, output={})

        domains = reg.all_domains()
        assert domains == sorted(domains)

    def test_summary_not_empty_when_registered(self):
        @register_agent(domain="summary_domain", description="A test agent", edition="open-source")
        class SummaryAgent(BaseAgent):
            def execute(self, context: AgentContext) -> AgentResult:
                return AgentResult.ok(context, output={})

        summary = AgentRegistry.get().summary()
        assert "summary_domain" in summary
        assert "SummaryAgent" in summary
