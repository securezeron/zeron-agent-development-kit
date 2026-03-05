"""
Tests for edition gating — OSS vs Enterprise access control.
"""

from __future__ import annotations

import os

import pytest

from zak.core.edition import Edition, EditionError, get_edition
from zak.core.runtime.agent import AgentContext, AgentResult, BaseAgent
from zak.core.runtime.registry import AgentRegistry, register_agent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fresh_registry():
    AgentRegistry.get().clear()
    return AgentRegistry.get()


# ---------------------------------------------------------------------------
# get_edition() — env var parsing
# ---------------------------------------------------------------------------

class TestGetEdition:
    def test_defaults_to_open_source(self, monkeypatch):
        monkeypatch.delenv("ZAK_EDITION", raising=False)
        assert get_edition() == Edition.OPEN_SOURCE

    def test_enterprise_exact(self, monkeypatch):
        monkeypatch.setenv("ZAK_EDITION", "enterprise")
        assert get_edition() == Edition.ENTERPRISE

    def test_enterprise_shorthand(self, monkeypatch):
        monkeypatch.setenv("ZAK_EDITION", "ent")
        assert get_edition() == Edition.ENTERPRISE

    def test_enterprise_uppercase(self, monkeypatch):
        monkeypatch.setenv("ZAK_EDITION", "ENTERPRISE")
        assert get_edition() == Edition.ENTERPRISE

    def test_unknown_value_defaults_to_open_source(self, monkeypatch):
        monkeypatch.setenv("ZAK_EDITION", "community")
        assert get_edition() == Edition.OPEN_SOURCE


# ---------------------------------------------------------------------------
# Registry edition filtering
# ---------------------------------------------------------------------------

class TestRegistryEditionFiltering:
    def setup_method(self):
        AgentRegistry.get().clear()

    def _register_pair(self):
        """Register one OSS and one enterprise agent."""
        @register_agent(domain="oss_domain", edition="open-source")
        class OSSAgent(BaseAgent):
            def execute(self, context: AgentContext) -> AgentResult:
                return AgentResult.ok(context, output={})

        @register_agent(domain="ent_domain", edition="enterprise")
        class EntAgent(BaseAgent):
            def execute(self, context: AgentContext) -> AgentResult:
                return AgentResult.ok(context, output={})

        return OSSAgent, EntAgent

    def test_oss_edition_sees_only_oss_domains(self, monkeypatch):
        monkeypatch.setenv("ZAK_EDITION", "open-source")
        self._register_pair()
        reg = AgentRegistry.get()

        domains = reg.all_domains()
        assert "oss_domain" in domains
        assert "ent_domain" not in domains

    def test_enterprise_edition_sees_all_domains(self, monkeypatch):
        monkeypatch.setenv("ZAK_EDITION", "enterprise")
        self._register_pair()
        reg = AgentRegistry.get()

        domains = reg.all_domains()
        assert "oss_domain" in domains
        assert "ent_domain" in domains

    def test_oss_resolve_enterprise_agent_raises_edition_error(self, monkeypatch):
        monkeypatch.setenv("ZAK_EDITION", "open-source")
        self._register_pair()
        reg = AgentRegistry.get()

        with pytest.raises(EditionError):
            reg.resolve("ent_domain")

    def test_enterprise_resolve_enterprise_agent_succeeds(self, monkeypatch):
        monkeypatch.setenv("ZAK_EDITION", "enterprise")
        self._register_pair()
        reg = AgentRegistry.get()

        _, EntAgent = self._register_pair()  # re-register to get reference
        # resolve should not raise
        resolved = reg.resolve("ent_domain")
        assert resolved is not None

    def test_edition_error_message_mentions_enterprise(self, monkeypatch):
        monkeypatch.setenv("ZAK_EDITION", "open-source")

        @register_agent(domain="locked_domain", edition="enterprise")
        class LockedAgent(BaseAgent):
            def execute(self, context: AgentContext) -> AgentResult:
                return AgentResult.ok(context, output={})

        reg = AgentRegistry.get()
        with pytest.raises(EditionError, match="enterprise"):
            reg.resolve("locked_domain")

    def test_all_registrations_filtered_by_edition(self, monkeypatch):
        monkeypatch.setenv("ZAK_EDITION", "open-source")
        self._register_pair()
        reg = AgentRegistry.get()

        registrations = reg.all_registrations()
        edition_values = {r.edition for r in registrations}
        assert "open-source" in edition_values
        assert "enterprise" not in edition_values

    def test_oss_agent_accessible_on_enterprise_edition(self, monkeypatch):
        monkeypatch.setenv("ZAK_EDITION", "enterprise")

        @register_agent(domain="shared_oss", edition="open-source")
        class SharedOSSAgent(BaseAgent):
            def execute(self, context: AgentContext) -> AgentResult:
                return AgentResult.ok(context, output={})

        reg = AgentRegistry.get()
        resolved = reg.resolve("shared_oss")
        assert resolved is SharedOSSAgent
