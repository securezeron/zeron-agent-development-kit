"""
Tests for the dep-patch agent — tool functions, semver logic, and agent execution.
"""

import yaml

from zak.core.dsl.schema import AgentDSL
from zak.core.runtime.agent import AgentContext
from zak.core.tools.substrate import ToolRegistry

# Import tools to trigger @zak_tool registration
import zak.agents.dep_patch.tools as dep_tools  # noqa: F401
from zak.agents.dep_patch.tools import (
    _get_range_type,
    _is_prerelease,
    _is_valid_semver,
    _parse_version,
    _satisfies_range,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

DEP_PATCH_YAML = """
agent:
  id: dep-patch-test
  name: "Dep Patch Test Agent"
  domain: supply_chain
  version: "1.0.0"

intent:
  goal: "Test dep patch"

reasoning:
  mode: deterministic
  autonomy_level: bounded

capabilities:
  tools:
    - fetch_package_json
    - parse_dependencies
    - fetch_registry_versions
    - find_compatible_updates
    - assess_update_risks
    - create_update_pr

boundaries:
  risk_budget: medium
  allowed_actions:
    - agent_execute
    - fetch_package_json
    - parse_dependencies
    - fetch_registry_versions
    - find_compatible_updates
    - assess_update_risks
    - create_update_pr

safety:
  sandbox_profile: standard
  audit_level: standard
"""


def make_context(
    yaml_str: str = DEP_PATCH_YAML,
    metadata: dict | None = None,
) -> AgentContext:
    dsl = AgentDSL.model_validate(yaml.safe_load(yaml_str))
    return AgentContext(
        tenant_id="test-tenant",
        trace_id="trace-dep-001",
        dsl=dsl,
        environment="staging",
        metadata=metadata or {
            "owner": "testorg",
            "repo": "testrepo",
            "github_token": "ghp_test123",
            "dry_run": True,
        },
    )


# ---------------------------------------------------------------------------
# Tests: Internal helpers
# ---------------------------------------------------------------------------


class TestParseVersion:
    def test_valid_semver(self) -> None:
        assert _parse_version("1.2.3") == (1, 2, 3)

    def test_zero_version(self) -> None:
        assert _parse_version("0.0.0") == (0, 0, 0)

    def test_large_version(self) -> None:
        assert _parse_version("12.34.56") == (12, 34, 56)

    def test_prerelease_version(self) -> None:
        assert _parse_version("1.0.0-beta.1") == (1, 0, 0)

    def test_build_metadata(self) -> None:
        assert _parse_version("1.0.0+build.123") == (1, 0, 0)

    def test_invalid_returns_none(self) -> None:
        assert _parse_version("not-a-version") is None

    def test_partial_returns_none(self) -> None:
        assert _parse_version("1.2") is None


class TestIsValidSemver:
    def test_valid(self) -> None:
        assert _is_valid_semver("1.2.3") is True

    def test_prerelease_is_valid(self) -> None:
        assert _is_valid_semver("1.0.0-alpha.1") is True

    def test_invalid(self) -> None:
        assert _is_valid_semver("latest") is False


class TestIsPrerelease:
    def test_not_prerelease(self) -> None:
        assert _is_prerelease("1.2.3") is False

    def test_is_prerelease(self) -> None:
        assert _is_prerelease("1.2.3-beta.1") is True

    def test_alpha(self) -> None:
        assert _is_prerelease("2.0.0-alpha") is True


# ---------------------------------------------------------------------------
# Tests: Range classification
# ---------------------------------------------------------------------------


class TestGetRangeType:
    def test_caret(self) -> None:
        assert _get_range_type("^1.2.3") == "caret"

    def test_tilde(self) -> None:
        assert _get_range_type("~1.2.3") == "tilde"

    def test_exact(self) -> None:
        assert _get_range_type("1.2.3") == "exact"

    def test_star(self) -> None:
        assert _get_range_type("*") == "any"

    def test_latest(self) -> None:
        assert _get_range_type("latest") == "any"

    def test_complex_or(self) -> None:
        assert _get_range_type(">=1.0.0 || <2.0.0") == "complex"

    def test_complex_gte(self) -> None:
        assert _get_range_type(">=1.0.0") == "complex"

    def test_complex_hyphen(self) -> None:
        assert _get_range_type("1.0.0 - 2.0.0") == "complex"

    def test_git_url(self) -> None:
        assert _get_range_type("git+https://github.com/user/repo") == "non_registry"

    def test_file_url(self) -> None:
        assert _get_range_type("file:../my-lib") == "non_registry"

    def test_link(self) -> None:
        assert _get_range_type("link:../my-lib") == "non_registry"

    def test_workspace(self) -> None:
        assert _get_range_type("workspace:*") == "non_registry"

    def test_github_shorthand(self) -> None:
        assert _get_range_type("user/repo") == "non_registry"

    def test_http_url(self) -> None:
        assert _get_range_type("https://example.com/pkg.tgz") == "non_registry"


# ---------------------------------------------------------------------------
# Tests: Semver range satisfaction
# ---------------------------------------------------------------------------


class TestSatisfiesRange:
    # Caret ranges
    def test_caret_patch_satisfies(self) -> None:
        assert _satisfies_range("1.2.4", "^1.2.3", "caret") is True

    def test_caret_minor_satisfies(self) -> None:
        assert _satisfies_range("1.3.0", "^1.2.3", "caret") is True

    def test_caret_major_does_not_satisfy(self) -> None:
        assert _satisfies_range("2.0.0", "^1.2.3", "caret") is False

    def test_caret_below_base_does_not_satisfy(self) -> None:
        assert _satisfies_range("1.2.2", "^1.2.3", "caret") is False

    def test_caret_zero_major(self) -> None:
        # ^0.2.3: >= 0.2.3 and < 0.3.0
        assert _satisfies_range("0.2.5", "^0.2.3", "caret") is True
        assert _satisfies_range("0.3.0", "^0.2.3", "caret") is False

    def test_caret_zero_zero(self) -> None:
        # ^0.0.3: only 0.0.3
        assert _satisfies_range("0.0.3", "^0.0.3", "caret") is True
        assert _satisfies_range("0.0.4", "^0.0.3", "caret") is False

    # Tilde ranges
    def test_tilde_patch_satisfies(self) -> None:
        assert _satisfies_range("1.1.1", "~1.1.0", "tilde") is True

    def test_tilde_minor_does_not_satisfy(self) -> None:
        assert _satisfies_range("1.2.0", "~1.1.0", "tilde") is False

    def test_tilde_major_does_not_satisfy(self) -> None:
        assert _satisfies_range("2.0.0", "~1.1.0", "tilde") is False

    def test_tilde_below_base_does_not_satisfy(self) -> None:
        assert _satisfies_range("1.0.9", "~1.1.0", "tilde") is False

    # Any
    def test_any_always_satisfies(self) -> None:
        assert _satisfies_range("99.99.99", "*", "any") is True

    # Complex (not supported)
    def test_complex_returns_false(self) -> None:
        assert _satisfies_range("1.0.0", ">=1.0.0", "complex") is False


# ---------------------------------------------------------------------------
# Tests: parse_dependencies tool
# ---------------------------------------------------------------------------


class TestParseDependencies:
    def setup_method(self) -> None:
        ToolRegistry.get().clear()
        import importlib
        importlib.reload(dep_tools)

    def test_caret_classified(self) -> None:
        ctx = make_context()
        pkg = {"dependencies": {"pkg-a": "^1.2.3"}}
        result = dep_tools.parse_dependencies(context=ctx, package_json=pkg)
        assert len(result) == 1
        assert result[0]["range_type"] == "caret"
        assert result[0]["is_updatable"] is True

    def test_tilde_classified(self) -> None:
        ctx = make_context()
        pkg = {"dependencies": {"pkg-b": "~1.1.0"}}
        result = dep_tools.parse_dependencies(context=ctx, package_json=pkg)
        assert result[0]["range_type"] == "tilde"
        assert result[0]["is_updatable"] is True

    def test_exact_classified(self) -> None:
        ctx = make_context()
        pkg = {"dependencies": {"pkg-c": "1.0.0"}}
        result = dep_tools.parse_dependencies(context=ctx, package_json=pkg)
        assert result[0]["range_type"] == "exact"
        assert result[0]["is_updatable"] is False

    def test_non_registry_classified(self) -> None:
        ctx = make_context()
        pkg = {"dependencies": {"my-lib": "file:../my-lib"}}
        result = dep_tools.parse_dependencies(context=ctx, package_json=pkg)
        assert result[0]["range_type"] == "non_registry"
        assert result[0]["is_updatable"] is False

    def test_both_sections_parsed(self) -> None:
        ctx = make_context()
        pkg = {
            "dependencies": {"pkg-a": "^1.0.0"},
            "devDependencies": {"pkg-b": "~2.0.0"},
        }
        result = dep_tools.parse_dependencies(context=ctx, package_json=pkg)
        assert len(result) == 2
        sections = {r["section"] for r in result}
        assert sections == {"dependencies", "devDependencies"}

    def test_empty_package_json(self) -> None:
        ctx = make_context()
        result = dep_tools.parse_dependencies(context=ctx, package_json={})
        assert result == []


# ---------------------------------------------------------------------------
# Tests: find_compatible_updates tool
# ---------------------------------------------------------------------------


class TestFindCompatibleUpdates:
    def setup_method(self) -> None:
        ToolRegistry.get().clear()
        import importlib
        importlib.reload(dep_tools)

    def test_caret_finds_minor_update(self) -> None:
        ctx = make_context()
        dep = {"name": "pkg-a", "range": "^1.2.3", "range_type": "caret"}
        versions = ["1.2.3", "1.2.5", "1.3.0", "2.0.0"]
        result = dep_tools.find_compatible_updates(
            context=ctx, dep=dep, available_versions=versions,
        )
        assert result["latest_compatible"] == "1.3.0"
        assert result["update_type"] == "minor"
        assert result["new_range"] == "^1.3.0"

    def test_caret_finds_patch_update(self) -> None:
        ctx = make_context()
        dep = {"name": "pkg-a", "range": "^1.2.3", "range_type": "caret"}
        versions = ["1.2.3", "1.2.5"]
        result = dep_tools.find_compatible_updates(
            context=ctx, dep=dep, available_versions=versions,
        )
        assert result["latest_compatible"] == "1.2.5"
        assert result["update_type"] == "patch"
        assert result["new_range"] == "^1.2.5"

    def test_tilde_stays_within_minor(self) -> None:
        ctx = make_context()
        dep = {"name": "pkg-b", "range": "~1.2.3", "range_type": "tilde"}
        versions = ["1.2.3", "1.2.5", "1.3.0"]
        result = dep_tools.find_compatible_updates(
            context=ctx, dep=dep, available_versions=versions,
        )
        assert result["latest_compatible"] == "1.2.5"
        assert result["update_type"] == "patch"
        assert result["new_range"] == "~1.2.5"

    def test_exact_returns_locked(self) -> None:
        ctx = make_context()
        dep = {"name": "pkg-c", "range": "1.0.0", "range_type": "exact"}
        result = dep_tools.find_compatible_updates(
            context=ctx, dep=dep, available_versions=["1.0.1"],
        )
        assert result["update_type"] == "locked"

    def test_non_registry_returns_skipped(self) -> None:
        ctx = make_context()
        dep = {"name": "my-lib", "range": "file:../lib", "range_type": "non_registry"}
        result = dep_tools.find_compatible_updates(
            context=ctx, dep=dep, available_versions=[],
        )
        assert result["update_type"] == "skipped"

    def test_no_new_versions(self) -> None:
        ctx = make_context()
        dep = {"name": "pkg-a", "range": "^1.2.3", "range_type": "caret"}
        versions = ["1.2.3"]
        result = dep_tools.find_compatible_updates(
            context=ctx, dep=dep, available_versions=versions,
        )
        assert result["update_type"] == "none"

    def test_prereleases_excluded(self) -> None:
        ctx = make_context()
        dep = {"name": "pkg-a", "range": "^1.0.0", "range_type": "caret"}
        versions = ["1.0.0", "1.1.0-beta.1", "1.0.1"]
        result = dep_tools.find_compatible_updates(
            context=ctx, dep=dep, available_versions=versions,
        )
        assert result["latest_compatible"] == "1.0.1"
        assert result["update_type"] == "patch"

    def test_new_range_preserves_caret_prefix(self) -> None:
        ctx = make_context()
        dep = {"name": "pkg", "range": "^2.0.0", "range_type": "caret"}
        versions = ["2.0.0", "2.1.0"]
        result = dep_tools.find_compatible_updates(
            context=ctx, dep=dep, available_versions=versions,
        )
        assert result["new_range"].startswith("^")

    def test_new_range_preserves_tilde_prefix(self) -> None:
        ctx = make_context()
        dep = {"name": "pkg", "range": "~2.0.0", "range_type": "tilde"}
        versions = ["2.0.0", "2.0.5"]
        result = dep_tools.find_compatible_updates(
            context=ctx, dep=dep, available_versions=versions,
        )
        assert result["new_range"].startswith("~")

    def test_empty_versions_list(self) -> None:
        ctx = make_context()
        dep = {"name": "pkg", "range": "^1.0.0", "range_type": "caret"}
        result = dep_tools.find_compatible_updates(
            context=ctx, dep=dep, available_versions=[],
        )
        assert result["update_type"] == "none"
        assert result["latest_compatible"] is None


# ---------------------------------------------------------------------------
# Tests: Agent registration
# ---------------------------------------------------------------------------


class TestDepPatchRegistration:
    def test_agent_registered_under_supply_chain(self) -> None:
        from zak.core.runtime.registry import AgentRegistry
        # Import agent module to trigger registration
        import zak.agents.dep_patch.agent  # noqa: F401
        registry = AgentRegistry.get()
        assert registry.is_registered("supply_chain")

    def test_agent_is_open_source(self) -> None:
        from zak.core.runtime.registry import AgentRegistry
        import zak.agents.dep_patch.agent  # noqa: F401
        registry = AgentRegistry.get()
        regs = registry.resolve_all("supply_chain")
        assert len(regs) >= 1
        assert regs[0].edition == "open-source"

    def test_agent_class_name(self) -> None:
        from zak.agents.dep_patch.agent import DepPatchAgent
        assert DepPatchAgent.__name__ == "DepPatchAgent"


# ---------------------------------------------------------------------------
# Tests: YAML template validation
# ---------------------------------------------------------------------------


class TestDepPatchYamlValidation:
    def test_yaml_validates_against_schema(self) -> None:
        from zak.core.dsl.parser import validate_agent
        result = validate_agent(
            "agent_templates/dep_patch.yaml",
        )
        assert result.valid, f"Validation errors: {result.errors}"

    def test_yaml_has_correct_domain(self) -> None:
        from zak.core.dsl.parser import load_agent_yaml
        dsl = load_agent_yaml("agent_templates/dep_patch.yaml")
        assert dsl.agent.domain.value == "supply_chain"
