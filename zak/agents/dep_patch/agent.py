"""
Dependency Patch Agent — ZAK supply chain security agent.

Scans a GitHub repository's package.json for compatible dependency updates
(patch/minor within semver range), assesses risk via LLM, and creates a PR.

This agent supports two execution modes:

  reasoning.mode: deterministic  (default)
    -> Sequential fetch -> parse -> check -> assess -> PR pipeline.
    -> Identical behavior on every run for the same input.

  reasoning.mode: llm_react
    -> Uses an LLM in a ReAct loop with the same tools.
    -> LLM decides which dependencies to update and how to assess risk.
    -> Produces natural language summary alongside structured output.
    -> Requires LLM provider env vars (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.).
"""

from __future__ import annotations

import copy
import json
import os
from datetime import datetime, timezone

from zak.core.dsl.schema import ReasoningMode
from zak.core.runtime.agent import AgentContext, AgentResult, BaseAgent
from zak.core.runtime.registry import register_agent
from zak.core.tools.substrate import ToolExecutor


@register_agent(
    domain="supply_chain",
    description="Scans dependencies for compatible updates and creates GitHub PRs",
    version="1.0.0",
    edition="open-source",
)
class DepPatchAgent(BaseAgent):
    """
    Dependency patch/minor update agent for supply chain security.

    Fetches package.json from GitHub, finds compatible updates within
    semver ranges, assesses risk via LLM, and optionally creates a PR.

    Configuration is read from ``context.metadata`` with env-var fallbacks.
    See ``tools.py`` for the full config key table.
    """

    def execute(self, context: AgentContext) -> AgentResult:
        if context.dsl.reasoning.mode == ReasoningMode.LLM_REACT:
            return self._execute_llm(context)
        return self._execute_deterministic(context)

    # ── Deterministic execution ──────────────────────────────────────────

    def _execute_deterministic(self, context: AgentContext) -> AgentResult:
        from zak.agents.dep_patch.tools import (
            assess_update_risks,
            create_update_pr,
            fetch_package_json,
            fetch_registry_versions,
            find_compatible_updates,
            parse_dependencies,
        )

        metadata = context.metadata
        dry_run = metadata.get("dry_run", os.environ.get("DEP_PATCH_DRY_RUN", "")).lower() in (
            "true", "1", "yes",
        ) if isinstance(metadata.get("dry_run"), str) else bool(metadata.get("dry_run", False))

        # 1. Fetch package.json
        try:
            pkg_result = ToolExecutor.call(
                fetch_package_json, context=context,
            )
        except Exception as e:
            return AgentResult.fail(context, errors=[f"Failed to fetch package.json: {e}"])

        package_json = pkg_result["content"]
        sha = pkg_result["sha"]
        default_branch = pkg_result["default_branch"]
        package_path = pkg_result.get("package_path", "package.json")

        # 2. Parse dependencies
        deps = ToolExecutor.call(parse_dependencies, context=context, package_json=package_json)
        updatable_deps = [d for d in deps if d["is_updatable"]]
        non_updatable_deps = [d for d in deps if not d["is_updatable"]]

        # 3. Check registry for updates
        results: list[dict] = []

        # Non-updatable: pass through with empty versions
        for dep in non_updatable_deps:
            result = ToolExecutor.call(
                find_compatible_updates, context=context,
                dep=dep, available_versions=[],
            )
            results.append(result)

        # Updatable: fetch versions then find updates (batched)
        batch_size = 10
        for i in range(0, len(updatable_deps), batch_size):
            batch = updatable_deps[i:i + batch_size]
            for dep in batch:
                versions_result = ToolExecutor.call(
                    fetch_registry_versions, context=context,
                    package_name=dep["name"],
                )
                if versions_result.get("error"):
                    results.append({
                        "name": dep["name"],
                        "current_range": dep["range"],
                        "current_version": None,
                        "latest_compatible": None,
                        "new_range": None,
                        "update_type": "skipped",
                        "risk": None,
                        "risk_reason": versions_result["error"],
                    })
                    continue
                update_result = ToolExecutor.call(
                    find_compatible_updates, context=context,
                    dep=dep, available_versions=versions_result["versions"],
                )
                results.append(update_result)

        # 4. Filter for risk assessment
        updatable_results = [
            r for r in results if r.get("update_type") in ("patch", "minor")
        ]

        # 5. Risk assessment
        assessed_updates: list[dict] = []
        if updatable_results:
            assessed_updates = ToolExecutor.call(
                assess_update_risks, context=context, updates=updatable_results,
            )
            # Merge assessed results back into main results
            assessed_by_name = {a["name"]: a for a in assessed_updates}
            for i, r in enumerate(results):
                if r.get("name") in assessed_by_name:
                    results[i] = assessed_by_name[r["name"]]

        # 6. Build summary
        summary: dict = {
            "total_dependencies": len(deps),
            "updatable": len([
                r for r in results
                if r.get("update_type") in ("patch", "minor", "major")
            ]),
            "up_to_date": len([r for r in results if r.get("update_type") == "none"]),
            "locked": len([r for r in results if r.get("update_type") == "locked"]),
            "skipped": len([r for r in results if r.get("update_type") == "skipped"]),
            "updates": results,
        }

        # 7. Dry run or no updates — return early
        if dry_run:
            summary["pr"] = None
            summary["mode"] = "dry_run"
            return AgentResult.ok(context, output=summary)

        if not assessed_updates:
            summary["pr"] = None
            summary["mode"] = "no_updates"
            return AgentResult.ok(context, output=summary)

        # 8. Build updated package.json
        updated_pj = copy.deepcopy(package_json)
        for update in assessed_updates:
            new_range = update.get("new_range")
            if not new_range:
                continue
            pkg_name = update["name"]
            if pkg_name in (updated_pj.get("dependencies") or {}):
                updated_pj["dependencies"][pkg_name] = new_range
            if pkg_name in (updated_pj.get("devDependencies") or {}):
                updated_pj["devDependencies"][pkg_name] = new_range

        # 9. Create PR
        owner = metadata.get("owner", "")
        repo = metadata.get("repo", "")
        if not owner or not repo:
            repo_full = metadata.get(
                "repo_full", os.environ.get("DEP_PATCH_REPO", ""),
            )
            if "/" in repo_full:
                owner, repo = repo_full.split("/", 1)

        date_suffix = datetime.now(timezone.utc).strftime("%Y%m%d")
        branch_name = metadata.get(
            "branch_name",
            os.environ.get("DEP_PATCH_BRANCH", f"deps/patch-updates-{date_suffix}"),
        )

        try:
            pr_result = ToolExecutor.call(
                create_update_pr, context=context,
                owner=owner, repo=repo,
                default_branch=default_branch,
                branch_name=branch_name,
                updated_package_json=updated_pj,
                original_sha=sha,
                updates=assessed_updates,
                package_path=package_path,
            )
            summary["pr"] = pr_result
        except Exception as e:
            summary["pr"] = None
            summary["pr_error"] = str(e)

        return AgentResult.ok(context, output=summary)

    # ── LLM-powered execution ───────────────────────────────────────────

    def _execute_llm(self, context: AgentContext) -> AgentResult:
        """Delegate to LLM ReAct agent."""
        agent = _LLMDepPatchAgent()
        return agent.execute(context)


# ---------------------------------------------------------------------------
# LLM-powered implementation — used when reasoning.mode == llm_react
# ---------------------------------------------------------------------------


class _LLMDepPatchAgent:
    """
    Internal LLM-powered dep-patch agent using the ReAct loop.

    Not registered in AgentRegistry — accessed only through DepPatchAgent
    when reasoning.mode == llm_react.

    The LLM follows this tool sequence:
        1. fetch_package_json     -> get repo's package.json
        2. parse_dependencies     -> classify all deps
        3. fetch_registry_versions -> check npm for each updatable dep
        4. find_compatible_updates -> find latest compatible version
        5. assess_update_risks    -> evaluate risk of updates
        6. create_update_pr       -> create the GitHub PR
        7. STOP + summarize       -> produce structured JSON summary

    All tool calls route through ToolExecutor -> policy check + audit trail.
    """

    def execute(self, context: AgentContext) -> AgentResult:
        from zak.agents.dep_patch.tools import (
            assess_update_risks,
            create_update_pr,
            fetch_package_json,
            fetch_registry_versions,
            find_compatible_updates,
            parse_dependencies,
        )
        from zak.core.llm.registry import get_llm_client
        from zak.core.runtime.llm_agent import _build_openai_schema

        available_tools = [
            fetch_package_json,
            parse_dependencies,
            fetch_registry_versions,
            find_compatible_updates,
            assess_update_risks,
            create_update_pr,
        ]
        tools_schema = _build_openai_schema(available_tools)

        # LLM config from DSL
        llm_cfg: dict = {}
        if context.dsl.reasoning.llm:
            llm_block = context.dsl.reasoning.llm
            llm_cfg = (
                llm_block if isinstance(llm_block, dict)
                else llm_block.model_dump(exclude_none=True)
            )

        client = get_llm_client(
            provider=llm_cfg.get("provider"),
            model=llm_cfg.get("model"),
        )
        temperature = float(llm_cfg.get("temperature", 0.2))
        max_tokens = int(llm_cfg.get("max_tokens", 4096))
        max_iter = int(llm_cfg.get("max_iterations", 15))

        metadata = context.metadata
        dry_run = bool(metadata.get("dry_run", False))

        system = (
            f"You are a dependency update agent for tenant '{context.tenant_id}'.\n\n"
            f"Repository: {metadata.get('owner', '')}/{metadata.get('repo', '')}\n"
            f"Registry: {metadata.get('registry_url', 'https://registry.npmjs.org')}\n"
            f"Dry Run: {dry_run}\n\n"
            "Your goal: Find and apply compatible dependency updates (patch/minor) "
            "for this repository.\n\n"
            "Follow this sequence:\n"
            "1. Call fetch_package_json to get the repository's package.json.\n"
            "2. Call parse_dependencies to classify all dependencies.\n"
            "3. For each updatable dependency, call fetch_registry_versions "
            "then find_compatible_updates.\n"
            "4. Call assess_update_risks with all updates that have patch or "
            "minor updates.\n"
            "5. If not dry_run, call create_update_pr to create a PR.\n"
            "6. When done, return a JSON summary with:\n"
            "   - total_dependencies: count\n"
            "   - updatable: count of deps with available updates\n"
            "   - updates: list of update details\n"
            "   - pr: PR URL if created, null otherwise\n\n"
            "Ground every decision in tool output. Do not invent version numbers."
        )

        messages: list[dict] = [
            {"role": "system", "content": system},
            {
                "role": "user",
                "content": (
                    f"Run dependency update scan for tenant '{context.tenant_id}'. "
                    f"Environment: {context.environment}."
                ),
            },
        ]

        reasoning_trace: list[dict] = []
        total_usage: dict = {
            "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0,
        }

        def resolve(name: str):  # type: ignore[return]
            for fn in available_tools:
                meta = getattr(fn, "_zak_tool", None)
                if meta and meta.action_id == name:
                    return fn
            return None

        for iteration in range(max_iter):
            response = client.chat(
                messages=messages,
                tools=tools_schema,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            for k in total_usage:
                total_usage[k] += response.usage.get(k, 0)

            if response.finish_reason == "stop" or not response.tool_calls:
                conclusion = response.content or "Dependency update scan complete."
                reasoning_trace.append({
                    "iteration": iteration + 1,
                    "type": "conclusion",
                    "content": conclusion,
                })
                return AgentResult.ok(
                    context,
                    output={
                        "summary": conclusion,
                        "reasoning_trace": reasoning_trace,
                        "iterations": iteration + 1,
                        "llm_usage": total_usage,
                        "provider": llm_cfg.get("provider", "openai"),
                        "model": llm_cfg.get("model"),
                    },
                )

            # Process tool calls
            tool_results: list[dict] = []
            for tc in response.tool_calls:
                entry: dict = {
                    "iteration": iteration + 1,
                    "type": "tool_call",
                    "tool": tc.name,
                    "arguments": tc.arguments,
                }
                reasoning_trace.append(entry)
                fn = resolve(tc.name)
                if fn is None:
                    err = {"error": f"Unknown tool: {tc.name}"}
                    entry["result"] = err
                    tool_results.append({
                        "role": "tool", "tool_call_id": tc.id,
                        "content": json.dumps(err),
                    })
                    continue
                try:
                    result = ToolExecutor.call(fn, context=context, **tc.arguments)
                    entry["result"] = result
                    tool_results.append({
                        "role": "tool", "tool_call_id": tc.id,
                        "content": (
                            json.dumps(result)
                            if not isinstance(result, str)
                            else result
                        ),
                    })
                except Exception as exc:
                    err = {"error": str(exc)}
                    entry["result"] = err
                    tool_results.append({
                        "role": "tool", "tool_call_id": tc.id,
                        "content": json.dumps(err),
                    })

            messages.append({
                "role": "assistant",
                "content": response.content,
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.name,
                            "arguments": json.dumps(tc.arguments),
                        },
                    }
                    for tc in response.tool_calls
                ],
            })
            messages.extend(tool_results)

        return AgentResult.fail(
            context,
            errors=[
                f"LLM dep_patch agent reached max_iterations ({max_iter}) "
                "without conclusion.",
            ],
        )
