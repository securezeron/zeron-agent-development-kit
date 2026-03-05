"""
ZAK Tool Substrate — @zak_tool decorator and ToolRegistry.

Design:
- @zak_tool(name, description, action_id) marks a function as a ZAK tool
- Tools are policy-aware: before execution, the tool checks action_id against the PolicyEngine
- Tools emit audit events on call and result
- ToolExecutor is the call entry point for agents (handles policy + audit)

Usage:
    from zak.core.tools.substrate import zak_tool, ToolExecutor

    @zak_tool(
        name="read_asset",
        description="Read an asset node from the SIF graph",
        action_id="read_asset",
    )
    def read_asset(context: AgentContext, asset_id: str) -> dict:
        ...

    # Inside an agent's execute():
    result = ToolExecutor.call(read_asset, context=context, asset_id="srv-001")
"""

from __future__ import annotations

import functools
import inspect
from dataclasses import dataclass, field
from typing import Any, Callable

from zak.core.audit.events import AuditEventType, ToolCalledEvent
from zak.core.audit.logger import AuditLogger
from zak.core.policy.engine import PolicyEngine
from zak.core.runtime.agent import AgentContext


@dataclass
class ToolMetadata:
    """Metadata attached to every @zak_tool-decorated function."""
    name: str
    description: str
    action_id: str
    requires_context: bool = True
    tags: list[str] = field(default_factory=list)


class ToolRegistry:
    """
    Singleton registry of all @zak_tool-decorated functions.

    Tools are keyed by their action_id. The registry is used to:
    - Validate that an agent's capabilities.tools list references real tools
    - Enumerate available tools per domain
    """

    _instance: ToolRegistry | None = None

    def __init__(self) -> None:
        self._tools: dict[str, tuple[ToolMetadata, Callable]] = {}

    @classmethod
    def get(cls) -> ToolRegistry:
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def register(self, metadata: ToolMetadata, fn: Callable) -> None:
        self._tools[metadata.action_id] = (metadata, fn)

    def get_tool(self, action_id: str) -> tuple[ToolMetadata, Callable] | None:
        return self._tools.get(action_id)

    def all_tools(self) -> list[ToolMetadata]:
        return [m for m, _ in self._tools.values()]

    def is_registered(self, action_id: str) -> bool:
        return action_id in self._tools

    def clear(self) -> None:
        self._tools.clear()

    def summary(self) -> str:
        if not self._tools:
            return "No tools registered."
        lines = ["Registered tools:"]
        for meta, _ in self._tools.values():
            lines.append(f"  {meta.action_id:<30} — {meta.description}")
        return "\n".join(lines)


def zak_tool(
    name: str,
    *,
    description: str = "",
    action_id: str | None = None,
    tags: list[str] | None = None,
) -> Callable:
    """
    Decorator that registers a function as a ZAK tool.

    The decorated function becomes policy-aware: when called via ToolExecutor.call(),
    it checks the agent's policy before executing.

    Args:
        name:        Human-readable tool name (e.g. "Read Asset").
        description: What the tool does (used in docs + audit logs).
        action_id:   Policy action identifier (defaults to snake_case of name).
                     Must match entries in AgentDSL.capabilities.tools and boundaries.allowed_actions.
        tags:        Optional categorization tags (e.g. ["sif", "read"]).

    Example:
        @zak_tool(name="read_asset", description="Read an asset from the SIF graph")
        def read_asset(context: AgentContext, asset_id: str) -> dict:
            ...
    """
    resolved_action_id = action_id or name.lower().replace(" ", "_")

    def decorator(fn: Callable) -> Callable:
        meta = ToolMetadata(
            name=name,
            description=description or (inspect.getdoc(fn) or "").split("\n")[0],
            action_id=resolved_action_id,
            tags=tags or [],
        )
        ToolRegistry.get().register(meta, fn)

        # Attach metadata to function for introspection
        fn._zak_tool = meta  # type: ignore[attr-defined]

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Direct call without ToolExecutor — skip policy/audit (discouraged but allowed)
            return fn(*args, **kwargs)

        wrapper._zak_tool = meta  # type: ignore[attr-defined]
        return wrapper

    return decorator


class ToolExecutor:
    """
    Policy-aware tool call executor.

    Always use this instead of calling tools directly so that:
    - Policy is enforced before the tool runs
    - Audit events are emitted on call and result
    - Tool capability check validates the tool is in the agent's allowed tools list
    """

    _policy = PolicyEngine()

    @classmethod
    def call(
        cls,
        tool_fn: Callable,
        context: AgentContext,
        **kwargs: Any,
    ) -> Any:
        """
        Execute a @zak_tool function with full policy and audit wrapping.

        Args:
            tool_fn:  The @zak_tool-decorated function to call.
            context:  Agent execution context (provides DSL + tenant + trace).
            **kwargs: Arguments to pass to the tool function (excluding context).

        Returns:
            The return value of tool_fn.

        Raises:
            PermissionError: If policy denies the tool's action_id.
            ValueError: If the tool is not in the agent's capabilities.tools list.
        """
        meta: ToolMetadata | None = getattr(tool_fn, "_zak_tool", None)
        if meta is None:
            raise ValueError(
                f"'{tool_fn.__name__}' is not a @zak_tool. "
                "Decorate it with @zak_tool before using ToolExecutor.call()."
            )

        logger = AuditLogger(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            trace_id=context.trace_id,
        )

        # Capability check — tool must be declared in agent's capabilities.tools
        if (
            context.dsl.capabilities.tools
            and meta.action_id not in context.dsl.capabilities.tools
        ):
            raise PermissionError(
                f"Tool '{meta.action_id}' is not declared in agent capabilities.tools. "
                f"Declared tools: {context.dsl.capabilities.tools}"
            )

        # Policy check against the tool's action_id
        decision = cls._policy.evaluate(
            dsl=context.dsl,
            action=meta.action_id,
            environment=context.environment,
        )
        if not decision.allowed:
            logger.log_raw(
                AuditEventType.POLICY_BLOCKED,
                action=meta.action_id,
                reason=decision.reason,
                tool=meta.name,
            )
            raise PermissionError(
                f"Policy denied tool '{meta.name}' (action_id={meta.action_id}): "
                f"{decision.reason}"
            )

        # Emit tool_called audit event
        logger.emit(ToolCalledEvent(
            agent_id=context.agent_id,
            tenant_id=context.tenant_id,
            trace_id=context.trace_id,
            tool_name=meta.name,
            input_summary=str(kwargs)[:200],
        ))

        # Execute — inject context if the function signature accepts it
        sig = inspect.signature(tool_fn)
        if "context" in sig.parameters:
            result = tool_fn(context=context, **kwargs)
        else:
            result = tool_fn(**kwargs)

        # Emit tool_result audit event
        logger.log_raw(
            AuditEventType.TOOL_RESULT,
            tool=meta.name,
            result_type=type(result).__name__,
        )

        return result
