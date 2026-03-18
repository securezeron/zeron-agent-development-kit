"""
ZAK Runtime — LLMAgent base class.

The LLMAgent implements the ReAct (Reason + Act) pattern, adding a proper
LLM reasoning loop on top of ZAK's existing governance infrastructure:

    Perceive (read context) → Reason (LLM call) → Act (ToolExecutor) → Observe → repeat

Key design principles:
    - Existing PolicyEngine / AuditLogger / TenantIsolation are fully preserved
    - Every LLM tool call routes through ToolExecutor (policy + audit fires)
    - max_iterations cap prevents runaway agents
    - LLM provider / model / temperature read from DSL's reasoning.llm block
    - Agents opt-in by subclassing LLMAgent instead of BaseAgent

Usage:
    class RedTeamAgent(LLMAgent):
        @property
        def tools(self):
            return [list_assets, list_vulnerabilities, compute_risk]

        def system_prompt(self, context):
            return f"You are a red team agent for tenant {context.tenant_id}..."
"""

from __future__ import annotations

import abc
import inspect
import json
import typing
import uuid
from typing import Any, Callable, Iterator, Union

from zak.core.audit.events import AuditEventType
from zak.core.audit.logger import AuditLogger
from zak.core.runtime.agent import AgentContext, AgentResult, BaseAgent
from zak.core.tools.substrate import ToolExecutor


# ---------------------------------------------------------------------------
# Schema generation — @zak_tool → OpenAI function-call JSON schema
# ---------------------------------------------------------------------------

def _build_openai_schema(tools: list[Any]) -> list[dict[str, Any]]:
    """
    Auto-generate OpenAI function-calling schema from @zak_tool decorated functions.

    Reads the function signature to infer parameter types and required fields.
    The 'context' parameter is excluded (injected automatically by ToolExecutor).
    """
    schemas: list[dict[str, Any]] = []
    for tool_fn in tools:
        meta = getattr(tool_fn, "_zak_tool", None)
        if meta is None:
            continue

        sig = inspect.signature(tool_fn)
        props: dict[str, Any] = {}
        required: list[str] = []

        _type_map: dict[Any, str] = {
            str: "string",
            int: "integer",
            float: "number",
            bool: "boolean",
            list: "array",
            dict: "object",
        }

        for param_name, param in sig.parameters.items():
            if param_name in ("context", "self"):
                continue

            ann = param.annotation
            json_type = _type_map.get(ann, "string")

            # Check for Optional[X] (Union[X, None]) via __args__
            origin = getattr(ann, "__origin__", None)
            if origin is Union or origin is typing.Union:
                args = getattr(ann, "__args__", ())
                for a in args:
                    if a is not type(None):
                        json_type = _type_map.get(a, "string")
                        break

            props[param_name] = {
                "type": json_type,
                "description": f"{param_name} parameter",
            }
            if param.default is inspect.Parameter.empty:
                required.append(param_name)

        schemas.append(
            {
                "type": "function",
                "function": {
                    "name": meta.action_id,
                    "description": meta.description or meta.name,
                    "parameters": {
                        "type": "object",
                        "properties": props,
                        "required": required,
                    },
                },
            }
        )

    return schemas


# ---------------------------------------------------------------------------
# LLMAgent base class
# ---------------------------------------------------------------------------

class LLMAgent(BaseAgent, abc.ABC):
    """
    LLM-powered agent base class using the ReAct (Reason + Act) loop.

    Subclasses define:
        - system_prompt(context) → str    — the agent's goal and persona
        - tools (property) → list         — @zak_tool functions the agent can call

    The ReAct loop, tool schema generation, and policy routing are handled
    automatically. Existing governance infrastructure is fully preserved.

    Default ReAct loop behaviour:
        1. Build initial messages (system + user goal)
        2. Call LLM → receive reasoning + tool calls
        3. Execute tool calls via ToolExecutor (policy + audit)
        4. Append tool results to conversation
        5. Repeat until LLM says "stop" or max_iterations reached
    """

    #: Default maximum ReAct iterations (override in subclass or DSL)
    max_iterations: int = 10

    def execute(self, context: AgentContext) -> AgentResult:
        from zak.core.llm.registry import get_llm_client

        # ── LLM config from DSL reasoning.llm block ────────────────────────
        llm_cfg: dict[str, Any] = {}
        if hasattr(context.dsl, "reasoning") and context.dsl.reasoning:
            r = context.dsl.reasoning
            llm_block = getattr(r, "llm", None)
            if llm_block is not None:
                llm_cfg = (
                    llm_block
                    if isinstance(llm_block, dict)
                    else llm_block.model_dump(exclude_none=True)
                )

        provider = llm_cfg.get("provider") or None
        model = llm_cfg.get("model") or None
        temperature = float(llm_cfg.get("temperature", 0.2))
        max_iter = int(llm_cfg.get("max_iterations", self.max_iterations))
        max_tokens = int(llm_cfg.get("max_tokens", 4096))

        client = get_llm_client(provider=provider, model=model)

        # ── Build initial conversation ──────────────────────────────────────
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": self.system_prompt(context)},
            {
                "role": "user",
                "content": (
                    f"Execute your security analysis goal for tenant '{context.tenant_id}'. "
                    f"Environment: {context.environment}. Trace ID: {context.trace_id}. "
                    "Use your available tools to gather data, then provide a structured summary."
                ),
            },
        ]

        tools_schema = _build_openai_schema(self.tools)

        audit = AuditLogger(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            trace_id=context.trace_id,
        )

        total_usage: dict[str, int] = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        }
        reasoning_trace: list[dict[str, Any]] = []

        # ── ReAct loop ──────────────────────────────────────────────────────
        for iteration in range(max_iter):
            audit.log_raw(
                AuditEventType.TOOL_CALLED,
                phase="llm_reason",
                iteration=iteration + 1,
                messages_in_context=len(messages),
            )

            response = client.chat(
                messages=messages,
                tools=tools_schema,
                temperature=temperature,
                max_tokens=max_tokens,
            )

            # Accumulate token usage
            for k in total_usage:
                total_usage[k] += response.usage.get(k, 0)

            # ── LLM decided it's done (finish_reason == "stop") ────────────
            if response.finish_reason == "stop" or not response.tool_calls:
                conclusion = response.content or "Task completed successfully."
                reasoning_trace.append(
                    {
                        "iteration": iteration + 1,
                        "type": "conclusion",
                        "content": conclusion,
                    }
                )
                audit.log_raw(
                    AuditEventType.TOOL_RESULT,
                    phase="llm_conclusion",
                    iteration=iteration + 1,
                    tokens_used=total_usage["total_tokens"],
                )
                return AgentResult.ok(
                    context,
                    output={
                        "summary": conclusion,
                        "reasoning_trace": reasoning_trace,
                        "iterations": iteration + 1,
                        "llm_usage": total_usage,
                        "provider": provider or "openai",
                        "model": model,
                    },
                )

            # ── Process tool calls ─────────────────────────────────────────
            tool_results: list[dict[str, Any]] = []

            for tool_call in response.tool_calls:
                trace_entry: dict[str, Any] = {
                    "iteration": iteration + 1,
                    "type": "tool_call",
                    "tool": tool_call.name,
                    "arguments": tool_call.arguments,
                }
                reasoning_trace.append(trace_entry)

                tool_fn = self._resolve_tool(tool_call.name)
                if tool_fn is None:
                    available = [
                        getattr(t, "_zak_tool", None).action_id
                        for t in self.tools
                        if getattr(t, "_zak_tool", None)
                    ]
                    err = {
                        "error": (
                            f"Unknown tool '{tool_call.name}'. "
                            f"Available tools: {available}. "
                            "Please use ONLY the tools listed above."
                        ),
                    }
                    trace_entry["result"] = err
                    tool_results.append(self._tool_result_msg(tool_call, err))
                    continue

                try:
                    result = ToolExecutor.call(
                        tool_fn,
                        context=context,
                        **tool_call.arguments,
                    )
                    trace_entry["result"] = result
                    tool_results.append(self._tool_result_msg(tool_call, result))
                except Exception as exc:
                    err = {"error": str(exc)}
                    trace_entry["result"] = err
                    tool_results.append(self._tool_result_msg(tool_call, err))

            # Append assistant message + all tool results to context
            messages.append(
                {
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
                }
            )
            messages.extend(tool_results)

        # ── Max iterations reached without natural conclusion ───────────────
        return AgentResult.fail(
            context,
            errors=[
                f"LLM agent reached max_iterations ({max_iter}) without a conclusion. "
                "Consider increasing max_iterations in the DSL reasoning.llm block."
            ],
        )

    def execute_stream(
        self,
        context: AgentContext,
        *,
        wait_for_approval: Callable[[str], bool] | None = None,
    ) -> Iterator[dict[str, Any]]:
        """
        Streaming variant of execute(). Yields event dicts at each ReAct step
        so callers can push them to an SSE endpoint in real time.

        Args:
            context: Agent execution context.
            wait_for_approval: Optional blocking callback used for human-in-the-loop
                approval gates. Signature: (gate_id: str) -> bool (approved).
                Called when a tool's action_id appears in
                context.dsl.boundaries.approval_gates. The generator blocks until
                the callback returns. Pass None to skip gate enforcement.

        Event shapes:
          {"type": "start",             "trace_id": str, "tenant_id": str}
          {"type": "iteration",         "iteration": int}
          {"type": "tool_call",         "iteration": int, "tool": str, "arguments": dict}
          {"type": "approval_required", "gate_id": str,  "iteration": int,
                                        "tool": str,     "arguments": dict}
          {"type": "approval_granted",  "gate_id": str,  "iteration": int, "tool": str}
          {"type": "approval_denied",   "gate_id": str,  "iteration": int, "tool": str}
          {"type": "tool_result",       "iteration": int, "tool": str,
                                        "result_preview": str, "error": bool}
          {"type": "reasoning",         "iteration": int, "content": str}
          {"type": "complete",          "output": dict,  "iterations": int, "llm_usage": dict}
          {"type": "error",             "message": str}
        """
        from zak.core.llm.registry import get_llm_client

        # Build the approval-gate set from DSL boundaries once
        _approval_gates: set[str] = set()
        if hasattr(context.dsl, "boundaries") and context.dsl.boundaries:
            _approval_gates = set(context.dsl.boundaries.approval_gates or [])

        yield {"type": "start", "trace_id": context.trace_id, "tenant_id": context.tenant_id}

        # ── LLM config from DSL ────────────────────────────────────────────
        llm_cfg: dict[str, Any] = {}
        if hasattr(context.dsl, "reasoning") and context.dsl.reasoning:
            r = context.dsl.reasoning
            llm_block = getattr(r, "llm", None)
            if llm_block is not None:
                llm_cfg = (
                    llm_block
                    if isinstance(llm_block, dict)
                    else llm_block.model_dump(exclude_none=True)
                )

        provider = llm_cfg.get("provider") or None
        model = llm_cfg.get("model") or None
        temperature = float(llm_cfg.get("temperature", 0.2))
        max_iter = int(llm_cfg.get("max_iterations", self.max_iterations))
        max_tokens = int(llm_cfg.get("max_tokens", 4096))

        try:
            client = get_llm_client(provider=provider, model=model)
        except Exception as exc:
            yield {"type": "error", "message": f"LLM client init failed: {exc}"}
            return

        # ── Build initial conversation ─────────────────────────────────────
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": self.system_prompt(context)},
            {
                "role": "user",
                "content": (
                    f"Execute your security analysis goal for tenant '{context.tenant_id}'. "
                    f"Environment: {context.environment}. Trace ID: {context.trace_id}. "
                    "Use your available tools to gather data, then provide a structured summary."
                ),
            },
        ]

        tools_schema = _build_openai_schema(self.tools)

        audit = AuditLogger(
            tenant_id=context.tenant_id,
            agent_id=context.agent_id,
            trace_id=context.trace_id,
        )

        total_usage: dict[str, int] = {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
        }
        reasoning_trace: list[dict[str, Any]] = []

        # ── ReAct loop ─────────────────────────────────────────────────────
        for iteration in range(max_iter):
            yield {"type": "iteration", "iteration": iteration + 1}

            audit.log_raw(
                AuditEventType.TOOL_CALLED,
                phase="llm_reason",
                iteration=iteration + 1,
                messages_in_context=len(messages),
            )

            try:
                response = client.chat(
                    messages=messages,
                    tools=tools_schema,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
            except Exception as exc:
                yield {
                    "type": "error",
                    "message": f"LLM call failed at iteration {iteration + 1}: {exc}",
                }
                return

            for k in total_usage:
                total_usage[k] += response.usage.get(k, 0)

            # ── LLM decided it's done ──────────────────────────────────────
            if response.finish_reason == "stop" or not response.tool_calls:
                conclusion = response.content or "Task completed successfully."
                reasoning_trace.append(
                    {"iteration": iteration + 1, "type": "conclusion", "content": conclusion}
                )
                yield {
                    "type": "reasoning",
                    "iteration": iteration + 1,
                    "content": conclusion[:1000],
                }
                audit.log_raw(
                    AuditEventType.TOOL_RESULT,
                    phase="llm_conclusion",
                    iteration=iteration + 1,
                    tokens_used=total_usage["total_tokens"],
                )
                output = {
                    "summary": conclusion,
                    "reasoning_trace": reasoning_trace,
                    "iterations": iteration + 1,
                    "llm_usage": total_usage,
                    "provider": provider or "openai",
                    "model": model,
                }
                yield {
                    "type": "complete",
                    "output": output,
                    "iterations": iteration + 1,
                    "llm_usage": total_usage,
                }
                return

            # ── Process tool calls ─────────────────────────────────────────
            tool_results: list[dict[str, Any]] = []

            for tool_call in response.tool_calls:
                yield {
                    "type": "tool_call",
                    "iteration": iteration + 1,
                    "tool": tool_call.name,
                    "arguments": tool_call.arguments,
                }

                trace_entry: dict[str, Any] = {
                    "iteration": iteration + 1,
                    "type": "tool_call",
                    "tool": tool_call.name,
                    "arguments": tool_call.arguments,
                }
                reasoning_trace.append(trace_entry)

                # ── Approval gate check ────────────────────────────────────
                if tool_call.name in _approval_gates and wait_for_approval is not None:
                    gate_id = uuid.uuid4().hex[:12]
                    yield {
                        "type": "approval_required",
                        "gate_id": gate_id,
                        "iteration": iteration + 1,
                        "tool": tool_call.name,
                        "arguments": tool_call.arguments,
                    }
                    approved = wait_for_approval(gate_id)
                    if approved:
                        yield {
                            "type": "approval_granted",
                            "gate_id": gate_id,
                            "iteration": iteration + 1,
                            "tool": tool_call.name,
                        }
                    else:
                        denied_msg = f"Tool '{tool_call.name}' denied by human reviewer."
                        yield {
                            "type": "approval_denied",
                            "gate_id": gate_id,
                            "iteration": iteration + 1,
                            "tool": tool_call.name,
                        }
                        denied_result = {"error": denied_msg}
                        trace_entry["result"] = denied_result
                        tool_results.append(self._tool_result_msg(tool_call, denied_result))
                        continue  # skip tool execution; LLM sees the denial in next iteration
                # ── /Approval gate check ───────────────────────────────────

                tool_fn = self._resolve_tool(tool_call.name)
                if tool_fn is None:
                    available = [
                        getattr(t, "_zak_tool", None).action_id
                        for t in self.tools
                        if getattr(t, "_zak_tool", None)
                    ]
                    err = {
                        "error": (
                            f"Unknown tool '{tool_call.name}'. "
                            f"Available tools: {available}. "
                            "Please use ONLY the tools listed above."
                        ),
                    }
                    trace_entry["result"] = err
                    tool_results.append(self._tool_result_msg(tool_call, err))
                    yield {
                        "type": "tool_result",
                        "iteration": iteration + 1,
                        "tool": tool_call.name,
                        "result_preview": str(err)[:300],
                        "error": True,
                    }
                    continue

                try:
                    result = ToolExecutor.call(
                        tool_fn,
                        context=context,
                        **tool_call.arguments,
                    )
                    trace_entry["result"] = result
                    tool_results.append(self._tool_result_msg(tool_call, result))
                    yield {
                        "type": "tool_result",
                        "iteration": iteration + 1,
                        "tool": tool_call.name,
                        "result_preview": str(result)[:300],
                        "error": False,
                    }
                except Exception as exc:
                    err = {"error": str(exc)}
                    trace_entry["result"] = err
                    tool_results.append(self._tool_result_msg(tool_call, err))
                    yield {
                        "type": "tool_result",
                        "iteration": iteration + 1,
                        "tool": tool_call.name,
                        "result_preview": str(err)[:300],
                        "error": True,
                    }

            # Append assistant + tool results to context
            messages.append(
                {
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
                }
            )
            messages.extend(tool_results)

        # ── Max iterations reached ─────────────────────────────────────────
        yield {
            "type": "error",
            "message": (
                f"LLM agent reached max_iterations ({max_iter}) without a conclusion. "
                "Consider increasing max_iterations in the DSL reasoning.llm block."
            ),
        }

    # ── Helpers ────────────────────────────────────────────────────────────

    def _resolve_tool(self, action_id: str) -> Any | None:
        """Find the @zak_tool function by its action_id from this agent's tool list."""
        for fn in self.tools:
            meta = getattr(fn, "_zak_tool", None)
            if meta and meta.action_id == action_id:
                return fn
        return None

    def _tool_result_msg(self, tool_call: Any, result: Any) -> dict[str, Any]:
        """Format a tool result as an OpenAI-compatible tool message."""
        return {
            "role": "tool",
            "tool_call_id": tool_call.id,
            "content": (
                json.dumps(result)
                if not isinstance(result, str)
                else result
            ),
        }

    # ── Abstract interface ─────────────────────────────────────────────────

    @abc.abstractmethod
    def system_prompt(self, context: AgentContext) -> str:
        """
        Define the agent's goal and persona.

        This is the system prompt sent to the LLM. It should:
        - State the agent's security objective clearly
        - Describe the expected tool call sequence
        - Specify the desired output format (structured JSON)
        - Remind the LLM to base every claim on tool output

        Example:
            return f"You are a risk quantification agent for tenant '{context.tenant_id}'.
            Goal: Compute risk scores for all assets..."
        """

    @property
    @abc.abstractmethod
    def tools(self) -> list[Any]:
        """
        Return the list of @zak_tool functions this agent may call.

        These functions must also be declared in the agent's DSL
        capabilities.tools list (otherwise ToolExecutor will reject them).

        Example:
            return [list_assets, list_vulnerabilities, compute_risk, write_risk_node]
        """
