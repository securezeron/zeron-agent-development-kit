package runtime

import (
	"fmt"
	"time"

	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/audit"
	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/policy"
)

// Executor orchestrates the full agent lifecycle:
//
//	preRun → (policy check → execute) → postRun → audit
//
// The executor is the only place where policy enforcement and audit emission happen.
type Executor struct {
	policy *policy.Engine
}

// NewExecutor creates a new AgentExecutor.
func NewExecutor() *Executor {
	return &Executor{
		policy: policy.NewEngine(),
	}
}

// Run executes an agent within a context, enforcing policy and emitting audit events.
func (e *Executor) Run(agent BaseAgent, ctx *AgentContext) *AgentResult {
	agentID := ctx.AgentID()
	logger := audit.NewLogger(ctx.TenantID, agentID, ctx.TraceID)

	// 1. Emit agent.started
	startEvent := audit.AgentStartedEvent(agentID, ctx.TenantID, ctx.TraceID)
	startEvent.WithPayload("domain", string(ctx.DSL.Agent.Domain))
	startEvent.WithPayload("version", ctx.DSL.Agent.Version)
	logger.Emit(startEvent)

	start := time.Now()

	// 2. Pre-run hook (if agent implements PreRunner)
	if pr, ok := agent.(PreRunner); ok {
		if err := pr.PreRun(ctx); err != nil {
			durationMs := float64(time.Since(start).Milliseconds())
			logger.Emit(audit.AgentFailedEvent(agentID, ctx.TenantID, ctx.TraceID, err.Error()))
			return ResultFail(ctx, []string{fmt.Sprintf("pre_run failed: %s", err)}, durationMs)
		}
	}

	// 3. Pre-execution policy evaluation
	policyCheck := e.policy.Evaluate(ctx.DSL, "agent_execute", ctx.Environment, nil)
	if !policyCheck.Allowed {
		durationMs := float64(time.Since(start).Milliseconds())
		logger.Emit(audit.PolicyBlockedEvent(agentID, ctx.TenantID, ctx.TraceID, "agent_execute", policyCheck.Reason))
		return ResultFail(ctx, []string{fmt.Sprintf("Policy denied: %s", policyCheck.Reason)}, durationMs)
	}

	// 4. Main execution
	result, err := agent.Execute(ctx)
	if err != nil {
		durationMs := float64(time.Since(start).Milliseconds())
		logger.Emit(audit.AgentFailedEvent(agentID, ctx.TenantID, ctx.TraceID, err.Error()))
		return ResultFail(ctx, []string{err.Error()}, durationMs)
	}

	result.DurationMs = float64(time.Since(start).Milliseconds())

	// 5. Post-run hook (if agent implements PostRunner)
	if pr, ok := agent.(PostRunner); ok {
		if postErr := pr.PostRun(ctx, result); postErr != nil {
			// Log but don't fail — post-run errors are non-fatal
			logger.Emit(audit.AgentFailedEvent(agentID, ctx.TenantID, ctx.TraceID,
				fmt.Sprintf("post_run error: %s", postErr)))
		}
	}

	// 6. Emit completion/failure audit event
	if result.Success {
		logger.Emit(audit.AgentCompletedEvent(agentID, ctx.TenantID, ctx.TraceID, true, result.DurationMs))
	} else {
		errMsg := ""
		for i, e := range result.Errors {
			if i > 0 {
				errMsg += "; "
			}
			errMsg += e
		}
		logger.Emit(audit.AgentFailedEvent(agentID, ctx.TenantID, ctx.TraceID, errMsg))
	}

	return result
}

// CheckAction performs a mid-execution policy check for a specific action.
// Agents should call this before performing sensitive operations.
func (e *Executor) CheckAction(ctx *AgentContext, action, environment string) policy.Decision {
	if environment == "" {
		environment = ctx.Environment
	}

	agentID := ctx.AgentID()
	logger := audit.NewLogger(ctx.TenantID, agentID, ctx.TraceID)

	decision := e.policy.Evaluate(ctx.DSL, action, environment, nil)
	if decision.Allowed {
		logger.LogRaw(audit.PolicyAllowed, map[string]interface{}{"action": action})
	} else {
		logger.Emit(audit.PolicyBlockedEvent(agentID, ctx.TenantID, ctx.TraceID, action, decision.Reason))
	}

	return decision
}
