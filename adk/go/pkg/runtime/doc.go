// Package runtime provides the agent execution runtime for the ZAK Agent
// Development Kit.
//
// This package contains:
//   - [BaseAgent] interface for implementing custom agents
//   - [AgentRegistry] for discovering and managing agent implementations
//   - [Executor] for running agents with full lifecycle management
//   - [RunLLMAgent] for executing LLM-powered ReAct reasoning loops
//
// # Agent Interface
//
// Implement the [BaseAgent] interface to create custom agents:
//
//	type MyAgent struct{}
//	func (a *MyAgent) Execute(ctx context.Context, ac *AgentContext) (*AgentResult, error) {
//	    return AgentResultOk("done", nil), nil
//	}
//
// # Registration
//
// Register agents globally using [RegisterAgent]:
//
//	RegisterAgent("my-domain", "my-agent", &MyAgent{})
//
// # Execution
//
// Execute agents with full lifecycle (policy check, pre/post hooks, audit):
//
//	exec := NewExecutor(policyEngine, auditLogger)
//	result, err := exec.Run(ctx, agentDSL, agent, inputData)
package runtime
