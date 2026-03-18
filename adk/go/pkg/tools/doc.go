// Package tools provides the tool substrate for the ZAK Agent Development Kit.
//
// Tools are the primary mechanism for agents to interact with external systems.
// The substrate wraps raw tool functions with automatic policy enforcement and
// audit logging.
//
// # Creating Tools
//
// Use [NewZakTool] to create policy-aware tools:
//
//	tool := tools.NewZakTool(tools.ZakToolConfig{
//	    Name:        "scan_code",
//	    Description: "Scan source code for vulnerabilities",
//	    Execute: func(ctx context.Context, params map[string]any) (any, error) {
//	        return map[string]any{"findings": []any{}}, nil
//	    },
//	})
//
// # Tool Registry
//
// Tools are registered globally and discovered by the executor:
//
//	tools.Register(tool)
//	t, ok := tools.Resolve("scan_code")
//
// # Tool Executor
//
// The [Executor] runs tools with the full security pipeline:
// capability check -> policy check -> audit -> execute -> audit
package tools
