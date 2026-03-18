package cli

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/dsl"
	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/edition"
	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/runtime"
	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/tenants"
	"github.com/spf13/cobra"
)

var (
	runTenant string
	runEnv    string
)

var runCmd = &cobra.Command{
	Use:   "run <path>",
	Short: "Run an agent defined by a YAML file under a tenant context",
	Long: `Load and validate an agent YAML definition, resolve the registered agent
implementation for its domain, and execute it within a tenant-scoped context.`,
	Args: cobra.ExactArgs(1),
	RunE: runAgent,
}

func init() {
	runCmd.Flags().StringVarP(&runTenant, "tenant", "t", "", "Tenant ID to run the agent under")
	runCmd.Flags().StringVarP(&runEnv, "env", "e", "staging", "Target environment (production, staging, dev)")
	_ = runCmd.MarkFlagRequired("tenant")
	rootCmd.AddCommand(runCmd)
}

func runAgent(cmd *cobra.Command, args []string) error {
	path := args[0]
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	cyan := color.New(color.FgCyan)
	yellow := color.New(color.FgYellow)
	bold := color.New(color.Bold)

	// 1. Validate the YAML first
	valResult := dsl.ValidateAgentFile(path)
	if !valResult.Valid {
		red.Fprintln(cmd.ErrOrStderr(), "Cannot run: agent YAML is invalid.")
		for _, e := range valResult.Errors {
			red.Fprintf(cmd.ErrOrStderr(), "  - %s\n", e)
		}
		return fmt.Errorf("agent YAML validation failed")
	}

	// 2. Load the DSL
	agentDSL, err := dsl.LoadAgentYaml(path)
	if err != nil {
		return fmt.Errorf("loading agent YAML: %w", err)
	}

	// 3. Generate a trace ID
	traceID := fmt.Sprintf("trace-%d", time.Now().UnixNano())

	// 4. Print run info
	fmt.Fprintln(cmd.OutOrStdout())
	bold.Fprintln(cmd.OutOrStdout(), "ZAK Agent Run")
	fmt.Fprintln(cmd.OutOrStdout(), "---")
	bold.Fprintf(cmd.OutOrStdout(), "  Agent:       ")
	fmt.Fprintf(cmd.OutOrStdout(), "%s (", agentDSL.Agent.Name)
	cyan.Fprintf(cmd.OutOrStdout(), "%s", agentDSL.Agent.ID)
	fmt.Fprintln(cmd.OutOrStdout(), ")")
	bold.Fprintf(cmd.OutOrStdout(), "  Tenant:      ")
	fmt.Fprintln(cmd.OutOrStdout(), runTenant)
	bold.Fprintf(cmd.OutOrStdout(), "  Environment: ")
	fmt.Fprintln(cmd.OutOrStdout(), runEnv)
	bold.Fprintf(cmd.OutOrStdout(), "  Trace ID:    ")
	fmt.Fprintln(cmd.OutOrStdout(), traceID)
	fmt.Fprintln(cmd.OutOrStdout(), "---")

	// 5. Ensure tenant exists
	tenantRegistry := tenants.RegistryGet()
	if !tenantRegistry.Exists(runTenant) {
		_, _ = tenantRegistry.Register(runTenant, runTenant, nil)
	}

	// 6. Resolve agent from registry
	domain := string(agentDSL.Agent.Domain)
	registry := runtime.AgentRegistryGet()

	if !registry.IsRegistered(domain) {
		yellow.Fprintf(cmd.OutOrStdout(), "No agent registered for domain '%s'.\n", domain)
		fmt.Fprintf(cmd.OutOrStdout(), "  Implement a BaseAgent and register it with "+
			"runtime.RegisterAgent(domain=\"%s\")\n", domain)
		allDomains := registry.AllDomains()
		if len(allDomains) > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "  Registered domains: %v\n", allDomains)
		}
		return nil
	}

	factory, err := registry.Resolve(domain)
	if err != nil {
		if _, ok := err.(*edition.Error); ok {
			red.Fprintln(cmd.ErrOrStderr(), err.Error())
			fmt.Fprintf(cmd.ErrOrStderr(), "  Current edition: %s\n", edition.GetEdition())
			fmt.Fprintln(cmd.ErrOrStderr(), "  Upgrade at https://zeron.one")
			return err
		}
		return err
	}

	// 7. Create context and execute
	agent := factory()
	ctx := runtime.NewAgentContext(runTenant, traceID, agentDSL)
	ctx.Environment = runEnv

	executor := runtime.NewExecutor()
	result := executor.Run(agent, ctx)

	// 8. Print result
	fmt.Fprintln(cmd.OutOrStdout())
	if result.Success {
		green.Fprintf(cmd.OutOrStdout(), "Agent completed successfully")
		fmt.Fprintf(cmd.OutOrStdout(), " in %.1fms\n", result.DurationMs)
		if len(result.Output) > 0 {
			jsonBytes, _ := json.MarshalIndent(result.Output, "  ", "  ")
			fmt.Fprintln(cmd.OutOrStdout())
			green.Fprintln(cmd.OutOrStdout(), "  Agent Output:")
			fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", string(jsonBytes))
		}
	} else {
		red.Fprintln(cmd.OutOrStdout(), "Agent failed")
		for _, e := range result.Errors {
			red.Fprintf(cmd.OutOrStdout(), "  - %s\n", e)
		}
		return fmt.Errorf("agent execution failed")
	}

	return nil
}
