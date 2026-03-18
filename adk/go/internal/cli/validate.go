package cli

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/dsl"
	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate <path>",
	Short: "Validate a US-ADSL agent YAML definition",
	Long: `Validate an agent YAML definition file against the US-ADSL schema.
Reports all validation errors with field paths and suggestions.`,
	Args: cobra.ExactArgs(1),
	RunE: runValidate,
}

func init() {
	rootCmd.AddCommand(validateCmd)
}

func runValidate(cmd *cobra.Command, args []string) error {
	path := args[0]
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	cyan := color.New(color.FgCyan)

	result := dsl.ValidateAgentFile(path)

	if result.Valid {
		green.Fprintf(cmd.OutOrStdout(), "PASS")
		fmt.Fprintf(cmd.OutOrStdout(), " -- Agent ID: ")
		cyan.Fprintln(cmd.OutOrStdout(), result.AgentID)
		return nil
	}

	red.Fprintf(cmd.OutOrStdout(), "FAIL")
	fmt.Fprintf(cmd.OutOrStdout(), " -- %d error(s):\n", len(result.Errors))
	for _, e := range result.Errors {
		red.Fprintf(cmd.OutOrStdout(), "  - %s\n", e)
	}
	return fmt.Errorf("validation failed with %d error(s)", len(result.Errors))
}
