package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version is set at build time via ldflags.
var Version = "0.1.4"

// rootCmd is the base command for the ZAK CLI.
var rootCmd = &cobra.Command{
	Use:   "zak",
	Short: "ZAK -- Zeron Universal Security Agent Development Kit",
	Long: `ZAK is the developer CLI for building, validating, and running
security agents using the Universal Security Agent DSL (US-ADSL).

Commands:
  init       Scaffold a new agent (YAML + Go source)
  validate   Validate a US-ADSL agent YAML definition
  run        Run an agent in a tenant context
  agents     List all registered agent classes
  info       Show ZAK version and configuration`,
}

func init() {
	rootCmd.Version = Version
	rootCmd.SetVersionTemplate(fmt.Sprintf("zak version %s\n", Version))
}

// RootCmd returns the root cobra.Command for testing and composition.
func RootCmd() *cobra.Command {
	return rootCmd
}

// Execute runs the root command. Called from main().
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
