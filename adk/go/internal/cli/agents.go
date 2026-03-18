package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/edition"
	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/runtime"
	"github.com/spf13/cobra"
)

var agentsCmd = &cobra.Command{
	Use:   "agents",
	Short: "List all registered agent classes and their domains",
	Long:  `Display a table of all registered agent implementations with their domain, class name, version, edition, and description.`,
	RunE:  runAgents,
}

func init() {
	rootCmd.AddCommand(agentsCmd)
}

func runAgents(cmd *cobra.Command, args []string) error {
	yellow := color.New(color.FgYellow)
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen)
	blue := color.New(color.FgBlue)

	registry := runtime.AgentRegistryGet()
	regs := registry.AllRegistrations()

	if len(regs) == 0 {
		yellow.Fprintln(cmd.OutOrStdout(), "No agents registered.")
		return nil
	}

	currentEdition := edition.GetEdition()
	editionLabel := "open-source"
	if currentEdition == edition.Enterprise {
		editionLabel = "enterprise"
	}

	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintf(cmd.OutOrStdout(), "Edition: %s  |  Showing %d agent(s)\n\n", editionLabel, len(regs))

	// Table output
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	cyan.Fprintf(w, "DOMAIN\tCLASS\tVERSION\tEDITION\tDESCRIPTION\n")
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
		strings.Repeat("-", 20),
		strings.Repeat("-", 20),
		strings.Repeat("-", 8),
		strings.Repeat("-", 12),
		strings.Repeat("-", 40),
	)

	for _, r := range regs {
		editionCell := r.Edition
		desc := r.Description
		if len(desc) > 55 {
			desc = desc[:55]
		}

		if r.Edition == "open-source" {
			green.Fprintf(w, "%s\t", r.Domain)
		} else {
			blue.Fprintf(w, "%s\t", r.Domain)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.ClassName, r.Version, editionCell, desc)
	}

	w.Flush()

	if currentEdition != edition.Enterprise {
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintln(cmd.OutOrStdout(), "Additional enterprise agents available at https://zeron.one")
	}

	return nil
}
