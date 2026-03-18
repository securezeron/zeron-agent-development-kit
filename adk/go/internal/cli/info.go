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

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show ZAK platform info",
	Long:  `Display ZAK version, edition, registered agents, graph backend, and other platform details.`,
	RunE:  runInfo,
}

func init() {
	rootCmd.AddCommand(infoCmd)
}

func runInfo(cmd *cobra.Command, args []string) error {
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)

	registry := runtime.AgentRegistryGet()
	currentEdition := edition.GetEdition()

	editionLabel := "open-source"
	if currentEdition == edition.Enterprise {
		editionLabel = "enterprise"
	}

	domains := registry.AllDomains()
	domainsStr := "none"
	if len(domains) > 0 {
		domainsStr = strings.Join(domains, ", ")
	}

	fmt.Fprintln(cmd.OutOrStdout())
	cyan.Fprintln(cmd.OutOrStdout(), "ZAK Platform Info")
	fmt.Fprintln(cmd.OutOrStdout(), strings.Repeat("=", 50))

	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Version\t%s\n", Version)

	if currentEdition == edition.Enterprise {
		fmt.Fprintf(w, "Edition\t")
		green.Fprintf(w, "%s\n", editionLabel)
	} else {
		fmt.Fprintf(w, "Edition\t")
		yellow.Fprintf(w, "%s\n", editionLabel)
	}

	fmt.Fprintf(w, "Agents Available\t%d\n", len(domains))
	fmt.Fprintf(w, "Registered Domains\t%s\n", domainsStr)
	fmt.Fprintf(w, "Graph Backend\tKuzu (embedded) -> Memgraph (production)\n")
	fmt.Fprintf(w, "Multi-tenant\tNamespace isolation\n")
	fmt.Fprintf(w, "Audit\tStructured JSON (zerolog)\n")

	if currentEdition != edition.Enterprise {
		fmt.Fprintf(w, "Upgrade\thttps://zeron.one\n")
	}

	w.Flush()
	fmt.Fprintln(cmd.OutOrStdout())

	return nil
}
