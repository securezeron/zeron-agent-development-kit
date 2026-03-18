package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/fatih/color"
	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/dsl"
	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/edition"
	"github.com/spf13/cobra"
)

var (
	initName   string
	initDomain string
	initOut    string
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Scaffold a new agent -- generates a YAML definition and Go source file",
	Long: `Scaffold a new agent with a US-ADSL YAML definition and a Go implementation
stub. The generated files contain all required fields and a skeleton Execute()
method ready for customisation.`,
	RunE: runInit,
}

func init() {
	initCmd.Flags().StringVarP(&initName, "name", "n", "", "Human-readable agent name (e.g. 'My Risk Agent')")
	initCmd.Flags().StringVarP(&initDomain, "domain", "d", "", "Security domain for this agent")
	initCmd.Flags().StringVarP(&initOut, "out", "o", ".", "Output directory")
	_ = initCmd.MarkFlagRequired("name")
	_ = initCmd.MarkFlagRequired("domain")
	rootCmd.AddCommand(initCmd)
}

// nonAlphaNum matches any character that is not alphanumeric.
var nonAlphaNum = regexp.MustCompile(`[^a-zA-Z0-9]+`)

// nonAlphaNumLower matches any character that is not lowercase alphanumeric.
var nonAlphaNumLower = regexp.MustCompile(`[^a-z0-9]+`)

func runInit(cmd *cobra.Command, args []string) error {
	green := color.New(color.FgGreen, color.Bold)
	cyan := color.New(color.FgCyan)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow)
	bold := color.New(color.Bold)

	currentEdition := edition.GetEdition()

	// Validate domain
	validDomains := OSSDomains
	if currentEdition == edition.Enterprise {
		validDomains = allTemplateDomains()
	}

	if !contains(validDomains, initDomain) {
		if _, exists := DomainTemplates[initDomain]; exists && currentEdition != edition.Enterprise {
			red.Fprintf(cmd.ErrOrStderr(), "Domain '%s' is an enterprise-only domain.\n", initDomain)
			fmt.Fprintf(cmd.ErrOrStderr(), "Available on open-source: %s\n", strings.Join(OSSDomains, ", "))
			fmt.Fprintf(cmd.ErrOrStderr(), "Visit https://zeron.one for enterprise domains.\n")
		} else {
			red.Fprintf(cmd.ErrOrStderr(), "Invalid domain '%s'.\n", initDomain)
			fmt.Fprintf(cmd.ErrOrStderr(), "Valid choices: %s\n", strings.Join(validDomains, ", "))
		}
		return fmt.Errorf("invalid domain: %s", initDomain)
	}

	tmpl := DomainTemplates[initDomain]

	// Derive safe ID and class name from the human name
	agentID := strings.Trim(nonAlphaNumLower.ReplaceAllString(strings.ToLower(initName), "-"), "-")
	words := nonAlphaNum.Split(initName, -1)
	var classNameParts []string
	for _, w := range words {
		if w != "" {
			classNameParts = append(classNameParts, strings.ToUpper(w[:1])+w[1:])
		}
	}
	className := strings.Join(classNameParts, "")
	if !strings.HasSuffix(className, "Agent") {
		className += "Agent"
	}

	// Create output directory
	outDir := initOut
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	// Template data
	data := map[string]string{
		"AgentID":   agentID,
		"AgentName": initName,
		"ClassName": className,
	}

	// Render YAML template
	yamlContent, err := renderTemplate("yaml", tmpl.YAMLTemplate, data)
	if err != nil {
		return fmt.Errorf("rendering YAML template: %w", err)
	}

	// Render Go template
	goContent, err := renderTemplate("go", tmpl.GoTemplate, data)
	if err != nil {
		return fmt.Errorf("rendering Go template: %w", err)
	}

	// Write files
	yamlPath := filepath.Join(outDir, agentID+".yaml")
	goPath := filepath.Join(outDir, strings.ReplaceAll(agentID, "-", "_")+".go")

	if err := os.WriteFile(yamlPath, []byte(yamlContent), 0o644); err != nil {
		return fmt.Errorf("writing YAML file: %w", err)
	}

	if err := os.WriteFile(goPath, []byte(goContent), 0o644); err != nil {
		return fmt.Errorf("writing Go file: %w", err)
	}

	// Validate the generated YAML
	result := dsl.ValidateAgentFile(yamlPath)

	// Print success
	fmt.Fprintln(cmd.OutOrStdout())
	green.Fprintln(cmd.OutOrStdout(), "Agent scaffolded!")
	fmt.Fprintln(cmd.OutOrStdout())
	bold.Fprintf(cmd.OutOrStdout(), "  YAML:  ")
	cyan.Fprintln(cmd.OutOrStdout(), yamlPath)
	bold.Fprintf(cmd.OutOrStdout(), "  Go:    ")
	cyan.Fprintln(cmd.OutOrStdout(), goPath)
	fmt.Fprintln(cmd.OutOrStdout())
	bold.Fprintln(cmd.OutOrStdout(), "  Next steps:")
	fmt.Fprintf(cmd.OutOrStdout(), "    1. Implement %s.Execute()\n", className)
	fmt.Fprintf(cmd.OutOrStdout(), "    2. zak validate %s\n", yamlPath)
	fmt.Fprintf(cmd.OutOrStdout(), "    3. zak run %s --tenant <id>\n", yamlPath)

	if currentEdition != edition.Enterprise {
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintln(cmd.OutOrStdout(), "  Enterprise edition adds more domains -- visit https://zeron.one")
	}

	if !result.Valid {
		fmt.Fprintln(cmd.OutOrStdout())
		yellow.Fprintln(cmd.OutOrStdout(), "  Validation warnings in generated YAML:")
		for _, e := range result.Errors {
			yellow.Fprintf(cmd.OutOrStdout(), "    - %s\n", e)
		}
	}

	return nil
}

// renderTemplate renders a Go text/template with the given data map.
func renderTemplate(name, tmplStr string, data map[string]string) (string, error) {
	t, err := template.New(name).Parse(tmplStr)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// contains checks if a string is in a slice.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// allTemplateDomains returns all domain keys from DomainTemplates.
func allTemplateDomains() []string {
	domains := make([]string, 0, len(DomainTemplates))
	for d := range DomainTemplates {
		domains = append(domains, d)
	}
	return domains
}
