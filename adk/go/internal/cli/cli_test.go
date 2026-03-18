package cli

import (
	"testing"
	"text/template"

	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/dsl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// DomainTemplates map coverage
// ---------------------------------------------------------------------------

func TestDomainTemplates_HasAllOSSDomains(t *testing.T) {
	expected := []string{"generic", "risk_quant", "vuln_triage", "appsec", "compliance"}
	for _, domain := range expected {
		tmpl, ok := DomainTemplates[domain]
		assert.True(t, ok, "DomainTemplates should contain domain %q", domain)
		assert.NotNil(t, tmpl, "template for domain %q should not be nil", domain)
		assert.Equal(t, domain, tmpl.Domain, "template Domain field should match key")
	}
	assert.Len(t, DomainTemplates, len(expected),
		"DomainTemplates should have exactly %d entries", len(expected))
}

// ---------------------------------------------------------------------------
// OSSDomains variable
// ---------------------------------------------------------------------------

func TestOSSDomains_MatchesExpected(t *testing.T) {
	expected := []string{"generic", "risk_quant", "vuln_triage", "appsec", "compliance"}
	assert.Equal(t, expected, OSSDomains)
}

// ---------------------------------------------------------------------------
// YAML template validation -- each template renders valid US-ADSL
// ---------------------------------------------------------------------------

func TestDomainTemplates_YAMLValidatesAgainstDSL(t *testing.T) {
	testData := map[string]string{
		"AgentID":   "test-agent-v1",
		"AgentName": "Test Agent",
		"ClassName": "TestAgent",
	}

	for domain, dt := range DomainTemplates {
		t.Run("yaml_"+domain, func(t *testing.T) {
			// Render the YAML template
			tmpl, err := template.New(domain).Parse(dt.YAMLTemplate)
			require.NoError(t, err, "YAML template for %q should parse as Go template", domain)

			var buf []byte
			w := &writerCollector{}
			err = tmpl.Execute(w, testData)
			require.NoError(t, err, "YAML template for %q should execute without error", domain)
			buf = w.data

			// Parse with the DSL parser
			agentDSL, parseErr := dsl.LoadAgentYamlString(string(buf))
			require.NoError(t, parseErr,
				"rendered YAML for domain %q should be valid US-ADSL; got error: %v\nYAML:\n%s",
				domain, parseErr, string(buf))
			require.NotNil(t, agentDSL)
			assert.Equal(t, "test-agent-v1", agentDSL.Agent.ID)
			assert.Equal(t, "Test Agent", agentDSL.Agent.Name)
		})
	}
}

// writerCollector is a simple io.Writer that collects bytes.
type writerCollector struct {
	data []byte
}

func (w *writerCollector) Write(p []byte) (n int, err error) {
	w.data = append(w.data, p...)
	return len(p), nil
}

// ---------------------------------------------------------------------------
// Go template parsing -- each template is a valid Go text/template
// ---------------------------------------------------------------------------

func TestDomainTemplates_GoTemplateParses(t *testing.T) {
	testData := map[string]string{
		"AgentID":   "test-agent-v1",
		"AgentName": "Test Agent",
		"ClassName": "TestAgent",
	}

	for domain, dt := range DomainTemplates {
		t.Run("go_"+domain, func(t *testing.T) {
			tmpl, err := template.New(domain).Parse(dt.GoTemplate)
			require.NoError(t, err, "Go template for %q should parse as Go template", domain)

			w := &writerCollector{}
			err = tmpl.Execute(w, testData)
			require.NoError(t, err, "Go template for %q should execute without error", domain)

			content := string(w.data)
			assert.Contains(t, content, "TestAgent",
				"Go template for %q should contain the class name placeholder value", domain)
			assert.Contains(t, content, "runtime.BaseAgent",
				"Go template for %q should reference runtime.BaseAgent", domain)
			assert.Contains(t, content, "Execute",
				"Go template for %q should contain Execute method", domain)
		})
	}
}

// ---------------------------------------------------------------------------
// Root command
// ---------------------------------------------------------------------------

func TestRootCmd_Exists(t *testing.T) {
	cmd := RootCmd()
	require.NotNil(t, cmd)
	assert.Equal(t, "zak", cmd.Use)
}

func TestRootCmd_HasSubcommands(t *testing.T) {
	cmd := RootCmd()
	subcommands := cmd.Commands()

	// Collect subcommand names
	names := make(map[string]bool)
	for _, sub := range subcommands {
		names[sub.Use] = true
	}

	// Check expected subcommands exist (Use may contain args after the command name)
	expectedPrefixes := []string{"init", "validate", "run", "agents", "info"}
	for _, prefix := range expectedPrefixes {
		found := false
		for _, sub := range subcommands {
			if sub.Name() == prefix {
				found = true
				break
			}
		}
		assert.True(t, found, "root command should have subcommand %q", prefix)
	}
}

// ---------------------------------------------------------------------------
// Helper: contains
// ---------------------------------------------------------------------------

func TestContains(t *testing.T) {
	assert.True(t, contains([]string{"a", "b", "c"}, "b"))
	assert.False(t, contains([]string{"a", "b", "c"}, "d"))
	assert.False(t, contains([]string{}, "a"))
}

// ---------------------------------------------------------------------------
// Helper: renderTemplate
// ---------------------------------------------------------------------------

func TestRenderTemplate(t *testing.T) {
	tmpl := "Hello, {{.Name}}! You are {{.Role}}."
	data := map[string]string{
		"Name": "ZAK",
		"Role": "an agent",
	}

	result, err := renderTemplate("test", tmpl, data)
	require.NoError(t, err)
	assert.Equal(t, "Hello, ZAK! You are an agent.", result)
}

func TestRenderTemplate_InvalidTemplate(t *testing.T) {
	_, err := renderTemplate("bad", "{{.Unclosed", map[string]string{})
	require.Error(t, err)
}
