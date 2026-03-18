package schema

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// SIFNode base tests
// ===========================================================================

func TestNewSIFNode_Defaults(t *testing.T) {
	node := NewSIFNode("node-1", "test-source")

	assert.Equal(t, "node-1", node.NodeID)
	assert.Equal(t, "test-source", node.Source)
	assert.Equal(t, 1.0, node.Confidence)
	assert.Nil(t, node.ValidTo)
	assert.False(t, node.ValidFrom.IsZero())
}

func TestSIFNode_IsActive_NoValidTo(t *testing.T) {
	node := NewSIFNode("n1", "src")
	assert.True(t, node.IsActive(), "Node without ValidTo should be active")
}

func TestSIFNode_IsActive_FutureValidTo(t *testing.T) {
	node := NewSIFNode("n2", "src")
	future := time.Now().UTC().Add(24 * time.Hour)
	node.ValidTo = &future
	assert.True(t, node.IsActive(), "Node with future ValidTo should be active")
}

func TestSIFNode_IsActive_PastValidTo(t *testing.T) {
	node := NewSIFNode("n3", "src")
	past := time.Now().UTC().Add(-24 * time.Hour)
	node.ValidTo = &past
	assert.False(t, node.IsActive(), "Node with past ValidTo should not be active")
}

// ===========================================================================
// AssetNode tests
// ===========================================================================

func TestNewAssetNode_Defaults(t *testing.T) {
	asset := NewAssetNode("asset-web-01", "scanner", "server")

	assert.Equal(t, "asset-web-01", asset.NodeID)
	assert.Equal(t, "scanner", asset.Source)
	assert.Equal(t, "server", asset.AssetType)
	assert.Equal(t, CriticalityMedium, asset.Criticality)
	assert.Equal(t, EnvironmentProduction, asset.Environment)
	assert.Equal(t, ExposureInternal, asset.ExposureLevel)
	assert.Equal(t, 0.0, asset.RiskScore)
	assert.Empty(t, asset.Tags)
	assert.Equal(t, "", asset.Owner)
}

func TestAssetNode_CustomFields(t *testing.T) {
	asset := NewAssetNode("db-01", "cmdb", "database")
	asset.Criticality = CriticalityCritical
	asset.Environment = EnvironmentStaging
	asset.ExposureLevel = ExposureExternal
	asset.Owner = "infra-team"
	asset.RiskScore = 7.5
	asset.Tags = []string{"pci", "sensitive"}

	assert.Equal(t, CriticalityCritical, asset.Criticality)
	assert.Equal(t, EnvironmentStaging, asset.Environment)
	assert.Equal(t, ExposureExternal, asset.ExposureLevel)
	assert.Equal(t, "infra-team", asset.Owner)
	assert.InDelta(t, 7.5, asset.RiskScore, 0.01)
	assert.Equal(t, []string{"pci", "sensitive"}, asset.Tags)
}

// ===========================================================================
// IdentityNode tests
// ===========================================================================

func TestNewIdentityNode_Defaults(t *testing.T) {
	identity := NewIdentityNode("user-alice", "iam", "human")

	assert.Equal(t, "user-alice", identity.NodeID)
	assert.Equal(t, "human", identity.IdentityType)
	assert.Equal(t, PrivilegeLow, identity.PrivilegeLevel)
	assert.False(t, identity.MFAEnabled)
	assert.Equal(t, 0.0, identity.RiskScore)
	assert.Equal(t, "", identity.Department)
}

func TestIdentityNode_AdminWithMFA(t *testing.T) {
	identity := NewIdentityNode("sa-deploy", "iam", "service_account")
	identity.PrivilegeLevel = PrivilegeAdmin
	identity.MFAEnabled = true
	identity.Department = "platform"

	assert.Equal(t, PrivilegeAdmin, identity.PrivilegeLevel)
	assert.True(t, identity.MFAEnabled)
	assert.Equal(t, "platform", identity.Department)
}

// ===========================================================================
// VulnerabilityNode tests
// ===========================================================================

func TestNewVulnerabilityNode_Defaults(t *testing.T) {
	vuln := NewVulnerabilityNode("vuln-001", "scanner-x", "cve")

	assert.Equal(t, "vuln-001", vuln.NodeID)
	assert.Equal(t, "cve", vuln.VulnType)
	assert.Equal(t, SeverityMedium, vuln.Severity)
	assert.InDelta(t, 0.5, vuln.Exploitability, 0.001)
	assert.Nil(t, vuln.CVSSScore)
	assert.Equal(t, VulnStatusOpen, vuln.Status)
	assert.Equal(t, "", vuln.CVEID)
}

func TestVulnerabilityNode_CriticalCVE(t *testing.T) {
	vuln := NewVulnerabilityNode("vuln-cve-2024-1234", "nessus", "cve")
	vuln.CVEID = "CVE-2024-1234"
	vuln.Severity = SeverityCritical
	vuln.Exploitability = 0.95
	cvss := 9.8
	vuln.CVSSScore = &cvss
	vuln.Status = VulnStatusOpen

	assert.Equal(t, "CVE-2024-1234", vuln.CVEID)
	assert.Equal(t, SeverityCritical, vuln.Severity)
	require.NotNil(t, vuln.CVSSScore)
	assert.InDelta(t, 9.8, *vuln.CVSSScore, 0.01)
}

// ===========================================================================
// ControlNode tests
// ===========================================================================

func TestNewControlNode_Defaults(t *testing.T) {
	ctrl := NewControlNode("ctrl-waf-01", "security-tools", "waf")

	assert.Equal(t, "ctrl-waf-01", ctrl.NodeID)
	assert.Equal(t, "waf", ctrl.ControlType)
	assert.InDelta(t, 0.5, ctrl.Effectiveness, 0.001)
	assert.True(t, ctrl.Automated)
	assert.Empty(t, ctrl.FrameworkRefs)
}

func TestControlNode_WithFrameworkRefs(t *testing.T) {
	ctrl := NewControlNode("ctrl-iam", "iam-system", "iam_policy")
	ctrl.FrameworkRefs = []string{"ISO27001:A.9.2.1", "NIST:AC-2"}
	ctrl.Effectiveness = 0.85

	assert.Len(t, ctrl.FrameworkRefs, 2)
	assert.InDelta(t, 0.85, ctrl.Effectiveness, 0.001)
}

// ===========================================================================
// RiskNode tests
// ===========================================================================

func TestNewRiskNode_Defaults(t *testing.T) {
	rn := NewRiskNode("risk-cyber-01", "risk-engine", "cyber")

	assert.Equal(t, "risk-cyber-01", rn.NodeID)
	assert.Equal(t, "cyber", rn.RiskType)
	assert.Equal(t, 0.0, rn.Likelihood)
	assert.Equal(t, 0.0, rn.Impact)
	assert.Equal(t, 0.0, rn.RiskScore)
	assert.Nil(t, rn.EAL)
	assert.Nil(t, rn.VaR95)
}

func TestRiskNode_WithFinancials(t *testing.T) {
	rn := NewRiskNode("risk-ai-01", "risk-engine", "ai")
	rn.Likelihood = 0.3
	rn.Impact = 8.5
	rn.RiskScore = 5.1
	eal := 250000.0
	var95 := 1500000.0
	rn.EAL = &eal
	rn.VaR95 = &var95

	assert.InDelta(t, 0.3, rn.Likelihood, 0.001)
	require.NotNil(t, rn.EAL)
	assert.InDelta(t, 250000.0, *rn.EAL, 0.1)
	require.NotNil(t, rn.VaR95)
	assert.InDelta(t, 1500000.0, *rn.VaR95, 0.1)
}

// ===========================================================================
// VendorNode tests
// ===========================================================================

func TestNewVendorNode_Defaults(t *testing.T) {
	vendor := NewVendorNode("vendor-acme", "tprm", "saas", 1)

	assert.Equal(t, "vendor-acme", vendor.NodeID)
	assert.Equal(t, "saas", vendor.VendorType)
	assert.Equal(t, 1, vendor.Tier)
	assert.Equal(t, 0.0, vendor.RiskScore)
	assert.Nil(t, vendor.LastAssessed)
	assert.Equal(t, "", vendor.Country)
}

func TestVendorNode_WithMetadata(t *testing.T) {
	vendor := NewVendorNode("vendor-xyz", "tprm", "infrastructure", 2)
	vendor.Country = "US"
	assessed := time.Now().UTC()
	vendor.LastAssessed = &assessed
	vendor.RiskScore = 4.2

	assert.Equal(t, "US", vendor.Country)
	require.NotNil(t, vendor.LastAssessed)
	assert.InDelta(t, 4.2, vendor.RiskScore, 0.01)
}

// ===========================================================================
// AIModelNode tests
// ===========================================================================

func TestNewAIModelNode_Defaults(t *testing.T) {
	ai := NewAIModelNode("model-gpt4", "ai-inventory", "llm", "openai")

	assert.Equal(t, "model-gpt4", ai.NodeID)
	assert.Equal(t, "llm", ai.ModelType)
	assert.Equal(t, "openai", ai.Provider)
	assert.Equal(t, DataSensitivityMedium, ai.DataSensitivity)
	assert.False(t, ai.GuardrailsEnabled)
	assert.Equal(t, 0.0, ai.RiskScore)
	assert.False(t, ai.ExposedViaAPI)
}

func TestAIModelNode_ExposedWithGuardrails(t *testing.T) {
	ai := NewAIModelNode("model-internal", "registry", "classifier", "internal")
	ai.DataSensitivity = DataSensitivityRestricted
	ai.GuardrailsEnabled = true
	ai.ExposedViaAPI = true
	ai.RiskScore = 6.7

	assert.Equal(t, DataSensitivityRestricted, ai.DataSensitivity)
	assert.True(t, ai.GuardrailsEnabled)
	assert.True(t, ai.ExposedViaAPI)
	assert.InDelta(t, 6.7, ai.RiskScore, 0.01)
}

// ===========================================================================
// Enum constants tests
// ===========================================================================

func TestCriticality_Values(t *testing.T) {
	assert.Equal(t, Criticality("low"), CriticalityLow)
	assert.Equal(t, Criticality("medium"), CriticalityMedium)
	assert.Equal(t, Criticality("high"), CriticalityHigh)
	assert.Equal(t, Criticality("critical"), CriticalityCritical)
}

func TestSeverity_Values(t *testing.T) {
	assert.Equal(t, Severity("low"), SeverityLow)
	assert.Equal(t, Severity("medium"), SeverityMedium)
	assert.Equal(t, Severity("high"), SeverityHigh)
	assert.Equal(t, Severity("critical"), SeverityCritical)
}

func TestVulnStatus_Values(t *testing.T) {
	assert.Equal(t, VulnStatus("open"), VulnStatusOpen)
	assert.Equal(t, VulnStatus("mitigated"), VulnStatusMitigated)
	assert.Equal(t, VulnStatus("accepted"), VulnStatusAccepted)
	assert.Equal(t, VulnStatus("false_positive"), VulnStatusFalsePositive)
}

func TestPrivilegeLevel_Values(t *testing.T) {
	assert.Equal(t, PrivilegeLevel("low"), PrivilegeLow)
	assert.Equal(t, PrivilegeLevel("medium"), PrivilegeMedium)
	assert.Equal(t, PrivilegeLevel("high"), PrivilegeHigh)
	assert.Equal(t, PrivilegeLevel("admin"), PrivilegeAdmin)
}

func TestDataSensitivity_Values(t *testing.T) {
	assert.Equal(t, DataSensitivity("low"), DataSensitivityLow)
	assert.Equal(t, DataSensitivity("medium"), DataSensitivityMedium)
	assert.Equal(t, DataSensitivity("high"), DataSensitivityHigh)
	assert.Equal(t, DataSensitivity("restricted"), DataSensitivityRestricted)
}

// ===========================================================================
// SIFEdge base tests
// ===========================================================================

func TestNewSIFEdge_Defaults(t *testing.T) {
	edge := NewSIFEdge("node-a", "node-b", "test-source")

	assert.Equal(t, "node-a", edge.FromID)
	assert.Equal(t, "node-b", edge.ToID)
	assert.Equal(t, "test-source", edge.Source)
	assert.Equal(t, 1.0, edge.Confidence)
	assert.Nil(t, edge.ValidTo)
	assert.False(t, edge.ValidFrom.IsZero())
}

func TestSIFEdge_IsActive_NoValidTo(t *testing.T) {
	edge := NewSIFEdge("a", "b", "s")
	assert.True(t, edge.IsActive())
}

func TestSIFEdge_IsActive_PastValidTo(t *testing.T) {
	edge := NewSIFEdge("a", "b", "s")
	past := time.Now().UTC().Add(-1 * time.Hour)
	edge.ValidTo = &past
	assert.False(t, edge.IsActive())
}

// ===========================================================================
// Typed edge tests
// ===========================================================================

func TestNewIdentityHasAccessToAsset(t *testing.T) {
	edge := NewIdentityHasAccessToAsset("user-1", "server-1", "iam")

	assert.Equal(t, "user-1", edge.FromID)
	assert.Equal(t, "server-1", edge.ToID)
	assert.Equal(t, "read", edge.AccessType)
	assert.Equal(t, "", edge.GrantedBy)
}

func TestNewAssetHasVulnerability(t *testing.T) {
	edge := NewAssetHasVulnerability("server-1", "vuln-1", "scanner")

	assert.Equal(t, "server-1", edge.FromID)
	assert.Equal(t, "vuln-1", edge.ToID)
	assert.False(t, edge.FirstSeen.IsZero())
	assert.Equal(t, "", edge.Scanner)
}

func TestNewControlMitigatesVulnerability(t *testing.T) {
	edge := NewControlMitigatesVulnerability("ctrl-1", "vuln-1", "policy-engine")

	assert.Equal(t, "ctrl-1", edge.FromID)
	assert.Equal(t, "vuln-1", edge.ToID)
	assert.Equal(t, "partial", edge.MitigationType)
}

func TestNewVendorSuppliesAsset(t *testing.T) {
	edge := NewVendorSuppliesAsset("vendor-1", "asset-1", "tprm")

	assert.Equal(t, "vendor-1", edge.FromID)
	assert.Equal(t, "asset-1", edge.ToID)
	assert.Equal(t, "", edge.ContractRef)
}

func TestNewAIModelAccessesDataStore(t *testing.T) {
	edge := NewAIModelAccessesDataStore("model-1", "datastore-1", "ai-registry")

	assert.Equal(t, "model-1", edge.FromID)
	assert.Equal(t, "datastore-1", edge.ToID)
	assert.Equal(t, "training", edge.AccessPurpose)
}

func TestNewRiskImpactsAsset(t *testing.T) {
	edge := NewRiskImpactsAsset("risk-1", "asset-1", "risk-engine")

	assert.Equal(t, "risk-1", edge.FromID)
	assert.Equal(t, "asset-1", edge.ToID)
	assert.Equal(t, "local", edge.BlastRadius)
}

func TestNewAssetCommunicatesWith(t *testing.T) {
	edge := NewAssetCommunicatesWith("app-1", "db-1", "netflow")

	assert.Equal(t, "app-1", edge.FromID)
	assert.Equal(t, "db-1", edge.ToID)
	assert.True(t, edge.Encrypted)
	assert.Equal(t, "", edge.Protocol)
	assert.Equal(t, 0, edge.Port)
}

func TestAssetCommunicatesWith_WithDetails(t *testing.T) {
	edge := NewAssetCommunicatesWith("web-1", "api-1", "nmap")
	edge.Protocol = "https"
	edge.Port = 443
	edge.Encrypted = true

	assert.Equal(t, "https", edge.Protocol)
	assert.Equal(t, 443, edge.Port)
	assert.True(t, edge.Encrypted)
}
