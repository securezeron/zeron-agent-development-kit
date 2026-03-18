// Package schema provides the canonical SIF (Security Intelligence Fabric)
// node and edge type definitions. Every node is time-aware with valid_from,
// valid_to, confidence, and source fields.
package schema

import "time"

// ---------------------------------------------------------------------------
// Enum constants (string-typed for JSON compatibility)
// ---------------------------------------------------------------------------

// Criticality represents the importance level of an asset.
type Criticality string

const (
	CriticalityLow      Criticality = "low"
	CriticalityMedium   Criticality = "medium"
	CriticalityHigh     Criticality = "high"
	CriticalityCritical Criticality = "critical"
)

// ExposureLevel describes how exposed an asset is.
type ExposureLevel string

const (
	ExposureInternal       ExposureLevel = "internal"
	ExposureExternal       ExposureLevel = "external"
	ExposureInternetFacing ExposureLevel = "internet_facing"
)

// Environment represents the deployment environment.
type Environment string

const (
	EnvironmentProduction Environment = "production"
	EnvironmentStaging    Environment = "staging"
	EnvironmentDev        Environment = "dev"
)

// Severity represents vulnerability severity levels.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// VulnStatus represents the status of a vulnerability.
type VulnStatus string

const (
	VulnStatusOpen          VulnStatus = "open"
	VulnStatusMitigated     VulnStatus = "mitigated"
	VulnStatusAccepted      VulnStatus = "accepted"
	VulnStatusFalsePositive VulnStatus = "false_positive"
)

// PrivilegeLevel represents the privilege level of an identity.
type PrivilegeLevel string

const (
	PrivilegeLow    PrivilegeLevel = "low"
	PrivilegeMedium PrivilegeLevel = "medium"
	PrivilegeHigh   PrivilegeLevel = "high"
	PrivilegeAdmin  PrivilegeLevel = "admin"
)

// DataSensitivity represents the data sensitivity classification.
type DataSensitivity string

const (
	DataSensitivityLow        DataSensitivity = "low"
	DataSensitivityMedium     DataSensitivity = "medium"
	DataSensitivityHigh       DataSensitivity = "high"
	DataSensitivityRestricted DataSensitivity = "restricted"
)

// ---------------------------------------------------------------------------
// SIFNode — time-aware base for all node types
// ---------------------------------------------------------------------------

// SIFNode is the base struct embedded by all SIF node types.
// It provides time-aware metadata fields.
type SIFNode struct {
	// NodeID is the unique identifier for this node.
	NodeID string `json:"node_id"`
	// ValidFrom is the timestamp from which this node is considered valid.
	ValidFrom time.Time `json:"valid_from"`
	// ValidTo is the timestamp at which this node expires.
	// A zero-value means the node is currently active.
	ValidTo *time.Time `json:"valid_to,omitempty"`
	// Confidence is the data confidence score (0.0 to 1.0).
	Confidence float64 `json:"confidence"`
	// Source is the system or integration that produced this node.
	Source string `json:"source"`
}

// NewSIFNode creates a SIFNode with defaults (ValidFrom = now, Confidence = 1.0).
func NewSIFNode(nodeID, source string) SIFNode {
	return SIFNode{
		NodeID:     nodeID,
		ValidFrom:  time.Now().UTC(),
		ValidTo:    nil,
		Confidence: 1.0,
		Source:     source,
	}
}

// IsActive returns true if the node is currently valid (not expired).
func (n *SIFNode) IsActive() bool {
	if n.ValidTo == nil {
		return true
	}
	return time.Now().UTC().Before(*n.ValidTo)
}

// ---------------------------------------------------------------------------
// Canonical Node Types
// ---------------------------------------------------------------------------

// AssetNode represents a technology asset (server, service, application,
// database, cloud service, etc.).
type AssetNode struct {
	SIFNode
	// AssetType describes the kind of asset (e.g. "server", "application",
	// "database", "cloud_service").
	AssetType string `json:"asset_type"`
	// Criticality is the importance classification.
	Criticality Criticality `json:"criticality"`
	// Environment is the deployment environment.
	Environment Environment `json:"environment"`
	// Owner is the identity or team that owns the asset.
	Owner string `json:"owner,omitempty"`
	// ExposureLevel describes how exposed the asset is.
	ExposureLevel ExposureLevel `json:"exposure_level"`
	// RiskScore is the computed risk score (0.0 to 10.0).
	RiskScore float64 `json:"risk_score"`
	// Tags are arbitrary labels for grouping and filtering.
	Tags []string `json:"tags,omitempty"`
}

// NewAssetNode creates an AssetNode with sensible defaults.
func NewAssetNode(nodeID, source, assetType string) *AssetNode {
	return &AssetNode{
		SIFNode:       NewSIFNode(nodeID, source),
		AssetType:     assetType,
		Criticality:   CriticalityMedium,
		Environment:   EnvironmentProduction,
		ExposureLevel: ExposureInternal,
		RiskScore:     0.0,
		Tags:          []string{},
	}
}

// IdentityNode represents a human or machine identity (user, service
// account, API key, role, etc.).
type IdentityNode struct {
	SIFNode
	// IdentityType describes the kind of identity (e.g. "human",
	// "service_account", "api_key", "role").
	IdentityType string `json:"identity_type"`
	// PrivilegeLevel is the access privilege classification.
	PrivilegeLevel PrivilegeLevel `json:"privilege_level"`
	// MFAEnabled indicates whether multi-factor authentication is active.
	MFAEnabled bool `json:"mfa_enabled"`
	// RiskScore is the computed risk score (0.0 to 10.0).
	RiskScore float64 `json:"risk_score"`
	// Department is the organizational unit (optional).
	Department string `json:"department,omitempty"`
}

// NewIdentityNode creates an IdentityNode with sensible defaults.
func NewIdentityNode(nodeID, source, identityType string) *IdentityNode {
	return &IdentityNode{
		SIFNode:        NewSIFNode(nodeID, source),
		IdentityType:   identityType,
		PrivilegeLevel: PrivilegeLow,
		MFAEnabled:     false,
		RiskScore:      0.0,
	}
}

// VulnerabilityNode represents a security vulnerability (CVE,
// misconfiguration, finding, etc.).
type VulnerabilityNode struct {
	SIFNode
	// VulnType describes the kind of vulnerability (e.g. "cve",
	// "misconfiguration", "secret_exposure", "injection").
	VulnType string `json:"vuln_type"`
	// CVEID is the CVE identifier (optional).
	CVEID string `json:"cve_id,omitempty"`
	// Severity is the vulnerability severity classification.
	Severity Severity `json:"severity"`
	// Exploitability is the CVSS exploitability score (0.0 to 1.0).
	Exploitability float64 `json:"exploitability"`
	// CVSSScore is the full CVSS score (0.0 to 10.0, optional).
	CVSSScore *float64 `json:"cvss_score,omitempty"`
	// Status is the current remediation status.
	Status VulnStatus `json:"status"`
}

// NewVulnerabilityNode creates a VulnerabilityNode with sensible defaults.
func NewVulnerabilityNode(nodeID, source, vulnType string) *VulnerabilityNode {
	return &VulnerabilityNode{
		SIFNode:        NewSIFNode(nodeID, source),
		VulnType:       vulnType,
		Severity:       SeverityMedium,
		Exploitability: 0.5,
		Status:         VulnStatusOpen,
	}
}

// ControlNode represents a security control (firewall rule, IAM policy,
// monitoring config, etc.).
type ControlNode struct {
	SIFNode
	// ControlType describes the kind of control (e.g. "firewall", "waf",
	// "iam_policy", "mfa", "dlp").
	ControlType string `json:"control_type"`
	// Effectiveness is the control effectiveness (0.0 to 1.0).
	Effectiveness float64 `json:"effectiveness"`
	// Automated indicates whether the control is automated.
	Automated bool `json:"automated"`
	// FrameworkRefs are framework control IDs this maps to
	// (e.g. "ISO27001:A.12.6.1").
	FrameworkRefs []string `json:"framework_refs,omitempty"`
}

// NewControlNode creates a ControlNode with sensible defaults.
func NewControlNode(nodeID, source, controlType string) *ControlNode {
	return &ControlNode{
		SIFNode:       NewSIFNode(nodeID, source),
		ControlType:   controlType,
		Effectiveness: 0.5,
		Automated:     true,
		FrameworkRefs: []string{},
	}
}

// RiskNode represents a computed risk scenario.
type RiskNode struct {
	SIFNode
	// RiskType describes the kind of risk (e.g. "cyber", "ai",
	// "third_party", "operational").
	RiskType string `json:"risk_type"`
	// Likelihood is the probability of the risk materializing (0.0 to 1.0).
	Likelihood float64 `json:"likelihood"`
	// Impact is the potential impact magnitude (0.0 to 10.0).
	Impact float64 `json:"impact"`
	// RiskScore is the computed risk score (0.0 to 10.0).
	RiskScore float64 `json:"risk_score"`
	// EAL is the Expected Annual Loss in USD (optional).
	EAL *float64 `json:"eal,omitempty"`
	// VaR95 is the Value at Risk at the 95th percentile in USD (optional).
	VaR95 *float64 `json:"var_95,omitempty"`
}

// NewRiskNode creates a RiskNode with sensible defaults.
func NewRiskNode(nodeID, source, riskType string) *RiskNode {
	return &RiskNode{
		SIFNode:    NewSIFNode(nodeID, source),
		RiskType:   riskType,
		Likelihood: 0.0,
		Impact:     0.0,
		RiskScore:  0.0,
	}
}

// VendorNode represents a third-party vendor or supplier.
type VendorNode struct {
	SIFNode
	// VendorType describes the kind of vendor (e.g. "saas", "infrastructure",
	// "professional_services").
	VendorType string `json:"vendor_type"`
	// Tier is the supply-chain tier (1 = direct, 3 = nth party).
	Tier int `json:"tier"`
	// RiskScore is the computed risk score (0.0 to 10.0).
	RiskScore float64 `json:"risk_score"`
	// LastAssessed is the last assessment date (optional).
	LastAssessed *time.Time `json:"last_assessed,omitempty"`
	// Country is the vendor's country of operation (optional).
	Country string `json:"country,omitempty"`
}

// NewVendorNode creates a VendorNode with sensible defaults.
func NewVendorNode(nodeID, source, vendorType string, tier int) *VendorNode {
	return &VendorNode{
		SIFNode:    NewSIFNode(nodeID, source),
		VendorType: vendorType,
		Tier:       tier,
		RiskScore:  0.0,
	}
}

// AIModelNode represents an AI/ML model in use within the organization.
type AIModelNode struct {
	SIFNode
	// ModelType describes the kind of model (e.g. "llm", "classifier",
	// "embedding", "generative").
	ModelType string `json:"model_type"`
	// Provider is the model provider (e.g. "openai", "anthropic",
	// "google", "internal").
	Provider string `json:"provider"`
	// DataSensitivity is the data sensitivity classification.
	DataSensitivity DataSensitivity `json:"data_sensitivity"`
	// GuardrailsEnabled indicates whether safety guardrails are active.
	GuardrailsEnabled bool `json:"guardrails_enabled"`
	// RiskScore is the computed risk score (0.0 to 10.0).
	RiskScore float64 `json:"risk_score"`
	// ExposedViaAPI indicates whether the model is exposed via API.
	ExposedViaAPI bool `json:"exposed_via_api"`
}

// NewAIModelNode creates an AIModelNode with sensible defaults.
func NewAIModelNode(nodeID, source, modelType, provider string) *AIModelNode {
	return &AIModelNode{
		SIFNode:           NewSIFNode(nodeID, source),
		ModelType:         modelType,
		Provider:          provider,
		DataSensitivity:   DataSensitivityMedium,
		GuardrailsEnabled: false,
		RiskScore:         0.0,
		ExposedViaAPI:     false,
	}
}
