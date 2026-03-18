// Package dsl provides the Universal Security Agent DSL (US-ADSL) schema types and enums.
package dsl

import "fmt"

// Domain represents supported security agent domains.
type Domain string

const (
	DomainRedTeam           Domain = "red_team"
	DomainAppSec            Domain = "appsec"
	DomainAISecurity        Domain = "ai_security"
	DomainRiskQuant         Domain = "risk_quant"
	DomainSupplyChain       Domain = "supply_chain"
	DomainCompliance        Domain = "compliance"
	DomainAPISecurity       Domain = "api_security"
	DomainAttackSurface     Domain = "attack_surface"
	DomainCloudPosture      Domain = "cloud_posture"
	DomainContainerSecurity Domain = "container_security"
	DomainCyberInsurance    Domain = "cyber_insurance"
	DomainDataPrivacy       Domain = "data_privacy"
	DomainIACSecurity       Domain = "iac_security"
	DomainIAMDrift          Domain = "iam_drift"
	DomainIdentityRisk      Domain = "identity_risk"
	DomainIncidentResponse  Domain = "incident_response"
	DomainMalwareAnalysis   Domain = "malware_analysis"
	DomainNetworkSecurity   Domain = "network_security"
	DomainPentestAuto       Domain = "pentest_auto"
	DomainThreatDetection   Domain = "threat_detection"
	DomainThreatIntel       Domain = "threat_intel"
	DomainVulnTriage        Domain = "vuln_triage"
	DomainUsageMetrics      Domain = "usage_metrics"
)

// AllDomains lists every valid domain value.
var AllDomains = []Domain{
	DomainRedTeam, DomainAppSec, DomainAISecurity, DomainRiskQuant,
	DomainSupplyChain, DomainCompliance, DomainAPISecurity, DomainAttackSurface,
	DomainCloudPosture, DomainContainerSecurity, DomainCyberInsurance,
	DomainDataPrivacy, DomainIACSecurity, DomainIAMDrift, DomainIdentityRisk,
	DomainIncidentResponse, DomainMalwareAnalysis, DomainNetworkSecurity,
	DomainPentestAuto, DomainThreatDetection, DomainThreatIntel,
	DomainVulnTriage, DomainUsageMetrics,
}

func (d Domain) Valid() bool {
	for _, v := range AllDomains {
		if d == v {
			return true
		}
	}
	return false
}

// ReasoningMode describes how the agent reasons and makes decisions.
type ReasoningMode string

const (
	ReasoningDeterministic ReasoningMode = "deterministic"
	ReasoningRuleBased     ReasoningMode = "rule_based"
	ReasoningLLMAssisted   ReasoningMode = "llm_assisted"
	ReasoningHybrid        ReasoningMode = "hybrid"
	ReasoningProbabilistic ReasoningMode = "probabilistic"
	ReasoningLLMReAct      ReasoningMode = "llm_react"
)

var AllReasoningModes = []ReasoningMode{
	ReasoningDeterministic, ReasoningRuleBased, ReasoningLLMAssisted,
	ReasoningHybrid, ReasoningProbabilistic, ReasoningLLMReAct,
}

func (r ReasoningMode) Valid() bool {
	for _, v := range AllReasoningModes {
		if r == v {
			return true
		}
	}
	return false
}

// AutonomyLevel describes how much autonomous action the agent is permitted.
type AutonomyLevel string

const (
	AutonomyObserve         AutonomyLevel = "observe"
	AutonomySuggest         AutonomyLevel = "suggest"
	AutonomyBounded         AutonomyLevel = "bounded"
	AutonomyHigh            AutonomyLevel = "high"
	AutonomyFullyAutonomous AutonomyLevel = "fully_autonomous"
)

var AllAutonomyLevels = []AutonomyLevel{
	AutonomyObserve, AutonomySuggest, AutonomyBounded,
	AutonomyHigh, AutonomyFullyAutonomous,
}

func (a AutonomyLevel) Valid() bool {
	for _, v := range AllAutonomyLevels {
		if a == v {
			return true
		}
	}
	return false
}

// Priority defines execution priority.
type Priority string

const (
	PriorityLow      Priority = "low"
	PriorityMedium   Priority = "medium"
	PriorityHigh     Priority = "high"
	PriorityCritical Priority = "critical"
)

var AllPriorities = []Priority{PriorityLow, PriorityMedium, PriorityHigh, PriorityCritical}

func (p Priority) Valid() bool {
	for _, v := range AllPriorities {
		if p == v {
			return true
		}
	}
	return false
}

// RiskBudget limits autonomous action scope.
type RiskBudget string

const (
	RiskBudgetLow    RiskBudget = "low"
	RiskBudgetMedium RiskBudget = "medium"
	RiskBudgetHigh   RiskBudget = "high"
)

var AllRiskBudgets = []RiskBudget{RiskBudgetLow, RiskBudgetMedium, RiskBudgetHigh}

func (r RiskBudget) Valid() bool {
	for _, v := range AllRiskBudgets {
		if r == v {
			return true
		}
	}
	return false
}

// SandboxProfile describes the execution sandboxing profile.
type SandboxProfile string

const (
	SandboxMinimal          SandboxProfile = "minimal"
	SandboxStandard         SandboxProfile = "standard"
	SandboxStrict           SandboxProfile = "strict"
	SandboxOffensiveIsolated SandboxProfile = "offensive_isolated"
)

var AllSandboxProfiles = []SandboxProfile{
	SandboxMinimal, SandboxStandard, SandboxStrict, SandboxOffensiveIsolated,
}

func (s SandboxProfile) Valid() bool {
	for _, v := range AllSandboxProfiles {
		if s == v {
			return true
		}
	}
	return false
}

// AuditLevel describes the verbosity of the audit trail.
type AuditLevel string

const (
	AuditMinimal  AuditLevel = "minimal"
	AuditStandard AuditLevel = "standard"
	AuditVerbose  AuditLevel = "verbose"
)

var AllAuditLevels = []AuditLevel{AuditMinimal, AuditStandard, AuditVerbose}

func (a AuditLevel) Valid() bool {
	for _, v := range AllAuditLevels {
		if a == v {
			return true
		}
	}
	return false
}

// ParameterType for tool parameter definitions.
type ParameterType string

const (
	ParamString  ParameterType = "string"
	ParamInt     ParameterType = "integer"
	ParamFloat   ParameterType = "float"
	ParamBool    ParameterType = "boolean"
	ParamObject  ParameterType = "object"
)

// validateEnum is a helper that checks if a value is in a set.
func validateEnum[T comparable](val T, allowed []T, name string) error {
	for _, v := range allowed {
		if val == v {
			return nil
		}
	}
	return fmt.Errorf("invalid %s value: %v", name, val)
}
