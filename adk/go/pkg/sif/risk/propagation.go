// Package risk implements the ZAK canonical risk propagation formula.
//
// Formula:
//
//	node_risk = base_risk * exposure_factor * exploitability
//	            * (1 - control_effectiveness) * privilege_amplifier
//
// All inputs are normalised to 0-1 before multiplication.
// Output is scaled to 0-10 to match standard risk score conventions.
package risk

import "math"

// ---------------------------------------------------------------------------
// RiskInputs
// ---------------------------------------------------------------------------

// RiskInputs holds the inputs required to compute node risk for a single asset.
// All float fields should be in the range 0.0-1.0 unless noted.
type RiskInputs struct {
	// BaseRisk is the inherent risk of the asset (derived from criticality).
	BaseRisk float64
	// ExposureFactor indicates how exposed the asset is
	// (internal=0.2, external=0.6, internet_facing=1.0).
	ExposureFactor float64
	// Exploitability is the highest exploitability score among associated
	// vulnerabilities (0.0 to 1.0).
	Exploitability float64
	// ControlEffectiveness is the effectiveness of mitigating controls
	// (0 = no controls, 1 = perfect).
	ControlEffectiveness float64
	// PrivilegeAmplifier is the risk amplifier from identity access levels
	// (1.0 = baseline).
	PrivilegeAmplifier float64
}

// ---------------------------------------------------------------------------
// RiskOutput
// ---------------------------------------------------------------------------

// RiskOutput holds the result of a risk propagation computation.
type RiskOutput struct {
	// RawScore is the risk score before scaling (0.0 to 1.0).
	RawScore float64 `json:"raw_score"`
	// RiskScore is the final scaled risk score (0.0 to 10.0).
	RiskScore float64 `json:"risk_score"`
	// RiskLevel is a human-readable classification:
	// "low", "medium", "high", or "critical".
	RiskLevel string `json:"risk_level"`
}

// riskOutputFromRaw creates a RiskOutput from a raw [0,1] score.
func riskOutputFromRaw(raw float64) *RiskOutput {
	score := math.Round(raw*10*100) / 100 // round to 2 decimal places
	var level string
	switch {
	case score < 2.5:
		level = "low"
	case score < 5.0:
		level = "medium"
	case score < 7.5:
		level = "high"
	default:
		level = "critical"
	}
	return &RiskOutput{
		RawScore:  math.Round(raw*10000) / 10000, // 4 decimal places
		RiskScore: score,
		RiskLevel: level,
	}
}

// ---------------------------------------------------------------------------
// Compute — the canonical risk formula
// ---------------------------------------------------------------------------

// Compute applies the canonical risk propagation formula:
//
//	raw = base_risk * exposure_factor * exploitability
//	      * (1 - control_effectiveness) * privilege_amplifier
//
// The raw result is clamped to [0, 1] before being scaled to [0, 10].
func Compute(inputs *RiskInputs) *RiskOutput {
	// Guard: control_effectiveness must be in [0,1].
	controlReduction := 1.0 - clamp(inputs.ControlEffectiveness, 0.0, 1.0)

	raw := inputs.BaseRisk *
		inputs.ExposureFactor *
		inputs.Exploitability *
		controlReduction *
		inputs.PrivilegeAmplifier

	// Clamp to [0, 1].
	raw = clamp(raw, 0.0, 1.0)

	return riskOutputFromRaw(raw)
}

// ---------------------------------------------------------------------------
// Helper converters
// ---------------------------------------------------------------------------

// CriticalityToBaseRisk converts a criticality label to a base_risk float.
//
//	low=0.2, medium=0.4, high=0.7, critical=1.0
func CriticalityToBaseRisk(criticality string) float64 {
	switch criticality {
	case "low":
		return 0.2
	case "medium":
		return 0.4
	case "high":
		return 0.7
	case "critical":
		return 1.0
	default:
		return 0.4
	}
}

// ExposureToFactor converts an exposure_level label to an exposure_factor float.
//
//	internal=0.2, external=0.6, internet_facing=1.0
func ExposureToFactor(exposure string) float64 {
	switch exposure {
	case "internal":
		return 0.2
	case "external":
		return 0.6
	case "internet_facing":
		return 1.0
	default:
		return 0.5
	}
}

// PrivilegeToAmplifier converts a privilege_level label to a privilege_amplifier float.
//
//	low=0.5, medium=0.8, high=1.2, admin=1.5
func PrivilegeToAmplifier(privilege string) float64 {
	switch privilege {
	case "low":
		return 0.5
	case "medium":
		return 0.8
	case "high":
		return 1.2
	case "admin":
		return 1.5
	default:
		return 1.0
	}
}

// clamp restricts v to the range [lo, hi].
func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
