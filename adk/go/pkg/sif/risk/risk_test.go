package risk

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Compute tests
// ===========================================================================

func TestCompute_BasicCase(t *testing.T) {
	inputs := &RiskInputs{
		BaseRisk:             0.7,
		ExposureFactor:       1.0,
		Exploitability:       0.8,
		ControlEffectiveness: 0.5,
		PrivilegeAmplifier:   1.2,
	}

	result := Compute(inputs)
	require.NotNil(t, result)

	// raw = 0.7 * 1.0 * 0.8 * (1-0.5) * 1.2 = 0.336
	assert.InDelta(t, 0.336, result.RawScore, 0.001)
	assert.InDelta(t, 3.36, result.RiskScore, 0.01)
	assert.Equal(t, "medium", result.RiskLevel)
}

func TestCompute_AllZeros(t *testing.T) {
	inputs := &RiskInputs{
		BaseRisk:             0.0,
		ExposureFactor:       0.0,
		Exploitability:       0.0,
		ControlEffectiveness: 0.0,
		PrivilegeAmplifier:   0.0,
	}

	result := Compute(inputs)
	assert.Equal(t, 0.0, result.RawScore)
	assert.Equal(t, 0.0, result.RiskScore)
	assert.Equal(t, "low", result.RiskLevel)
}

func TestCompute_MaxRisk(t *testing.T) {
	inputs := &RiskInputs{
		BaseRisk:             1.0,
		ExposureFactor:       1.0,
		Exploitability:       1.0,
		ControlEffectiveness: 0.0,
		PrivilegeAmplifier:   1.5,
	}

	result := Compute(inputs)

	// raw = 1.0 * 1.0 * 1.0 * 1.0 * 1.5 = 1.5 -> clamped to 1.0
	assert.Equal(t, 1.0, result.RawScore)
	assert.Equal(t, 10.0, result.RiskScore)
	assert.Equal(t, "critical", result.RiskLevel)
}

func TestCompute_PerfectControls(t *testing.T) {
	inputs := &RiskInputs{
		BaseRisk:             1.0,
		ExposureFactor:       1.0,
		Exploitability:       1.0,
		ControlEffectiveness: 1.0, // perfect controls
		PrivilegeAmplifier:   1.5,
	}

	result := Compute(inputs)

	// (1 - 1.0) = 0.0, so raw = 0
	assert.Equal(t, 0.0, result.RawScore)
	assert.Equal(t, 0.0, result.RiskScore)
	assert.Equal(t, "low", result.RiskLevel)
}

func TestCompute_HighRiskLevel(t *testing.T) {
	// Aim for a score in [5.0, 7.5) range -> "high"
	inputs := &RiskInputs{
		BaseRisk:             0.7,
		ExposureFactor:       1.0,
		Exploitability:       0.9,
		ControlEffectiveness: 0.0,
		PrivilegeAmplifier:   1.0,
	}

	result := Compute(inputs)

	// raw = 0.7 * 1.0 * 0.9 * 1.0 * 1.0 = 0.63
	assert.InDelta(t, 0.63, result.RawScore, 0.001)
	assert.InDelta(t, 6.3, result.RiskScore, 0.1)
	assert.Equal(t, "high", result.RiskLevel)
}

func TestCompute_LowRiskLevel(t *testing.T) {
	inputs := &RiskInputs{
		BaseRisk:             0.2,
		ExposureFactor:       0.2,
		Exploitability:       0.5,
		ControlEffectiveness: 0.5,
		PrivilegeAmplifier:   0.5,
	}

	result := Compute(inputs)

	// raw = 0.2 * 0.2 * 0.5 * 0.5 * 0.5 = 0.005
	assert.InDelta(t, 0.005, result.RawScore, 0.0001)
	assert.InDelta(t, 0.05, result.RiskScore, 0.01)
	assert.Equal(t, "low", result.RiskLevel)
}

func TestCompute_CriticalRiskLevel(t *testing.T) {
	inputs := &RiskInputs{
		BaseRisk:             1.0,
		ExposureFactor:       1.0,
		Exploitability:       1.0,
		ControlEffectiveness: 0.0,
		PrivilegeAmplifier:   1.0,
	}

	result := Compute(inputs)

	// raw = 1.0 * 1.0 * 1.0 * 1.0 * 1.0 = 1.0
	assert.Equal(t, 1.0, result.RawScore)
	assert.Equal(t, 10.0, result.RiskScore)
	assert.Equal(t, "critical", result.RiskLevel)
}

// ===========================================================================
// Clamping tests
// ===========================================================================

func TestCompute_ClampsNegativeToZero(t *testing.T) {
	inputs := &RiskInputs{
		BaseRisk:             -0.5,
		ExposureFactor:       1.0,
		Exploitability:       1.0,
		ControlEffectiveness: 0.0,
		PrivilegeAmplifier:   1.0,
	}

	result := Compute(inputs)
	// raw = -0.5 * ... = negative -> clamped to 0
	assert.GreaterOrEqual(t, result.RawScore, 0.0)
	assert.GreaterOrEqual(t, result.RiskScore, 0.0)
}

func TestCompute_ClampsAboveOneToOne(t *testing.T) {
	inputs := &RiskInputs{
		BaseRisk:             1.0,
		ExposureFactor:       1.0,
		Exploitability:       1.0,
		ControlEffectiveness: 0.0,
		PrivilegeAmplifier:   5.0, // extreme amplifier
	}

	result := Compute(inputs)
	// raw = 5.0 -> clamped to 1.0
	assert.LessOrEqual(t, result.RawScore, 1.0)
	assert.LessOrEqual(t, result.RiskScore, 10.0)
}

func TestCompute_ControlEffectivenessClampedToRange(t *testing.T) {
	// Control effectiveness > 1.0 should be clamped to 1.0
	inputs := &RiskInputs{
		BaseRisk:             0.5,
		ExposureFactor:       0.5,
		Exploitability:       0.5,
		ControlEffectiveness: 1.5, // > 1.0, should be treated as 1.0
		PrivilegeAmplifier:   1.0,
	}

	result := Compute(inputs)
	// (1 - clamped(1.5, 0, 1)) = (1 - 1.0) = 0.0
	assert.Equal(t, 0.0, result.RawScore)
	assert.Equal(t, 0.0, result.RiskScore)
}

func TestCompute_NegativeControlEffectivenessClampedToZero(t *testing.T) {
	inputs := &RiskInputs{
		BaseRisk:             0.5,
		ExposureFactor:       1.0,
		Exploitability:       1.0,
		ControlEffectiveness: -0.5, // < 0.0, should be treated as 0.0
		PrivilegeAmplifier:   1.0,
	}

	result := Compute(inputs)
	// (1 - clamped(-0.5, 0, 1)) = (1 - 0.0) = 1.0
	// raw = 0.5 * 1.0 * 1.0 * 1.0 * 1.0 = 0.5
	assert.InDelta(t, 0.5, result.RawScore, 0.001)
}

// ===========================================================================
// Risk level boundary tests
// ===========================================================================

func TestRiskLevel_Boundaries(t *testing.T) {
	tests := []struct {
		name     string
		raw      float64
		expected string
	}{
		{"zero is low", 0.0, "low"},
		{"0.24 is low", 0.24, "low"},
		{"0.25 is medium", 0.25, "medium"},
		{"0.49 is medium", 0.49, "medium"},
		{"0.50 is high", 0.50, "high"},
		{"0.74 is high", 0.74, "high"},
		{"0.75 is critical", 0.75, "critical"},
		{"1.0 is critical", 1.0, "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := riskOutputFromRaw(tt.raw)
			assert.Equal(t, tt.expected, output.RiskLevel)
		})
	}
}

// ===========================================================================
// Helper function tests
// ===========================================================================

func TestCriticalityToBaseRisk(t *testing.T) {
	tests := []struct {
		criticality string
		expected    float64
	}{
		{"low", 0.2},
		{"medium", 0.4},
		{"high", 0.7},
		{"critical", 1.0},
		{"unknown", 0.4},   // default
		{"CRITICAL", 0.4},  // case-sensitive: not found -> default
	}

	for _, tt := range tests {
		t.Run(tt.criticality, func(t *testing.T) {
			assert.InDelta(t, tt.expected, CriticalityToBaseRisk(tt.criticality), 0.001)
		})
	}
}

func TestExposureToFactor(t *testing.T) {
	tests := []struct {
		exposure string
		expected float64
	}{
		{"internal", 0.2},
		{"external", 0.6},
		{"internet_facing", 1.0},
		{"unknown", 0.5},  // default
	}

	for _, tt := range tests {
		t.Run(tt.exposure, func(t *testing.T) {
			assert.InDelta(t, tt.expected, ExposureToFactor(tt.exposure), 0.001)
		})
	}
}

func TestPrivilegeToAmplifier(t *testing.T) {
	tests := []struct {
		privilege string
		expected  float64
	}{
		{"low", 0.5},
		{"medium", 0.8},
		{"high", 1.2},
		{"admin", 1.5},
		{"unknown", 1.0},  // default
	}

	for _, tt := range tests {
		t.Run(tt.privilege, func(t *testing.T) {
			assert.InDelta(t, tt.expected, PrivilegeToAmplifier(tt.privilege), 0.001)
		})
	}
}

// ===========================================================================
// Integration-style tests combining helpers with Compute
// ===========================================================================

func TestCompute_WithHelpers_CriticalInternetFacingAdmin(t *testing.T) {
	inputs := &RiskInputs{
		BaseRisk:             CriticalityToBaseRisk("critical"),      // 1.0
		ExposureFactor:       ExposureToFactor("internet_facing"),    // 1.0
		Exploitability:       0.9,
		ControlEffectiveness: 0.3,
		PrivilegeAmplifier:   PrivilegeToAmplifier("admin"),          // 1.5
	}

	result := Compute(inputs)

	// raw = 1.0 * 1.0 * 0.9 * 0.7 * 1.5 = 0.945
	assert.InDelta(t, 0.945, result.RawScore, 0.001)
	assert.InDelta(t, 9.45, result.RiskScore, 0.1)
	assert.Equal(t, "critical", result.RiskLevel)
}

func TestCompute_WithHelpers_LowInternalLow(t *testing.T) {
	inputs := &RiskInputs{
		BaseRisk:             CriticalityToBaseRisk("low"),       // 0.2
		ExposureFactor:       ExposureToFactor("internal"),       // 0.2
		Exploitability:       0.3,
		ControlEffectiveness: 0.8,
		PrivilegeAmplifier:   PrivilegeToAmplifier("low"),        // 0.5
	}

	result := Compute(inputs)

	// raw = 0.2 * 0.2 * 0.3 * 0.2 * 0.5 = 0.0012
	assert.InDelta(t, 0.0012, result.RawScore, 0.0001)
	assert.Equal(t, "low", result.RiskLevel)
}
