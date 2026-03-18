package edition

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// GetEdition — default
// ---------------------------------------------------------------------------

func TestGetEdition_DefaultIsOpenSource(t *testing.T) {
	t.Setenv("ZAK_EDITION", "")
	assert.Equal(t, OpenSource, GetEdition())
}

func TestGetEdition_UnsetIsOpenSource(t *testing.T) {
	// t.Setenv with empty string clears the var for the test duration
	t.Setenv("ZAK_EDITION", "")
	ed := GetEdition()
	assert.Equal(t, OpenSource, ed)
	assert.Equal(t, Edition("open-source"), ed)
}

// ---------------------------------------------------------------------------
// GetEdition — enterprise variants
// ---------------------------------------------------------------------------

func TestGetEdition_EnterpriseFullString(t *testing.T) {
	t.Setenv("ZAK_EDITION", "enterprise")
	assert.Equal(t, Enterprise, GetEdition())
}

func TestGetEdition_EnterpriseShortForm(t *testing.T) {
	t.Setenv("ZAK_EDITION", "ent")
	assert.Equal(t, Enterprise, GetEdition())
}

func TestGetEdition_EnterpriseCaseInsensitive(t *testing.T) {
	t.Setenv("ZAK_EDITION", "ENTERPRISE")
	assert.Equal(t, Enterprise, GetEdition())
}

func TestGetEdition_EntShortCaseInsensitive(t *testing.T) {
	t.Setenv("ZAK_EDITION", "ENT")
	assert.Equal(t, Enterprise, GetEdition())
}

func TestGetEdition_EnterpriseWithWhitespace(t *testing.T) {
	t.Setenv("ZAK_EDITION", "  enterprise  ")
	assert.Equal(t, Enterprise, GetEdition())
}

// ---------------------------------------------------------------------------
// GetEdition — open-source explicit
// ---------------------------------------------------------------------------

func TestGetEdition_OpenSourceExplicit(t *testing.T) {
	t.Setenv("ZAK_EDITION", "open-source")
	assert.Equal(t, OpenSource, GetEdition())
}

func TestGetEdition_UnknownValueDefaultsToOpenSource(t *testing.T) {
	t.Setenv("ZAK_EDITION", "community")
	assert.Equal(t, OpenSource, GetEdition())
}

// ---------------------------------------------------------------------------
// IsEnterprise
// ---------------------------------------------------------------------------

func TestIsEnterprise_WhenEnterprise(t *testing.T) {
	t.Setenv("ZAK_EDITION", "enterprise")
	assert.True(t, IsEnterprise())
}

func TestIsEnterprise_WhenEnt(t *testing.T) {
	t.Setenv("ZAK_EDITION", "ent")
	assert.True(t, IsEnterprise())
}

func TestIsEnterprise_WhenOpenSource(t *testing.T) {
	t.Setenv("ZAK_EDITION", "open-source")
	assert.False(t, IsEnterprise())
}

func TestIsEnterprise_WhenDefault(t *testing.T) {
	t.Setenv("ZAK_EDITION", "")
	assert.False(t, IsEnterprise())
}

// ---------------------------------------------------------------------------
// Edition constants
// ---------------------------------------------------------------------------

func TestEditionConstants(t *testing.T) {
	assert.Equal(t, Edition("open-source"), OpenSource)
	assert.Equal(t, Edition("enterprise"), Enterprise)
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

func TestError_Message(t *testing.T) {
	err := NewError("multi-tenant")
	require.NotNil(t, err)
	assert.Equal(t, "multi-tenant", err.Feature)
	assert.Contains(t, err.Error(), "multi-tenant")
	assert.Contains(t, err.Error(), "enterprise")
	assert.Contains(t, err.Error(), "open-source")
}

func TestError_ImplementsErrorInterface(t *testing.T) {
	var err error = NewError("sso")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sso")
}

func TestError_DifferentFeatures(t *testing.T) {
	features := []string{"sso", "rbac", "multi-tenant", "audit-export"}
	for _, f := range features {
		t.Run(f, func(t *testing.T) {
			err := NewError(f)
			assert.Equal(t, f, err.Feature)
			assert.Contains(t, err.Error(), f)
		})
	}
}
