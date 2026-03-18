// Package edition provides runtime edition detection for open-source vs enterprise gating.
//
// Control via environment variable:
//
//	ZAK_EDITION=open-source   (default)
//	ZAK_EDITION=enterprise
package edition

import (
	"fmt"
	"os"
	"strings"
)

// Edition represents the ZAK deployment edition.
type Edition string

const (
	OpenSource Edition = "open-source"
	Enterprise Edition = "enterprise"
)

// GetEdition returns the current edition based on the ZAK_EDITION environment variable.
func GetEdition() Edition {
	val := strings.ToLower(strings.TrimSpace(os.Getenv("ZAK_EDITION")))
	if val == "" {
		val = "open-source"
	}
	if val == "enterprise" || val == "ent" {
		return Enterprise
	}
	return OpenSource
}

// IsEnterprise returns true if running under the enterprise edition.
func IsEnterprise() bool {
	return GetEdition() == Enterprise
}

// Error is raised when an enterprise-only feature is accessed on the open-source edition.
type Error struct {
	Feature string
}

func (e *Error) Error() string {
	return fmt.Sprintf("enterprise feature '%s' is not available in the open-source edition", e.Feature)
}

// NewError creates a new EditionError.
func NewError(feature string) *Error {
	return &Error{Feature: feature}
}
