package schema

import "time"

// ---------------------------------------------------------------------------
// SIFEdge — time-aware base for all edge types
// ---------------------------------------------------------------------------

// SIFEdge is the base struct embedded by all SIF edge types.
// It encodes a directed, time-aware, confidence-scored relationship.
type SIFEdge struct {
	// FromID is the source node ID.
	FromID string `json:"from_id"`
	// ToID is the target node ID.
	ToID string `json:"to_id"`
	// ValidFrom is the timestamp from which this edge is valid.
	ValidFrom time.Time `json:"valid_from"`
	// ValidTo is the timestamp at which this edge expires.
	// A nil value means the edge is currently active.
	ValidTo *time.Time `json:"valid_to,omitempty"`
	// Confidence is the data confidence score (0.0 to 1.0).
	Confidence float64 `json:"confidence"`
	// Source is the integration or system that produced this edge.
	Source string `json:"source"`
}

// NewSIFEdge creates a SIFEdge with defaults (ValidFrom = now, Confidence = 1.0).
func NewSIFEdge(fromID, toID, source string) SIFEdge {
	return SIFEdge{
		FromID:     fromID,
		ToID:       toID,
		ValidFrom:  time.Now().UTC(),
		ValidTo:    nil,
		Confidence: 1.0,
		Source:     source,
	}
}

// IsActive returns true if the edge is currently valid (not expired).
func (e *SIFEdge) IsActive() bool {
	if e.ValidTo == nil {
		return true
	}
	return time.Now().UTC().Before(*e.ValidTo)
}

// ---------------------------------------------------------------------------
// Typed Edge Types
// ---------------------------------------------------------------------------

// IdentityHasAccessToAsset represents IDENTITY -> ASSET:
// an identity has access to an asset.
type IdentityHasAccessToAsset struct {
	SIFEdge
	// AccessType is the kind of access: "read", "write", or "admin".
	AccessType string `json:"access_type"`
	// GrantedBy is the identity or system that granted the access (optional).
	GrantedBy string `json:"granted_by,omitempty"`
}

// NewIdentityHasAccessToAsset creates an IdentityHasAccessToAsset edge.
func NewIdentityHasAccessToAsset(fromID, toID, source string) *IdentityHasAccessToAsset {
	return &IdentityHasAccessToAsset{
		SIFEdge:    NewSIFEdge(fromID, toID, source),
		AccessType: "read",
	}
}

// AssetHasVulnerability represents ASSET -> VULNERABILITY:
// a vulnerability was found on an asset.
type AssetHasVulnerability struct {
	SIFEdge
	// Scanner is the scanner that detected the vulnerability (optional).
	Scanner string `json:"scanner,omitempty"`
	// FirstSeen is the timestamp when the vulnerability was first detected.
	FirstSeen time.Time `json:"first_seen"`
}

// NewAssetHasVulnerability creates an AssetHasVulnerability edge.
func NewAssetHasVulnerability(fromID, toID, source string) *AssetHasVulnerability {
	return &AssetHasVulnerability{
		SIFEdge:   NewSIFEdge(fromID, toID, source),
		FirstSeen: time.Now().UTC(),
	}
}

// ControlMitigatesVulnerability represents CONTROL -> VULNERABILITY:
// a control reduces the risk of a vulnerability.
type ControlMitigatesVulnerability struct {
	SIFEdge
	// MitigationType describes the mitigation: "full", "partial", or
	// "compensating".
	MitigationType string `json:"mitigation_type"`
}

// NewControlMitigatesVulnerability creates a ControlMitigatesVulnerability edge.
func NewControlMitigatesVulnerability(fromID, toID, source string) *ControlMitigatesVulnerability {
	return &ControlMitigatesVulnerability{
		SIFEdge:        NewSIFEdge(fromID, toID, source),
		MitigationType: "partial",
	}
}

// VendorSuppliesAsset represents VENDOR -> ASSET:
// a vendor provides or manages an asset.
type VendorSuppliesAsset struct {
	SIFEdge
	// ContractRef is the contract reference identifier (optional).
	ContractRef string `json:"contract_ref,omitempty"`
}

// NewVendorSuppliesAsset creates a VendorSuppliesAsset edge.
func NewVendorSuppliesAsset(fromID, toID, source string) *VendorSuppliesAsset {
	return &VendorSuppliesAsset{
		SIFEdge: NewSIFEdge(fromID, toID, source),
	}
}

// AIModelAccessesDataStore represents AI_MODEL -> ASSET (data_store):
// an AI model reads from a data store.
type AIModelAccessesDataStore struct {
	SIFEdge
	// AccessPurpose describes the purpose: "training", "inference", or
	// "evaluation".
	AccessPurpose string `json:"access_purpose"`
}

// NewAIModelAccessesDataStore creates an AIModelAccessesDataStore edge.
func NewAIModelAccessesDataStore(fromID, toID, source string) *AIModelAccessesDataStore {
	return &AIModelAccessesDataStore{
		SIFEdge:       NewSIFEdge(fromID, toID, source),
		AccessPurpose: "training",
	}
}

// RiskImpactsAsset represents RISK -> ASSET:
// a risk scenario could impact an asset if realized.
type RiskImpactsAsset struct {
	SIFEdge
	// BlastRadius describes the scope: "local", "department", or "org_wide".
	BlastRadius string `json:"blast_radius"`
}

// NewRiskImpactsAsset creates a RiskImpactsAsset edge.
func NewRiskImpactsAsset(fromID, toID, source string) *RiskImpactsAsset {
	return &RiskImpactsAsset{
		SIFEdge:     NewSIFEdge(fromID, toID, source),
		BlastRadius: "local",
	}
}

// AssetCommunicatesWith represents ASSET -> ASSET:
// network communication relationship.
type AssetCommunicatesWith struct {
	SIFEdge
	// Protocol is the communication protocol (optional).
	Protocol string `json:"protocol,omitempty"`
	// Port is the network port (optional, 0 means unset).
	Port int `json:"port,omitempty"`
	// Encrypted indicates whether the communication is encrypted.
	Encrypted bool `json:"encrypted"`
}

// NewAssetCommunicatesWith creates an AssetCommunicatesWith edge.
func NewAssetCommunicatesWith(fromID, toID, source string) *AssetCommunicatesWith {
	return &AssetCommunicatesWith{
		SIFEdge:   NewSIFEdge(fromID, toID, source),
		Encrypted: true,
	}
}
