/**
 * ZAK SIF Edge Schemas -- typed relationship definitions for the
 * Security Intelligence Fabric.
 *
 * Edges represent relationships between nodes. Each edge type encodes the
 * semantics of the relationship (e.g. IDENTITY_HAS_ACCESS_TO means
 * read/write access, not ownership).
 *
 * TypeScript equivalent of zak/sif/schema/edges.py.
 */

// ---------------------------------------------------------------------------
// SIFEdge -- base interface
// ---------------------------------------------------------------------------

/**
 * Base interface for all SIF edges. Time-aware and confidence-scored.
 */
export interface SIFEdge {
  /** Source node ID. */
  fromId: string;
  /** Target node ID. */
  toId: string;
  /** When this edge became valid (ISO 8601 string or Date). */
  validFrom: string;
  /** When this edge expires (null means currently active). */
  validTo: string | null;
  /** Data confidence score (0.0 to 1.0). */
  confidence: number;
  /** Integration or system that produced this edge. */
  source: string;
}

/**
 * Check whether a SIF edge is currently active (not expired).
 */
export function isEdgeActive(edge: SIFEdge): boolean {
  if (edge.validTo === null) return true;
  return new Date() < new Date(edge.validTo);
}

// ---------------------------------------------------------------------------
// Canonical Edge Types
// ---------------------------------------------------------------------------

/**
 * IDENTITY -> ASSET: an identity has access to an asset.
 */
export interface IdentityHasAccessToAsset extends SIFEdge {
  /** read | write | admin */
  accessType: string;
  grantedBy: string | null;
}

/**
 * ASSET -> VULNERABILITY: a vulnerability was found on an asset.
 */
export interface AssetHasVulnerability extends SIFEdge {
  scanner: string | null;
  firstSeen: string;
}

/**
 * CONTROL -> VULNERABILITY: a control reduces the risk of a vulnerability.
 */
export interface ControlMitigatesVulnerability extends SIFEdge {
  /** full | partial | compensating */
  mitigationType: string;
}

/**
 * VENDOR -> ASSET: a vendor provides or manages an asset.
 */
export interface VendorSuppliesAsset extends SIFEdge {
  contractRef: string | null;
}

/**
 * AI_MODEL -> ASSET (data_store): an AI model reads from a data store.
 */
export interface AIModelAccessesDataStore extends SIFEdge {
  /** training | inference | evaluation */
  accessPurpose: string;
}

/**
 * RISK -> ASSET: a risk scenario could impact an asset if realized.
 */
export interface RiskImpactsAsset extends SIFEdge {
  /** local | department | org_wide */
  blastRadius: string;
}

/**
 * ASSET -> ASSET: network communication relationship.
 */
export interface AssetCommunicatesWith extends SIFEdge {
  protocol: string | null;
  port: number | null;
  encrypted: boolean;
}
