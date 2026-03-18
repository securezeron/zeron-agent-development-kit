// Package sif provides the Security Intelligence Fabric (SIF) for the ZAK
// Agent Development Kit.
//
// SIF is a graph-based security data model that represents infrastructure,
// vulnerabilities, threats, and controls as interconnected nodes and edges.
//
// # Sub-packages
//
//   - sif/schema — Node types (7) and edge types (7) for the security graph
//   - sif/risk — Risk propagation engine with quantitative scoring
//
// # Node Types
//
// Asset, Vulnerability, Threat, Control, Identity, Finding, Compliance
//
// # Edge Types
//
// AffectedBy, Exploits, Mitigates, Owns, DependsOn, Violates, Remediates
package sif
