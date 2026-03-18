/**
 * ZAK SIF Node Schemas -- canonical TypeScript interfaces for all
 * Security Intelligence Fabric node types.
 *
 * Every node is:
 * - Time-aware: validFrom, validTo, confidence, source
 * - Tenant-scoped: tenantId injected at graph adapter level
 *
 * TypeScript equivalent of zak/sif/schema/nodes.py.
 */

// ---------------------------------------------------------------------------
// Enums shared across node types
// ---------------------------------------------------------------------------

export enum Criticality {
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high",
  CRITICAL = "critical",
}

export enum ExposureLevel {
  INTERNAL = "internal",
  EXTERNAL = "external",
  INTERNET_FACING = "internet_facing",
}

export enum Environment {
  PRODUCTION = "production",
  STAGING = "staging",
  DEV = "dev",
}

export enum Severity {
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high",
  CRITICAL = "critical",
}

export enum VulnStatus {
  OPEN = "open",
  MITIGATED = "mitigated",
  ACCEPTED = "accepted",
  FALSE_POSITIVE = "false_positive",
}

export enum PrivilegeLevel {
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high",
  ADMIN = "admin",
}

export enum DataSensitivity {
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high",
  RESTRICTED = "restricted",
}

// ---------------------------------------------------------------------------
// SIFNode -- base interface
// ---------------------------------------------------------------------------

/**
 * Base interface for all SIF nodes. Provides time-aware metadata.
 */
export interface SIFNode {
  /** Unique identifier for this node. */
  nodeId: string;
  /** When this node became valid (ISO 8601 string or Date). */
  validFrom: string;
  /** When this node expires (null means currently active). */
  validTo: string | null;
  /** Data confidence score (0.0 to 1.0). */
  confidence: number;
  /** System or integration that produced this node. */
  source: string;
}

/**
 * Check whether a SIF node is currently active (not expired).
 */
export function isNodeActive(node: SIFNode): boolean {
  if (node.validTo === null) return true;
  return new Date() < new Date(node.validTo);
}

// ---------------------------------------------------------------------------
// Canonical Node Types
// ---------------------------------------------------------------------------

/**
 * Represents a technology asset (server, service, application, database, etc.).
 */
export interface AssetNode extends SIFNode {
  /** e.g. server, application, database, cloud_service */
  assetType: string;
  criticality: Criticality;
  environment: Environment;
  owner: string | null;
  exposureLevel: ExposureLevel;
  riskScore: number;
  tags: string[];
}

/**
 * Represents a human or machine identity (user, service account, API key, etc.).
 */
export interface IdentityNode extends SIFNode {
  /** e.g. human, service_account, api_key, role */
  identityType: string;
  privilegeLevel: PrivilegeLevel;
  mfaEnabled: boolean;
  riskScore: number;
  department: string | null;
}

/**
 * Represents a security vulnerability (CVE, misconfiguration, finding, etc.).
 */
export interface VulnerabilityNode extends SIFNode {
  /** e.g. cve, misconfiguration, secret_exposure, injection */
  vulnType: string;
  cveId: string | null;
  severity: Severity;
  /** CVSS exploitability score (0-1) */
  exploitability: number;
  cvssScore: number | null;
  status: VulnStatus;
}

/**
 * Represents a security control (firewall rule, policy, monitoring, etc.).
 */
export interface ControlNode extends SIFNode {
  /** e.g. firewall, waf, iam_policy, mfa, dlp */
  controlType: string;
  /** Control effectiveness (0-1) */
  effectiveness: number;
  automated: boolean;
  /** Framework control IDs this maps to (e.g. ISO27001:A.12.6.1) */
  frameworkRefs: string[];
}

/**
 * Represents a computed risk scenario.
 */
export interface RiskNode extends SIFNode {
  /** e.g. cyber, ai, third_party, operational */
  riskType: string;
  likelihood: number;
  impact: number;
  riskScore: number;
  /** Expected Annual Loss in USD */
  eal: number | null;
  /** Value at Risk (95th percentile) in USD */
  var95: number | null;
}

/**
 * Represents a third-party vendor or supplier.
 */
export interface VendorNode extends SIFNode {
  /** e.g. saas, infrastructure, professional_services */
  vendorType: string;
  /** Supply chain tier (1=direct, 3=nth party) */
  tier: number;
  riskScore: number;
  lastAssessed: string | null;
  country: string | null;
}

/**
 * Represents an AI/ML model in use within the organization.
 */
export interface AIModelNode extends SIFNode {
  /** e.g. llm, classifier, embedding, generative */
  modelType: string;
  /** e.g. openai, anthropic, google, internal */
  provider: string;
  dataSensitivity: DataSensitivity;
  guardrailsEnabled: boolean;
  riskScore: number;
  exposedViaApi: boolean;
}
