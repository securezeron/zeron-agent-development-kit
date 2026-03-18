/**
 * @zeron/zak — ZAK Agent Development Kit for Node.js/TypeScript
 *
 * Public barrel export for all modules:
 * - DSL Schema & Parser
 * - Policy Engine
 * - Audit Events & Logger
 * - Edition detection
 * - Runtime: BaseAgent, AgentContext, AgentResult
 * - Runtime: LLMAgent, ReAct loop, schema generation
 * - Registry: Agent registration and discovery
 * - Executor: Agent lifecycle orchestration
 * - Tools: Tool substrate with policy + audit
 * - Tools: Built-in SIF graph tools
 * - Tools: Orchestration (spawnAgent)
 * - LLM: Client interface, registry, mock
 * - SIF: Node types, Edge types
 * - SIF: Risk propagation engine
 * - Tenants: Multi-tenancy support
 */

// DSL Schema — enums and schemas
export {
  Domain,
  ReasoningMode,
  AutonomyLevel,
  Priority,
  RiskBudget,
  SandboxProfile,
  AuditLevel,
  AgentIdentitySchema,
  AgentIntentSchema,
  LLMConfigSchema,
  ReasoningConfigSchema,
  CapabilitiesConfigSchema,
  BoundariesConfigSchema,
  SafetyConfigSchema,
  AgentDSLSchema,
} from "./core/dsl/schema.js";

export type {
  AgentIdentity,
  AgentIntent,
  LLMConfig,
  ReasoningConfig,
  CapabilitiesConfig,
  BoundariesConfig,
  SafetyConfig,
  AgentDSL,
} from "./core/dsl/schema.js";

// DSL Parser
export {
  loadAgentYaml,
  loadAgentYamlString,
  validateAgent,
  validateAgentString,
  formatValidationResult,
} from "./core/dsl/parser.js";

export type { ValidationResult } from "./core/dsl/parser.js";

// Policy Engine
export { PolicyEngine, permit, deny } from "./core/policy/engine.js";
export type { PolicyDecision } from "./core/policy/engine.js";

// Audit Events
export {
  AuditEventType,
  agentStartedEvent,
  agentCompletedEvent,
  agentFailedEvent,
  policyBlockedEvent,
  toolCalledEvent,
  graphWriteEvent,
} from "./core/audit/events.js";

export type {
  AuditEvent,
  AgentStartedEvent,
  AgentCompletedEvent,
  AgentFailedEvent,
  PolicyBlockedEvent,
  ToolCalledEvent,
  GraphWriteEvent,
} from "./core/audit/events.js";

// Audit Logger
export { AuditLogger } from "./core/audit/logger.js";

// Edition
export {
  Edition,
  getEdition,
  isEnterprise,
  EditionError,
} from "./core/edition.js";

// Runtime — BaseAgent, AgentContext, AgentResult
export {
  BaseAgent,
  createAgentContext,
  getAgentId,
  agentResultOk,
  agentResultFail,
} from "./core/runtime/agent.js";

export type {
  AgentContext,
  AgentResult,
} from "./core/runtime/agent.js";

// Registry — Agent registration and discovery
export {
  AgentRegistry,
  registerAgent,
} from "./core/runtime/registry.js";

export type {
  AgentRegistration,
  AgentConstructor,
} from "./core/runtime/registry.js";

// Executor — Agent lifecycle orchestration
export { AgentExecutor } from "./core/runtime/executor.js";

// Tools — Tool substrate
export {
  zakTool,
  ToolRegistry,
  ToolExecutor,
} from "./core/tools/substrate.js";

export type {
  ToolMetadata,
  ToolFunction,
  ZakToolFunction,
} from "./core/tools/substrate.js";

// LLM — Client interface
export { LLMClient } from "./core/llm/base.js";

export type {
  ToolCall,
  LLMResponse,
  ChatMessage,
  ToolSchema,
} from "./core/llm/base.js";

// LLM — Registry and factory
export { getLLMClient, MockLLMClient } from "./core/llm/registry.js";

export type { LLMClientOptions } from "./core/llm/registry.js";

// Runtime — LLMAgent (ReAct loop)
export { LLMAgent, buildOpenAISchema } from "./core/runtime/llm-agent.js";

export type { StreamEvent } from "./core/runtime/llm-agent.js";

// Tools — Built-in SIF graph tools
export {
  readAsset,
  listAssets,
  listVulnerabilities,
  listIdentities,
  listRisks,
  listControls,
  listVendors,
  listAIModels,
  writeRiskNode,
  computeRisk,
  executePython,
  ALL_BUILTIN_TOOLS,
} from "./core/tools/builtins.js";

// Tools — Orchestration
export { spawnAgent } from "./core/tools/orchestration.js";

// SIF — Node types
export {
  Criticality,
  ExposureLevel,
  Environment,
  Severity,
  VulnStatus,
  PrivilegeLevel,
  DataSensitivity,
  isNodeActive,
} from "./sif/schema/nodes.js";

export type {
  SIFNode,
  AssetNode,
  IdentityNode,
  VulnerabilityNode,
  ControlNode,
  RiskNode,
  VendorNode,
  AIModelNode,
} from "./sif/schema/nodes.js";

// SIF — Edge types
export { isEdgeActive } from "./sif/schema/edges.js";

export type {
  SIFEdge,
  IdentityHasAccessToAsset,
  AssetHasVulnerability,
  ControlMitigatesVulnerability,
  VendorSuppliesAsset,
  AIModelAccessesDataStore,
  RiskImpactsAsset,
  AssetCommunicatesWith,
} from "./sif/schema/edges.js";

// SIF — Risk propagation engine
export { RiskPropagationEngine } from "./sif/risk/propagation.js";

export type { RiskInputs, RiskOutput } from "./sif/risk/propagation.js";

// Tenants — Multi-tenancy
export {
  TenantRegistry,
  TenantContext,
} from "./tenants/context.js";

export type { Tenant } from "./tenants/context.js";
