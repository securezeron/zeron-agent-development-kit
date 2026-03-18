package tools

import (
	"fmt"
	"time"

	"github.com/securezeron/zeron-agent-development-kit/adk/go/pkg/runtime"
)

// ---------------------------------------------------------------------------
// Placeholder built-in tools
//
// These are stub implementations that return placeholder responses. They
// exist so that agents can declare them in their capabilities.tools list
// and the ReAct loop can dispatch to them. Real implementations will be
// wired up to graph adapters and data sources in later phases.
// ---------------------------------------------------------------------------

// ReadAssetTool reads a single asset by ID.
var ReadAssetTool = NewZakTool(
	"Read Asset",
	"Read a single asset from the SIF graph by its node ID",
	readAssetFn,
	WithActionID("read_asset"),
	WithTags("sif", "asset", "read"),
)

func readAssetFn(_ *runtime.AgentContext, args map[string]interface{}) (interface{}, error) {
	id, _ := args["asset_id"].(string)
	if id == "" {
		return nil, fmt.Errorf("read_asset requires 'asset_id' argument")
	}
	return map[string]interface{}{
		"node_id":        id,
		"asset_type":     "server",
		"criticality":    "medium",
		"environment":    "production",
		"exposure_level": "internal",
		"risk_score":     0.0,
		"source":         "placeholder",
		"_placeholder":   true,
	}, nil
}

// ListAssetsTool lists assets, optionally filtered by type or environment.
var ListAssetsTool = NewZakTool(
	"List Assets",
	"List assets from the SIF graph, optionally filtered by asset_type or environment",
	listAssetsFn,
	WithActionID("list_assets"),
	WithTags("sif", "asset", "list"),
)

func listAssetsFn(_ *runtime.AgentContext, args map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{
		"assets":       []interface{}{},
		"total":        0,
		"_placeholder": true,
	}, nil
}

// ListVulnerabilitiesTool lists vulnerabilities associated with an asset.
var ListVulnerabilitiesTool = NewZakTool(
	"List Vulnerabilities",
	"List vulnerabilities from the SIF graph, optionally filtered by asset_id or severity",
	listVulnerabilitiesFn,
	WithActionID("list_vulnerabilities"),
	WithTags("sif", "vulnerability", "list"),
)

func listVulnerabilitiesFn(_ *runtime.AgentContext, args map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{
		"vulnerabilities": []interface{}{},
		"total":           0,
		"_placeholder":    true,
	}, nil
}

// ComputeRiskTool computes risk for a given asset.
var ComputeRiskTool = NewZakTool(
	"Compute Risk",
	"Compute the risk score for an asset using the SIF risk propagation formula",
	computeRiskFn,
	WithActionID("compute_risk"),
	WithTags("sif", "risk", "compute"),
)

func computeRiskFn(_ *runtime.AgentContext, args map[string]interface{}) (interface{}, error) {
	assetID, _ := args["asset_id"].(string)
	return map[string]interface{}{
		"asset_id":    assetID,
		"risk_score":  0.0,
		"risk_level":  "low",
		"raw_score":   0.0,
		"_placeholder": true,
	}, nil
}

// WriteRiskNodeTool writes a computed risk node back to the SIF graph.
var WriteRiskNodeTool = NewZakTool(
	"Write Risk Node",
	"Write a computed risk node to the SIF graph",
	writeRiskNodeFn,
	WithActionID("write_risk_node"),
	WithTags("sif", "risk", "write"),
)

func writeRiskNodeFn(_ *runtime.AgentContext, args map[string]interface{}) (interface{}, error) {
	nodeID, _ := args["node_id"].(string)
	if nodeID == "" {
		nodeID = fmt.Sprintf("risk-%d", time.Now().UnixNano())
	}
	return map[string]interface{}{
		"node_id":      nodeID,
		"written":      true,
		"_placeholder": true,
	}, nil
}

// ListControlsTool lists security controls from the SIF graph.
var ListControlsTool = NewZakTool(
	"List Controls",
	"List security controls from the SIF graph",
	listControlsFn,
	WithActionID("list_controls"),
	WithTags("sif", "control", "list"),
)

func listControlsFn(_ *runtime.AgentContext, args map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{
		"controls":     []interface{}{},
		"total":        0,
		"_placeholder": true,
	}, nil
}

// ListIdentitiesTool lists identity nodes from the SIF graph.
var ListIdentitiesTool = NewZakTool(
	"List Identities",
	"List identity nodes from the SIF graph",
	listIdentitiesFn,
	WithActionID("list_identities"),
	WithTags("sif", "identity", "list"),
)

func listIdentitiesFn(_ *runtime.AgentContext, args map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{
		"identities":   []interface{}{},
		"total":        0,
		"_placeholder": true,
	}, nil
}

// ListVendorsTool lists vendor nodes from the SIF graph.
var ListVendorsTool = NewZakTool(
	"List Vendors",
	"List vendor nodes from the SIF graph",
	listVendorsFn,
	WithActionID("list_vendors"),
	WithTags("sif", "vendor", "list"),
)

func listVendorsFn(_ *runtime.AgentContext, args map[string]interface{}) (interface{}, error) {
	return map[string]interface{}{
		"vendors":      []interface{}{},
		"total":        0,
		"_placeholder": true,
	}, nil
}
