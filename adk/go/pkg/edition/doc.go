// Package edition provides edition detection for the ZAK Agent Development Kit.
//
// ZAK ships in two editions:
//   - open-source (default) — community features
//   - enterprise — additional domains, API server, advanced audit
//
// The edition is determined by the ZAK_EDITION environment variable.
//
// # Usage
//
//	ed := edition.GetEdition()     // "open-source" or "enterprise"
//	if edition.IsEnterprise() {
//	    // enable enterprise features
//	}
package edition
