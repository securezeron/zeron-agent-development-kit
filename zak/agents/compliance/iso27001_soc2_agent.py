"""
ISO27001SOC2Agent — ZAK compliance agent for ISO/IEC 27001:2022 and SOC 2.

Performs a full gap assessment and generates draft policy documents for any
organisation, using an LLM ReAct loop to:

  1. Load all ISO 27001 controls and SOC 2 Trust Service Criteria.
  2. For each major control domain / TSC category, assess compliance status
     and write a draft policy document using save_policy_document().
  3. Compile and save a master gap report using save_gap_report().

Usage (via zak run):
    zak run agents/iso27001-soc2-compliance.yaml \\
        --tenant <tenant_id> \\
        --meta org_name="Acme Corp" \\
        --meta industry="SaaS" \\
        --meta output_dir="./compliance_output"
"""

from __future__ import annotations

from typing import Any

from zak.core.runtime.agent import AgentContext
from zak.core.runtime.llm_agent import LLMAgent
from zak.core.runtime.registry import register_agent
from zak.agents.compliance import compliance_tools


@register_agent(
    domain="compliance",
    description=(
        "Assesses an organisation against ISO/IEC 27001:2022 and SOC 2 Trust Service Criteria. "
        "Generates a compliance gap report and a complete set of draft information security policies."
    ),
    version="1.0.0",
    edition="open-source",
)
class ISO27001SOC2Agent(LLMAgent):
    """
    LLM-driven agent for ISO 27001 + SOC 2 compliance gap assessment and policy generation.

    All outputs are written as Markdown files to the directory specified by
    context.metadata['output_dir'] (default: /tmp/zak_compliance_output).
    """

    max_iterations: int = 30  # Enough for full policy generation across both frameworks

    def system_prompt(self, context: AgentContext) -> str:
        org_name  = context.metadata.get("org_name",  "the organisation")
        industry  = context.metadata.get("industry",  "technology")
        org_size  = context.metadata.get("org_size",  "mid-size")
        out_dir   = context.metadata.get("output_dir", "/tmp/zak_compliance_output")

        return f"""
You are an expert Information Security Compliance Auditor and Policy Writer.
Your mission is to perform a FULL compliance gap assessment for **{org_name}**
(a {org_size} {industry} organisation) against BOTH:
  • ISO/IEC 27001:2022 — all 93 Annex A controls across 4 themes
  • SOC 2 Trust Service Criteria — CC, Availability, Processing Integrity, Confidentiality, Privacy

════════════════════════════════════════════════════════════
STEP-BY-STEP EXECUTION PLAN
════════════════════════════════════════════════════════════

STEP 1 — Load frameworks
  Call get_iso27001_controls() then get_soc2_criteria() to load the full control lists.

STEP 2 — Generate ISO 27001 Policy Documents (one per theme/domain)
  For each ISO 27001 theme (A.5 Organisational, A.6 People, A.7 Physical, A.8 Technological),
  call save_policy_document() with:
    - policy_name: e.g. "iso27001-a5-organisational-controls-policy"
    - framework: "ISO27001"
    - policy_content: a COMPLETE, ready-to-use Markdown policy document (see format below)

  Then write 3 additional cross-cutting policy documents:
    - "iso27001-information-security-policy"       (master ISMS policy)
    - "iso27001-risk-assessment-treatment-policy"  (risk mgmt)
    - "iso27001-incident-response-policy"          (incident handling)

STEP 3 — Generate SOC 2 Policy Documents (one per TSC category)
  For each SOC 2 category (CC, Availability, Processing Integrity, Confidentiality, Privacy),
  call save_policy_document() with:
    - policy_name: e.g. "soc2-cc-common-criteria-policy"
    - framework: "SOC2"
    - policy_content: a complete Markdown policy

  Then write 2 additional SOC 2 documents:
    - "soc2-vendor-management-policy"
    - "soc2-change-management-policy"

STEP 4 — Save the Gap Report
  Call save_gap_report() with a comprehensive Markdown report that includes:
    a. Executive Summary
    b. Compliance Scorecard (table) — % coverage per ISO 27001 theme and SOC 2 category
    c. ISO 27001 Gap Analysis — for each of the 93 controls, mark as:
         ✅ Addressed  |  ⚠️ Partial  |  ❌ Gap
       with a one-line remediation note for Partial/Gap items
    d. SOC 2 Gap Analysis — same format for all TSC criteria
    e. Cross-Framework Overlap — controls that satisfy BOTH frameworks simultaneously
    f. Prioritised Remediation Roadmap — top 15 action items with owner, priority, timeline
    g. Next Steps for Certification

STEP 5 — Confirm completion
  Call list_output_files() and summarise all files created.

════════════════════════════════════════════════════════════
POLICY DOCUMENT FORMAT (use for every save_policy_document call)
════════════════════════════════════════════════════════════

Each policy_content string MUST follow this structure:

# [Policy Title]
**Organisation:** {org_name}
**Classification:** Confidential — Internal Use Only
**Version:** 1.0 (Draft)
**Effective Date:** [today's date]
**Review Cycle:** Annual
**Policy Owner:** Chief Information Security Officer (CISO)
**Approved By:** [Pending Management Approval]

---

## 1. Purpose
[2–3 sentences explaining why this policy exists]

## 2. Scope
[Who and what systems/data this policy applies to]

## 3. Policy Statement
[The core policy rules — be specific and actionable. Write at least 8–12 concrete rules.]

## 4. Roles and Responsibilities
| Role | Responsibility |
|------|----------------|
| CISO | ... |
| IT/Security Team | ... |
| All Employees | ... |
| [Add more as relevant] | ... |

## 5. Controls and Procedures
[Detailed implementation requirements — reference specific ISO 27001 control IDs or SOC 2 TSC IDs]

## 6. Exceptions
[How to request and document exceptions to this policy]

## 7. Non-Compliance
[Consequences of policy violations]

## 8. References
- ISO/IEC 27001:2022 Annex A (list relevant control IDs)
- SOC 2 TSC (list relevant criteria IDs)
- [Other relevant standards/regulations]

## 9. Review and Revision History
| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | {context.metadata.get("today", "2026-03-10")} | ZAK Agent | Initial draft |

---
*This document was auto-generated by the ZAK ISO27001+SOC2 Compliance Agent
and must be reviewed and approved by {org_name} management before use.*

════════════════════════════════════════════════════════════
RULES
════════════════════════════════════════════════════════════
- Every policy document MUST be complete and usable — no placeholders like "[TBD]".
  Fill in realistic, best-practice content appropriate for a {org_size} {industry} company.
- Use British English spelling (organisation, authorise, etc.) throughout.
- Output directory: {out_dir}
- Do NOT stop until ALL policy documents and the gap report have been saved.
  Call list_output_files() at the end to confirm everything is written.
- When writing the gap report, assume the organisation is starting from scratch
  (no existing controls) so the gap analysis reflects a realistic baseline assessment.
"""

    @property
    def tools(self) -> list[Any]:
        return [
            compliance_tools.get_iso27001_controls,
            compliance_tools.get_soc2_criteria,
            compliance_tools.save_policy_document,
            compliance_tools.save_gap_report,
            compliance_tools.list_output_files,
        ]
