"""
Compliance tools for ISO 27001:2022 and SOC 2 (Trust Service Criteria).

These @zak_tool functions provide structured control framework data and
file-saving utilities to the ISO27001SOC2Agent's LLM ReAct loop.
"""

from __future__ import annotations

import os
from datetime import date
from typing import Any
from zak.core.runtime.agent import AgentContext
from zak.core.tools.substrate import zak_tool


# ---------------------------------------------------------------------------
# ISO 27001:2022 — 93 controls across 4 themes
# ---------------------------------------------------------------------------

ISO27001_CONTROLS: list[dict[str, Any]] = [
    # Theme 1: Organisational Controls (A.5)
    {
        "theme": "Organisational Controls",
        "id": "A.5",
        "controls": [
            {"id": "A.5.1",  "name": "Policies for information security"},
            {"id": "A.5.2",  "name": "Information security roles and responsibilities"},
            {"id": "A.5.3",  "name": "Segregation of duties"},
            {"id": "A.5.4",  "name": "Management responsibilities"},
            {"id": "A.5.5",  "name": "Contact with authorities"},
            {"id": "A.5.6",  "name": "Contact with special interest groups"},
            {"id": "A.5.7",  "name": "Threat intelligence"},
            {"id": "A.5.8",  "name": "Information security in project management"},
            {"id": "A.5.9",  "name": "Inventory of information and other associated assets"},
            {"id": "A.5.10", "name": "Acceptable use of information and other associated assets"},
            {"id": "A.5.11", "name": "Return of assets"},
            {"id": "A.5.12", "name": "Classification of information"},
            {"id": "A.5.13", "name": "Labelling of information"},
            {"id": "A.5.14", "name": "Information transfer"},
            {"id": "A.5.15", "name": "Access control"},
            {"id": "A.5.16", "name": "Identity management"},
            {"id": "A.5.17", "name": "Authentication information"},
            {"id": "A.5.18", "name": "Access rights"},
            {"id": "A.5.19", "name": "Information security in supplier relationships"},
            {"id": "A.5.20", "name": "Addressing information security within supplier agreements"},
            {"id": "A.5.21", "name": "Managing information security in the ICT supply chain"},
            {"id": "A.5.22", "name": "Monitoring, review and change management of supplier services"},
            {"id": "A.5.23", "name": "Information security for use of cloud services"},
            {"id": "A.5.24", "name": "Information security incident management planning and preparation"},
            {"id": "A.5.25", "name": "Assessment and decision on information security events"},
            {"id": "A.5.26", "name": "Response to information security incidents"},
            {"id": "A.5.27", "name": "Learning from information security incidents"},
            {"id": "A.5.28", "name": "Collection of evidence"},
            {"id": "A.5.29", "name": "Information security during disruption"},
            {"id": "A.5.30", "name": "ICT readiness for business continuity"},
            {"id": "A.5.31", "name": "Legal, statutory, regulatory and contractual requirements"},
            {"id": "A.5.32", "name": "Intellectual property rights"},
            {"id": "A.5.33", "name": "Protection of records"},
            {"id": "A.5.34", "name": "Privacy and protection of personal identifiable information (PII)"},
            {"id": "A.5.35", "name": "Independent review of information security"},
            {"id": "A.5.36", "name": "Compliance with policies, rules and standards for information security"},
            {"id": "A.5.37", "name": "Documented operating procedures"},
        ],
    },
    # Theme 2: People Controls (A.6)
    {
        "theme": "People Controls",
        "id": "A.6",
        "controls": [
            {"id": "A.6.1", "name": "Screening"},
            {"id": "A.6.2", "name": "Terms and conditions of employment"},
            {"id": "A.6.3", "name": "Information security awareness, education and training"},
            {"id": "A.6.4", "name": "Disciplinary process"},
            {"id": "A.6.5", "name": "Responsibilities after termination or change of employment"},
            {"id": "A.6.6", "name": "Confidentiality or non-disclosure agreements"},
            {"id": "A.6.7", "name": "Remote working"},
            {"id": "A.6.8", "name": "Information security event reporting"},
        ],
    },
    # Theme 3: Physical Controls (A.7)
    {
        "theme": "Physical Controls",
        "id": "A.7",
        "controls": [
            {"id": "A.7.1",  "name": "Physical security perimeters"},
            {"id": "A.7.2",  "name": "Physical entry"},
            {"id": "A.7.3",  "name": "Securing offices, rooms and facilities"},
            {"id": "A.7.4",  "name": "Physical security monitoring"},
            {"id": "A.7.5",  "name": "Protecting against physical and environmental threats"},
            {"id": "A.7.6",  "name": "Working in secure areas"},
            {"id": "A.7.7",  "name": "Clear desk and clear screen"},
            {"id": "A.7.8",  "name": "Equipment siting and protection"},
            {"id": "A.7.9",  "name": "Security of assets off-premises"},
            {"id": "A.7.10", "name": "Storage media"},
            {"id": "A.7.11", "name": "Supporting utilities"},
            {"id": "A.7.12", "name": "Cabling security"},
            {"id": "A.7.13", "name": "Equipment maintenance"},
            {"id": "A.7.14", "name": "Secure disposal or re-use of equipment"},
        ],
    },
    # Theme 4: Technological Controls (A.8)
    {
        "theme": "Technological Controls",
        "id": "A.8",
        "controls": [
            {"id": "A.8.1",  "name": "User endpoint devices"},
            {"id": "A.8.2",  "name": "Privileged access rights"},
            {"id": "A.8.3",  "name": "Information access restriction"},
            {"id": "A.8.4",  "name": "Access to source code"},
            {"id": "A.8.5",  "name": "Secure authentication"},
            {"id": "A.8.6",  "name": "Capacity management"},
            {"id": "A.8.7",  "name": "Protection against malware"},
            {"id": "A.8.8",  "name": "Management of technical vulnerabilities"},
            {"id": "A.8.9",  "name": "Configuration management"},
            {"id": "A.8.10", "name": "Information deletion"},
            {"id": "A.8.11", "name": "Data masking"},
            {"id": "A.8.12", "name": "Data leakage prevention"},
            {"id": "A.8.13", "name": "Information backup"},
            {"id": "A.8.14", "name": "Redundancy of information processing facilities"},
            {"id": "A.8.15", "name": "Logging"},
            {"id": "A.8.16", "name": "Monitoring activities"},
            {"id": "A.8.17", "name": "Clock synchronisation"},
            {"id": "A.8.18", "name": "Use of privileged utility programs"},
            {"id": "A.8.19", "name": "Installation of software on operational systems"},
            {"id": "A.8.20", "name": "Networks security"},
            {"id": "A.8.21", "name": "Security of network services"},
            {"id": "A.8.22", "name": "Segregation of networks"},
            {"id": "A.8.23", "name": "Web filtering"},
            {"id": "A.8.24", "name": "Use of cryptography"},
            {"id": "A.8.25", "name": "Secure development life cycle"},
            {"id": "A.8.26", "name": "Application security requirements"},
            {"id": "A.8.27", "name": "Secure system architecture and engineering principles"},
            {"id": "A.8.28", "name": "Secure coding"},
            {"id": "A.8.29", "name": "Security testing in development and acceptance"},
            {"id": "A.8.30", "name": "Outsourced development"},
            {"id": "A.8.31", "name": "Separation of development, test and production environments"},
            {"id": "A.8.32", "name": "Change management"},
            {"id": "A.8.33", "name": "Test information"},
            {"id": "A.8.34", "name": "Protection of information systems during audit testing"},
        ],
    },
]


# ---------------------------------------------------------------------------
# SOC 2 Trust Service Criteria (2017 + 2022 updates)
# ---------------------------------------------------------------------------

SOC2_CRITERIA: list[dict[str, Any]] = [
    {
        "category": "Common Criteria (CC) — Security",
        "id": "CC",
        "criteria": [
            {"id": "CC1", "name": "Control Environment", "sub": [
                {"id": "CC1.1", "name": "COSO Principle 1: Demonstrates commitment to integrity and ethical values"},
                {"id": "CC1.2", "name": "COSO Principle 2: Board exercises oversight responsibility"},
                {"id": "CC1.3", "name": "COSO Principle 3: Management establishes structure, authority, and responsibility"},
                {"id": "CC1.4", "name": "COSO Principle 4: Demonstrates commitment to competence"},
                {"id": "CC1.5", "name": "COSO Principle 5: Enforces accountability"},
            ]},
            {"id": "CC2", "name": "Communication and Information", "sub": [
                {"id": "CC2.1", "name": "Obtains or generates and uses relevant, quality information"},
                {"id": "CC2.2", "name": "Communicates information internally"},
                {"id": "CC2.3", "name": "Communicates with external parties"},
            ]},
            {"id": "CC3", "name": "Risk Assessment", "sub": [
                {"id": "CC3.1", "name": "Specifies suitable objectives"},
                {"id": "CC3.2", "name": "Identifies and analyses risk"},
                {"id": "CC3.3", "name": "Assesses fraud risk"},
                {"id": "CC3.4", "name": "Identifies and assesses changes"},
            ]},
            {"id": "CC4", "name": "Monitoring Activities", "sub": [
                {"id": "CC4.1", "name": "Conducts ongoing and/or separate evaluations"},
                {"id": "CC4.2", "name": "Evaluates and communicates deficiencies"},
            ]},
            {"id": "CC5", "name": "Control Activities", "sub": [
                {"id": "CC5.1", "name": "Selects and develops control activities"},
                {"id": "CC5.2", "name": "Selects and develops general controls over technology"},
                {"id": "CC5.3", "name": "Deploys through policies and procedures"},
            ]},
            {"id": "CC6", "name": "Logical and Physical Access Controls", "sub": [
                {"id": "CC6.1", "name": "Implements logical access security measures"},
                {"id": "CC6.2", "name": "Prior to issuing system credentials, registers and authorizes new users"},
                {"id": "CC6.3", "name": "Removes access when no longer required"},
                {"id": "CC6.4", "name": "Restricts physical access"},
                {"id": "CC6.5", "name": "Discontinues logical and physical access upon termination"},
                {"id": "CC6.6", "name": "Restricts logical access from external threats"},
                {"id": "CC6.7", "name": "Restricts transmission, movement, and removal of information"},
                {"id": "CC6.8", "name": "Prevents or detects and acts upon introduction of unauthorized software"},
            ]},
            {"id": "CC7", "name": "System Operations", "sub": [
                {"id": "CC7.1", "name": "Detects and monitors for new vulnerabilities"},
                {"id": "CC7.2", "name": "Monitors system components for anomalous behavior"},
                {"id": "CC7.3", "name": "Evaluates security events"},
                {"id": "CC7.4", "name": "Responds to identified security incidents"},
                {"id": "CC7.5", "name": "Identifies, develops, and implements activities to recover"},
            ]},
            {"id": "CC8", "name": "Change Management", "sub": [
                {"id": "CC8.1", "name": "Authorizes, designs, develops, configures, documents, tests, approves, and implements changes"},
            ]},
            {"id": "CC9", "name": "Risk Mitigation", "sub": [
                {"id": "CC9.1", "name": "Identifies, selects, and develops risk mitigation activities"},
                {"id": "CC9.2", "name": "Assesses and manages risks from vendors and business partners"},
            ]},
        ],
    },
    {
        "category": "Availability (A)",
        "id": "A",
        "criteria": [
            {"id": "A1.1", "name": "Maintains, monitors, and evaluates current processing capacity and use"},
            {"id": "A1.2", "name": "Environmental threats — monitors and responds to environmental threats"},
            {"id": "A1.3", "name": "Recovery plan procedures — tests recovery plan procedures"},
        ],
    },
    {
        "category": "Processing Integrity (PI)",
        "id": "PI",
        "criteria": [
            {"id": "PI1.1", "name": "Obtains and accurately processes inputs"},
            {"id": "PI1.2", "name": "Processes complete, accurate, timely, authorised, and consistent outputs"},
            {"id": "PI1.3", "name": "Stores and maintains system inputs, items in processing, and outputs completely and accurately"},
            {"id": "PI1.4", "name": "Addresses errors or omissions in system input and processing"},
            {"id": "PI1.5", "name": "Distributes or makes available outputs only to intended parties"},
        ],
    },
    {
        "category": "Confidentiality (C)",
        "id": "C",
        "criteria": [
            {"id": "C1.1", "name": "Identifies and maintains confidential information"},
            {"id": "C1.2", "name": "Disposes of confidential information"},
        ],
    },
    {
        "category": "Privacy (P)",
        "id": "P",
        "criteria": [
            {"id": "P1.1", "name": "Privacy notice — communicates privacy practices to data subjects"},
            {"id": "P2.1", "name": "Consent and choice — obtains data subjects' consent for collection"},
            {"id": "P3.1", "name": "Collection — collects personal information consistent with stated objectives"},
            {"id": "P3.2", "name": "Collection — collects personal information from reliable sources"},
            {"id": "P4.1", "name": "Use, retention, and disposal — limits use of personal information"},
            {"id": "P4.2", "name": "Retention schedules — retains personal information only as long as needed"},
            {"id": "P4.3", "name": "Disposal — securely disposes of personal information"},
            {"id": "P5.1", "name": "Access — grants individuals access to their personal information"},
            {"id": "P5.2", "name": "Correction — corrects inaccurate personal information"},
            {"id": "P6.1", "name": "Disclosure and notification — discloses personal information only to authorised third parties"},
            {"id": "P6.2", "name": "Third-party agreements — governs third-party use of personal information"},
            {"id": "P6.3", "name": "Disclosure to third parties — discloses personal information to third parties with consent"},
            {"id": "P6.4", "name": "Notification of disclosure — notifies data subjects of disclosures"},
            {"id": "P6.5", "name": "Disclosures to public authorities — makes disclosures to public authorities only as required"},
            {"id": "P6.6", "name": "Notification of breaches — notifies affected data subjects and authorities"},
            {"id": "P6.7", "name": "Cross-border transfers — transfers personal information across borders only appropriately"},
            {"id": "P7.1", "name": "Quality — ensures accuracy and completeness of personal information"},
            {"id": "P8.1", "name": "Monitoring and enforcement — monitors compliance with privacy commitments"},
        ],
    },
]


# ---------------------------------------------------------------------------
# @zak_tool functions
# ---------------------------------------------------------------------------

@zak_tool(
    name="get_iso27001_controls",
    description="Returns the full ISO 27001:2022 control framework (all 93 controls across 4 themes) as structured data.",
    action_id="get_iso27001_controls",
    tags=["compliance", "iso27001", "read"],
)
def get_iso27001_controls(context: AgentContext) -> dict[str, Any]:
    """Return all ISO 27001:2022 Annex A controls grouped by theme."""
    total = sum(len(theme["controls"]) for theme in ISO27001_CONTROLS)
    return {
        "framework": "ISO/IEC 27001:2022",
        "total_controls": total,
        "themes": ISO27001_CONTROLS,
    }


@zak_tool(
    name="get_soc2_criteria",
    description="Returns the full SOC 2 Trust Service Criteria (Common Criteria + Availability, Processing Integrity, Confidentiality, Privacy) as structured data.",
    action_id="get_soc2_criteria",
    tags=["compliance", "soc2", "read"],
)
def get_soc2_criteria(context: AgentContext) -> dict[str, Any]:
    """Return all SOC 2 Trust Service Criteria grouped by category."""
    return {
        "framework": "SOC 2 (AICPA Trust Service Criteria 2017)",
        "categories": SOC2_CRITERIA,
    }


@zak_tool(
    name="save_policy_document",
    description="Saves a drafted policy document for a specific compliance domain to the output directory.",
    action_id="save_policy_document",
    tags=["compliance", "write"],
)
def save_policy_document(
    context: AgentContext,
    policy_name: str,
    policy_content: str,
    framework: str,
) -> dict[str, Any]:
    """
    Saves a draft policy document as a Markdown file.

    Args:
        policy_name: Short slug for the policy (e.g. 'access-control-policy').
        policy_content: Full Markdown content of the policy document.
        framework: e.g. 'ISO27001', 'SOC2', or 'ISO27001+SOC2'.

    Returns:
        Dict with saved file path and status.
    """
    org_name = context.metadata.get("org_name", "Organization")
    out_dir = context.metadata.get("output_dir", "/tmp/zak_compliance_output")
    os.makedirs(out_dir, exist_ok=True)

    safe_name = policy_name.lower().replace(" ", "-").replace("/", "-")
    filename = f"{safe_name}.md"
    filepath = os.path.join(out_dir, filename)

    header = f"""---
organization: {org_name}
framework: {framework}
policy: {policy_name}
generated_by: ZAK ISO27001+SOC2 Compliance Agent
generated_date: {date.today().isoformat()}
status: DRAFT — Requires review and approval by {org_name} management
---

"""
    with open(filepath, "w") as f:
        f.write(header + policy_content)

    return {
        "status": "saved",
        "file": filepath,
        "policy": policy_name,
        "framework": framework,
    }


@zak_tool(
    name="save_gap_report",
    description="Saves the final compliance gap report (covering both ISO 27001 and SOC 2) to the output directory.",
    action_id="save_gap_report",
    tags=["compliance", "write"],
)
def save_gap_report(
    context: AgentContext,
    report_content: str,
) -> dict[str, Any]:
    """
    Saves the master compliance gap report as a Markdown file.

    Args:
        report_content: Full Markdown content of the gap report.

    Returns:
        Dict with saved file path and status.
    """
    org_name = context.metadata.get("org_name", "Organization")
    out_dir = context.metadata.get("output_dir", "/tmp/zak_compliance_output")
    os.makedirs(out_dir, exist_ok=True)

    filename = "compliance-gap-report.md"
    filepath = os.path.join(out_dir, filename)

    header = f"""---
organization: {org_name}
frameworks: ISO/IEC 27001:2022 + SOC 2 (TSC)
generated_by: ZAK ISO27001+SOC2 Compliance Agent
generated_date: {date.today().isoformat()}
classification: CONFIDENTIAL
---

"""
    with open(filepath, "w") as f:
        f.write(header + report_content)

    return {
        "status": "saved",
        "file": filepath,
        "report": "compliance-gap-report",
    }


@zak_tool(
    name="list_output_files",
    description="Lists all compliance policy and report files saved so far in the output directory.",
    action_id="list_output_files",
    tags=["compliance", "read"],
)
def list_output_files(context: AgentContext) -> dict[str, Any]:
    """Lists all files saved to the compliance output directory."""
    out_dir = context.metadata.get("output_dir", "/tmp/zak_compliance_output")
    if not os.path.exists(out_dir):
        return {"output_dir": out_dir, "files": [], "count": 0}

    files = sorted(os.listdir(out_dir))
    return {
        "output_dir": out_dir,
        "files": files,
        "count": len(files),
    }
