"""
DomainShield Agent – tools package.
Exports all @zak_tool-decorated functions for use by the agent class.
"""

from .email_ingestion_tools import ingest_email
from .domain_verification_tools import (
    parse_email_headers,
    verify_domain_whitelist,
    check_spf_alignment,
    check_dkim_alignment,
    check_dmarc_alignment,
    normalize_domain,
    detect_subdomain_spoof,
)
from .phishing_detection_tools import (
    detect_display_name_spoof,
    classify_phishing_risk,
)
from .alerting_tools import generate_alert, forward_webhook_alert
from .logging_tools import log_email_event, export_audit_log
from .policy_tools import manage_whitelist

__all__ = [
    "ingest_email",
    "parse_email_headers",
    "verify_domain_whitelist",
    "check_spf_alignment",
    "check_dkim_alignment",
    "check_dmarc_alignment",
    "normalize_domain",
    "detect_subdomain_spoof",
    "detect_display_name_spoof",
    "classify_phishing_risk",
    "generate_alert",
    "forward_webhook_alert",
    "log_email_event",
    "export_audit_log",
    "manage_whitelist",
]
