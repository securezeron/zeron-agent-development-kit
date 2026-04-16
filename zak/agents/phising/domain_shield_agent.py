"""
DomainShield Agent – Core Agent Class
Orchestrates all phishing detection modules via the ZAK BaseAgent interface.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# ── ZAK SDK shim ─────────────────────────────────────────────────────────────
try:
    from zin_adk import BaseAgent, AgentContext, AgentResult, register_agent
except ImportError:
    # Standalone-compatible shim when ZAK SDK is not installed
    class AgentContext:  # type: ignore[no-redef]
        def __init__(self, inputs: dict):
            self.inputs = inputs

    class AgentResult(dict):  # type: ignore[no-redef]
        @staticmethod
        def success(data: dict) -> "AgentResult":
            return AgentResult({"status": "success", **data})

        @staticmethod
        def error(msg: str, data: dict | None = None) -> "AgentResult":
            return AgentResult({"status": "error", "message": msg, **(data or {})})

    class BaseAgent:  # type: ignore[no-redef]
        def call_tool(self, _ctx: Any, action_id: str, **kwargs: Any) -> dict:
            """Dispatch to the matching tool function directly."""
            from tools import (
                ingest_email, parse_email_headers, verify_domain_whitelist,
                check_spf_alignment, check_dkim_alignment, check_dmarc_alignment,
                detect_display_name_spoof, detect_subdomain_spoof,
                classify_phishing_risk, generate_alert,
                forward_webhook_alert, log_email_event, manage_whitelist,
            )
            _tool_map = {
                "ingest_email": ingest_email,
                "parse_email_headers": parse_email_headers,
                "verify_domain_whitelist": verify_domain_whitelist,
                "check_spf_alignment": check_spf_alignment,
                "check_dkim_alignment": check_dkim_alignment,
                "check_dmarc_alignment": check_dmarc_alignment,
                "detect_display_name_spoof": detect_display_name_spoof,
                "detect_subdomain_spoof": detect_subdomain_spoof,
                "classify_phishing_risk": classify_phishing_risk,
                "generate_alert": generate_alert,
                "forward_webhook_alert": forward_webhook_alert,
                "log_email_event": log_email_event,
                "manage_whitelist": manage_whitelist,
            }
            fn = _tool_map.get(action_id)
            if fn is None:
                raise ValueError(f"Unknown tool action_id: {action_id!r}")
            return fn(**kwargs)

    def register_agent(domain: str):
        def _dec(cls):
            return cls
        return _dec


# ─────────────────────────────────────────────────────────────────────────────

@register_agent(domain="email_security")
class DomainShieldAgent(BaseAgent):
    """
    DomainShield Agent
    ──────────────────
    Processes a batch of emails through:
      Phase 1 – Ingest emails (IMAP / file / raw)
      Phase 2 – Parse headers
      Phase 3 – Whitelist + subdomain-spoof check
      Phase 4 – SPF / DKIM / DMARC alignment checks
      Phase 5 – Display-name spoof detection
      Phase 6 – Risk classification
      Phase 7 – Alert generation
      Phase 8 – Webhook forwarding
      Phase 9 – Audit logging
    """

    def execute(self, context: AgentContext) -> AgentResult:
        inp = context.inputs

        # ── Required inputs ────────────────────────────────────────────
        whitelist_domains: list[str] = inp.get("whitelist_domains", [])
        if not whitelist_domains:
            return AgentResult.error(
                "whitelist_domains is required and must not be empty."
            )

        strict_mode: bool = inp.get("strict_mode", True)
        alert_threshold: str = inp.get("alert_threshold", "medium_and_above")
        webhook_url: str = inp.get("webhook_url", "")
        webhook_format: str = inp.get("webhook_format", "generic")

        # Ingestion params
        source: str = inp.get("source", "raw")
        raw_eml: str = inp.get("raw_eml", "")
        eml_path: str = inp.get("eml_path", "")
        imap_host: str = inp.get("imap_host", "")
        imap_port: int = inp.get("imap_port", 993)
        imap_user: str = inp.get("imap_user", "")
        imap_password: str = inp.get("imap_password", "")
        imap_folder: str = inp.get("imap_folder", "INBOX")
        max_emails: int = inp.get("max_emails", 100)

        run_summary = {
            "run_id": _run_id(),
            "started_at": datetime.now(timezone.utc).isoformat(),
            "whitelist_domains": whitelist_domains,
            "strict_mode": strict_mode,
            "alert_threshold": alert_threshold,
        }

        # ── Phase 1: Ingest ────────────────────────────────────────────
        ingest_result = self.call_tool(
            context, "ingest_email",
            source=source,
            raw_eml=raw_eml,
            eml_path=eml_path,
            imap_host=imap_host,
            imap_port=imap_port,
            imap_user=imap_user,
            imap_password=imap_password,
            imap_folder=imap_folder,
            max_emails=max_emails,
        )
        if ingest_result.get("status") == "error":
            return AgentResult.error(
                f"Email ingestion failed: {ingest_result.get('message')}"
            )

        emails: list[dict] = ingest_result.get("data", {}).get("emails", [])
        if not emails:
            return AgentResult.success({
                **run_summary,
                "processed_count": 0,
                "message": "No emails to process.",
            })

        # ── Per-email processing ───────────────────────────────────────
        processed_count = 0
        safe_count = 0
        suspicious_count = 0
        high_risk_count = 0
        medium_risk_count = 0
        alerts: list[dict] = []

        for raw_email in emails:
            result = self._process_single_email(
                context=context,
                raw_email=raw_email,
                whitelist_domains=whitelist_domains,
                strict_mode=strict_mode,
                alert_threshold=alert_threshold,
                webhook_url=webhook_url,
                webhook_format=webhook_format,
            )
            processed_count += 1
            risk = result.get("risk_level", "SAFE")
            if risk == "SAFE":
                safe_count += 1
            else:
                suspicious_count += 1
                if risk == "HIGH_RISK":
                    high_risk_count += 1
                else:
                    medium_risk_count += 1
            if result.get("alert"):
                alerts.append(result["alert"])

        run_summary.update({
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "processed_count": processed_count,
            "safe_count": safe_count,
            "suspicious_count": suspicious_count,
            "high_risk_count": high_risk_count,
            "medium_risk_count": medium_risk_count,
            "alerts_generated": len(alerts),
            "alerts": alerts,
        })

        return AgentResult.success(run_summary)

    # ── Single-email pipeline ─────────────────────────────────────────
    def _process_single_email(
        self,
        context: AgentContext,
        raw_email: dict,
        whitelist_domains: list[str],
        strict_mode: bool,
        alert_threshold: str,
        webhook_url: str,
        webhook_format: str,
    ) -> dict:
        result: dict[str, Any] = {"email_uid": raw_email.get("uid", ""), "risk_level": "SAFE"}

        # Phase 2 – Parse headers
        parsed = self.call_tool(context, "parse_email_headers", email_dict=raw_email)
        if parsed.get("status") == "error":
            return {**result, "error": parsed.get("message")}
        p = parsed.get("data", {})

        from_domain: str = p.get("from_domain", "")
        subject: str = p.get("subject", "")
        from_raw: str = p.get("from_raw", "")
        display_name: str = p.get("display_name", "")
        auth_results_raw: str = p.get("authentication_results_raw", "")
        received_spf_raw: str = p.get("received_spf_raw", "")

        # Phase 3 – Whitelist + subdomain spoof
        wl_result = self.call_tool(
            context, "verify_domain_whitelist",
            from_domain=from_domain,
            whitelist_domains=whitelist_domains,
        )
        in_whitelist: bool = wl_result.get("data", {}).get("in_whitelist", False)

        sd_result = self.call_tool(
            context, "detect_subdomain_spoof",
            from_domain=from_domain,
            whitelist_domains=whitelist_domains,
        )
        subdomain_spoof: bool = sd_result.get("data", {}).get("subdomain_spoof", False)

        # Phase 4 – SPF / DKIM / DMARC
        spf = self.call_tool(
            context, "check_spf_alignment",
            received_spf_raw=received_spf_raw,
            authentication_results_raw=auth_results_raw,
            from_domain=from_domain,
        ).get("data", {})

        dkim = self.call_tool(
            context, "check_dkim_alignment",
            authentication_results_raw=auth_results_raw,
            from_domain=from_domain,
        ).get("data", {})

        dmarc = self.call_tool(
            context, "check_dmarc_alignment",
            authentication_results_raw=auth_results_raw,
        ).get("data", {})

        # Phase 5 – Display-name spoof
        dn = self.call_tool(
            context, "detect_display_name_spoof",
            display_name=display_name,
            from_domain=from_domain,
            whitelist_domains=whitelist_domains,
        ).get("data", {})
        display_name_spoof: bool = dn.get("display_name_spoof", False)

        # Phase 6 – Classify risk
        clf = self.call_tool(
            context, "classify_phishing_risk",
            in_whitelist=in_whitelist,
            spf_pass=spf.get("spf_pass"),
            spf_aligned=spf.get("spf_aligned"),
            dkim_pass=dkim.get("dkim_pass"),
            dkim_aligned=dkim.get("dkim_aligned"),
            dmarc_pass=dmarc.get("dmarc_pass"),
            display_name_spoof=display_name_spoof,
            subdomain_spoof=subdomain_spoof,
            from_domain=from_domain,
            strict_mode=strict_mode,
        ).get("data", {})

        risk_level: str = clf.get("risk_level", "SAFE")
        action: str = clf.get("action", "ALLOW")
        reasons: list = clf.get("reasons", [])
        flags: dict = clf.get("flags", {})
        result["risk_level"] = risk_level

        # Phase 7 – Generate alert
        alert_res = self.call_tool(
            context, "generate_alert",
            email_uid=raw_email.get("uid", ""),
            subject=subject,
            from_raw=from_raw,
            from_domain=from_domain,
            risk_level=risk_level,
            action=action,
            reasons=reasons,
            flags=flags,
            alert_threshold=alert_threshold,
        ).get("data", {})

        alert: dict | None = alert_res.get("alert") if alert_res.get("alert_generated") else None
        result["alert"] = alert

        # Phase 8 – Webhook
        if alert and webhook_url:
            self.call_tool(
                context, "forward_webhook_alert",
                alert=alert,
                webhook_url=webhook_url,
                webhook_format=webhook_format,
            )

        # Phase 9 – Audit log
        self.call_tool(
            context, "log_email_event",
            email_uid=raw_email.get("uid", ""),
            subject=subject,
            from_raw=from_raw,
            from_domain=from_domain,
            risk_level=risk_level,
            action=action,
            reasons=reasons,
            alert_id=alert.get("alert_id", "") if alert else "",
        )

        return result


def _run_id() -> str:
    from datetime import datetime, timezone
    return f"ds-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
