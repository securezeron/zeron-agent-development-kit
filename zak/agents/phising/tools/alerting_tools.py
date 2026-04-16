"""
Alerting Module – DomainShield Agent
Generates structured alerts and forwards them via webhook (Slack / SIEM).
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any
import uuid

try:
    from zin_adk import zak_tool, ToolResult
except ImportError:
    def zak_tool(*args, **kwargs):
        def _decorator(fn):
            return fn
        return _decorator

    class ToolResult(dict):
        @staticmethod
        def ok(data: Any) -> "ToolResult":
            return ToolResult({"status": "ok", "data": data})

        @staticmethod
        def error(msg: str) -> "ToolResult":
            return ToolResult({"status": "error", "message": msg})


# ─── Alert schema ─────────────────────────────────────────────────────────────

def _build_alert(
    email_uid: str,
    subject: str,
    from_raw: str,
    from_domain: str,
    risk_level: str,
    action: str,
    reasons: list[str],
    flags: dict,
) -> dict:
    return {
        "alert_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "email_uid": email_uid,
        "subject": subject,
        "from_raw": from_raw,
        "from_domain": from_domain,
        "risk_level": risk_level,   # SAFE | MEDIUM_RISK | HIGH_RISK
        "action": action,           # ALLOW | WARN | BLOCK
        "reasons": reasons,
        "flags": flags,
        "severity": "critical" if risk_level == "HIGH_RISK" else (
            "warning" if risk_level == "MEDIUM_RISK" else "info"
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
@zak_tool(
    action_id="generate_alert",
    description="Generate a structured alert dict for a suspicious or blocked email.",
)
def generate_alert(
    email_uid: str,
    subject: str,
    from_raw: str,
    from_domain: str,
    risk_level: str,
    action: str,
    reasons: list,
    flags: dict,
    alert_threshold: str = "medium_and_above",
) -> ToolResult:
    """
    alert_threshold: 'high_only' | 'medium_and_above' | 'all'
    """
    try:
        # Decide whether this risk level clears the threshold
        level_order = {"SAFE": 0, "MEDIUM_RISK": 1, "HIGH_RISK": 2}
        threshold_map = {
            "high_only": 2,
            "medium_and_above": 1,
            "all": 0,
        }
        min_level = threshold_map.get(alert_threshold, 1)
        current_level = level_order.get(risk_level, 0)

        if current_level < min_level:
            return ToolResult.ok({
                "alert_generated": False,
                "reason": f"Risk level {risk_level!r} below threshold {alert_threshold!r}",
            })

        alert = _build_alert(
            email_uid=email_uid,
            subject=subject,
            from_raw=from_raw,
            from_domain=from_domain,
            risk_level=risk_level,
            action=action,
            reasons=list(reasons),
            flags=dict(flags),
        )

        return ToolResult.ok({"alert_generated": True, "alert": alert})

    except Exception as exc:
        return ToolResult.error(f"generate_alert failed: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
@zak_tool(
    action_id="forward_webhook_alert",
    description="POST an alert payload to a webhook URL (Slack / SIEM / custom HTTP endpoint).",
)
def forward_webhook_alert(
    alert: dict,
    webhook_url: str,
    webhook_format: str = "generic",
    timeout_seconds: int = 10,
) -> ToolResult:
    """
    webhook_format: 'generic' (raw JSON) | 'slack' (Slack Block Kit message)
    """
    try:
        if not webhook_url:
            return ToolResult.ok({"forwarded": False, "reason": "No webhook_url configured"})

        if webhook_format == "slack":
            payload = _slack_payload(alert)
        else:
            payload = alert  # raw JSON

        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "DomainShield-Agent/1.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            status = resp.status
            resp_body = resp.read().decode(errors="replace")[:500]

        return ToolResult.ok({
            "forwarded": True,
            "http_status": status,
            "response_preview": resp_body,
        })

    except urllib.error.HTTPError as exc:
        return ToolResult.error(f"Webhook HTTP {exc.code}: {exc.reason}")
    except Exception as exc:
        return ToolResult.error(f"forward_webhook_alert failed: {exc}")


def _slack_payload(alert: dict) -> dict:
    risk_emoji = {"HIGH_RISK": "🔴", "MEDIUM_RISK": "🟡", "SAFE": "🟢"}.get(
        alert.get("risk_level", ""), "⚪"
    )
    reasons_text = "\n• ".join(alert.get("reasons", [])) or "None"
    return {
        "text": f"{risk_emoji} *DomainShield Alert* – {alert.get('risk_level')}",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{risk_emoji} Phishing Alert: {alert.get('risk_level')}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*From:*\n{alert.get('from_raw', '')}"},
                    {"type": "mrkdwn", "text": f"*Subject:*\n{alert.get('subject', '')}"},
                    {"type": "mrkdwn", "text": f"*Action:*\n{alert.get('action', '')}"},
                    {"type": "mrkdwn", "text": f"*Alert ID:*\n{alert.get('alert_id', '')}"},
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Reasons:*\n• {reasons_text}",
                },
            },
            {"type": "divider"},
        ],
    }
