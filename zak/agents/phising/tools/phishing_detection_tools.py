"""
Phishing Detection Engine – DomainShield Agent
Detects display-name spoofing and aggregates all signals into a final risk verdict.
"""

from __future__ import annotations

import re
import unicodedata
from difflib import SequenceMatcher
from typing import Any

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


# ─── Helpers ─────────────────────────────────────────────────────────────────

_TRUSTED_BRAND_ALIASES = [
    "microsoft", "google", "amazon", "apple", "paypal", "dropbox",
    "linkedin", "facebook", "twitter", "netflix", "bank", "chase",
    "wellsfargo", "citibank", "irs", "fedex", "ups", "dhl",
]


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def _strip_to_alpha(s: str) -> str:
    """Remove non-alpha chars for fuzzy comparison."""
    return re.sub(r"[^a-z0-9]", "", unicodedata.normalize("NFKD", s).lower())


def _looks_like_trusted_entity(display_name: str, whitelist_domains: list[str]) -> dict:
    """
    Returns whether the display name impersonates a whitelisted org or well-known brand.
    """
    name_clean = _strip_to_alpha(display_name)

    # Check against whitelist org names (strip TLD)
    for domain in whitelist_domains:
        org = _strip_to_alpha(domain.split(".")[0])
        sim = _similarity(name_clean, org)
        # Check both high similarity and simple substring inclusion (if org is non-trivial)
        if sim >= 0.75 or (len(org) >= 4 and org in name_clean):
            return {"impersonates": domain, "similarity": max(sim, 0.9)}

    # Check against known brand list
    for brand in _TRUSTED_BRAND_ALIASES:
        if brand in name_clean:
            return {"impersonates": brand, "similarity": 1.0}

    return {}


# ─────────────────────────────────────────────────────────────────────────────
@zak_tool(
    action_id="detect_display_name_spoof",
    description=(
        "Detect if the email display name mimics a trusted entity "
        "while the actual sender domain is different."
    ),
)
def detect_display_name_spoof(
    display_name: str,
    from_domain: str,
    whitelist_domains: list,
) -> ToolResult:
    """
    A spoofed display name is one that:
    1. Closely resembles a whitelisted org name or well-known brand
    2. But the actual from_domain is NOT in the whitelist
    """
    try:
        impersonation = _looks_like_trusted_entity(display_name, list(whitelist_domains))

        if not impersonation:
            return ToolResult.ok({
                "display_name_spoof": False,
                "display_name": display_name,
                "from_domain": from_domain,
            })

        # If from_domain matches the impersonated entity, it's legitimate
        impersonated = impersonation.get("impersonates", "")
        domain_matches = (
            from_domain.endswith(impersonated)
            or impersonated.endswith(from_domain.split(".")[0])
        )

        spoof_detected = not domain_matches

        return ToolResult.ok({
            "display_name_spoof": spoof_detected,
            "display_name": display_name,
            "from_domain": from_domain,
            "impersonates": impersonated,
            "similarity_score": round(impersonation.get("similarity", 0), 3),
            "reason": (
                f"Display name '{display_name}' resembles '{impersonated}' "
                f"but sent from '{from_domain}'"
            ) if spoof_detected else "",
        })

    except Exception as exc:
        return ToolResult.error(f"detect_display_name_spoof failed: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
@zak_tool(
    action_id="classify_phishing_risk",
    description=(
        "Aggregate all verification signals into a final risk level: "
        "SAFE, MEDIUM_RISK, or HIGH_RISK."
    ),
)
def classify_phishing_risk(
    in_whitelist: bool,
    spf_pass: bool,
    spf_aligned: bool | None,
    dkim_pass: bool,
    dkim_aligned: bool | None,
    dmarc_pass: bool,
    display_name_spoof: bool,
    subdomain_spoof: bool,
    from_domain: str,
    strict_mode: bool = True,
) -> ToolResult:
    """
    Risk Classification Rules
    ─────────────────────────
    HIGH_RISK  : spoofing detected OR authentication failures on otherwise whitelisted domain
    MEDIUM_RISK: external domain not in whitelist (but no explicit spoofing)
    SAFE       : whitelist match + all auth checks pass (or unavailable)
    """
    try:
        reasons: list[str] = []
        flags: dict[str, bool] = {}

        # --- Spoofing signals (always HIGH) ---
        if display_name_spoof:
            reasons.append("Display name impersonates a trusted entity")
            flags["display_name_spoof"] = True

        if subdomain_spoof:
            reasons.append("Sender uses unauthorized subdomain of whitelisted domain")
            flags["subdomain_spoof"] = True

        # --- Authentication failures ---
        auth_fail = False
        if spf_pass is False:  # explicit fail (not missing)
            reasons.append("SPF check failed")
            auth_fail = True
        if spf_aligned is False:
            reasons.append("SPF domain misaligned with From header")
            auth_fail = True
        if dkim_pass is False:
            reasons.append("DKIM check failed")
            auth_fail = True
        if dkim_aligned is False:
            reasons.append("DKIM signing domain misaligned with From header")
            auth_fail = True
        if dmarc_pass is False:
            reasons.append("DMARC check failed")
            auth_fail = True

        # --- Whitelist miss ---
        if not in_whitelist:
            reasons.append(f"Sender domain '{from_domain}' is not in the approved whitelist")

        # ─── Final verdict ───
        if flags or (auth_fail and in_whitelist):
            risk_level = "HIGH_RISK"
        elif not in_whitelist or auth_fail:
            risk_level = "MEDIUM_RISK"
        else:
            risk_level = "SAFE"

        action = "BLOCK" if (risk_level != "SAFE" and strict_mode) else (
            "WARN" if risk_level != "SAFE" else "ALLOW"
        )

        return ToolResult.ok({
            "risk_level": risk_level,
            "action": action,
            "reasons": reasons,
            "flags": flags,
            "in_whitelist": in_whitelist,
            "auth_summary": {
                "spf_pass": spf_pass,
                "spf_aligned": spf_aligned,
                "dkim_pass": dkim_pass,
                "dkim_aligned": dkim_aligned,
                "dmarc_pass": dmarc_pass,
            },
        })

    except Exception as exc:
        return ToolResult.error(f"classify_phishing_risk failed: {exc}")
