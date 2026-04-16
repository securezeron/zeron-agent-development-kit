"""
Domain Verification Engine – DomainShield Agent
Handles whitelist checks, SPF/DKIM/DMARC header parsing, IDN normalization,
and subdomain-spoofing detection.
"""

from __future__ import annotations

import re
import unicodedata
from email.utils import parseaddr
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

_EMAIL_RE = re.compile(r"[\w.+\-]+@([\w.\-]+\.\w+)", re.IGNORECASE)


def _extract_domain(address: str) -> str:
    """Extract bare domain from 'Display Name <user@domain.com>' or 'user@domain.com'."""
    _, addr = parseaddr(address)
    addr = addr.strip().lower()
    m = _EMAIL_RE.search(addr)
    return m.group(1) if m else ""


def _normalize(domain: str) -> str:
    """
    Normalize a domain for safe comparison:
    - lowercase + strip whitespace
    - IDNA-decode internationalized domains (IDN)
    - Remove leading/trailing dots
    """
    domain = domain.strip().lower()
    # Replace Unicode look-alike characters (Punycode)
    try:
        domain = domain.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        # fall back to NFKD normalization
        domain = unicodedata.normalize("NFKD", domain)
    domain = domain.strip(".")
    return domain


def _is_subdomain_of(candidate: str, parent: str) -> bool:
    """Return True if *candidate* is a subdomain of *parent* (not equal)."""
    candidate = _normalize(candidate)
    parent = _normalize(parent)
    return candidate != parent and candidate.endswith("." + parent)


# ─────────────────────────────────────────────────────────────────────────────
@zak_tool(
    action_id="normalize_domain",
    description="Normalize a raw domain string: lowercase, strip, IDNA-decode.",
)
def normalize_domain(domain: str) -> ToolResult:
    try:
        normalized = _normalize(domain)
        return ToolResult.ok({"original": domain, "normalized": normalized})
    except Exception as exc:
        return ToolResult.error(f"normalize_domain failed: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
@zak_tool(
    action_id="parse_email_headers",
    description="Extract sender domain and key authentication fields from an email dict.",
)
def parse_email_headers(email_dict: dict) -> ToolResult:
    """
    Parses the ingested email dict produced by ingest_email and returns
    structured header fields needed for all downstream checks.
    """
    try:
        from_raw = email_dict.get("from", "")
        return_path_raw = email_dict.get("return_path", "")
        auth_results = email_dict.get("authentication_results", "")
        received_spf = email_dict.get("received_spf", "")
        dkim_sig = email_dict.get("dkim_signature", "")

        from_domain = _extract_domain(from_raw)
        return_path_domain = _extract_domain(return_path_raw)

        _, display_name = parseaddr(from_raw)
        display_name_part = from_raw.split("<")[0].strip().strip('"')

        parsed = {
            "uid": email_dict.get("uid", ""),
            "subject": email_dict.get("subject", ""),
            "from_raw": from_raw,
            "display_name": display_name_part,
            "from_domain": _normalize(from_domain),
            "return_path_domain": _normalize(return_path_domain) if return_path_domain else "",
            "authentication_results_raw": auth_results,
            "received_spf_raw": received_spf,
            "dkim_signature_present": bool(dkim_sig),
            "date": email_dict.get("date", ""),
            "message_id": email_dict.get("message_id", ""),
        }
        return ToolResult.ok(parsed)

    except Exception as exc:
        return ToolResult.error(f"parse_email_headers failed: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
@zak_tool(
    action_id="verify_domain_whitelist",
    description="Check whether the sender domain is in the approved whitelist.",
)
def verify_domain_whitelist(
    from_domain: str,
    whitelist_domains: list,
) -> ToolResult:
    """
    Parameters
    ----------
    from_domain       : normalized sender domain
    whitelist_domains : list of approved domains (e.g. ["company.com"])
    """
    try:
        from_domain_norm = _normalize(from_domain)
        normalized_whitelist = [_normalize(d) for d in whitelist_domains]

        in_whitelist = from_domain_norm in normalized_whitelist
        # exact match only – subdomains require explicit listing
        return ToolResult.ok({
            "from_domain": from_domain_norm,
            "in_whitelist": in_whitelist,
            "whitelist_size": len(normalized_whitelist),
        })

    except Exception as exc:
        return ToolResult.error(f"verify_domain_whitelist failed: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
@zak_tool(
    action_id="check_spf_alignment",
    description="Parse Received-SPF / Authentication-Results for SPF pass/fail and domain alignment.",
)
def check_spf_alignment(
    received_spf_raw: str,
    authentication_results_raw: str,
    from_domain: str,
) -> ToolResult:
    """
    Returns spf_pass (bool) and spf_aligned (bool – does spf domain match from_domain).
    """
    try:
        combined = (received_spf_raw + " " + authentication_results_raw).lower()

        if "spf=" not in combined:
            spf_pass = None
            spf_fail = None
        else:
            spf_pass = bool(re.search(r"spf=pass", combined))
            spf_fail = bool(re.search(r"spf=(fail|softfail|neutral|none|permerror|temperror)", combined))

        # Extract envelope-from / smtp.mailfrom domain from auth results
        envelope_domain = ""
        m = re.search(r"smtp\.mailfrom=([^\s;]+)", combined)
        if m:
            envelope_domain = _normalize(m.group(1).split("@")[-1])

        spf_aligned = (_normalize(from_domain) == envelope_domain) if envelope_domain else None

        return ToolResult.ok({
            "spf_pass": spf_pass,
            "spf_fail": spf_fail,
            "spf_domain": envelope_domain,
            "spf_aligned": spf_aligned,
            "raw_snippet": combined[:200],
        })

    except Exception as exc:
        return ToolResult.error(f"check_spf_alignment failed: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
@zak_tool(
    action_id="check_dkim_alignment",
    description="Parse Authentication-Results for DKIM pass/fail and domain alignment.",
)
def check_dkim_alignment(
    authentication_results_raw: str,
    from_domain: str,
) -> ToolResult:
    try:
        ar = authentication_results_raw.lower()

        if "dkim=" not in ar:
            dkim_pass = None
            dkim_fail = None
        else:
            dkim_pass = bool(re.search(r"dkim=pass", ar))
            dkim_fail = bool(re.search(r"dkim=(fail|none|neutral|policy|permerror|temperror)", ar))

        # Extract signing domain (d= tag in auth results)
        signing_domain = ""
        m = re.search(r"header\.d=([^\s;]+)", ar)
        if not m:
            m = re.search(r"dkim=pass[^;]*?\bd=([^\s;]+)", ar)
        if m:
            signing_domain = _normalize(m.group(1))

        dkim_aligned = (
            _normalize(from_domain) == signing_domain
            or _is_subdomain_of(signing_domain, _normalize(from_domain))
        ) if signing_domain else None

        return ToolResult.ok({
            "dkim_pass": dkim_pass,
            "dkim_fail": dkim_fail,
            "dkim_signing_domain": signing_domain,
            "dkim_aligned": dkim_aligned,
        })

    except Exception as exc:
        return ToolResult.error(f"check_dkim_alignment failed: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
@zak_tool(
    action_id="check_dmarc_alignment",
    description="Parse Authentication-Results for DMARC policy outcome.",
)
def check_dmarc_alignment(authentication_results_raw: str) -> ToolResult:
    try:
        ar = authentication_results_raw.lower()
        if "dmarc=" not in ar:
            dmarc_pass = None
            dmarc_fail = None
        else:
            dmarc_pass = bool(re.search(r"dmarc=pass", ar))
            dmarc_fail = bool(re.search(r"dmarc=(fail|none|bestguesspass|temperror|permerror)", ar))

        policy = ""
        m = re.search(r"dmarc=\w+\s+policy\.applied=(\w+)", ar)
        if m:
            policy = m.group(1)

        return ToolResult.ok({
            "dmarc_pass": dmarc_pass,
            "dmarc_fail": dmarc_fail,
            "dmarc_policy_applied": policy,
        })

    except Exception as exc:
        return ToolResult.error(f"check_dmarc_alignment failed: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
@zak_tool(
    action_id="detect_subdomain_spoof",
    description=(
        "Detect if sender domain is a confusable subdomain of a whitelisted domain "
        "(e.g. evil.company.com spoofing company.com)."
    ),
)
def detect_subdomain_spoof(
    from_domain: str,
    whitelist_domains: list,
) -> ToolResult:
    try:
        from_norm = _normalize(from_domain)
        normalized_wl = [_normalize(d) for d in whitelist_domains]

        # Already exact match → not a subdomain spoof
        if from_norm in normalized_wl:
            return ToolResult.ok({"subdomain_spoof": False, "parent_domain": None})

        for parent in normalized_wl:
            if _is_subdomain_of(from_norm, parent):
                return ToolResult.ok({
                    "subdomain_spoof": True,
                    "parent_domain": parent,
                    "spoofing_domain": from_norm,
                    "note": (
                        f"'{from_norm}' is a subdomain of whitelisted '{parent}' "
                        "but is NOT explicitly approved."
                    ),
                })

        return ToolResult.ok({"subdomain_spoof": False, "parent_domain": None})

    except Exception as exc:
        return ToolResult.error(f"detect_subdomain_spoof failed: {exc}")
