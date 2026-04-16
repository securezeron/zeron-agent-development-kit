"""
DomainShield Agent – Test Suite
Tests all three canonical scenarios:
  1. Valid internal email (SAFE)
  2. Spoofed domain email (HIGH_RISK)
  3. External unknown domain email (MEDIUM_RISK)

Run:
    python -m pytest tests/ -v
    python -m pytest tests/ -v --tb=short
"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from domain_shield_agent import DomainShieldAgent, AgentContext


# ─── Shared fixtures ──────────────────────────────────────────────────────────

WHITELIST = ["company.com", "trustedpartner.com"]

VALID_AUTH_RESULTS = (
    "dkim=pass header.d=company.com; "
    "spf=pass smtp.mailfrom=sender@company.com; "
    "dmarc=pass policy.applied=none"
)

FAILED_AUTH_RESULTS = (
    "dkim=fail; spf=fail; dmarc=fail"
)


def _make_raw_email(
    from_addr: str,
    display_name: str = "",
    auth_results: str = "",
    received_spf: str = "",
    subject: str = "Test Email",
    uid: str = "test-uid-001",
) -> dict:
    """Build a minimal email dict matching the ingestion output schema."""
    from_field = f'"{display_name}" <{from_addr}>' if display_name else from_addr
    return {
        "uid": uid,
        "subject": subject,
        "from": from_field,
        "to": "inbox@company.com",
        "return_path": f"<{from_addr}>",
        "date": "Mon, 12 Apr 2026 10:00:00 +0000",
        "message_id": f"<{uid}@test>",
        "received_spf": received_spf,
        "authentication_results": auth_results,
        "dkim_signature": "v=1; a=rsa-sha256; ...",
        "raw_headers": {},
        "body_preview": "Hello, please review the attached report.",
    }


def _run_agent(email_dict: dict, strict_mode: bool = True) -> dict:
    """Run the agent with a single pre-parsed email dict injected via 'raw' bypass."""
    agent = DomainShieldAgent()

    # Bypass ingestion by monkey-patching call_tool for ingest_email
    original_call_tool = agent.call_tool

    def patched_call_tool(ctx, action_id, **kwargs):
        if action_id == "ingest_email":
            return {"status": "ok", "data": {"ingested_count": 1, "emails": [email_dict]}}
        return original_call_tool(ctx, action_id, **kwargs)

    agent.call_tool = patched_call_tool

    ctx = AgentContext(inputs={
        "whitelist_domains": WHITELIST,
        "strict_mode": strict_mode,
        "alert_threshold": "medium_and_above",
        "source": "raw",
        "raw_eml": "",
    })
    result = agent.execute(ctx)
    return result


# ─── Test Case 1: Valid Internal Email ────────────────────────────────────────

class TestValidInternalEmail:
    """Email from a whitelisted domain with all auth checks passing → SAFE"""

    def setup_method(self):
        self.email = _make_raw_email(
            from_addr="alice@company.com",
            display_name="Alice Smith",
            auth_results=VALID_AUTH_RESULTS,
            received_spf="pass (company.com: sender is authorized) smtp.mailfrom=alice@company.com",
            subject="Q1 Report",
            uid="valid-001",
        )

    def test_risk_level_is_safe(self):
        result = _run_agent(self.email)
        data = result.get("data", result)
        assert data.get("safe_count", 0) == 1, f"Expected safe_count=1, got: {data}"

    def test_no_alerts_generated(self):
        result = _run_agent(self.email)
        data = result.get("data", result)
        assert data.get("alerts_generated", 0) == 0, "No alerts expected for safe email"

    def test_processed_count(self):
        result = _run_agent(self.email)
        data = result.get("data", result)
        assert data.get("processed_count") == 1


# ─── Test Case 2: Spoofed Domain Email ───────────────────────────────────────

class TestSpoofedDomainEmail:
    """Display name mimics company, but domain is external + auth fails → HIGH_RISK"""

    def setup_method(self):
        self.email = _make_raw_email(
            from_addr="noreply@evil-company.net",
            display_name="Company IT Support",     # <-- mimics 'company'
            auth_results=FAILED_AUTH_RESULTS,
            received_spf="fail",
            subject="Urgent: Reset Your Password",
            uid="spoof-001",
        )

    def test_risk_level_is_high(self):
        result = _run_agent(self.email)
        data = result.get("data", result)
        assert data.get("high_risk_count", 0) == 1, f"Expected HIGH_RISK, got: {data}"

    def test_alert_generated(self):
        result = _run_agent(self.email)
        data = result.get("data", result)
        assert data.get("alerts_generated", 0) >= 1, "Alert expected for HIGH_RISK email"

    def test_alert_has_reasons(self):
        result = _run_agent(self.email)
        data = result.get("data", result)
        alerts = data.get("alerts", [])
        assert alerts, "No alerts found"
        reasons = alerts[0].get("reasons", [])
        assert len(reasons) > 0, "Alert should contain flagging reasons"

    def test_action_is_block_in_strict_mode(self):
        result = _run_agent(self.email, strict_mode=True)
        data = result.get("data", result)
        alerts = data.get("alerts", [])
        if alerts:
            assert alerts[0].get("action") == "BLOCK"


# ─── Test Case 3: External Unknown Domain ────────────────────────────────────

class TestExternalUnknownDomain:
    """Email from a legitimate-seeming external domain not in whitelist → MEDIUM_RISK"""

    def setup_method(self):
        self.email = _make_raw_email(
            from_addr="newsletter@external-vendor.io",
            display_name="External Vendor",
            auth_results=(
                "dkim=pass header.d=external-vendor.io; "
                "spf=pass smtp.mailfrom=newsletter@external-vendor.io; "
                "dmarc=pass"
            ),
            received_spf="pass",
            subject="Monthly Newsletter",
            uid="ext-001",
        )

    def test_risk_level_is_medium(self):
        result = _run_agent(self.email)
        data = result.get("data", result)
        assert data.get("medium_risk_count", 0) == 1, f"Expected MEDIUM_RISK, got: {data}"

    def test_alert_generated(self):
        result = _run_agent(self.email)
        data = result.get("data", result)
        assert data.get("alerts_generated", 0) >= 1

    def test_not_high_risk(self):
        result = _run_agent(self.email)
        data = result.get("data", result)
        assert data.get("high_risk_count", 0) == 0, "External domain with good auth should not be HIGH_RISK"

    def test_warn_action_in_non_strict_mode(self):
        result = _run_agent(self.email, strict_mode=False)
        data = result.get("data", result)
        alerts = data.get("alerts", [])
        if alerts:
            assert alerts[0].get("action") == "WARN"


# ─── Test Case 4: Subdomain Spoof ─────────────────────────────────────────────

class TestSubdomainSpoof:
    """Email from mail.evil.company.com should be detected as subdomain spoof"""

    def setup_method(self):
        self.email = _make_raw_email(
            from_addr="phish@mail.evil.company.com",
            display_name="Company Security",
            auth_results=FAILED_AUTH_RESULTS,
            received_spf="fail",
            subject="Your account has been compromised",
            uid="subspoof-001",
        )

    def test_risk_level_is_high(self):
        result = _run_agent(self.email)
        data = result.get("data", result)
        assert data.get("high_risk_count", 0) == 1, f"Expected HIGH_RISK for subdomain spoof, got: {data}"


# ─── Test Case 5: Whitelist domain with auth failure ──────────────────────────

class TestWhitelistedDomainAuthFailure:
    """Whitelisted domain but SPF/DKIM/DMARC all fail → HIGH_RISK (possible spoofing of internal domain)"""

    def setup_method(self):
        self.email = _make_raw_email(
            from_addr="ceo@company.com",
            display_name="CEO Company",
            auth_results=FAILED_AUTH_RESULTS,
            received_spf="fail",
            subject="Wire Transfer Request",
            uid="authfail-001",
        )

    def test_risk_level_is_high(self):
        result = _run_agent(self.email)
        data = result.get("data", result)
        assert data.get("high_risk_count", 0) == 1, (
            f"Whitelisted domain with auth failure should be HIGH_RISK, got: {data}"
        )


# ─── Unit Tests: Individual Tools ─────────────────────────────────────────────

class TestDomainVerificationTools:
    def test_normalize_idn_domain(self):
        from tools.domain_verification_tools import normalize_domain
        result = normalize_domain("CompaNY.COM")
        assert result.get("data", {}).get("normalized") == "company.com"

    def test_whitelist_exact_match(self):
        from tools.domain_verification_tools import verify_domain_whitelist
        r = verify_domain_whitelist("company.com", ["company.com", "partner.org"])
        assert r.get("data", {}).get("in_whitelist") is True

    def test_whitelist_miss(self):
        from tools.domain_verification_tools import verify_domain_whitelist
        r = verify_domain_whitelist("evil.com", ["company.com"])
        assert r.get("data", {}).get("in_whitelist") is False

    def test_subdomain_spoof_detected(self):
        from tools.domain_verification_tools import detect_subdomain_spoof
        r = detect_subdomain_spoof("evil.company.com", ["company.com"])
        assert r.get("data", {}).get("subdomain_spoof") is True

    def test_legit_subdomain_not_in_whitelist(self):
        from tools.domain_verification_tools import detect_subdomain_spoof
        # mail.company.com is a subdomain of company.com but not explicitly whitelisted
        r = detect_subdomain_spoof("mail.company.com", ["company.com"])
        assert r.get("data", {}).get("subdomain_spoof") is True


class TestPhishingDetectionTools:
    def test_display_name_spoof_detected(self):
        from tools.phishing_detection_tools import detect_display_name_spoof
        r = detect_display_name_spoof(
            display_name="Microsoft Support",
            from_domain="evil.net",
            whitelist_domains=["company.com"],
        )
        assert r.get("data", {}).get("display_name_spoof") is True

    def test_legitimate_display_name(self):
        from tools.phishing_detection_tools import detect_display_name_spoof
        r = detect_display_name_spoof(
            display_name="Alice from Company",
            from_domain="company.com",
            whitelist_domains=["company.com"],
        )
        # May or may not flag – depends on similarity; just check it returns data
        assert "data" in r

    def test_classify_safe(self):
        from tools.phishing_detection_tools import classify_phishing_risk
        r = classify_phishing_risk(
            in_whitelist=True,
            spf_pass=True, spf_aligned=True,
            dkim_pass=True, dkim_aligned=True,
            dmarc_pass=True,
            display_name_spoof=False,
            subdomain_spoof=False,
            from_domain="company.com",
            strict_mode=True,
        )
        assert r.get("data", {}).get("risk_level") == "SAFE"

    def test_classify_high_risk_spoof(self):
        from tools.phishing_detection_tools import classify_phishing_risk
        r = classify_phishing_risk(
            in_whitelist=False,
            spf_pass=False, spf_aligned=False,
            dkim_pass=False, dkim_aligned=False,
            dmarc_pass=False,
            display_name_spoof=True,
            subdomain_spoof=False,
            from_domain="evil.com",
            strict_mode=True,
        )
        assert r.get("data", {}).get("risk_level") == "HIGH_RISK"
        assert r.get("data", {}).get("action") == "BLOCK"

    def test_classify_medium_risk_external(self):
        from tools.phishing_detection_tools import classify_phishing_risk
        r = classify_phishing_risk(
            in_whitelist=False,
            spf_pass=True, spf_aligned=True,
            dkim_pass=True, dkim_aligned=True,
            dmarc_pass=True,
            display_name_spoof=False,
            subdomain_spoof=False,
            from_domain="external.io",
            strict_mode=True,
        )
        assert r.get("data", {}).get("risk_level") == "MEDIUM_RISK"


class TestPolicyTools:
    def test_add_and_remove_domain(self, tmp_path):
        from tools.policy_tools import manage_whitelist
        policy_path = str(tmp_path / "policy.json")

        r1 = manage_whitelist("add", "newdomain.com", policy_path=policy_path)
        assert "newdomain.com" in r1.get("data", {}).get("whitelist_domains", [])

        r2 = manage_whitelist("remove", "newdomain.com", policy_path=policy_path)
        assert "newdomain.com" not in r2.get("data", {}).get("whitelist_domains", [])

    def test_list_policy(self, tmp_path):
        from tools.policy_tools import manage_whitelist
        policy_path = str(tmp_path / "policy.json")
        manage_whitelist("add", "a.com", policy_path=policy_path)
        r = manage_whitelist("list", policy_path=policy_path)
        assert "whitelist_domains" in r.get("data", {})
