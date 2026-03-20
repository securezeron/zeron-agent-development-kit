"""
Tools for the Risk Scenario Generator Agent.

Provides domain intelligence gathering and CRML scenario generation/validation
capabilities that the LLM uses in its ReAct loop.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
from typing import Any
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from zak.core.runtime.agent import AgentContext
from zak.core.tools.substrate import zak_tool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ALLOWED_SCHEMES = ("https", "http")


def _is_host_allowed(host: str) -> bool:
    """Return True only if the host resolves to globally routable IPs (SSRF mitigation)."""
    if not host or not host.strip():
        return False
    host = host.strip().lower()
    if host in ("localhost", "localhost.", "::1"):
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, socket.herror, OSError):
        return False
    if not infos:
        return False
    for (_family, _type, _proto, _canon, sockaddr) in infos:
        ip_str = sockaddr[0] if isinstance(sockaddr, (list, tuple)) else sockaddr
        try:
            ip = ipaddress.ip_address(ip_str)
            if not ip.is_global:
                return False
        except ValueError:
            return False
    return True


def _validate_url(url: str) -> None:
    """Validate URL scheme and host for safe external fetching."""
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise PermissionError(
            f"Access denied: URL scheme must be one of {_ALLOWED_SCHEMES}, got {scheme or 'empty'}."
        )
    netloc = parsed.netloc or parsed.path.split("/")[0] or ""
    host = netloc.rsplit(":", 1)[0] if netloc else ""
    if not host:
        raise PermissionError("Access denied: URL has no host.")
    if not _is_host_allowed(host):
        raise PermissionError(
            f"Access denied: '{host}' resolves to internal or disallowed addresses. "
            "Only public website URLs are allowed."
        )


def _clean_html(html: str, max_chars: int = 15000) -> str:
    """Extract and clean text from HTML content."""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()
    text = soup.get_text(separator="\n")
    lines = (line.strip() for line in text.splitlines())
    chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
    text = "\n".join(chunk for chunk in chunks if chunk)
    return text[:max_chars]


# ---------------------------------------------------------------------------
# Tool: fetch_domain_intel
# ---------------------------------------------------------------------------

@zak_tool(
    name="fetch_domain_intel",
    description=(
        "Gather publicly available intelligence about a domain/company for risk scenario generation. "
        "Fetches the company's website homepage and attempts to identify industry, size, tech stack, "
        "and other risk-relevant context from the page content."
    ),
    action_id="fetch_domain_intel",
    tags=["risk_scenario", "recon", "read"],
)
def fetch_domain_intel(context: AgentContext, domain: str) -> dict[str, Any]:
    """
    Fetch publicly available information about a domain to inform risk scenario generation.

    Gathers the homepage content and extracts text for the LLM to analyse. The LLM
    then uses this intelligence to calibrate realistic CRML scenario parameters.

    Args:
        domain: The target domain (e.g. 'example.com'). Can also be a full URL.

    Returns:
        Dict with domain, url, page_text, and any extracted metadata.
    """
    # Normalise: accept both "example.com" and "https://example.com"
    if not domain.startswith(("http://", "https://")):
        url = f"https://{domain}"
    else:
        url = domain

    parsed = urlparse(url)
    clean_domain = parsed.netloc or parsed.hostname or domain

    _validate_url(url)

    result: dict[str, Any] = {
        "domain": clean_domain,
        "url": url,
        "page_text": "",
        "http_headers": {},
        "error": None,
    }

    try:
        resp = httpx.get(
            url,
            timeout=15.0,
            follow_redirects=True,
            headers={"User-Agent": "ZAK-RiskScenarioAgent/1.0"},
        )
        resp.raise_for_status()

        # Capture useful headers for tech-stack inference
        interesting_headers = [
            "server", "x-powered-by", "x-frame-options",
            "content-security-policy", "strict-transport-security",
            "x-content-type-options", "x-xss-protection",
        ]
        result["http_headers"] = {
            k: v for k, v in resp.headers.items()
            if k.lower() in interesting_headers
        }

        result["page_text"] = _clean_html(resp.text)

    except PermissionError:
        raise
    except Exception as exc:
        result["error"] = f"Failed to fetch {url}: {str(exc)}"

    return result


# ---------------------------------------------------------------------------
# Tool: generate_crml_scenario
# ---------------------------------------------------------------------------

@zak_tool(
    name="generate_crml_scenario",
    description=(
        "Generate a valid CRML (Cyber Risk Modeling Language) scenario YAML document. "
        "Accepts structured risk parameters (name, description, frequency model, severity model, "
        "controls, metadata) and produces a schema-valid crml_scenario YAML string."
    ),
    action_id="generate_crml_scenario",
    tags=["risk_scenario", "crml", "write"],
)
def generate_crml_scenario(
    context: AgentContext,
    name: str,
    description: str,
    frequency_model: str,
    frequency_lambda: float,
    severity_model: str,
    severity_median: str,
    severity_sigma: float,
    severity_currency: str = "USD",
    tags: str = "",
    company_size: str = "",
    industries: str = "",
    controls_json: str = "",
    frequency_basis: str = "per_organization_per_year",
    author: str = "ZAK Risk Scenario Agent",
    frequency_alpha_base: float = 0.0,
    frequency_beta_base: float = 0.0,
    severity_components_json: str = "",
) -> dict[str, Any]:
    """
    Build a CRML scenario YAML document from structured parameters.

    The LLM calls this tool after analysing domain intelligence to produce
    a properly formatted CRML scenario. Supports FAIR-style (poisson + lognormal)
    and QBER-style (hierarchical_gamma_poisson + mixture) models.

    Args:
        name:                   Scenario name (kebab-case recommended).
        description:            Human-readable description of the risk scenario.
        frequency_model:        One of: poisson, hierarchical_gamma_poisson, gamma.
        frequency_lambda:       Poisson lambda (events/year). Used for poisson model.
        severity_model:         One of: lognormal, gamma, mixture.
        severity_median:        Median loss amount as string (e.g. "250 000").
        severity_sigma:         Lognormal sigma (loss variability). Typical: 0.8-2.0.
        severity_currency:      ISO 4217 currency code (default: USD).
        tags:                   Comma-separated tags (e.g. "ransomware,encryption").
        company_size:           Comma-separated sizes (e.g. "smb,enterprise").
        industries:             Comma-separated industries (e.g. "healthcare,finance").
        controls_json:          JSON array of controls, each with id and effectiveness_against_threat.
        frequency_basis:        per_organization_per_year or per_asset_unit_per_year.
        author:                 Scenario author.
        frequency_alpha_base:   Gamma shape for hierarchical_gamma_poisson model.
        frequency_beta_base:    Gamma scale for hierarchical_gamma_poisson model.
        severity_components_json: JSON array of mixture components for mixture severity model.

    Returns:
        Dict with 'yaml' (the CRML YAML string) and 'scenario_name'.
    """
    import yaml  # type: ignore[import-untyped]

    # --- Build meta ---
    meta: dict[str, Any] = {
        "name": name,
        "version": "1.0",
        "description": description,
        "author": author,
    }
    if tags:
        meta["tags"] = [t.strip() for t in tags.split(",") if t.strip()]
    if company_size:
        meta["company_size"] = [s.strip() for s in company_size.split(",") if s.strip()]
    if industries:
        meta["industries"] = [i.strip() for i in industries.split(",") if i.strip()]

    # --- Build frequency ---
    frequency: dict[str, Any] = {
        "basis": frequency_basis,
        "model": frequency_model,
    }
    if frequency_model == "poisson":
        frequency["parameters"] = {"lambda": frequency_lambda}
    elif frequency_model == "hierarchical_gamma_poisson":
        frequency["parameters"] = {
            "alpha_base": frequency_alpha_base or 1.5,
            "beta_base": frequency_beta_base or 1.5,
        }
    elif frequency_model == "gamma":
        frequency["parameters"] = {
            "shape": frequency_alpha_base or 2.0,
            "scale": frequency_beta_base or 1.0,
        }

    # --- Build severity ---
    severity: dict[str, Any] = {"model": severity_model}

    if severity_model == "lognormal":
        severity["parameters"] = {
            "median": severity_median,
            "currency": severity_currency,
            "sigma": severity_sigma,
        }
    elif severity_model == "gamma":
        severity["parameters"] = {
            "shape": severity_sigma,
            "scale": severity_median,
            "currency": severity_currency,
        }
    elif severity_model == "mixture":
        severity["parameters"] = {}
        if severity_components_json:
            try:
                severity["components"] = json.loads(severity_components_json)
            except json.JSONDecodeError:
                severity["components"] = [
                    {"lognormal": {"weight": 0.7, "median": severity_median, "currency": severity_currency, "sigma": severity_sigma}},
                    {"gamma": {"weight": 0.3, "shape": 2.5, "scale": "10 000", "currency": severity_currency}},
                ]
        else:
            severity["components"] = [
                {"lognormal": {"weight": 0.7, "median": severity_median, "currency": severity_currency, "sigma": severity_sigma}},
                {"gamma": {"weight": 0.3, "shape": 2.5, "scale": "10 000", "currency": severity_currency}},
            ]

    # --- Build controls ---
    controls = []
    if controls_json:
        try:
            controls = json.loads(controls_json)
        except json.JSONDecodeError:
            pass

    # --- Assemble scenario ---
    scenario_payload: dict[str, Any] = {
        "frequency": frequency,
        "severity": severity,
    }
    if controls:
        scenario_payload["controls"] = controls

    doc = {
        "crml_scenario": "1.0",
        "meta": meta,
        "scenario": scenario_payload,
    }

    yaml_str = yaml.dump(doc, default_flow_style=False, sort_keys=False, allow_unicode=True)

    return {
        "yaml": yaml_str,
        "scenario_name": name,
    }


# ---------------------------------------------------------------------------
# Tool: validate_crml_scenario
# ---------------------------------------------------------------------------

@zak_tool(
    name="validate_crml_scenario",
    description=(
        "Validate a CRML scenario YAML string against the CRML specification. "
        "Checks required fields, frequency/severity model validity, control ID formats, "
        "and parameter ranges. Returns validation result with any errors found."
    ),
    action_id="validate_crml_scenario",
    tags=["risk_scenario", "crml", "validation"],
)
def validate_crml_scenario(context: AgentContext, yaml_content: str) -> dict[str, Any]:
    """
    Validate a CRML scenario YAML string for structural and semantic correctness.

    Checks:
    - Required top-level fields (crml_scenario, meta.name, scenario)
    - Frequency model is supported and has required parameters
    - Severity model is supported and has required parameters
    - Control IDs follow the namespace:key format
    - Parameter value ranges are sensible

    Args:
        yaml_content: The CRML scenario as a YAML string.

    Returns:
        Dict with 'valid' (bool), 'errors' (list[str]), and 'warnings' (list[str]).
    """
    import yaml

    errors: list[str] = []
    warnings: list[str] = []

    # --- Parse YAML ---
    try:
        doc = yaml.safe_load(yaml_content)
    except yaml.YAMLError as exc:
        return {"valid": False, "errors": [f"YAML parse error: {exc}"], "warnings": []}

    if not isinstance(doc, dict):
        return {"valid": False, "errors": ["Document root must be a mapping"], "warnings": []}

    # --- Top-level fields ---
    if "crml_scenario" not in doc:
        errors.append("Missing required field: crml_scenario (must be '1.0')")
    elif str(doc["crml_scenario"]) != "1.0":
        warnings.append(f"crml_scenario version '{doc['crml_scenario']}' — only '1.0' is currently supported")

    meta = doc.get("meta", {})
    if not meta.get("name"):
        errors.append("Missing required field: meta.name")

    scenario = doc.get("scenario")
    if not scenario:
        errors.append("Missing required field: scenario")
        return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings}

    # --- Frequency validation ---
    freq = scenario.get("frequency")
    if not freq:
        errors.append("Missing required field: scenario.frequency")
    else:
        valid_freq_models = {"poisson", "hierarchical_gamma_poisson", "gamma"}
        model = freq.get("model", "")
        if model not in valid_freq_models:
            errors.append(f"Invalid frequency model '{model}'. Must be one of: {valid_freq_models}")

        basis = freq.get("basis", "per_organization_per_year")
        valid_bases = {"per_organization_per_year", "per_asset_unit_per_year"}
        if basis not in valid_bases:
            errors.append(f"Invalid frequency basis '{basis}'. Must be one of: {valid_bases}")

        params = freq.get("parameters", {})
        if model == "poisson":
            lam = params.get("lambda")
            if lam is None:
                errors.append("Poisson frequency model requires 'lambda' parameter")
            elif isinstance(lam, (int, float)) and lam < 0:
                errors.append(f"Poisson lambda must be non-negative, got {lam}")
            elif isinstance(lam, (int, float)) and lam > 100:
                warnings.append(f"Poisson lambda={lam} is unusually high — verify this is intentional")
        elif model == "hierarchical_gamma_poisson":
            if "alpha_base" not in params:
                errors.append("hierarchical_gamma_poisson requires 'alpha_base' parameter")
            if "beta_base" not in params:
                errors.append("hierarchical_gamma_poisson requires 'beta_base' parameter")

    # --- Severity validation ---
    sev = scenario.get("severity")
    if not sev:
        errors.append("Missing required field: scenario.severity")
    else:
        valid_sev_models = {"lognormal", "gamma", "mixture"}
        model = sev.get("model", "")
        if model not in valid_sev_models:
            errors.append(f"Invalid severity model '{model}'. Must be one of: {valid_sev_models}")

        params = sev.get("parameters", {})
        if model == "lognormal":
            has_median = "median" in params
            has_mu = "mu" in params
            if not has_median and not has_mu:
                errors.append("Lognormal severity requires 'median' or 'mu' parameter")
            if "sigma" not in params:
                errors.append("Lognormal severity requires 'sigma' parameter")
            sigma = params.get("sigma")
            if isinstance(sigma, (int, float)) and sigma <= 0:
                errors.append(f"Lognormal sigma must be positive, got {sigma}")
        elif model == "mixture":
            components = sev.get("components", [])
            if not components:
                errors.append("Mixture severity model requires at least one component")
            else:
                total_weight = 0.0
                for comp in components:
                    if isinstance(comp, dict):
                        for dist_type, dist_params in comp.items():
                            w = dist_params.get("weight", 0)
                            total_weight += float(w)
                if abs(total_weight - 1.0) > 0.01:
                    warnings.append(f"Mixture component weights sum to {total_weight}, expected ~1.0")

    # --- Controls validation ---
    controls = scenario.get("controls", [])
    control_id_pattern = re.compile(r"^[a-z][a-z0-9_-]{0,31}:[^\s]{1,223}$")
    for ctrl in controls:
        if isinstance(ctrl, dict):
            ctrl_id = ctrl.get("id", "")
            if ctrl_id.startswith("attck:"):
                errors.append(f"Control ID '{ctrl_id}' must not start with 'attck:' (reserved for attacks)")
            elif ctrl_id and not control_id_pattern.match(ctrl_id):
                warnings.append(f"Control ID '{ctrl_id}' does not match recommended format namespace:key")
            eff = ctrl.get("effectiveness_against_threat")
            if eff is not None and (float(eff) < 0.0 or float(eff) > 1.0):
                errors.append(f"Control effectiveness must be 0.0-1.0, got {eff} for '{ctrl_id}'")

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
    }
