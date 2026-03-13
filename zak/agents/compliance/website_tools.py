"""
Website tools for the DPDP Compliance Agent.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import httpx
from bs4 import BeautifulSoup

from zak.core.runtime.agent import AgentContext
from zak.core.tools.substrate import zak_tool

_ALLOWED_SCHEMES = ("https", "http")


def _is_host_allowed(host: str) -> bool:
    """
    Return True only if the host resolves to globally routable IPs.
    Blocks private, loopback, link-local, and reserved addresses (SSRF mitigation).
    """
    if not host or not host.strip():
        return False
    host = host.strip().lower()
    # Reject obvious internal hostnames even before resolution
    if host in ("localhost", "localhost.", "::1"):
        return False
    try:
        # Resolve to all addresses (IPv4 and IPv6)
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


def _validate_fetch_url(url: str) -> None:
    """
    Validate that the URL is allowed for fetching (scheme and host).
    Raises PermissionError if the URL targets internal or disallowed resources.
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise PermissionError(
            f"Access denied: URL scheme must be one of {_ALLOWED_SCHEMES}, got {scheme or 'empty'}."
        )
    netloc = parsed.netloc or parsed.path.split("/")[0] or ""
    # Strip optional port for hostname
    host = netloc.rsplit(":", 1)[0] if netloc else ""
    if not host:
        raise PermissionError("Access denied: URL has no host.")
    if not _is_host_allowed(host):
        raise PermissionError(
            f"Access denied: '{host}' resolves to internal or disallowed addresses. "
            "Only public website URLs are allowed."
        )


@zak_tool(
    name="fetch_website_content",
    description="Fetch and clean text content from a website URL for compliance analysis.",
    action_id="fetch_website_content",
    tags=["compliance", "web", "read"],
)
def fetch_website_content(context: AgentContext, url: str) -> str:
    """
    Downloads the HTML from a URL, extracts the text, and cleans it.

    Only public website URLs are allowed. The URL must use https or http and must
    resolve to globally routable addresses; internal hosts (e.g. localhost, private
    IPs, link-local, cloud metadata) are rejected to prevent SSRF.
    Redirects are not followed so that the server cannot be induced to request
    internal URLs via a redirect.

    Args:
        url: The URL of the website or privacy policy page.

    Returns:
        Cleaned text content of the page.
    """
    try:
        _validate_fetch_url(url)
    except PermissionError:
        raise

    try:
        response = httpx.get(url, timeout=10.0, follow_redirects=False)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")

        # Remove script and style elements
        for script_or_style in soup(["script", "style"]):
            script_or_style.decompose()

        # Get text
        text = soup.get_text(separator="\n")

        # Clean up whitespace
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        text = "\n".join(chunk for chunk in chunks if chunk)

        return text[:20000]  # Limit to 20k chars for LLM safety

    except PermissionError:
        raise
    except Exception as e:
        return f"Error fetching website content: {str(e)}"
