"""
Website tools for the DPDP Compliance Agent.
"""

from __future__ import annotations

import httpx
from bs4 import BeautifulSoup
from zak.core.runtime.agent import AgentContext
from zak.core.tools.substrate import zak_tool

@zak_tool(
    name="fetch_website_content",
    description="Fetch and clean text content from a website URL for compliance analysis.",
    action_id="fetch_website_content",
    tags=["compliance", "web", "read"],
)
def fetch_website_content(context: AgentContext, url: str) -> str:
    """
    Downloads the HTML from a URL, extracts the text, and cleans it.
    
    Args:
        url: The URL of the website or privacy policy page.
        
    Returns:
        Cleaned text content of the page.
    """
    try:
        response = httpx.get(url, timeout=10.0, follow_redirects=True)
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
        
    except Exception as e:
        return f"Error fetching website content: {str(e)}"
