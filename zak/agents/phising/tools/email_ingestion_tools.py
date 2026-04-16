"""
Email Ingestion Module – DomainShield Agent
Supports IMAP, local .eml files, and in-memory raw RFC-2822 payloads.
"""

from __future__ import annotations

import email
import imaplib
import os
import ssl
from email.message import Message
from typing import Any

# ── ZAK SDK shim (falls back gracefully when sdk not installed) ──────────────
try:
    from zin_adk import zak_tool, ToolResult
except ImportError:  # pragma: no cover
    def zak_tool(*args, **kwargs):  # type: ignore[return-value]
        def _decorator(fn):
            return fn
        return _decorator

    class ToolResult(dict):  # type: ignore[misc]
        @staticmethod
        def ok(data: Any) -> "ToolResult":
            return ToolResult({"status": "ok", "data": data})

        @staticmethod
        def error(msg: str) -> "ToolResult":
            return ToolResult({"status": "error", "message": msg})


# ─────────────────────────────────────────────────────────────────────────────

def _msg_to_dict(msg: Message, uid: str = "") -> dict:
    """Convert email.message.Message → plain dict for downstream tools."""
    return {
        "uid": uid,
        "subject": msg.get("Subject", ""),
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "return_path": msg.get("Return-Path", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "received_spf": msg.get("Received-SPF", ""),
        "authentication_results": msg.get("Authentication-Results", ""),
        "dkim_signature": msg.get("DKIM-Signature", ""),
        "raw_headers": dict(msg.items()),
        "body_preview": _body_preview(msg),
    }


def _body_preview(msg: Message, max_chars: int = 300) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    return payload.decode(errors="replace")[:max_chars]
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            return payload.decode(errors="replace")[:max_chars]
    return ""


# ─────────────────────────────────────────────────────────────────────────────
@zak_tool(
    action_id="ingest_email",
    description="Ingest emails from IMAP server, local .eml file, or raw RFC-2822 string.",
)
def ingest_email(
    source: str,
    imap_host: str = "",
    imap_port: int = 993,
    imap_user: str = "",
    imap_password: str = "",
    imap_folder: str = "INBOX",
    max_emails: int = 100,
    raw_eml: str = "",
    eml_path: str = "",
) -> ToolResult:
    """
    Parameters
    ----------
    source      : 'imap' | 'file' | 'raw'
    imap_*      : IMAP credentials (only for source='imap')
    raw_eml     : RFC-2822 string  (only for source='raw')
    eml_path    : path to .eml    (only for source='file')
    max_emails  : cap for IMAP fetch
    """
    try:
        emails: list[dict] = []

        if source == "raw":
            if not raw_eml:
                return ToolResult.error("raw_eml must be provided when source='raw'")
            msg = email.message_from_string(raw_eml)
            emails.append(_msg_to_dict(msg, uid="raw-0"))

        elif source == "file":
            if not eml_path or not os.path.exists(eml_path):
                return ToolResult.error(f"eml_path not found: {eml_path!r}")
            with open(eml_path, "rb") as fh:
                msg = email.message_from_bytes(fh.read())
            emails.append(_msg_to_dict(msg, uid=os.path.basename(eml_path)))

        elif source == "imap":
            if not all([imap_host, imap_user, imap_password]):
                return ToolResult.error(
                    "imap_host, imap_user, imap_password are required for IMAP source"
                )
            ctx = ssl.create_default_context()
            with imaplib.IMAP4_SSL(imap_host, imap_port, ssl_context=ctx) as conn:
                conn.login(imap_user, imap_password)
                conn.select(imap_folder, readonly=True)
                _, data = conn.search(None, "UNSEEN")
                uids = data[0].split()[-max_emails:]
                for uid in uids:
                    _, raw = conn.fetch(uid, "(RFC822)")
                    if raw and raw[0]:
                        raw_bytes: bytes = raw[0][1]  # type: ignore[index]
                        msg = email.message_from_bytes(raw_bytes)
                        emails.append(_msg_to_dict(msg, uid=uid.decode()))
        else:
            return ToolResult.error(f"Unknown source type: {source!r}. Use 'imap', 'file', or 'raw'.")

        return ToolResult.ok({
            "ingested_count": len(emails),
            "emails": emails,
        })

    except Exception as exc:  # noqa: BLE001
        return ToolResult.error(f"Email ingestion failed: {exc}")
