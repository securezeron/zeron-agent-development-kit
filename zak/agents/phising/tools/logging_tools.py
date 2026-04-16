"""
Logging & Audit Module – DomainShield Agent
Persists email processing events to a JSONL audit log and supports CSV export.
"""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime, timezone
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


_DEFAULT_LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs")


def _ensure_log_dir(log_dir: str) -> str:
    path = os.path.abspath(log_dir)
    os.makedirs(path, exist_ok=True)
    return path


# ─────────────────────────────────────────────────────────────────────────────
@zak_tool(
    action_id="log_email_event",
    description="Append a single email processing event to the JSONL audit log.",
)
def log_email_event(
    email_uid: str,
    subject: str,
    from_raw: str,
    from_domain: str,
    risk_level: str,
    action: str,
    reasons: list,
    alert_id: str = "",
    log_dir: str = "",
) -> ToolResult:
    try:
        log_dir = _ensure_log_dir(log_dir or _DEFAULT_LOG_DIR)
        log_file = os.path.join(log_dir, "audit.jsonl")

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "email_uid": email_uid,
            "subject": subject,
            "from_raw": from_raw,
            "from_domain": from_domain,
            "risk_level": risk_level,
            "action": action,
            "reasons": reasons,
            "alert_id": alert_id,
        }

        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")

        # Sync live data to the UI dashboard automatically
        try:
            records = []
            with open(log_file, "r", encoding="utf-8") as rf:
                for line in rf:
                    line = line.strip()
                    if line:
                        records.append(json.loads(line))
                        
            js_emails_list = []
            for r in reversed(records[-100:]):
                js_emails_list.append({
                    "uid": r.get("email_uid"),
                    "from_raw": r.get("from_raw", ""),
                    "from_domain": r.get("from_domain", ""),
                    "display_name": r.get("from_raw", "").split("<")[0].strip().replace('"', ''),
                    "subject": r.get("subject", ""),
                    "date": r.get("timestamp", "")[:16].replace("T", " "),
                    "risk_level": r.get("risk_level", "SAFE"),
                    "action": r.get("action", "ALLOW"),
                    "reasons": r.get("reasons", []),
                    "flags": {},
                    "spf_pass": "SPF" not in str(r.get("reasons", [])),
                    "dkim_pass": "DKIM" not in str(r.get("reasons", [])),
                    "dmarc_pass": "DMARC" not in str(r.get("reasons", [])),
                    "in_whitelist": "whitelist" not in str(r.get("reasons", [])).lower(),
                    "body_preview": "No preview available for security reasons."
                })
                
            ui_js_path = os.path.join(log_dir, "..", "ui", "data.js")
            os.makedirs(os.path.dirname(ui_js_path), exist_ok=True)
            with open(ui_js_path, "w", encoding="utf-8") as jsf:
                jsf.write(f"window.LIVE_EMAILS = {json.dumps(js_emails_list, indent=2)};\n")
        except Exception:
            pass

        return ToolResult.ok({
            "logged": True,
            "log_file": log_file,
            "record": record,
        })

    except Exception as exc:
        return ToolResult.error(f"log_email_event failed: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
@zak_tool(
    action_id="export_audit_log",
    description="Export the JSONL audit log to a CSV file for compliance review.",
)
def export_audit_log(
    log_dir: str = "",
    export_format: str = "csv",
    filter_risk_level: str = "",
) -> ToolResult:
    """
    Parameters
    ----------
    filter_risk_level : '' (all) | 'SAFE' | 'MEDIUM_RISK' | 'HIGH_RISK'
    export_format     : 'csv' (future: 'json')
    """
    try:
        log_dir = _ensure_log_dir(log_dir or _DEFAULT_LOG_DIR)
        log_file = os.path.join(log_dir, "audit.jsonl")

        if not os.path.exists(log_file):
            return ToolResult.error(f"Audit log not found: {log_file}")

        records: list[dict] = []
        with open(log_file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

        if filter_risk_level:
            records = [r for r in records if r.get("risk_level") == filter_risk_level]

        if export_format == "csv":
            export_path = os.path.join(log_dir, f"audit_export_{_ts_slug()}.csv")
            _write_csv(records, export_path)
            return ToolResult.ok({
                "exported": True,
                "record_count": len(records),
                "export_path": export_path,
                "filter_applied": filter_risk_level or "none",
            })

        # default JSON return
        return ToolResult.ok({
            "exported": False,
            "records": records,
            "record_count": len(records),
        })

    except Exception as exc:
        return ToolResult.error(f"export_audit_log failed: {exc}")


def _ts_slug() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _write_csv(records: list[dict], path: str) -> None:
    if not records:
        with open(path, "w", newline="", encoding="utf-8") as fh:
            fh.write("No records found\n")
        return
    fieldnames = [
        "timestamp", "email_uid", "from_raw", "from_domain",
        "subject", "risk_level", "action", "alert_id", "reasons",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for rec in records:
            row = dict(rec)
            row["reasons"] = " | ".join(rec.get("reasons", []))
            writer.writerow(row)
