"""
Admin Policy Controller – DomainShield Agent
Persists whitelist and agent config to a local JSON policy store.
"""

from __future__ import annotations

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


_DEFAULT_POLICY_PATH = os.path.join(
    os.path.dirname(__file__), "..", "config", "policy.json"
)

_DEFAULT_POLICY: dict = {
    "whitelist_domains": ["company.com", "trustedpartner.com"],
    "strict_mode": True,
    "alert_threshold": "medium_and_above",
    "webhook_url": "",
    "last_modified": "",
    "modified_by": "system",
}


def _load_policy(policy_path: str) -> dict:
    if os.path.exists(policy_path):
        with open(policy_path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return dict(_DEFAULT_POLICY)


def _save_policy(policy: dict, policy_path: str) -> None:
    os.makedirs(os.path.dirname(policy_path), exist_ok=True)
    policy["last_modified"] = datetime.now(timezone.utc).isoformat()
    with open(policy_path, "w", encoding="utf-8") as fh:
        json.dump(policy, fh, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
@zak_tool(
    action_id="manage_whitelist",
    description="Add, remove, or list domains in the approved whitelist policy store.",
)
def manage_whitelist(
    operation: str,
    domain: str = "",
    policy_path: str = "",
    modified_by: str = "admin",
) -> ToolResult:
    """
    Parameters
    ----------
    operation  : 'add' | 'remove' | 'list' | 'set_strict_mode' | 'set_alert_threshold'
    domain     : domain to add/remove (or True/False for set_strict_mode, threshold value)
    policy_path: override default config/policy.json path
    """
    try:
        path = os.path.abspath(policy_path or _DEFAULT_POLICY_PATH)
        policy = _load_policy(path)

        if operation == "list":
            return ToolResult.ok({
                "whitelist_domains": policy.get("whitelist_domains", []),
                "strict_mode": policy.get("strict_mode", True),
                "alert_threshold": policy.get("alert_threshold", "medium_and_above"),
                "last_modified": policy.get("last_modified", ""),
            })

        elif operation == "add":
            if not domain:
                return ToolResult.error("domain is required for operation='add'")
            normalized = domain.strip().lower()
            wl: list = policy.setdefault("whitelist_domains", [])
            if normalized in wl:
                return ToolResult.ok({"message": f"'{normalized}' already in whitelist", "whitelist_domains": wl})
            wl.append(normalized)
            policy["modified_by"] = modified_by
            _save_policy(policy, path)
            return ToolResult.ok({"added": normalized, "whitelist_domains": wl})

        elif operation == "remove":
            if not domain:
                return ToolResult.error("domain is required for operation='remove'")
            normalized = domain.strip().lower()
            wl = policy.get("whitelist_domains", [])
            if normalized not in wl:
                return ToolResult.ok({"message": f"'{normalized}' not in whitelist", "whitelist_domains": wl})
            wl.remove(normalized)
            policy["modified_by"] = modified_by
            _save_policy(policy, path)
            return ToolResult.ok({"removed": normalized, "whitelist_domains": wl})

        elif operation == "set_strict_mode":
            value = domain.strip().lower() in ("true", "1", "yes", "on")
            policy["strict_mode"] = value
            policy["modified_by"] = modified_by
            _save_policy(policy, path)
            return ToolResult.ok({"strict_mode": value})

        elif operation == "set_alert_threshold":
            valid = ("high_only", "medium_and_above", "all")
            if domain not in valid:
                return ToolResult.error(f"alert_threshold must be one of {valid}")
            policy["alert_threshold"] = domain
            policy["modified_by"] = modified_by
            _save_policy(policy, path)
            return ToolResult.ok({"alert_threshold": domain})

        else:
            return ToolResult.error(
                f"Unknown operation '{operation}'. "
                "Use: add | remove | list | set_strict_mode | set_alert_threshold"
            )

    except Exception as exc:
        return ToolResult.error(f"manage_whitelist failed: {exc}")
