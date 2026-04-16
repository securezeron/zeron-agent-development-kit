"""
DomainShield Agent – CLI Entry Point
Usage:
    python run.py --help
    python run.py --source raw --raw-eml "From: attacker@evil.com\r\nSubject: Test"
    python run.py --source imap --imap-host mail.company.com --imap-user user@company.com
    python run.py --admin add-domain partner.org
    python run.py --admin remove-domain partner.org
    python run.py --admin export-log
"""

from __future__ import annotations

import argparse
import json
import os
import sys

# Ensure project root is on PYTHONPATH
sys.path.insert(0, os.path.dirname(__file__))

from domain_shield_agent import DomainShieldAgent, AgentContext, AgentResult


def _load_env() -> dict:
    """Load configuration from environment variables (optionally .env file)."""
    env_file = os.path.join(os.path.dirname(__file__), "config", "config.env")
    if os.path.exists(env_file):
        with open(env_file) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    os.environ.setdefault(k.strip(), v.strip())

    return {
        "whitelist_domains": [
            d.strip()
            for d in os.getenv("WHITELIST_DOMAINS", "company.com,trustedpartner.com").split(",")
            if d.strip()
        ],
        "strict_mode": os.getenv("STRICT_MODE", "true").lower() == "true",
        "alert_threshold": os.getenv("ALERT_THRESHOLD", "medium_and_above"),
        "webhook_url": os.getenv("WEBHOOK_URL", ""),
        "webhook_format": os.getenv("WEBHOOK_FORMAT", "generic"),
        "imap_host": os.getenv("IMAP_HOST", ""),
        "imap_port": int(os.getenv("IMAP_PORT", "993")),
        "imap_user": os.getenv("IMAP_USER", ""),
        "imap_password": os.getenv("IMAP_PASSWORD", ""),
        "imap_folder": os.getenv("IMAP_FOLDER", "INBOX"),
        "max_emails": int(os.getenv("MAX_EMAILS", "100")),
    }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="DomainShield",
        description="AI-powered phishing detection agent (ZAK-based).",
    )
    p.add_argument("--source", choices=["imap", "file", "raw"], default="raw",
                   help="Email source type (default: raw)")
    p.add_argument("--raw-eml", default="", metavar="EML",
                   help="Raw RFC-2822 email string (for --source raw)")
    p.add_argument("--eml-path", default="", metavar="PATH",
                   help="Path to .eml file (for --source file)")
    p.add_argument("--whitelist", nargs="+", metavar="DOMAIN",
                   help="Override whitelist domains (space-separated)")
    p.add_argument("--no-strict", action="store_true",
                   help="Disable strict mode (warn instead of block)")
    p.add_argument("--alert-threshold",
                   choices=["high_only", "medium_and_above", "all"],
                   help="Alert sensitivity level")
    p.add_argument("--webhook-url", metavar="URL",
                   help="Webhook URL for alert forwarding")

    # Admin sub-commands
    p.add_argument("--admin", metavar="CMD",
                   help="Admin command: add-domain, remove-domain, list-policy, export-log")
    p.add_argument("--admin-arg", metavar="ARG", default="",
                   help="Argument for the admin command (e.g. domain name)")
    p.add_argument("--json", action="store_true", dest="output_json",
                   help="Output results as JSON")
    return p


def handle_admin(cmd: str, arg: str, output_json: bool) -> None:
    from tools.policy_tools import manage_whitelist
    from tools.logging_tools import export_audit_log

    if cmd == "add-domain":
        result = manage_whitelist(operation="add", domain=arg)
    elif cmd == "remove-domain":
        result = manage_whitelist(operation="remove", domain=arg)
    elif cmd == "list-policy":
        result = manage_whitelist(operation="list")
    elif cmd == "export-log":
        result = export_audit_log()
    elif cmd == "set-strict":
        result = manage_whitelist(operation="set_strict_mode", domain=arg)
    elif cmd == "set-threshold":
        result = manage_whitelist(operation="set_alert_threshold", domain=arg)
    else:
        print(f"Unknown admin command: {cmd!r}")
        print("Available: add-domain, remove-domain, list-policy, export-log, set-strict, set-threshold")
        sys.exit(1)

    _print_result(result, output_json)


def _print_result(result: dict, output_json: bool) -> None:
    if output_json:
        print(json.dumps(result, indent=2, default=str))
        return

    status = result.get("status", "ok")
    data = result.get("data", result)
    if status == "error":
        print(f"[ERROR] {result.get('message', result)}")
        return

    # Pretty summary
    if isinstance(data, dict):
        for k, v in data.items():
            if isinstance(v, list) and len(v) > 5:
                print(f"  {k}: [{len(v)} items]")
            else:
                print(f"  {k}: {v}")
    else:
        print(data)


def _dump_ui_config(env_vars: dict) -> None:
    try:
        import os
        import json
        os.makedirs(os.path.join(os.path.dirname(__file__), "ui"), exist_ok=True)
        conf_path = os.path.join(os.path.dirname(__file__), "ui", "config.js")
        with open(conf_path, "w", encoding="utf-8") as f:
            f.write(f"window.LIVE_WHITELIST = {json.dumps(env_vars['whitelist_domains'])};\n")
            f.write(f"window.LIVE_STRICT_MODE = {str(env_vars['strict_mode']).lower()};\n")
    except Exception:
        pass


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    env = _load_env()
    
    _dump_ui_config(env)

    # ── Admin commands ────────────────────────────────────────────────
    if args.admin:
        handle_admin(args.admin, args.admin_arg, args.output_json)
        return

    # ── Build context ─────────────────────────────────────────────────
    context_inputs = {
        "source": args.source,
        "raw_eml": args.raw_eml,
        "eml_path": args.eml_path,
        "whitelist_domains": args.whitelist or env["whitelist_domains"],
        "strict_mode": not args.no_strict if args.no_strict else env["strict_mode"],
        "alert_threshold": args.alert_threshold or env["alert_threshold"],
        "webhook_url": args.webhook_url or env["webhook_url"],
        "webhook_format": env["webhook_format"],
        "imap_host": env["imap_host"],
        "imap_port": env["imap_port"],
        "imap_user": env["imap_user"],
        "imap_password": env["imap_password"],
        "imap_folder": env["imap_folder"],
        "max_emails": env["max_emails"],
    }

    # ── Run agent ─────────────────────────────────────────────────────
    agent = DomainShieldAgent()
    ctx = AgentContext(inputs=context_inputs)

    print("\n[+] DomainShield Agent - Starting email scan...\n")
    result = agent.execute(ctx)
    print()
    _print_result(result, args.output_json)

    # Exit non-zero if any suspicious emails found
    data = result.get("data", result)
    if isinstance(data, dict) and data.get("suspicious_count", 0) > 0:
        sys.exit(2)


if __name__ == "__main__":
    main()
