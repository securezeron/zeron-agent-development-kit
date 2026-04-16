# DomainShield Agent 🛡️

> AI-powered phishing detection ZAK agent that enforces **strict domain whitelisting** on incoming email — flagging, categorizing, and blocking any message from outside the approved domain list.

---

## Project Structure

```
phising/
├── agents/
│   └── domain-shield-agent.yaml        ← ZAK DSL contract
├── tools/
│   ├── __init__.py
│   ├── email_ingestion_tools.py        ← IMAP / file / raw ingestion
│   ├── domain_verification_tools.py   ← whitelist, SPF, DKIM, DMARC, IDN
│   ├── phishing_detection_tools.py    ← display-name spoof + risk classifier
│   ├── alerting_tools.py              ← alert generation + Slack/SIEM webhook
│   ├── logging_tools.py               ← JSONL audit log + CSV export
│   └── policy_tools.py                ← admin whitelist CRUD + config store
├── config/
│   ├── config.env.example             ← environment variable template
│   └── policy.json                    ← live whitelist policy store
├── tests/
│   └── test_domain_shield.py          ← pytest test suite (5 scenarios)
├── logs/                              ← auto-created audit logs (JSONL + CSV)
├── domain_shield_agent.py             ← BaseAgent class (9-phase pipeline)
├── run.py                             ← CLI entry point
├── requirements.txt
└── README.md
```

---

## Quick Start

### 1. Install dependencies
```powershell
pip install -r requirements.txt
```

### 2. Configure
```powershell
Copy-Item config\config.env.example config\config.env
# Edit config\config.env with your whitelist domains, IMAP credentials, etc.
```

### 3. Run – test with a raw email string
```powershell
python run.py --source raw --raw-eml "From: alice@company.com`r`nSubject: Hello`r`n`r`nBody"
```

### 4. Run – scan IMAP inbox
```powershell
python run.py --source imap
# (Credentials loaded from config/config.env)
```

### 5. JSON output mode
```powershell
python run.py --source raw --raw-eml "..." --json
```

---

## Sample Configuration

```env
WHITELIST_DOMAINS=company.com,trustedpartner.com
STRICT_MODE=true
ALERT_THRESHOLD=medium_and_above
WEBHOOK_URL=https://hooks.slack.com/services/your/webhook/url
WEBHOOK_FORMAT=slack
```

---

## Admin Commands

| Command | Description |
|---|---|
| `python run.py --admin add-domain --admin-arg partner.org` | Add domain to whitelist |
| `python run.py --admin remove-domain --admin-arg old.com` | Remove domain |
| `python run.py --admin list-policy` | Show current policy |
| `python run.py --admin export-log` | Export audit log to CSV |
| `python run.py --admin set-strict --admin-arg true` | Enable strict mode |
| `python run.py --admin set-threshold --admin-arg high_only` | Change alert threshold |

---

## Risk Classification

| Risk Level | Trigger | Action (strict mode) |
|---|---|---|
| `SAFE` | Whitelisted domain + all auth checks pass | `ALLOW` |
| `MEDIUM_RISK` | External domain not in whitelist | `BLOCK` |
| `HIGH_RISK` | Spoofing / auth failure / subdomain hijack | `BLOCK` |

---

## Detection Signals

1. **Domain Whitelist** – exact domain match (subdomains require explicit listing)
2. **SPF Alignment** – `Received-SPF` + `Authentication-Results` parsing
3. **DKIM Alignment** – signing domain vs. `From:` header
4. **DMARC** – policy outcome from `Authentication-Results`
5. **Display-Name Spoof** – fuzzy match against whitelisted org names + 20+ known brands
6. **Subdomain Spoof** – detects `evil.company.com` bypassing `company.com`
7. **IDN Normalization** – punycode decode prevents Unicode look-alike bypass

---

## Running Tests

```powershell
python -m pytest tests/ -v
python -m pytest tests/ -v --tb=short --cov=tools --cov=domain_shield_agent
```

### Test Scenarios

| Test | Email | Expected |
|---|---|---|
| `TestValidInternalEmail` | `alice@company.com` + all auth pass | `SAFE` / no alert |
| `TestSpoofedDomainEmail` | Display name "Company IT" + `evil-company.net` + auth fail | `HIGH_RISK` / `BLOCK` |
| `TestExternalUnknownDomain` | `newsletter@external-vendor.io` (good auth) | `MEDIUM_RISK` / alert |
| `TestSubdomainSpoof` | `phish@mail.evil.company.com` | `HIGH_RISK` |
| `TestWhitelistedDomainAuthFailure` | `ceo@company.com` + SPF/DKIM/DMARC all fail | `HIGH_RISK` |

---

## Integration Points

| System | How |
|---|---|
| **IMAP / Exchange** | `source=imap` via `imaplib` (SSL) |
| **Slack** | `WEBHOOK_FORMAT=slack` → Block Kit payload |
| **SIEM / generic** | `WEBHOOK_FORMAT=generic` → raw JSON POST |
| **ZAK Platform** | `agents/domain-shield-agent.yaml` + `register_agent` decorator |

---

## Security Notes

- **No whitelist inheritance** – `mail.company.com` is NOT trusted unless explicitly added
- **IDN/Punycode** – domains normalized before comparison to prevent homograph attacks
- **Auth failure on whitelisted domain** → escalated to `HIGH_RISK` (possible internal spoofing)
- **Audit logs** – append-only JSONL; never delete email content
- **Strict mode** – set `STRICT_MODE=false` only to downgrade blocking to warnings

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | All emails safe |
| `2` | One or more suspicious emails detected |
| `1` | Fatal error (misconfiguration, ingestion failure) |
