# Prompt Injection Tester Agent

> Test **any AI system** — OpenAI, Anthropic, Ollama (local or remote), HuggingFace, or any HTTP chatbot — for prompt injection vulnerabilities using a multi-phase AI red team approach. Built on [ZAK open-source](https://github.com/securezeron/zeron-agent-development-kit).

---

## Two Versions

| | v1 — Quick Scan | v2 — Deep Red Team |
|---|---|---|
| **File** | `prompt-injection-tester-agent.yaml` | `pit-v2-agent.yaml` |
| **Phases** | Single phase | 4 phases |
| **Payloads** | 24 basic | 69 static + 25 mutations per vuln |
| **Canary tokens** | No | Yes — zero false positives |
| **Mutation fuzzer** | No | Yes — 5 techniques, 25 variants |
| **Target profiling** | No | Yes — Phase 0 |
| **Rate limit protection** | No | Yes — backoff + WAF evasion |
| **Report** | PDF | PDF (multi-phase) |
| **Run time** | ~10 mins | ~15-60 mins |
| **Use case** | Daily checks | Full security audit |

---

## Prerequisites

```bash
pip install zin-adk reportlab      # ZAK framework + PDF generation
ollama pull lfm2.5-thinking        # judge model (local, required)
ollama pull llama3                 # target model (only if testing local Ollama)
ollama serve
```

---

## v1 — Quick Scan

### Test local Ollama
```bash
zak run my_agents/prompt-injection-tester-agent.yaml \
    --tenant security-team \
    -m provider=ollama \
    -m target_model=llama3 \
    -m judge_model=lfm2.5-thinking:latest \
    -m target_desc="Local LLM"
```

### Test OpenAI
```bash
zak run my_agents/prompt-injection-tester-agent.yaml \
    --tenant security-team \
    -m provider=openai \
    -m api_key=sk-proj-YOURKEY \
    -m target_model=gpt-4o \
    -m judge_model=lfm2.5-thinking:latest \
    -m target_desc="Company GPT-4o"
```

### Test Anthropic Claude
```bash
zak run my_agents/prompt-injection-tester-agent.yaml \
    --tenant security-team \
    -m provider=anthropic \
    -m api_key=sk-ant-YOURKEY \
    -m target_model=claude-haiku-4-5-20251001 \
    -m judge_model=lfm2.5-thinking:latest \
    -m target_desc="Company Claude"
```

### Test remote Ollama (ngrok or private IP)
```bash
zak run my_agents/prompt-injection-tester-agent.yaml \
    --tenant security-team \
    -m provider=ollama \
    -m ollama_host=https://abc123.ngrok-free.app \
    -m target_model=tinyllama \
    -m judge_model=lfm2.5-thinking:latest \
    -m target_desc="Remote Team LLM"
```

### Test any HTTP chatbot
```bash
zak run my_agents/prompt-injection-tester-agent.yaml \
    --tenant security-team \
    -m provider=http \
    -m target_url=https://your-chatbot.com/api/chat \
    -m response_field=reply \
    -m auth_header="Authorization: Bearer TOKEN" \
    -m judge_model=lfm2.5-thinking:latest \
    -m target_desc="Production Chatbot"
```

---

## v2 — Deep Red Team Audit

### Test local Ollama
```bash
zak run my_agents/pit-v2-agent.yaml \
    --tenant security-team \
    -m provider=ollama \
    -m target_model=llama3 \
    -m judge_model=lfm2.5-thinking:latest \
    -m target_desc="llama3 Deep Red Team Audit v2"
```

### Test OpenAI GPT-4o
```bash
zak run my_agents/pit-v2-agent.yaml \
    --tenant security-team \
    -m provider=openai \
    -m api_key=sk-proj-YOURKEY \
    -m target_model=gpt-4o \
    -m judge_model=lfm2.5-thinking:latest \
    -m target_desc="GPT-4o Deep Red Team Audit v2"
```

### Test Anthropic Claude
```bash
zak run my_agents/pit-v2-agent.yaml \
    --tenant security-team \
    -m provider=anthropic \
    -m api_key=sk-ant-YOURKEY \
    -m target_model=claude-haiku-4-5-20251001 \
    -m judge_model=lfm2.5-thinking:latest \
    -m target_desc="Claude Haiku Deep Red Team Audit v2"
```

### Test HuggingFace model
```bash
zak run my_agents/pit-v2-agent.yaml \
    --tenant security-team \
    -m provider=huggingface \
    -m api_key=hf_YOURTOKEN \
    -m hf_model=meta-llama/Llama-3.1-8B-Instruct:cerebras \
    -m judge_model=lfm2.5-thinking:latest \
    -m target_desc="HuggingFace Llama-3.1-8B Audit v2"
```

### Test remote Ollama (ngrok)
```bash
zak run my_agents/pit-v2-agent.yaml \
    --tenant security-team \
    -m provider=ollama \
    -m ollama_host=https://abc123.ngrok-free.app \
    -m target_model=tinyllama \
    -m judge_model=lfm2.5-thinking:latest \
    -m target_desc="Remote TinyLlama Audit v2"
```

### Test remote Ollama (private IP)
```bash
zak run my_agents/pit-v2-agent.yaml \
    --tenant security-team \
    -m provider=ollama \
    -m ollama_host=http://192.168.1.50:11434 \
    -m target_model=llama3 \
    -m judge_model=lfm2.5-thinking:latest \
    -m target_desc="Team Server Audit v2"
```

---

## All `-m` parameters

| Parameter | Default | Description |
|---|---|---|
| `provider` | `ollama` | `openai` \| `anthropic` \| `ollama` \| `http` \| `huggingface` |
| `api_key` | — | API key for openai, anthropic, or huggingface |
| `target_model` | `llama3` | Model name for the target |
| `hf_model` | `meta-llama/Llama-3.1-8B-Instruct:cerebras` | HuggingFace model with provider suffix |
| `ollama_host` | `http://localhost:11434` | Ollama server URL (local or remote) |
| `target_url` | — | Full URL for `http` provider |
| `request_field` | `message` | JSON field to inject into (http) |
| `response_field` | `reply` | JSON field to read from (http) |
| `auth_header` | — | e.g. `Authorization: Bearer TOKEN` |
| `target_desc` | `AI Target System` | Name shown in report (also PDF filename) |
| `system_prompt` | `You are a helpful assistant.` | System prompt for the target |
| `judge_model` | `lfm2.5-thinking:latest` | Local Ollama judge model |
| `judge_host` | `http://localhost:11434` | Ollama host for judge |
| `categories` | all | Comma-separated Phase 2 categories (v2 only) |

---

## v2 Attack Phases

### Phase 0 — Target Profiling
Probes target to detect capabilities before attacking.
Detects: `file_upload`, `web_search`, `memory`, `code_execution`, `data_access`.

### Phase 1 — Basic Scan (24 payloads)

| Category | Payloads | What it tests |
|---|---|---|
| `system_prompt_leak` | 5 | Can attacker extract your system prompt? |
| `instruction_override` | 4 | Can attacker override your instructions? |
| `rag_indirect_injection` | 5 | Are document/email injections dangerous? |
| `role_hijack` | 3 | Can model be jailbroken into unrestricted mode? |
| `data_exfiltration` | 4 | Can attacker extract internal data? |
| `delimiter_confusion` | 3 | Can spoofed tokens inject fake system messages? |

### Phase 2 — Specialist Tools (45 payloads)

| Tool | Payloads | Technique |
|---|---|---|
| `fuzz_json_injection` | 8 | JSON/XML structural attacks, __proto__ injection |
| `fuzz_encoding_bypass` | 7 | Base64, Hex, ROT13, URL encoding, leetspeak |
| `fuzz_token_smuggling` | 8 | Zero-width spaces, homoglyphs, hyphen splits |
| `fuzz_multilingual` | 8 | Hindi, Arabic, Chinese, Russian payloads |
| `fuzz_fictional_framing` | 8 | Story, academic, debug terminal framing |
| `fuzz_chain_of_thought` | 6 | Reasoning manipulation via logical syllogisms |

### Phase 3 — Mutation Fuzzer (25 variants per vulnerable payload)
5 mutation techniques applied automatically:
1. **Encoding** — Base64, Hex, ROT13, URL, Double-Base64
2. **Token smuggling** — Zero-width spaces, hyphen split, reverse, random case
3. **Contextual framing** — Debug terminal, story, academic, maintenance mode
4. **Payload splitting** — Two-part, numbered steps, word game
5. **Markdown masking** — Code blocks, tables, HTML comments, JSON, YAML

### Phase 4 — PDF Report
Professional multi-phase PDF with all findings and recommendations.

---

## Canary Token System

Every payload has a unique verification token appended:
```
ZAK-PH1-B34C0N  →  Phase 1 basic scan
ZAK-PH2-B34C0N  →  Phase 2 specialist tools
ZAK-PH3-B34C0N  →  Phase 3 mutation fuzzer
```
If canary appears in response → **100% confirmed VULNERABLE** — instant, zero false positives.

---

**Key finding:** Even GPT-4o showed HIGH risk with 20 confirmed bypass techniques found by the mutation fuzzer. Multilingual attacks bypassed ALL models tested.

---

## Architecture

```
Your machine                          Target (anywhere)
────────────────────────────          ──────────────────────────────
ZAK Agent v2 (orchestrator)  → HTTP  OpenAI / Anthropic / Ollama
  Phase 0: profile_target             HuggingFace / HTTP chatbot
  Phase 1: fire_probe_v2              Remote Ollama via ngrok
  Phase 2: fuzz_* tools               Private IP Ollama
  Phase 3: deep_fuzz_target
  Phase 4: generate_pdf_report_v2
lfm2.5-thinking (judge)      ←        reads responses locally
PDF report saved locally
```

---

## File Structure

```
my_agents/
├── prompt-injection-tester-agent.yaml   # v1 ZAK DSL
├── prompt_injection_tester_agent.py     # v1 agent — quick scan
├── pit-v2-agent.yaml                    # v2 ZAK DSL
├── pit_v2_agent.py                      # v2 agent — deep red team
├── payloads.py                          # v1 payload library (24 payloads)
├── payloads_v2.py                       # v2 payload library (69 + fuzzer)
└── README.md
```

---

## Remote Ollama Setup

### Via ngrok (different networks):
```bash
# On target machine
OLLAMA_HOST=0.0.0.0 ollama serve         # Linux/Mac
$env:OLLAMA_HOST="0.0.0.0"; ollama serve  # Windows PowerShell

ngrok http 11434
# Use forwarding URL: -m ollama_host=https://abc123.ngrok-free.app
```

### Via private IP (same network):
```bash
# Find IP: hostname -I (Linux) or ipconfig (Windows)
# Use: -m ollama_host=http://192.168.1.XXX:11434
```

---

## License
Apache 2.0 — ZAK open-source edition
