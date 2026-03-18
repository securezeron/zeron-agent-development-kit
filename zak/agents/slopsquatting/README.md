# Slopsquatting Detector Agent

## The Problem

When developers use AI coding assistants (ChatGPT, Copilot, etc.), the LLM sometimes **hallucinate package names** that don't actually exist. For example, it might suggest `import fastauth` when no such PyPI package exists.

Attackers exploit this by:

1. Identifying commonly hallucinated package names
2. **Pre-registering** those names on PyPI/npm with malicious code
3. Waiting for developers to `pip install` or `npm install` the hallucinated package

The developer trusts the AI's suggestion, installs the package, and unknowingly runs malicious code. This is a supply chain attack that specifically targets AI-assisted development workflows.

## What the Agent Does

The Slopsquatting Detector scans source code files through a 4-step pipeline:

1. **`read_local_code_file`** — reads the target source file
2. **`extract_imports`** — parses all `import`/`require` statements, filtering out stdlib and builtins
3. **`check_pypi_package`** / **`check_npm_package`** — verifies each package against the real registry

Each package is classified as:

| Status | Meaning |
|---|---|
| **phantom** | Does not exist on the registry (likely hallucinated) |
| **suspicious** | Exists but was created less than 30 days ago (could be a pre-registered trap) |
| **verified** | Exists and is well-established |

## Supported Languages

- **Python** — parses `import X` and `from X import Y`, filters Python stdlib
- **JavaScript / TypeScript** — parses `require('X')` and `import ... from 'X'`, filters Node.js builtins and relative imports

## Usage

```bash
# Scan the demo file (default target)
zak run zak/agents/slopsquatting/slopsquatting-detector.yaml --tenant acme

# Scan a specific file
zak run zak/agents/slopsquatting/slopsquatting-detector.yaml --tenant acme --meta target_file=path/to/file.py
```

### Requirements

- An OpenAI API key (`OPENAI_API_KEY` environment variable) — the agent uses `gpt-4o` for reasoning
- Install with LLM support: `pip install -e ".[llm]"`

## Demo

The included [`demo/slopsquatting-demo.py`](../../../demo/slopsquatting-demo.py) contains a mix of real and hallucinated packages:

**Real packages:** `requests`, `flask`, `pandas`, `cryptography`

**Phantom packages:** `fastauth`, `cloudstoragelib`, `dataprocessorx`, `securevaultpython`, `ailoggingutil`

## Output

The agent produces a structured JSON report containing:

```json
{
  "file_scanned": "demo/slopsquatting-demo.py",
  "language": "python",
  "total_imports": 9,
  "phantom_packages": ["fastauth", "cloudstoragelib", "dataprocessorx", "securevaultpython", "ailoggingutil"],
  "suspicious_packages": [],
  "verified_packages": ["requests", "flask", "pandas", "cryptography"],
  "risk_assessment": "critical",
  "summary": "5 out of 9 imported packages do not exist on PyPI."
}
```

## Architecture

- **Agent class:** `SlopsquattingDetectorAgent` (subclass of `LLMAgent`)
- **Domain:** `supply_chain`
- **Tools:** defined in `tools.py` — `extract_imports`, `check_pypi_package`, `check_npm_package`
- **YAML DSL:** `slopsquatting-detector.yaml`
- **Reasoning mode:** `llm_react` with bounded autonomy
