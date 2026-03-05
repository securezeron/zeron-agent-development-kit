# Changelog

## 0.1.3 (2026-03-05)

Initial open-source release of ZAK (Zeron Agentic Kit).

- 4 built-in agents: `risk_quant`, `vuln_triage`, `appsec`, `generic`
- US-ADSL YAML schema for declarative agent definitions
- Policy engine with 6 runtime guardrails
- Tool substrate with `@zak_tool` decorator
- Security Intelligence Fabric (SIF) graph integration
- CLI: `zak init`, `validate`, `run`, `agents`, `info`
- Multi-tenant namespace isolation
- LLM-powered ReAct reasoning mode (OpenAI, Anthropic, Google, Ollama)
