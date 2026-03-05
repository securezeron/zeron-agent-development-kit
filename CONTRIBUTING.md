# Contributing to ZAK

Thank you for your interest in contributing to ZAK!

## Getting Started

```bash
git clone https://github.com/securezeron/zak.git
cd zak
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v
```

## Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `pytest tests/ -v`
5. Run linting: `ruff check zak/`
6. Submit a pull request

## Code Style

- We use [Ruff](https://docs.astral.sh/ruff/) for linting (line length: 100)
- Type hints are required for all public functions
- Tests go in `tests/unit/`

## Adding a New Agent

```bash
zak init --name "My Agent" --domain risk_quant --out ./agents
```

See the [Building Agents](https://securezeron.github.io/zak/03_building_agents/) guide.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
