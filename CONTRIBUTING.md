# Contributing to McpVanguard

First off — thanks for taking the time to contribute! McpVanguard is a community project. Every validated exploit makes MCP safer for everyone.

## Ways to Contribute

### 🏹 Hunt Exploits (The Gauntlet)
The best way to contribute is to find real security gaps:

1. Clone the repo and `pip install -r requirements.txt`
2. Run a challenge: `python arena/hunter.py 1 --handle your-github`
3. Find a bypass, collect your Proof of Exploit bundle
4. Submit via GitHub issue with the `exploit-submission` label
5. GitHub Actions auto-validates — you earn points on the leaderboard!

See the [Vanguard Dashboard](https://vanguard.provnai.com) for all active challenges.

### 🛡️ Write New Rules
Add Layer 1 rules to catch new attack patterns:

1. Open the relevant `rules/*.yaml` file (or create a new one)
2. Add a new rule following the schema:
   ```yaml
   - id: "CAT-NNN"
     description: "Human readable description"
     severity: CRITICAL  # CRITICAL | HIGH | MEDIUM | LOW
     action: BLOCK       # BLOCK | WARN
     match_fields:
       - "params.arguments.path"
       - "params.arguments.command"
     pattern: 'your_regex_here'
   ```
3. Add a test case to `tests/test_rules.py`
4. Run `pytest tests/test_rules.py -v` — all tests must pass
5. Open a PR with the new rule + test

### 🐛 Report Bugs
Open a GitHub issue with:
- What you expected vs what happened
- Minimal reproduction steps
- Python version and OS

### 📚 Improve Documentation
- Fix typos, improve clarity, add examples
- All docs are in `docs/` (Markdown)

## Development Setup

```bash
1.  Fork the repository on GitHub: [https://github.com/provnai/McpVanguard](https://github.com/provnai/McpVanguard)
2.  Clone your fork locally: `git clone https://github.com/provnai/McpVanguard`
python -m venv .venv
.venv\Scripts\activate      # Windows
# or: source .venv/bin/activate  # Mac/Linux
pip install -r requirements.txt
pytest tests/ -v
```

## Code Style

- **Python**: PEP 8, type hints where practical, docstrings on all public methods
- **YAML rules**: Follow the existing schema exactly
- **Tests**: Every new rule needs a corresponding test — both a block case and an allow case

## Pull Request Checklist

- [ ] `pytest tests/ -v` passes (all green)
- [ ] New rules have both block and allow test cases
- [ ] No sensitive data in the PR (no real credentials, etc.)
- [ ] If adding a challenge level: include `SUCCESS_CONDITION`, hints, and `get_challenge_config()`

## Code of Conduct

- Be respectful
- No real exploits against production systems — Gauntlet challenges are sandboxed only
- Validated bypass techniques are disclosed responsibly (they become public rules)

## Questions?

Open a GitHub Discussion or file an issue with the `question` label.
