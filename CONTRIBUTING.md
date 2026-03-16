# Contributing to McpVanguard

First off — thanks for taking the time to contribute! McpVanguard is a community project. Every validated exploit makes MCP safer for everyone.

## Ways to Contribute

### Write New Rules
While core filesystem isolation is handled deterministically via `safe_zones.yaml` and OS kernel features (`openat2`), we rely on the community to build Layer 1 regex signatures to catch malicious payloads and command injections.

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
     message: "User-facing block reason"
   ```
3. Add a test case to `tests/test_rules.py`
4. Run `pytest tests/test_rules.py -v` — all tests must pass
5. Open a PR with the new rule + test

### Report Bugs (Issue Tracker)
Open a GitHub issue with:
- What you expected vs what happened
- Minimal reproduction steps
- Python version and OS

### Report Security Vulnerabilities
**Do NOT open a public issue.** Email **contact@provnai.com** instead.
See [SECURITY.md](SECURITY.md) for the full disclosure policy.

### Documentation Standards
- Fix typos, improve clarity, add examples
- Docs live in `docs/` and `README.md`

---

## Development Setup

```bash
# 1. Fork and clone
git clone https://github.com/provnai/McpVanguard
cd McpVanguard

# 2. Create a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Mac/Linux:
source .venv/bin/activate

# 3. Install dependencies
pip install -e ".[dev]"

# 4. Run the full test suite
pytest tests/ -v
```

---

## Code Style

- **Python**: PEP 8, type hints where practical, docstrings on all public methods
- **YAML rules**: Follow the existing schema exactly — `id`, `description`, `severity`, `action`, `match_fields`, `pattern`, `message`
- **Tests**: Every new rule needs a corresponding test — both a block case and an allow case

---

## Pull Request Checklist

- [ ] `pytest tests/ -v` passes (all green)
- [ ] New rules have both block and allow test cases
- [ ] No sensitive data in the PR (no real credentials, etc.)
- [ ] `CHANGELOG.md` updated for any user-facing changes

---

## Code of Conduct

- Be respectful
- Validated bypass techniques should be disclosed responsibly so they can become public rules

## Questions?

Open a GitHub Discussion or file an issue with the `question` label.
