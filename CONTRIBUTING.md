# Contributing to McpVanguard

Thanks for taking the time to contribute. McpVanguard is a community project, and thoughtful bug reports, rules, tests, and documentation all help make MCP deployments safer.

## Ways to Contribute

### Write New Rules

While core filesystem isolation is handled deterministically via `safe_zones.yaml` and OS kernel features such as `openat2`, community rule contributions help expand Layer 1 signature coverage for malicious payloads and command injections.

1. Open the relevant `rules/*.yaml` file, or create a new one.
2. Add a new rule following the existing schema:

   ```yaml
   - id: "CAT-NNN"
     description: "Human readable description"
     severity: CRITICAL  # CRITICAL | HIGH | MEDIUM | LOW
     action: BLOCK       # BLOCK | WARN
     match_fields:
       - "params.arguments.path"
       - "params.arguments.command"
     pattern: "your_regex_here"
     message: "User-facing block reason"
   ```

3. Add a test case to `tests/test_rules.py`.
4. Run `pytest tests/test_rules.py -v` - all tests must pass.
5. Open a PR with the new rule and test.

### Report Bugs

Open a GitHub issue with:

- what you expected versus what happened
- minimal reproduction steps
- Python version and OS

### Report Security Vulnerabilities

Do not open a public issue for vulnerabilities. Email **contact@provnai.com** instead.

See [SECURITY.md](SECURITY.md) for the full disclosure policy.

### Improve Documentation

- fix typos
- improve clarity
- add examples where they help

Docs live in `docs/` and `README.md`.

## Development Setup

```bash
# 1. Fork and clone
git clone https://github.com/provnai/McpVanguard
cd McpVanguard

# 2. Create a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate

# 3. Install dependencies
pip install -e ".[dev]"

# 4. Run the full test suite
pytest tests/ -v
```

## Code Style

- **Python**: PEP 8, type hints where practical, docstrings on public methods where useful
- **YAML rules**: Follow the existing schema exactly - `id`, `description`, `severity`, `action`, `match_fields`, `pattern`, `message`
- **Tests**: Every new rule should include both a block case and an allow case

## Pull Request Checklist

- [ ] `pytest tests/ -v` passes
- [ ] new rules include both block and allow test cases
- [ ] no sensitive data is included in the PR
- [ ] `CHANGELOG.md` is updated for user-facing changes

## Code of Conduct

- be respectful
- disclose bypass techniques responsibly so they can be fixed and documented safely

## Questions

Open a GitHub Discussion or file an issue with the `question` label.
