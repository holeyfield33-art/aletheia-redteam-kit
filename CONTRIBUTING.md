# Contributing to Aletheia Red-Team Kit

Thank you for your interest in contributing! This guide will help you get started.

## Getting Started

### Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/holeyfield33-art/aletheia-redteam-kit
   cd aletheia-redteam-kit
   ```

2. Create a Python 3.11+ environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # on Windows: .venv\Scripts\activate
   ```

3. Install development dependencies:
   ```bash
   pip install -e ".[deps]"  # includes optional pip-audit and osv-scanner
   pip install pytest pytest-cov
   ```

4. Verify your setup:
   ```bash
   python -m pytest tests/ -v
   ```

### Project Structure

```
aletheia-redteam-kit/
├── kit/                    # Main package
│   ├── runner.py          # CLI entry point and orchestrator
│   ├── client.py          # Aletheia API client
│   ├── command_center.py  # Normalized artifact model
│   ├── dashboard_server.py # Hosted dashboard HTTP server
│   └── api_analysis.py, catalog.py, verify.py, ...
├── engine/                 # Audit engines
│   ├── repo_audit/        # Repository security scanner
│   ├── agentic.py         # Agentic attack engine
│   └── tests/             # Probing strategies
├── dashboard/             # Static HTML/JS UI
├── attacks/               # Attack catalogs (JSON)
├── tests/                 # Test suite (pytest)
├── docs/                  # Documentation
└── README.md, pyproject.toml, ...
```

## Workflow

### 1. Pick an Issue

Look for issues labeled:
- `good-first-issue` — Great for first-time contributors
- `help-wanted` — Need community assistance
- `P0`, `P1`, `P1.5` — Priority levels

See [`.github/ISSUES.md`](.github/ISSUES.md) for the full roadmap.

### 2. Create a Feature Branch

```bash
git checkout -b feature/short-description
# or for bug fixes:
git checkout -b fix/short-description
```

### 3. Make Changes

- Follow the existing code style (Python: PEP 8 with 4-space indent)
- Add tests for new functionality in `tests/`
- Update docs if you change user-facing behavior

### 4. Run Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run a specific test file
python -m pytest tests/test_runner.py -v

# Run with coverage
python -m pytest tests/ --cov=kit --cov=engine
```

### 5. Commit and Push

```bash
git add .
git commit -m "feat(component): brief description

Longer explanation of the change. Link to any related issues.

Fixes #123  # if this closes an issue
"
git push origin feature/short-description
```

### 6. Open a Pull Request

- Title should match commit message format (e.g., `feat(api): reconcile unknown decisions`)
- Include a clear description of the change
- Reference any related issues with `Fixes #123`
- Ensure all tests pass in CI

## Code Style

- **Python**: PEP 8, 120-character line limit
- **Commits**: Conventional Commits format (`feat:`, `fix:`, `docs:`, `test:`, etc.)
- **Tests**: Use `pytest`, aim for >80% coverage on new code
- **Docstrings**: Include for public functions (no strict format, clarity over verbosity)

## Testing

### Example: Adding a Test

```python
# tests/test_my_feature.py
import pytest
from kit.my_module import my_function

def test_my_function_does_something():
    result = my_function(input_data)
    assert result == expected_output

def test_my_function_raises_on_invalid_input(monkeypatch):
    with pytest.raises(ValueError):
        my_function(invalid_data)
```

### Running Specific Tests

```bash
# Run tests matching a name pattern
python -m pytest tests/ -k "test_reconciliation"

# Run with verbose output
python -m pytest tests/test_runner.py -vv

# Stop on first failure
python -m pytest tests/ -x
```

## Key Components to Know

### CLI Entry Point
- **File**: `kit/runner.py`
- **Modes**: `api`, `website`, `repo`, `combined`, `agentic`
- **Subcommands**: `run`, `dashboard`, `compare`, `export`, `gate`
- Synchronous only (no async/await)

### API Audit
- **File**: `kit/client.py`
- Sends payloads to `https://api.aletheia-core.com/v1/audit`
- Captures `request_id` for receipt reconciliation
- Implements adaptive backoff (1s baseline, up to 30s on 429s)

### Command-Center Artifact Model
- **File**: `kit/command_center.py`
- Normalizes API, website, repo summaries to common JSON schema
- Emits `command_center.json` and `command_center.sqlite`
- Tables: `runs`, `findings`, `metrics`, `artifacts`, `gate_results`

### Repository Audit
- **File**: `engine/repo_audit/scanner.py`
- Static analysis: secrets, weak crypto, code patterns
- Dependency scanning: `pip-audit`, `osv-scanner`
- Supply-chain findings with malware/typosquatting indicators

### Dashboard
- **File**: `dashboard/index.html`
- Pure JavaScript, no framework
- Loads JSON or SQLite artifacts
- Hosted server in `kit/dashboard_server.py`

## Common Tasks

### Add a New Attack Category

1. Create `attacks/my_category.json` with attack definitions
2. Update `engine/agentic.py` to recognize the category
3. Add tests to `tests/test_catalog.py`
4. Update README

### Add a New CLI Flag

1. Add argument to the relevant parser in `kit/runner.py`
2. Pass the flag through to the audit function
3. Add tests in `tests/test_runner.py`

### Fix a Gate Violation

1. Update the violation check in `kit/command_center.py` or `kit/runner.py`
2. Add/update tests in `tests/test_runner.py` or `tests/test_gap_analysis.py`
3. Update README if gate behavior changed

## Debugging

### Print Debug Info

```python
import sys
print("Debug info here", file=sys.stderr)  # Use stderr for logging
```

### Use Pytest's `--pdb` Flag

```bash
python -m pytest tests/test_file.py::test_name --pdb
# Hit '?' in the debugger for help
```

### Check Test Artifacts

Test runs may write artifacts to `tmp_path` (pytest fixture):
```python
def test_something(tmp_path):
    artifact = tmp_path / "output.json"
    # Use artifact in test
    print(f"Artifact at: {artifact}")  # See where it was written
```

## Performance & Benchmarking

No performance tests are currently in the suite, but be mindful of:
- API pacing (min 1s between requests by design)
- Website crawl depth (configurable, default 5)
- Repository scan performance on large monorepos

## Questions?

- Check existing issues and discussions
- Review test files for usage examples
- Ask in a new issue or discussion thread

## License

By contributing, you agree your code will be licensed under the same license as the project (see LICENSE file).

Thank you for contributing to Aletheia!
