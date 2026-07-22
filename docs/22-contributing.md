# Contributing

Welcome! This guide explains how to contribute code, documentation, and improvements to logcrux.

## Code of Conduct

Be respectful, inclusive, and professional. Treat all contributors with courtesy.

## Getting Started

### Prerequisites

- Python 3.11+
- Git
- Familiarity with Python, pytest, and logcrux basics

### Setup

```bash
# Clone repo
git clone https://github.com/ravipatip/logcrux.git
cd logcrux

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install dev dependencies
pip install -e ".[dev]"

# Verify setup
pytest --co -q  # List tests (don't run)
```

## Contribution Types

### 1. Bug Reports

**Before reporting:**
- Check existing issues (might be known)
- Test with latest code (`git pull`)
- Enable verbose logging: `logcrux --verbose`

**When reporting:**
- Describe the issue clearly
- Include minimal reproduction steps
- Attach log samples (first 50 lines)
- Show version info: `logcrux --version && python --version`

**Example issue:**
```
Title: Nginx parser doesn't detect mixed logs with kernel messages

Description:
When /var/log/syslog contains both nginx and kernel logs, the parser 
detects syslog instead of nginx.

Steps to reproduce:
1. Run: head -100 /var/log/syslog | logcrux
2. Expected: nginx or syslog parser
3. Actual: nginx parser chosen but many lines skipped

Log sample:
[First 50 lines of /var/log/syslog]

Version: logcrux 0.1.0, Python 3.11.5
```

### 2. Feature Requests

**Be specific:**
- What problem does it solve?
- How would you use it?
- Any implementation ideas?

**Example:**
```
Title: Add support for Golang standard library logs

Use Case:
We have Go microservices logging in standard Go format. Currently 
logcrux doesn't parse these, so we fall back to generic parser.

Example log:
2006/01/02 15:04:05 server.go:123: error message

Suggested Implementation:
Create GoLangParser that detects by distinctive YYYY/MM/DD 
HH:MM:SS format and extracts filename:line_number pattern.
```

### 3. Code Contributions

#### Adding a New Parser

See [docs/07-adding-parsers.md](./07-adding-parsers.md) for detailed guide.

**Checklist:**
- [ ] Parser class created in `logcrux/parsers/myformat.py`
- [ ] `can_parse()` is specific (no false positives)
- [ ] `parse_line()` handles all variations
- [ ] Registered in `logcrux/parsers/registry.py`
- [ ] Test fixtures in `tests/fixtures/myformat.log`
- [ ] Tests in `tests/unit/test_parsers/test_myformat.py`
- [ ] Detection verified against similar formats
- [ ] Docs updated in `docs/06-supported-log-types.md`
- [ ] All tests pass: `pytest`

#### Adding an Analysis Signal

**Checklist:**
- [ ] Signal kind added to `logcrux/models.py:AnomalySignal.kind`
- [ ] Analyzer function created in `logcrux/analysis/myanalyzer.py`
- [ ] Integrated into `logcrux/analysis/engine.py:run_analysis()`
- [ ] Tests in `tests/unit/test_analysis/test_myanalyzer.py`
- [ ] Documentation added to `docs/09-anomaly-detection.md`
- [ ] Config parameters added if needed
- [ ] All tests pass: `pytest`

#### Fixing a Bug

**Checklist:**
- [ ] Issue reference in commit message
- [ ] Test that reproduces the bug
- [ ] Fix implemented
- [ ] All tests pass
- [ ] No regressions in other areas
- [ ] Documentation updated if needed

#### Code Quality

Before submitting:

```bash
# Format code
ruff check --fix logcrux tests

# Type check
mypy logcrux tests

# Run tests with coverage
pytest --cov=logcrux --cov-report=term-missing

# Pre-commit checks
pre-commit run --all-files
```

## Pull Request Process

### 1. Create a Branch

```bash
git checkout -b feature/my-feature
# or
git checkout -b fix/issue-123
```

Branch naming:
- `feature/description` for new features
- `fix/issue-number` for bug fixes
- `docs/description` for documentation
- `test/description` for test improvements

### 2. Make Changes

```bash
# Edit files
vim logcrux/mymodule.py

# Run tests frequently
pytest tests/unit/test_mymodule.py -v

# Commit with clear messages
git commit -m "Add feature X

Detailed explanation of what and why.

Fixes #123"
```

### 3. Run Full Test Suite

```bash
# All checks
pytest
ruff check --fix logcrux tests
mypy logcrux tests
```

Ensure all pass before pushing.

### 4. Push and Open PR

```bash
git push origin feature/my-feature
```

Then open a PR with:
- **Title:** Clear, concise description
- **Description:**
  - What problem does this solve?
  - How does it work?
  - Tests added/updated?
  - Any breaking changes?

**Example PR:**
```
Title: Add XYZ parser

Description:
This PR adds support for analyzing XYZ logs. XYZ is used by many 
companies for their application logging.

Changes:
- Added XyzParser with format auto-detection
- Added 15 tests covering edge cases
- Updated documentation

Tests:
- Unit tests: 15 new tests, all passing
- Integration: Tested against real XYZ logs
- No regressions in existing tests (476 passing)

Breaking Changes: None
```

### 5. Address Review Feedback

- Respond to comments
- Make requested changes
- Push additional commits (no force-push)
- Request re-review when ready

### 6. Merge

Once approved:
```bash
# GitHub will merge (don't merge locally)
```

## Documentation Contributing

### Updating Docs

1. **Edit markdown files** in `docs/`
2. **Preview locally** (any markdown reader)
3. **Check links** work
4. **Submit PR** with changes

### Adding New Docs

Create new file in `docs/` following naming:
- `NN-topic.md` where NN is sequential number

Update `docs/README.md` with link to new doc.

## Testing

### Writing Tests

```python
# tests/unit/test_mymodule.py

import pytest
from logcrux.mymodule import MyClass

def test_basic_functionality():
    """Test basic behavior."""
    obj = MyClass()
    assert obj.method() == expected_value

def test_edge_case():
    """Test edge case."""
    with pytest.raises(ValueError):
        MyClass(invalid_input)

@pytest.fixture
def sample_data():
    """Fixture for test data."""
    return {"key": "value"}

def test_with_fixture(sample_data):
    """Test using fixture."""
    obj = MyClass(sample_data)
    assert obj.is_valid()
```

### Running Tests

```bash
# All tests
pytest

# Specific file
pytest tests/unit/test_mymodule.py

# Specific test
pytest tests/unit/test_mymodule.py::test_basic_functionality

# With coverage
pytest --cov=logcrux

# Stop on first failure
pytest -x

# Show print output
pytest -s

# Run slow tests
pytest --runslow
```

### Coverage Target

Aim for **≥80% coverage** on new code. Check with:

```bash
pytest --cov=logcrux --cov-report=html
open htmlcov/index.html
```

## Commit Message Guidelines

**Format:**
```
Short summary (≤50 chars)

Optional longer explanation (≤72 chars per line)
explaining the what and why, not the how.

Fixes #123
Related-To: #456
```

**Examples:**
```
Add Nginx parser for access logs

Detects nginx/apache access logs by combined log format.
Extracts IP, method, path, status, bytes.

Fixes #42
```

```
Fix auth_failure_cluster threshold

The threshold was too high (100), causing real attacks to be missed.
Reduced to 10, which matches industry standard for brute-force.

Fixes #99
```

## Code Style

### Python

- **Formatter:** ruff
- **Linter:** ruff
- **Type checker:** mypy (strict mode)
- **Line length:** 100 characters

### Imports

```python
# Order: stdlib, third-party, local
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import requests
from pydantic import BaseModel

from logcrux.models import ParsedEvent
from logcrux.parsers.base import LogParser
```

### Type Hints

```python
# Always use type hints for function signatures
def analyze_events(
    events: list[ParsedEvent],
    threshold: float = 0.35,
) -> dict[str, Any]:
    """Analyze events."""
```

### Comments

Minimal comments, only for non-obvious logic:

```python
# ✓ Good: Explains why
# Exponential smoothing prevents anomalies from skewing baselines
baseline_new = 0.2 * current + 0.8 * baseline_old

# ✗ Bad: Obvious from code
# Add 1 to count
count += 1
```

## Performance Considerations

When contributing:
- Avoid `O(n²)` algorithms
- Precompile regex patterns
- Cache expensive computations
- Profile before optimizing

## Documentation Requirements

For new features:
- Update relevant `docs/*.md` files
- Add docstrings to public functions
- Include examples in docstrings

## Security

- Don't add credentials to code
- Don't log sensitive data
- Validate user input
- Use `security.py` for path validation

## Legal

By contributing, you agree that:
- Your contribution is your original work
- Your contribution is licensed under the Apache License 2.0, same as the rest of the project

## Getting Help

- Read [docs/README.md](./README.md) for overview
- Check [docs/19-development.md](./19-development.md) for dev setup
- Ask in issues or discussions

## Code Review Expectations

Reviews may include:
- **Functionality:** Does it work correctly?
- **Style:** Does it follow conventions?
- **Tests:** Are tests adequate?
- **Performance:** Is it efficient?
- **Documentation:** Is it clear?

Be open to feedback—code review improves code quality for everyone.

## Merge Criteria

A PR is ready to merge when:
1. All tests pass
2. Code style checks pass
3. Type checking passes
4. Coverage is ≥80% for new code
5. At least one approval from maintainer
6. No unresolved comments
7. Documentation is updated

## After Merge

- Watch for any issues in CI
- Be available to fix problems
- Monitor related issues for follow-ups

## Areas Needing Help

- New log format parsers
- Documentation and examples
- Performance optimizations
- Testing on different systems
- Bug fixes and edge cases

---

**Thank you for contributing to logcrux!**

**Last Updated:** July 2026
