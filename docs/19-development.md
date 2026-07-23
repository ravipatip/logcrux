# Development Guide

This guide covers setting up a development environment, running tests, and debugging logcrux.

## Prerequisites

- **Python:** 3.11 or later
- **Git:** For version control
- **pip:** Python package manager
- **Optional:** Docker for isolated testing

## Setup

### 1. Clone Repository

```bash
git clone https://github.com/ravipatip/logcrux.git
cd logcrux
```

The bundled ONNX models (~22MB each, INT8-quantized) are committed directly
in the repo — no separate download step needed.

### 2. Create Virtual Environment

```bash
python3.11 -m venv venv
source venv/bin/activate  # macOS/Linux
# or
venv\Scripts\activate  # Windows
```

### 3. Install Package (Development Mode)

```bash
# Install with all dependencies (including test/dev tools)
pip install -e ".[dev]"
```

This makes the `logcrux` command available and editable—changes to code are immediately reflected.

### 4. Verify Installation

```bash
logcrux --version
pytest --version
mypy --version
ruff --version
```

## Project Structure

```
logcrux/
├── logcrux/                    # Source code
│   ├── cli.py                  # Entry point
│   ├── models.py               # Data structures
│   ├── config.py               # Configuration
│   ├── parsers/                # 200+ log parsers
│   ├── analysis/               # 5 analysis engines
│   ├── inference/              # ONNX AI models
│   ├── state/                  # SQLite persistence
│   ├── summarizer/             # Incident summarization
│   └── output/                 # Terminal/JSON rendering
├── tests/                      # Test suite
│   ├── unit/                   # Unit tests
│   ├── integration/            # End-to-end tests
│   └── fixtures/               # Test data
├── docs/                       # Documentation (this folder)
├── pyproject.toml              # Package metadata
└── README.md                   # Project README
```

## Running Tests

### All Tests

```bash
pytest                          # Run all tests
pytest --cov=logcrux          # With coverage report
pytest -v                      # Verbose output
pytest -x                      # Stop on first failure
```

### Specific Tests

```bash
# By module
pytest tests/unit/test_config.py

# By pattern
pytest -k "test_parse" -v

# Integration tests only
pytest tests/integration

# Unit tests only
pytest tests/unit
```

### Test with Timing

```bash
pytest --durations=10          # Show 10 slowest tests
pytest --durations=0           # Show all timings
```

### Coverage Report

```bash
pytest --cov=logcrux --cov-report=html
open htmlcov/index.html         # View report
```

## Code Quality

### Linting & Formatting

```bash
# Check code style (without fixing)
ruff check logcrux tests

# Fix formatting issues
ruff check --fix logcrux tests

# Type checking
mypy logcrux tests

# All checks (pre-commit)
pre-commit run --all-files
```

### Before Committing

Run the pre-commit checks:

```bash
pre-commit run --all-files
```

Or set up hooks to run automatically:

```bash
pre-commit install
```

## Running the CLI

### Analyze a Log File

```bash
logcrux /var/log/syslog
```

### With Options

```bash
logcrux /var/log/syslog --verbose --last 1h --threshold 0.5
```

### From stdin

```bash
tail /var/log/syslog | logcrux
```

### Debugging

```bash
# Verbose logging
logcrux /var/log/syslog --verbose

# Print parsed events (requires modifying code)
# Add to cli.py:
#   for event in parsed_events[:10]:
#       print(event.model_dump_json(indent=2))

# Or use Python REPL
python
>>> from logcrux.parsers.registry import detect_parser
>>> parser = detect_parser(Path("/var/log/syslog"), [])
>>> # ...
```

## Common Development Tasks

### Adding a New Parser

1. **Create parser file** `logcrux/parsers/myformat.py`

```python
from logcrux.parsers.base import LogParser
from logcrux.models import ParsedEvent, Severity
from pathlib import Path

class MyFormatParser(LogParser):
    FORMAT_NAME = "myformat"
    
    @classmethod
    def can_parse(cls, path: Path | None, sample_lines: list[str]) -> bool:
        if not sample_lines:
            return False
        return "special_marker" in sample_lines[0]
    
    def parse_line(self, line: str, line_number: int) -> ParsedEvent | None:
        # Parse and return ParsedEvent
        return ParsedEvent(
            timestamp=...,
            severity=Severity.INFO,
            source="myformat",
            message=line,
            raw=line,
            line_number=line_number,
        )
```

2. **Register in parser registry** `logcrux/parsers/registry.py`

```python
from logcrux.parsers.myformat import MyFormatParser

_PARSERS: list[type[LogParser]] = [
    # ... existing parsers
    MyFormatParser,  # Add in appropriate position
    # ...
]
```

3. **Add test fixtures** `tests/fixtures/myformat.log`

```
Line 1: special_marker message
Line 2: special_marker error
```

4. **Add tests** `tests/unit/test_parsers/test_myformat.py`

```python
import pytest
from pathlib import Path
from logcrux.parsers.myformat import MyFormatParser

def test_can_parse():
    parser = MyFormatParser.can_parse(
        Path("/var/log/myformat.log"),
        ["special_marker message"]
    )
    assert parser is True

def test_parse_line():
    parser = MyFormatParser()
    event = parser.parse_line("special_marker message", 1)
    assert event is not None
    assert event.message == "message"
```

5. **Test**

```bash
pytest tests/unit/test_parsers/test_myformat.py -v
```

### Adding an Analysis Signal

1. **Create signal type** in `logcrux/models.py`:

```python
class AnomalySignal(BaseModel):
    kind: Literal[
        # ... existing kinds
        "new_signal_type",  # Add here
    ]
```

2. **Implement detector** in `logcrux/analysis/mydetector.py`

```python
def analyze_new_signal(
    events: list[ParsedEvent],
    config: Config,
) -> list[AnomalySignal]:
    signals = []
    # Detection logic
    return signals
```

3. **Integrate** in `logcrux/analysis/engine.py`

```python
def run_analysis(...) -> AnalysisResult:
    all_signals = []
    # ... existing engines
    all_signals.extend(analyze_new_signal(parsed_events, config))
    # ...
```

4. **Test**

```bash
pytest tests/unit/test_analysis/ -v
```

### Updating Configuration

Edit `pyproject.toml` or `logcrux/config.py`:

```python
@dataclass
class Config:
    # Add new field
    new_parameter: float = 1.5
```

Update `docs/04-configuration.md` to document the new setting.

## Debugging Tips

### Print Events

```python
# In any analysis function
for event in events[:5]:
    print(event.model_dump_json(indent=2))
```

### Enable Verbose Logging

```bash
logcrux /var/log/syslog --verbose 2>&1 | grep -i "keyword"
```

### Use Python REPL

```python
python
>>> from pathlib import Path
>>> from logcrux.parsers.registry import detect_parser
>>> from logcrux.analysis.engine import run_analysis
>>> from logcrux.config import Config
>>> 
>>> # Load and parse
>>> path = Path("/var/log/syslog")
>>> parser = detect_parser(path, [])
>>> events = [parser.parse_line(line, i) for i, line in enumerate(Path.read_text(path).split("\n")) if parser.parse_line(line, i)]
>>> 
>>> # Analyze
>>> config = Config()
>>> results = run_analysis(events, str(path), parser.FORMAT_NAME, config, {})
>>> print(f"Found {len(results.signals)} signals")
```

### Check Models Are Present

```bash
# Verify models exist and are the right size
ls -lah logcrux/inference/models/*/model.onnx
# Should show ~22MB files each (INT8-quantized)
```

If missing or wrong size, re-clone the repo — the models are committed
directly, not fetched separately.

### Run Single Test with Output

```bash
pytest tests/unit/test_config.py::test_name -s
```

The `-s` flag shows print output.

## Performance Profiling

Profile analysis speed:

```bash
python -m cProfile -s cumtime -m logcrux /var/log/syslog > profile.txt
# Shows which functions take most time
```

Or use a profiler tool:

```bash
pip install py-spy
py-spy record -o profile.svg -- logcrux /var/log/syslog
```

## Database Management

### View Baseline State

```bash
sqlite3 ~/.local/share/logcrux/state.db
> SELECT * FROM baselines;
> SELECT * FROM run_history;
> .quit
```

### Clear State

```bash
rm ~/.local/share/logcrux/state.db
# Or use --no-baseline flag
```

## Documentation

Build and view docs:

```bash
# Docs are in Markdown in docs/ folder
# View in any editor or browser
cat docs/README.md
```

Update docs when:
- Adding a parser
- Adding an analysis signal
- Changing configuration
- Fixing a bug (add to troubleshooting)

## Dependency Management

### Check Outdated Packages

```bash
pip list --outdated
```

### Update Packages

```bash
pip install --upgrade package_name
```

### Lock Dependencies

```bash
pip freeze > requirements-lock.txt
```

## Release Process

1. **Update version** in `pyproject.toml`
2. **Update CHANGELOG.md** with changes
3. **Run full test suite** `pytest`
4. **Run linting** `ruff check --fix . && mypy .`
5. **Tag release** `git tag vX.Y.Z && git push origin vX.Y.Z`
6. **Build** `python -m build`
7. **Upload** `python -m twine upload dist/*`

---

**Last Updated:** July 2026
