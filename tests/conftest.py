from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture
def syslog_oom_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "syslog_oom.log"


@pytest.fixture
def syslog_clean_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "syslog_clean.log"


@pytest.fixture
def auth_bruteforce_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "auth_bruteforce.log"


@pytest.fixture
def apache_access_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "apache_access.log"


@pytest.fixture
def nginx_error_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "nginx_error.log"


@pytest.fixture
def journald_path(fixtures_dir: Path) -> Path:
    return fixtures_dir / "journald_export.log"
