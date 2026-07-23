
import pytest

from logcrux.config import LogcruxConfig, load_config


def test_load_defaults_when_no_file():
    cfg = load_config(None)
    assert isinstance(cfg, LogcruxConfig)
    assert cfg.analysis.window_size_minutes == 5
    assert cfg.inference.threshold == 0.35
    assert cfg.state.baseline_alpha == 0.2


def test_load_from_yaml(tmp_path):
    yaml_file = tmp_path / "logcrux.yaml"
    yaml_file.write_text("analysis:\n  window_size_minutes: 10\n")
    cfg = load_config(yaml_file)
    assert cfg.analysis.window_size_minutes == 10
    assert cfg.inference.threshold == 0.35


def test_invalid_yaml_raises(tmp_path):
    from logcrux.exceptions import ConfigError
    bad = tmp_path / "bad.yaml"
    bad.write_text(": bad: yaml: [")
    with pytest.raises(ConfigError):
        load_config(bad)


def test_missing_config_file_raises(tmp_path):
    from logcrux.exceptions import ConfigError
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")


def test_empty_config_file_uses_defaults(tmp_path):
    empty = tmp_path / "empty.yaml"
    empty.write_text("")
    cfg = load_config(empty)
    assert cfg.inference.threshold == 0.35


def test_out_of_range_value_raises(tmp_path):
    from logcrux.exceptions import ConfigError
    bad = tmp_path / "badval.yaml"
    bad.write_text("inference:\n  threshold: 5.0\n")
    with pytest.raises(ConfigError, match="inference.threshold"):
        load_config(bad)


def test_unknown_key_raises(tmp_path):
    # A typo'd section must fail loudly, not silently keep the default.
    from logcrux.exceptions import ConfigError
    bad = tmp_path / "typo.yaml"
    bad.write_text("inferrence:\n  threshold: 0.5\n")
    with pytest.raises(ConfigError, match="inferrence"):
        load_config(bad)
