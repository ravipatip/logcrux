from logcrux.exceptions import (
    ConfigError,
    InferenceError,
    LogcruxError,
    ParseError,
    PathValidationError,
    StateError,
)


def test_exception_hierarchy():
    assert issubclass(PathValidationError, LogcruxError)
    assert issubclass(ParseError, LogcruxError)
    assert issubclass(InferenceError, LogcruxError)
    assert issubclass(StateError, LogcruxError)
    assert issubclass(ConfigError, LogcruxError)


def test_exceptions_carry_message():
    e = PathValidationError("path /foo/bar is not allowed")
    assert "not allowed" in str(e)
