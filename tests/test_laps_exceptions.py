"""Additional tests for taskhound/laps/exceptions.py module."""

import pytest

from taskhound.laps.exceptions import (
    LAPSConnectionError,
    LAPSEmptyCacheError,
    LAPSError,
    LAPSParseError,
)


class TestLAPSError:
    """Tests for LAPSError base exception."""

    def test_inheritance(self):
        """LAPSError inherits from Exception."""
        assert issubclass(LAPSError, Exception)

    def test_can_be_raised(self):
        """LAPSError can be raised and caught."""
        with pytest.raises(LAPSError):
            raise LAPSError("Test error")

    def test_message(self):
        """LAPSError preserves message."""
        try:
            raise LAPSError("Test error message")
        except LAPSError as e:
            assert "Test error message" in str(e)


class TestLAPSConnectionError:
    """Tests for LAPSConnectionError exception."""

    def test_inheritance(self):
        """LAPSConnectionError inherits from LAPSError."""
        assert issubclass(LAPSConnectionError, LAPSError)

    def test_can_be_raised(self):
        """LAPSConnectionError can be raised and caught."""
        with pytest.raises(LAPSConnectionError):
            raise LAPSConnectionError("Connection failed")

    def test_caught_as_base(self):
        """LAPSConnectionError can be caught as LAPSError."""
        with pytest.raises(LAPSError):
            raise LAPSConnectionError("Connection failed")


class TestLAPSEmptyCacheError:
    """Tests for LAPSEmptyCacheError exception."""

    def test_inheritance(self):
        """LAPSEmptyCacheError inherits from LAPSError."""
        assert issubclass(LAPSEmptyCacheError, LAPSError)

    def test_can_be_raised(self):
        """LAPSEmptyCacheError can be raised and caught."""
        with pytest.raises(LAPSEmptyCacheError):
            raise LAPSEmptyCacheError("Cache is empty")

    def test_caught_as_base(self):
        """LAPSEmptyCacheError can be caught as LAPSError."""
        with pytest.raises(LAPSError):
            raise LAPSEmptyCacheError("Cache is empty")


class TestLAPSParseError:
    """Tests for LAPSParseError exception."""

    def test_inheritance(self):
        """LAPSParseError inherits from LAPSError."""
        assert issubclass(LAPSParseError, LAPSError)

    def test_can_be_raised(self):
        """LAPSParseError can be raised and caught."""
        with pytest.raises(LAPSParseError):
            raise LAPSParseError("Parse failed")

    def test_caught_as_base(self):
        """LAPSParseError can be caught as LAPSError."""
        with pytest.raises(LAPSError):
            raise LAPSParseError("Parse failed")

    def test_message_with_context(self):
        """LAPSParseError message includes context."""
        try:
            raise LAPSParseError("Invalid JSON: missing field 'p'")
        except LAPSParseError as e:
            assert "Invalid JSON" in str(e)
            assert "missing field" in str(e)


class TestExceptionChaining:
    """Tests for exception chaining."""

    def test_laps_parse_error_from_json_error(self):
        """LAPSParseError can chain from JSONDecodeError."""
        import json

        try:
            try:
                json.loads("invalid")
            except json.JSONDecodeError as e:
                raise LAPSParseError(f"Failed to parse: {e}") from e
        except LAPSParseError as e:
            assert "Failed to parse" in str(e)
            assert e.__cause__ is not None

    def test_laps_connection_error_from_socket(self):
        """LAPSConnectionError can chain from socket error."""
        try:
            try:
                raise ConnectionRefusedError("Connection refused")
            except ConnectionRefusedError as e:
                raise LAPSConnectionError(f"LDAP connection failed: {e}") from e
        except LAPSConnectionError as e:
            assert "LDAP connection failed" in str(e)
            assert e.__cause__ is not None
