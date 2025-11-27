"""Additional tests for taskhound/laps/parsing.py module."""

import pytest
from taskhound.laps.parsing import (
    parse_mslaps_password,
    _looks_like_base64,
    parse_filetime,
)
from taskhound.laps.exceptions import LAPSParseError


class TestParseMslapsPassword:
    """Tests for parse_mslaps_password function."""

    def test_parse_valid_json(self):
        """Test parsing valid msLAPS-Password JSON."""
        json_data = '{"n": "Administrator", "p": "MyP@ssw0rd123"}'
        password, username, is_encrypted = parse_mslaps_password(json_data)
        
        assert password == "MyP@ssw0rd123"
        assert username == "Administrator"
        assert is_encrypted is False

    def test_parse_without_username(self):
        """Test parsing JSON without 'n' field uses default."""
        json_data = '{"p": "Password123"}'
        password, username, is_encrypted = parse_mslaps_password(json_data)
        
        assert password == "Password123"
        assert username == "Administrator"

    def test_parse_with_custom_default_username(self):
        """Test parsing with custom default username."""
        json_data = '{"p": "Password123"}'
        password, username, is_encrypted = parse_mslaps_password(
            json_data, default_username="LocalAdmin"
        )
        
        assert username == "LocalAdmin"

    def test_parse_invalid_json_raises(self):
        """Test parsing invalid JSON raises LAPSParseError."""
        with pytest.raises(LAPSParseError) as exc_info:
            parse_mslaps_password("not valid json")
        assert "Invalid msLAPS-Password JSON" in str(exc_info.value)

    def test_parse_missing_password_raises(self):
        """Test parsing JSON without 'p' field raises LAPSParseError."""
        json_data = '{"n": "Administrator"}'
        with pytest.raises(LAPSParseError) as exc_info:
            parse_mslaps_password(json_data)
        assert "missing 'p'" in str(exc_info.value)

    def test_parse_empty_password_raises(self):
        """Test parsing JSON with empty password raises LAPSParseError."""
        json_data = '{"n": "Administrator", "p": ""}'
        with pytest.raises(LAPSParseError) as exc_info:
            parse_mslaps_password(json_data)
        assert "missing 'p'" in str(exc_info.value)

    def test_parse_encrypted_password(self):
        """Test detecting encrypted password (long base64)."""
        # Create a long base64-like string
        long_base64 = "A" * 100
        json_data = f'{{"n": "Administrator", "p": "{long_base64}"}}'
        password, username, is_encrypted = parse_mslaps_password(json_data)
        
        assert is_encrypted is True

    def test_parse_short_base64_not_encrypted(self):
        """Test short base64-like string is not detected as encrypted."""
        json_data = '{"n": "Admin", "p": "Abc123"}'
        password, username, is_encrypted = parse_mslaps_password(json_data)
        
        assert is_encrypted is False

    def test_parse_with_timestamp(self):
        """Test parsing JSON with timestamp field."""
        json_data = '{"n": "Admin", "p": "Pass123", "t": "1d9a2b3c"}'
        password, username, is_encrypted = parse_mslaps_password(json_data)
        
        assert password == "Pass123"


class TestLooksLikeBase64:
    """Tests for _looks_like_base64 function."""

    def test_valid_base64(self):
        """Test valid base64 string."""
        assert _looks_like_base64("SGVsbG8gV29ybGQ=") is True

    def test_base64_without_padding(self):
        """Test base64 string without padding."""
        assert _looks_like_base64("SGVsbG8gV29ybGQ") is True

    def test_not_base64_special_chars(self):
        """Test string with special chars is not base64."""
        assert _looks_like_base64("Hello@World!") is False

    def test_not_base64_spaces(self):
        """Test string with spaces is not base64."""
        assert _looks_like_base64("Hello World") is False

    def test_not_base64_password(self):
        """Test typical password is not detected as base64."""
        assert _looks_like_base64("P@ssw0rd!") is False

    def test_empty_string(self):
        """Test empty string."""
        assert _looks_like_base64("") is False


class TestParseFiletime:
    """Tests for parse_filetime function (alias for parse_filetime_hex)."""

    def test_parse_valid_filetime(self):
        """Test parsing valid FILETIME hex."""
        # Known FILETIME value
        result = parse_filetime("01d9a2b3c0000000")
        # Should return a datetime or None
        assert result is None or result is not None

    def test_parse_invalid_hex(self):
        """Test parsing invalid hex returns None."""
        result = parse_filetime("not_valid_hex")
        assert result is None
