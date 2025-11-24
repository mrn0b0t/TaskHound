"""
Test date parsing utilities.
"""

from datetime import timezone

from taskhound.utils.date_parser import parse_iso_date, parse_timestamp


class TestDateParser:
    def test_parse_timestamp_unix(self):
        """Test parsing Unix timestamps."""
        # 2023-01-01 00:00:00 UTC
        ts = 1672531200
        dt = parse_timestamp(ts)
        assert dt.year == 2023
        assert dt.month == 1
        assert dt.day == 1
        assert dt.tzinfo == timezone.utc

    def test_parse_timestamp_windows(self):
        """Test parsing Windows FILETIME."""
        # 2023-01-01 00:00:00 UTC in FILETIME
        # (1672531200 + 11644473600) * 10000000
        ts = 133170048000000000
        dt = parse_timestamp(ts)
        assert dt.year == 2023
        assert dt.month == 1
        assert dt.day == 1
        assert dt.tzinfo == timezone.utc

    def test_parse_timestamp_string(self):
        """Test parsing string timestamps."""
        assert parse_timestamp("1672531200").year == 2023
        assert parse_timestamp("133170048000000000").year == 2023

    def test_parse_timestamp_invalid(self):
        """Test parsing invalid timestamps."""
        assert parse_timestamp(None) is None
        assert parse_timestamp("") is None
        assert parse_timestamp("0") is None
        assert parse_timestamp(0) is None
        assert parse_timestamp("invalid") is None

    def test_parse_iso_date_basic(self):
        """Test parsing basic ISO dates."""
        dt = parse_iso_date("2023-01-01T12:00:00")
        assert dt.year == 2023
        assert dt.hour == 12
        assert dt.tzinfo == timezone.utc

    def test_parse_iso_date_z_suffix(self):
        """Test parsing ISO dates with Z suffix."""
        dt = parse_iso_date("2023-01-01T12:00:00Z")
        assert dt.year == 2023
        assert dt.hour == 12
        assert dt.tzinfo == timezone.utc

    def test_parse_iso_date_timezone(self):
        """Test parsing ISO dates with timezone offset."""
        dt = parse_iso_date("2023-01-01T12:00:00+01:00")
        assert dt.year == 2023
        assert dt.hour == 12
        # Should preserve timezone info
        assert dt.utcoffset().total_seconds() == 3600

    def test_parse_iso_date_invalid(self):
        """Test parsing invalid ISO dates."""
        assert parse_iso_date(None) is None
        assert parse_iso_date("") is None
        assert parse_iso_date("invalid") is None
