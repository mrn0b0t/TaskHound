"""
Date parsing utilities for TaskHound.

This module provides centralized date parsing logic to handle various formats
encountered in Windows Task Scheduler XML and BloodHound data.
"""

from datetime import datetime, timezone
from typing import Optional, Union


def parse_timestamp(timestamp_value: Union[str, int, float]) -> Optional[datetime]:
    """
    Convert various timestamp formats to datetime.
    Supports Windows FILETIME, Unix timestamps, and string representations.
    Returns None if conversion fails or timestamp is 0/invalid.
    """
    if not timestamp_value:
        return None

    if isinstance(timestamp_value, str):
        if timestamp_value.strip() == "" or timestamp_value == "0":
            return None
        try:
            timestamp = float(timestamp_value)
        except ValueError:
            return None
    else:
        timestamp = float(timestamp_value)

    if timestamp == 0:
        return None

    try:
        # Detect format based on magnitude
        # Windows FILETIME is very large (> 100 billion for dates after 1970)
        # Unix timestamp is smaller (< 10 billion for dates before 2286)
        if timestamp > 10000000000:  # Likely Windows FILETIME
            # Windows FILETIME epoch: January 1, 1601 00:00:00 UTC
            # Convert 100-nanosecond intervals to seconds
            unix_timestamp = (timestamp - 116444736000000000) / 10000000.0
            return datetime.fromtimestamp(unix_timestamp, tz=timezone.utc)
        else:  # Likely Unix timestamp
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)

    except (ValueError, OSError, OverflowError):
        return None


def parse_iso_date(date_str: str) -> Optional[datetime]:
    """
    Parse ISO 8601 date strings with various formats.
    Handles 'Z' suffix, timezone offsets, and missing timezones.
    Always returns timezone-aware datetime (UTC if not specified).
    """
    if not date_str:
        return None

    try:
        # Handle 'Z' suffix for UTC
        if date_str.endswith("Z"):
            # Replace Z with +00:00 for fromisoformat compatibility in older Python versions
            # (though Python 3.11+ handles Z natively, we want to be robust)
            clean_str = date_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_str)
        elif "+" in date_str or date_str.count("-") > 2:
            # Likely has timezone offset already
            dt = datetime.fromisoformat(date_str)
        else:
            # Naive datetime, assume UTC
            dt = datetime.fromisoformat(date_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)

        return dt
    except (ValueError, TypeError):
        return None
