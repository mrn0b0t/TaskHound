"""
Test suite for LAPS helper functions.

Tests cover:
- get_laps_credential_for_host function
- print_laps_summary function
"""

from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from taskhound.laps.helpers import (
    get_laps_credential_for_host,
    print_laps_summary,
)
from taskhound.laps.models import LAPSCache, LAPSCredential, LAPSFailure

# ============================================================================
# Test: get_laps_credential_for_host
# ============================================================================


class TestGetLapsCredentialForHost:
    """Tests for get_laps_credential_for_host function"""

    def test_returns_credential_when_found(self):
        """Should return credential when found in cache"""
        mock_cache = MagicMock(spec=LAPSCache)
        mock_cred = MagicMock(spec=LAPSCredential)
        mock_cred.encrypted = False
        mock_cred.is_expired.return_value = False
        mock_cache.get.return_value = mock_cred

        cred, failure = get_laps_credential_for_host(mock_cache, "WS01")

        assert cred == mock_cred
        assert failure is None

    def test_returns_failure_when_not_found(self):
        """Should return failure when host not in cache"""
        mock_cache = MagicMock(spec=LAPSCache)
        mock_cache.get.return_value = None

        cred, failure = get_laps_credential_for_host(mock_cache, "WS01")

        assert cred is None
        assert failure is not None
        assert failure.failure_type == "not_found"
        assert failure.hostname == "WS01"

    def test_returns_failure_for_encrypted_password(self):
        """Should return failure when LAPS password is encrypted"""
        mock_cache = MagicMock(spec=LAPSCache)
        mock_cred = MagicMock(spec=LAPSCredential)
        mock_cred.encrypted = True
        mock_cred.laps_type = "mslaps"
        mock_cache.get.return_value = mock_cred

        cred, failure = get_laps_credential_for_host(mock_cache, "WS01")

        assert cred is None
        assert failure is not None
        assert failure.failure_type == "encrypted"
        assert failure.laps_type_tried == "mslaps"

    def test_returns_credential_when_expired_with_warning(self):
        """Should return credential but warn when expired"""
        mock_cache = MagicMock(spec=LAPSCache)
        mock_cred = MagicMock(spec=LAPSCredential)
        mock_cred.encrypted = False
        mock_cred.is_expired.return_value = True
        mock_cred.expiration = datetime.now() - timedelta(hours=1)
        mock_cache.get.return_value = mock_cred

        with patch('taskhound.laps.helpers.warn') as mock_warn:
            cred, failure = get_laps_credential_for_host(mock_cache, "WS01")

        assert cred == mock_cred
        assert failure is None
        mock_warn.assert_called_once()
        assert "expired" in mock_warn.call_args[0][0].lower()

    def test_hostname_passed_to_cache(self):
        """Should pass hostname to cache.get"""
        mock_cache = MagicMock(spec=LAPSCache)
        mock_cache.get.return_value = None

        get_laps_credential_for_host(mock_cache, "TESTHOST.example.com")

        mock_cache.get.assert_called_once_with("TESTHOST.example.com")


# ============================================================================
# Test: print_laps_summary
# ============================================================================


class TestPrintLapsSummary:
    """Tests for print_laps_summary function"""

    def test_prints_total_entries(self, capsys):
        """Should print total LAPS entries"""
        mock_cache = MagicMock(spec=LAPSCache)
        mock_cache.get_statistics.return_value = {
            "total": 10,
            "mslaps": 5,
            "legacy": 3,
            "encrypted": 2
        }

        print_laps_summary(mock_cache, successes=8, failures=[])

        captured = capsys.readouterr()
        assert "10" in captured.out
        assert "Total LAPS entries" in captured.out

    def test_prints_mslaps_count(self, capsys):
        """Should print Windows LAPS count"""
        mock_cache = MagicMock(spec=LAPSCache)
        mock_cache.get_statistics.return_value = {
            "total": 10,
            "mslaps": 5,
            "legacy": 0,
            "encrypted": 0
        }

        print_laps_summary(mock_cache, successes=5, failures=[])

        captured = capsys.readouterr()
        assert "Windows LAPS" in captured.out
        assert "5" in captured.out

    def test_prints_legacy_count(self, capsys):
        """Should print Legacy LAPS count"""
        mock_cache = MagicMock(spec=LAPSCache)
        mock_cache.get_statistics.return_value = {
            "total": 10,
            "mslaps": 0,
            "legacy": 7,
            "encrypted": 0
        }

        print_laps_summary(mock_cache, successes=7, failures=[])

        captured = capsys.readouterr()
        assert "Legacy LAPS" in captured.out
        assert "7" in captured.out

    def test_prints_encrypted_count(self, capsys):
        """Should print encrypted entries count"""
        mock_cache = MagicMock(spec=LAPSCache)
        mock_cache.get_statistics.return_value = {
            "total": 10,
            "mslaps": 0,
            "legacy": 0,
            "encrypted": 3
        }

        print_laps_summary(mock_cache, successes=0, failures=[])

        captured = capsys.readouterr()
        assert "Encrypted" in captured.out
        assert "skipped" in captured.out

    def test_prints_success_count(self, capsys):
        """Should print success count"""
        mock_cache = MagicMock(spec=LAPSCache)
        mock_cache.get_statistics.return_value = {
            "total": 10,
            "mslaps": 0,
            "legacy": 0,
            "encrypted": 0
        }

        print_laps_summary(mock_cache, successes=5, failures=[])

        captured = capsys.readouterr()
        assert "Successful" in captured.out
        assert "5" in captured.out

    def test_prints_failure_counts_by_type(self, capsys):
        """Should group and print failures by type"""
        mock_cache = MagicMock(spec=LAPSCache)
        mock_cache.get_statistics.return_value = {
            "total": 10,
            "mslaps": 0,
            "legacy": 0,
            "encrypted": 0
        }

        failures = [
            LAPSFailure(hostname="WS01", failure_type="not_found", message="Not found"),
            LAPSFailure(hostname="WS02", failure_type="not_found", message="Not found"),
            LAPSFailure(hostname="WS03", failure_type="auth_failed", message="Auth failed"),
        ]

        print_laps_summary(mock_cache, successes=7, failures=failures)

        captured = capsys.readouterr()
        assert "No password in cache" in captured.out
        assert "2" in captured.out  # 2 not_found failures
        assert "Auth failed" in captured.out

    def test_skips_zero_mslaps(self, capsys):
        """Should not print Windows LAPS line if count is 0"""
        mock_cache = MagicMock(spec=LAPSCache)
        mock_cache.get_statistics.return_value = {
            "total": 10,
            "mslaps": 0,
            "legacy": 10,
            "encrypted": 0
        }

        print_laps_summary(mock_cache, successes=10, failures=[])

        captured = capsys.readouterr()
        assert "Windows LAPS" not in captured.out

    def test_skips_zero_legacy(self, capsys):
        """Should not print Legacy LAPS line if count is 0"""
        mock_cache = MagicMock(spec=LAPSCache)
        mock_cache.get_statistics.return_value = {
            "total": 10,
            "mslaps": 10,
            "legacy": 0,
            "encrypted": 0
        }

        print_laps_summary(mock_cache, successes=10, failures=[])

        captured = capsys.readouterr()
        assert "Legacy LAPS" not in captured.out

    def test_skips_zero_encrypted(self, capsys):
        """Should not print Encrypted line if count is 0"""
        mock_cache = MagicMock(spec=LAPSCache)
        mock_cache.get_statistics.return_value = {
            "total": 10,
            "mslaps": 10,
            "legacy": 0,
            "encrypted": 0
        }

        print_laps_summary(mock_cache, successes=10, failures=[])

        captured = capsys.readouterr()
        assert "skipped" not in captured.out.lower()

    def test_handles_remote_uac_failure(self, capsys):
        """Should handle remote UAC failure type"""
        mock_cache = MagicMock(spec=LAPSCache)
        mock_cache.get_statistics.return_value = {
            "total": 5,
            "mslaps": 5,
            "legacy": 0,
            "encrypted": 0
        }

        failures = [
            LAPSFailure(hostname="WS01", failure_type="remote_uac", message="Remote UAC"),
        ]

        print_laps_summary(mock_cache, successes=4, failures=failures)

        captured = capsys.readouterr()
        assert "Remote UAC" in captured.out

    def test_handles_encrypted_failure_type(self, capsys):
        """Should handle encrypted failure type"""
        mock_cache = MagicMock(spec=LAPSCache)
        mock_cache.get_statistics.return_value = {
            "total": 5,
            "mslaps": 0,
            "legacy": 0,
            "encrypted": 5
        }

        failures = [
            LAPSFailure(hostname="WS01", failure_type="encrypted", message="Encrypted"),
        ]

        print_laps_summary(mock_cache, successes=0, failures=failures)

        captured = capsys.readouterr()
        assert "unsupported" in captured.out.lower()
