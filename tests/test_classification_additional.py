"""
Additional classification tests to boost coverage.
"""
from unittest.mock import MagicMock

from taskhound.classification import (
    _analyze_password_age,
    _get_task_date_for_analysis,
    classify_task,
)
from taskhound.models.task import TaskRow, TaskType


class TestClassifyTask:
    """Tests for classify_task function."""

    def _make_task_row(self, runas: str, creds_hint: str = "stored_credentials"):
        """Helper to create a TaskRow."""
        return TaskRow(
            host="testhost",
            path="Tasks\\Test",
            runas=runas,
            credentials_hint=creds_hint,
            command="cmd.exe",
            author="Admin",
            date="2023-01-01",
            enabled="True",
            type=TaskType.TASK.value,
        )

    def test_skips_no_saved_creds_by_default(self):
        """Should skip tasks without saved credentials by default."""
        row = self._make_task_row("DOMAIN\\user", "no_saved_credentials")

        result = classify_task(
            row=row,
            meta={},
            runas="DOMAIN\\user",
            rel_path="Tasks\\Test",
            hv=None,
            show_unsaved_creds=False,
            include_local=False,
        )

        assert result.should_include is False
        assert result.task_type == "TASK"

    def test_includes_no_saved_creds_when_requested(self):
        """Should include tasks without saved credentials when requested."""
        row = self._make_task_row("DOMAIN\\user", "no_saved_credentials")

        result = classify_task(
            row=row,
            meta={},
            runas="DOMAIN\\user",
            rel_path="Tasks\\Test",
            hv=None,
            show_unsaved_creds=True,
            include_local=False,
        )

        assert result.should_include is True

    def test_returns_task_for_no_hv_data(self):
        """Should return TASK when no BloodHound data."""
        row = self._make_task_row("DOMAIN\\user")

        result = classify_task(
            row=row,
            meta={},
            runas="DOMAIN\\user",
            rel_path="Tasks\\Test",
            hv=None,
            show_unsaved_creds=False,
            include_local=False,
        )

        assert result.task_type == "TASK"

    def test_returns_tier0_for_tier0_user(self):
        """Should return TIER-0 for Tier-0 user in BloodHound."""
        row = self._make_task_row("DOMAIN\\admin")

        mock_hv = MagicMock()
        mock_hv.loaded = True
        mock_hv.check_tier0.return_value = (True, ["Domain Admins member"])
        mock_hv.check_highvalue.return_value = False
        mock_hv.analyze_password_age.return_value = ("UNKNOWN", None)  # Fix: return tuple

        result = classify_task(
            row=row,
            meta={},
            runas="DOMAIN\\admin",
            rel_path="Tasks\\Test",
            hv=mock_hv,
            show_unsaved_creds=False,
            include_local=False,
        )

        assert result.task_type == "TIER-0"
        assert "Domain Admins member" in result.reason

    def test_uses_ldap_tier0_cache(self):
        """Should use LDAP tier0_cache when BloodHound not available."""
        row = self._make_task_row("DOMAIN\\admin")

        tier0_cache = {"admin": (True, ["Domain Admins", "Administrators"])}

        result = classify_task(
            row=row,
            meta={},
            runas="DOMAIN\\admin",
            rel_path="Tasks\\Test",
            hv=None,
            show_unsaved_creds=False,
            include_local=False,
            tier0_cache=tier0_cache,
        )

        assert result.task_type == "TIER-0"
        assert "Domain Admins" in result.reason

    def test_uses_resolved_runas_for_sid_in_tier0_cache(self):
        """Should use resolved_runas for tier0_cache lookup when runas is a SID.

        This test verifies the fix for the issue where tasks with SID-based runas
        values (instead of username) were not being classified as TIER-0 even when
        the resolved username was in the tier0_cache.
        """
        row = self._make_task_row("S-1-5-21-1234567890-1234567890-1234567890-500")

        # tier0_cache is keyed by lowercase username
        tier0_cache = {"adm-service": (True, ["Domain Admins", "Enterprise Admins"])}

        result = classify_task(
            row=row,
            meta={},
            runas="S-1-5-21-1234567890-1234567890-1234567890-500",
            rel_path="Tasks\\Test",
            hv=None,
            show_unsaved_creds=False,
            include_local=False,
            tier0_cache=tier0_cache,
            resolved_runas="DOMAIN\\adm-service",  # SID resolved to this username
        )

        assert result.task_type == "TIER-0"
        assert "Domain Admins" in result.reason
        assert "Enterprise Admins" in result.reason

    def test_sid_without_resolved_runas_not_tier0(self):
        """When runas is a SID and no resolved_runas provided, should not match tier0_cache."""
        row = self._make_task_row("S-1-5-21-1234567890-1234567890-1234567890-500")

        # tier0_cache is keyed by lowercase username - SID won't match
        tier0_cache = {"adm-service": (True, ["Domain Admins"])}

        result = classify_task(
            row=row,
            meta={},
            runas="S-1-5-21-1234567890-1234567890-1234567890-500",
            rel_path="Tasks\\Test",
            hv=None,
            show_unsaved_creds=False,
            include_local=False,
            tier0_cache=tier0_cache,
            resolved_runas=None,  # No resolved username available
        )

        # Without resolved_runas, the SID won't match "adm-service" in tier0_cache
        assert result.task_type == "TASK"


class TestGetTaskDateForAnalysis:
    """Tests for _get_task_date_for_analysis function."""

    def test_prefers_explicit_date(self):
        """Should prefer explicit date over start_boundary."""
        meta = {
            "date": "2023-06-15T12:00:00",
            "start_boundary": "2023-01-01T08:00:00",
        }

        date, is_fallback = _get_task_date_for_analysis(meta)

        assert date == "2023-06-15T12:00:00"
        assert is_fallback is False

    def test_falls_back_to_start_boundary(self):
        """Should fall back to start_boundary if no date."""
        meta = {"start_boundary": "2023-01-01T08:00:00"}

        date, is_fallback = _get_task_date_for_analysis(meta)

        assert date == "2023-01-01T08:00:00"
        assert is_fallback is True

    def test_returns_none_for_empty_meta(self):
        """Should return None if no date information."""
        date, is_fallback = _get_task_date_for_analysis({})

        assert date is None
        assert is_fallback is False


class TestAnalyzePasswordAge:
    """Tests for _analyze_password_age function."""

    def test_returns_none_without_hv(self):
        """Should return None if no HighValueLoader."""
        result = _analyze_password_age(None, "user", {}, "path")
        assert result is None

    def test_returns_none_when_hv_not_loaded(self):
        """Should return None if hv is not loaded."""
        mock_hv = MagicMock()
        mock_hv.loaded = False

        result = _analyze_password_age(mock_hv, "user", {}, "path")
        assert result is None

