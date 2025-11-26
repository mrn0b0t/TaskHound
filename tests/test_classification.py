# Tests for task classification logic.

from unittest.mock import MagicMock, patch

from taskhound.classification import (
    ClassificationResult,
    _analyze_password_age,
    _get_task_date_for_analysis,
    classify_task,
)
from taskhound.models.task import TaskRow, TaskType


class TestGetTaskDateForAnalysis:
    """Tests for _get_task_date_for_analysis helper."""

    def test_prefers_explicit_date(self):
        """Should prefer explicit date over start_boundary."""
        meta = {
            "date": "2024-01-15T10:00:00",
            "start_boundary": "2024-06-01T08:00:00",
        }
        date, is_fallback = _get_task_date_for_analysis(meta)
        assert date == "2024-01-15T10:00:00"
        assert is_fallback is False

    def test_falls_back_to_start_boundary(self):
        """Should use start_boundary when date is not available."""
        meta = {
            "start_boundary": "2024-06-01T08:00:00",
        }
        date, is_fallback = _get_task_date_for_analysis(meta)
        assert date == "2024-06-01T08:00:00"
        assert is_fallback is True

    def test_returns_none_when_no_dates(self):
        """Should return None when neither date is available."""
        meta = {}
        date, is_fallback = _get_task_date_for_analysis(meta)
        assert date is None
        assert is_fallback is False

    def test_empty_date_uses_fallback(self):
        """Should use fallback when date is empty string."""
        meta = {
            "date": "",
            "start_boundary": "2024-06-01T08:00:00",
        }
        date, is_fallback = _get_task_date_for_analysis(meta)
        # Empty string is falsy, so should use fallback
        assert date == "2024-06-01T08:00:00"
        assert is_fallback is True


class TestAnalyzePasswordAge:
    """Tests for _analyze_password_age helper."""

    def test_returns_none_when_hv_is_none(self):
        """Should return None when hv is None."""
        result = _analyze_password_age(None, "user@domain.local", {}, "\\Task")
        assert result is None

    def test_returns_none_when_hv_not_loaded(self):
        """Should return None when hv is not loaded."""
        hv = MagicMock()
        hv.loaded = False
        result = _analyze_password_age(hv, "user@domain.local", {}, "\\Task")
        assert result is None

    def test_returns_analysis_when_risk_known(self):
        """Should return analysis when risk level is known."""
        hv = MagicMock()
        hv.loaded = True
        hv.analyze_password_age.return_value = ("HIGH", "Password 180+ days old")

        meta = {"date": "2024-01-01T00:00:00"}
        result = _analyze_password_age(hv, "user@domain.local", meta, "\\Task")

        assert result == "Password 180+ days old"
        hv.analyze_password_age.assert_called_once()

    def test_returns_none_when_risk_unknown(self):
        """Should return None when risk level is UNKNOWN."""
        hv = MagicMock()
        hv.loaded = True
        hv.analyze_password_age.return_value = ("UNKNOWN", None)

        meta = {"date": "2024-01-01T00:00:00"}
        result = _analyze_password_age(hv, "user@domain.local", meta, "\\Task")

        assert result is None


class TestClassifyTask:
    """Tests for classify_task function."""

    def test_tier0_with_stored_credentials(self):
        """Should classify as TIER-0 when tier0 check passes."""
        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (True, ["Domain Admin member"])
        hv.analyze_password_age.return_value = ("HIGH", "Password old")

        row = TaskRow(
            host="host1.domain.local",
            path="\\AdminTask",
            runas="admin@domain.local",
            credentials_hint="stored_credentials",
        )
        meta = {"date": "2024-01-01"}

        result = classify_task(
            row=row,
            meta=meta,
            runas="admin@domain.local",
            rel_path="\\AdminTask",
            hv=hv,
            show_unsaved_creds=False,
            include_local=False,
        )

        assert result.task_type == "TIER-0"
        assert result.reason == "Domain Admin member"
        assert result.password_analysis == "Password old"
        assert result.should_include is True
        assert row.type == TaskType.TIER0.value

    def test_tier0_without_saved_credentials(self):
        """Should note when TIER-0 task has no saved credentials."""
        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (True, ["Domain Admin"])

        row = TaskRow(
            host="host1.domain.local",
            path="\\AdminTask",
            runas="admin@domain.local",
            credentials_hint="no_saved_credentials",
        )
        meta = {}

        result = classify_task(
            row=row,
            meta=meta,
            runas="admin@domain.local",
            rel_path="\\AdminTask",
            hv=hv,
            show_unsaved_creds=True,
            include_local=False,
        )

        assert result.task_type == "TIER-0"
        assert "no saved credentials" in result.reason
        assert "DPAPI dump not applicable" in result.reason

    def test_priv_classification(self):
        """Should classify as PRIV when high-value check passes."""
        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (False, [])
        hv.check_highvalue.return_value = True
        hv.analyze_password_age.return_value = ("MEDIUM", "Password 90 days old")

        row = TaskRow(
            host="host1.domain.local",
            path="\\ServiceTask",
            runas="serviceaccount@domain.local",
            credentials_hint="stored_credentials",
        )
        meta = {"date": "2024-06-01"}

        result = classify_task(
            row=row,
            meta=meta,
            runas="serviceaccount@domain.local",
            rel_path="\\ServiceTask",
            hv=hv,
            show_unsaved_creds=False,
            include_local=False,
        )

        assert result.task_type == "PRIV"
        assert "High Value match" in result.reason
        assert result.should_include is True
        assert row.type == TaskType.PRIV.value

    @patch("taskhound.utils.sid_resolver.looks_like_domain_user")
    def test_regular_task_domain_user(self, mock_looks_like):
        """Should include regular domain user tasks."""
        mock_looks_like.return_value = True

        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (False, [])
        hv.check_highvalue.return_value = False
        hv.analyze_password_age.return_value = ("UNKNOWN", None)

        row = TaskRow(
            host="host1.domain.local",
            path="\\UserTask",
            runas="user@domain.local",
            credentials_hint="stored_credentials",
        )
        meta = {}

        result = classify_task(
            row=row,
            meta=meta,
            runas="user@domain.local",
            rel_path="\\UserTask",
            hv=hv,
            show_unsaved_creds=False,
            include_local=False,
        )

        assert result.task_type == "TASK"
        assert result.should_include is True

    @patch("taskhound.classification.looks_like_domain_user")
    def test_excludes_no_saved_creds_by_default(self, mock_looks_like):
        """Should exclude tasks without saved credentials by default."""
        mock_looks_like.return_value = True

        row = TaskRow(
            host="host1.domain.local",
            path="\\Task",
            runas="user@domain.local",
            credentials_hint="no_saved_credentials",
        )
        meta = {}

        result = classify_task(
            row=row,
            meta=meta,
            runas="user@domain.local",
            rel_path="\\Task",
            hv=None,
            show_unsaved_creds=False,
            include_local=False,
        )

        assert result.should_include is False

    @patch("taskhound.classification.looks_like_domain_user")
    def test_includes_no_saved_creds_when_requested(self, mock_looks_like):
        """Should include tasks without saved credentials when show_unsaved_creds=True."""
        mock_looks_like.return_value = True

        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (False, [])
        hv.check_highvalue.return_value = False

        row = TaskRow(
            host="host1.domain.local",
            path="\\Task",
            runas="user@domain.local",
            credentials_hint="no_saved_credentials",
        )
        meta = {}

        result = classify_task(
            row=row,
            meta=meta,
            runas="user@domain.local",
            rel_path="\\Task",
            hv=hv,
            show_unsaved_creds=True,
            include_local=False,
        )

        assert result.should_include is True

    @patch("taskhound.classification.looks_like_domain_user")
    def test_includes_local_accounts_when_requested(self, mock_looks_like):
        """Should include local accounts when include_local=True."""
        mock_looks_like.return_value = False  # Not a domain user

        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (False, [])
        hv.check_highvalue.return_value = False
        hv.analyze_password_age.return_value = ("UNKNOWN", None)

        row = TaskRow(
            host="host1.domain.local",
            path="\\LocalTask",
            runas="LocalAdmin",
            credentials_hint="stored_credentials",
        )
        meta = {}

        result = classify_task(
            row=row,
            meta=meta,
            runas="LocalAdmin",
            rel_path="\\LocalTask",
            hv=hv,
            show_unsaved_creds=False,
            include_local=True,
        )

        assert result.should_include is True

    @patch("taskhound.classification.looks_like_domain_user")
    def test_excludes_local_accounts_by_default(self, mock_looks_like):
        """Should exclude local accounts by default."""
        mock_looks_like.return_value = False  # Not a domain user

        hv = MagicMock()
        hv.loaded = True
        hv.check_tier0.return_value = (False, [])
        hv.check_highvalue.return_value = False

        row = TaskRow(
            host="host1.domain.local",
            path="\\LocalTask",
            runas="LocalUser",
            credentials_hint=None,
        )
        meta = {}

        result = classify_task(
            row=row,
            meta=meta,
            runas="LocalUser",
            rel_path="\\LocalTask",
            hv=hv,
            show_unsaved_creds=False,
            include_local=False,
        )

        assert result.should_include is False

    def test_no_hv_classification(self):
        """Should work without HighValueLoader (no privilege detection)."""
        row = TaskRow(
            host="host1.domain.local",
            path="\\Task",
            runas="user@domain.local",
            credentials_hint="stored_credentials",
        )
        meta = {}

        with patch("taskhound.classification.looks_like_domain_user", return_value=True):
            result = classify_task(
                row=row,
                meta=meta,
                runas="user@domain.local",
                rel_path="\\Task",
                hv=None,
                show_unsaved_creds=False,
                include_local=False,
            )

        assert result.task_type == "TASK"
        assert result.should_include is True


class TestClassificationResult:
    """Tests for ClassificationResult dataclass."""

    def test_default_values(self):
        """Should have sensible defaults."""
        result = ClassificationResult(task_type="TASK")
        assert result.task_type == "TASK"
        assert result.reason is None
        assert result.password_analysis is None
        assert result.should_include is True

    def test_all_values(self):
        """Should store all provided values."""
        result = ClassificationResult(
            task_type="TIER-0",
            reason="Domain Admin",
            password_analysis="Old password",
            should_include=True,
        )
        assert result.task_type == "TIER-0"
        assert result.reason == "Domain Admin"
        assert result.password_analysis == "Old password"
        assert result.should_include is True
