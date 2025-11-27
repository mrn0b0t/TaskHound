"""
Test suite for output summary functions.

Tests cover:
- print_summary_table function
- print_decrypted_credentials function
- TaskRow object handling
"""

import pytest
from unittest.mock import MagicMock, patch

from taskhound.output.summary import print_summary_table, print_decrypted_credentials


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def sample_task_dict():
    """Sample task as dictionary"""
    return {
        "host": "DC01.example.com",
        "path": "\\BackupTask",
        "type": "PRIV",
        "runas": "EXAMPLE\\backupuser",
        "reason": ""
    }


@pytest.fixture
def sample_task_object():
    """Sample task as object with to_dict method"""
    task = MagicMock()
    task.to_dict.return_value = {
        "host": "WS01.example.com",
        "path": "\\MaintTask",
        "type": "TASK",
        "runas": "SYSTEM",
        "reason": ""
    }
    return task


@pytest.fixture
def task_with_decrypted_password():
    """Task with decrypted password"""
    return {
        "host": "DC01.example.com",
        "path": "\\BackupTask",
        "type": "PRIV",
        "runas": "EXAMPLE\\svcaccount",
        "decrypted_password": "SecretP@ss123",
        "reason": ""
    }


@pytest.fixture
def tier0_task():
    """TIER-0 task"""
    return {
        "host": "DC01.example.com",
        "path": "\\AdminTask",
        "type": "TIER-0",
        "runas": "DOMAIN\\admin",
        "reason": ""
    }


@pytest.fixture
def failure_task():
    """Failure task"""
    return {
        "host": "WS02.example.com",
        "path": "",
        "type": "FAILURE",
        "runas": "",
        "reason": "Access denied"
    }


# ============================================================================
# Unit Tests: print_summary_table
# ============================================================================


class TestPrintSummaryTable:
    """Tests for print_summary_table function"""

    @patch('taskhound.output.summary.rich_summary_table')
    def test_empty_rows_no_output(self, mock_rich_table):
        """Should not output anything for empty rows"""
        print_summary_table([])
        
        mock_rich_table.assert_not_called()

    @patch('taskhound.output.summary.rich_summary_table')
    def test_single_priv_task(self, mock_rich_table, sample_task_dict):
        """Should aggregate single privileged task"""
        print_summary_table([sample_task_dict])
        
        mock_rich_table.assert_called_once()
        host_stats = mock_rich_table.call_args[0][0]
        assert "DC01.example.com" in host_stats
        assert host_stats["DC01.example.com"]["privileged"] == 1
        assert host_stats["DC01.example.com"]["tier0"] == 0
        assert host_stats["DC01.example.com"]["normal"] == 0

    @patch('taskhound.output.summary.rich_summary_table')
    def test_tier0_task(self, mock_rich_table, tier0_task):
        """Should correctly count TIER-0 tasks"""
        print_summary_table([tier0_task])
        
        mock_rich_table.assert_called_once()
        host_stats = mock_rich_table.call_args[0][0]
        assert host_stats["DC01.example.com"]["tier0"] == 1

    @patch('taskhound.output.summary.rich_summary_table')
    def test_normal_task(self, mock_rich_table):
        """Should correctly count normal tasks"""
        task = {"host": "WS01", "type": "TASK", "reason": ""}
        print_summary_table([task])
        
        mock_rich_table.assert_called_once()
        host_stats = mock_rich_table.call_args[0][0]
        assert host_stats["WS01"]["normal"] == 1

    @patch('taskhound.output.summary.rich_summary_table')
    def test_failure_task(self, mock_rich_table, failure_task):
        """Should correctly handle failure tasks"""
        print_summary_table([failure_task])
        
        mock_rich_table.assert_called_once()
        host_stats = mock_rich_table.call_args[0][0]
        assert host_stats["WS02.example.com"]["status"] == "[-]"
        assert host_stats["WS02.example.com"]["failure_reason"] == "Access denied"

    @patch('taskhound.output.summary.rich_summary_table')
    def test_multiple_hosts(self, mock_rich_table, sample_task_dict, tier0_task):
        """Should aggregate tasks from multiple hosts"""
        # Add another task for WS01
        ws_task = {"host": "WS01.example.com", "type": "TASK", "reason": ""}
        
        print_summary_table([sample_task_dict, tier0_task, ws_task])
        
        mock_rich_table.assert_called_once()
        host_stats = mock_rich_table.call_args[0][0]
        # DC01 has both priv and tier0
        assert "DC01.example.com" in host_stats
        assert host_stats["DC01.example.com"]["privileged"] == 1
        assert host_stats["DC01.example.com"]["tier0"] == 1
        # WS01 has normal task
        assert "WS01.example.com" in host_stats
        assert host_stats["WS01.example.com"]["normal"] == 1

    @patch('taskhound.output.summary.rich_summary_table')
    def test_task_row_object(self, mock_rich_table, sample_task_object):
        """Should handle TaskRow objects with to_dict method"""
        print_summary_table([sample_task_object])
        
        mock_rich_table.assert_called_once()
        host_stats = mock_rich_table.call_args[0][0]
        assert "WS01.example.com" in host_stats

    @patch('taskhound.output.summary.rich_summary_table')
    def test_backup_dir_passed(self, mock_rich_table, sample_task_dict):
        """Should pass backup_dir to rich_summary_table"""
        print_summary_table([sample_task_dict], backup_dir="/tmp/backup")
        
        call_kwargs = mock_rich_table.call_args[1]
        assert call_kwargs["backup_dir"] == "/tmp/backup"

    @patch('taskhound.output.summary.rich_summary_table')
    def test_has_hv_data_passed(self, mock_rich_table, sample_task_dict):
        """Should pass has_hv_data flag to rich_summary_table"""
        print_summary_table([sample_task_dict], has_hv_data=True)
        
        call_kwargs = mock_rich_table.call_args[1]
        assert call_kwargs["has_hv_data"] is True


# ============================================================================
# Unit Tests: print_decrypted_credentials
# ============================================================================


class TestPrintDecryptedCredentials:
    """Tests for print_decrypted_credentials function"""

    @patch('taskhound.output.summary.console')
    def test_no_decrypted_passwords(self, mock_console):
        """Should return 0 when no decrypted passwords"""
        task = {"host": "DC01", "path": "\\Task", "type": "TASK", "runas": "SYSTEM"}
        
        result = print_decrypted_credentials([task])
        
        assert result == 0

    @patch('taskhound.output.summary.console')
    def test_single_decrypted_password(self, mock_console, task_with_decrypted_password):
        """Should return 1 and print credentials"""
        result = print_decrypted_credentials([task_with_decrypted_password])
        
        assert result == 1
        # Should call console.print multiple times
        assert mock_console.print.call_count > 0

    @patch('taskhound.output.summary.console')
    def test_multiple_decrypted_passwords(self, mock_console, task_with_decrypted_password):
        """Should return count of all decrypted credentials"""
        task2 = task_with_decrypted_password.copy()
        task2["host"] = "WS01.example.com"
        task2["decrypted_password"] = "AnotherP@ss"
        
        result = print_decrypted_credentials([task_with_decrypted_password, task2])
        
        assert result == 2

    @patch('taskhound.output.summary.console')
    def test_tier0_credential_formatting(self, mock_console):
        """Should format TIER-0 credentials differently"""
        task = {
            "host": "DC01",
            "path": "\\AdminTask",
            "type": "TIER-0",
            "runas": "DOMAIN\\admin",
            "decrypted_password": "AdminP@ss"
        }
        
        result = print_decrypted_credentials([task])
        
        assert result == 1

    @patch('taskhound.output.summary.console')
    def test_resolved_sid_formatting(self, mock_console):
        """Should show both resolved name and SID when available"""
        task = {
            "host": "DC01",
            "path": "\\Task",
            "type": "TASK",
            "runas": "S-1-5-21-12345-67890-11111-1001",
            "resolved_runas": "DOMAIN\\serviceaccount",
            "decrypted_password": "Pass123"
        }
        
        result = print_decrypted_credentials([task])
        
        assert result == 1

    @patch('taskhound.output.summary.console')
    def test_groups_by_host(self, mock_console, task_with_decrypted_password):
        """Should group credentials by host"""
        # Two tasks on same host
        task2 = task_with_decrypted_password.copy()
        task2["path"] = "\\OtherTask"
        task2["decrypted_password"] = "Pass2"
        
        result = print_decrypted_credentials([task_with_decrypted_password, task2])
        
        assert result == 2

    @patch('taskhound.output.summary.console')
    def test_empty_list_returns_zero(self, mock_console):
        """Should return 0 for empty list"""
        result = print_decrypted_credentials([])
        
        assert result == 0

    @patch('taskhound.output.summary.console')
    def test_task_row_object_support(self, mock_console):
        """Should handle TaskRow objects with to_dict method"""
        task = MagicMock()
        task.to_dict.return_value = {
            "host": "DC01",
            "path": "\\Task",
            "type": "PRIV",
            "runas": "DOMAIN\\svc",
            "decrypted_password": "Secret"
        }
        
        result = print_decrypted_credentials([task])
        
        assert result == 1
        task.to_dict.assert_called_once()

    @patch('taskhound.output.summary.console')
    def test_mixed_with_and_without_passwords(self, mock_console, task_with_decrypted_password):
        """Should only count tasks with decrypted passwords"""
        task_no_password = {
            "host": "WS01",
            "path": "\\Task",
            "type": "TASK",
            "runas": "SYSTEM"
        }
        
        result = print_decrypted_credentials([task_with_decrypted_password, task_no_password])
        
        assert result == 1
