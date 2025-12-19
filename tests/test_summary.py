"""
Tests for taskhound.output.summary module.
"""

from unittest.mock import MagicMock, patch

from taskhound.output.summary import print_decrypted_credentials, print_summary_table


class TestPrintSummaryTable:
    """Tests for print_summary_table function."""

    def test_empty_rows(self):
        """Test with empty rows list."""
        # Should not raise
        print_summary_table([])

    @patch("taskhound.output.summary.rich_summary_table")
    def test_single_host_single_task(self, mock_table):
        """Test with one host and one task."""
        rows = [
            {"host": "DC01.lab.local", "type": "TASK", "reason": ""}
        ]

        print_summary_table(rows)
        mock_table.assert_called_once()
        call_args = mock_table.call_args[0][0]
        assert "DC01.lab.local" in call_args
        assert call_args["DC01.lab.local"]["normal"] == 1

    @patch("taskhound.output.summary.rich_summary_table")
    def test_tier0_task_counted(self, mock_table):
        """Test that TIER-0 tasks are counted correctly."""
        rows = [
            {"host": "DC01.lab.local", "type": "TIER-0", "reason": "DA member"}
        ]

        print_summary_table(rows)
        call_args = mock_table.call_args[0][0]
        assert call_args["DC01.lab.local"]["tier0"] == 1

    @patch("taskhound.output.summary.rich_summary_table")
    def test_priv_task_counted(self, mock_table):
        """Test that PRIV tasks are counted correctly."""
        rows = [
            {"host": "DC01.lab.local", "type": "PRIV", "reason": "High value"}
        ]

        print_summary_table(rows)
        call_args = mock_table.call_args[0][0]
        assert call_args["DC01.lab.local"]["privileged"] == 1

    @patch("taskhound.output.summary.rich_summary_table")
    def test_failure_task_status(self, mock_table):
        """Test that FAILURE tasks set status correctly."""
        rows = [
            {"host": "DC01.lab.local", "type": "FAILURE", "reason": "Access denied"}
        ]

        print_summary_table(rows)
        call_args = mock_table.call_args[0][0]
        assert call_args["DC01.lab.local"]["status"] == "[-]"
        assert call_args["DC01.lab.local"]["failure_reason"] == "Access denied"

    @patch("taskhound.output.summary.rich_summary_table")
    def test_multiple_hosts(self, mock_table):
        """Test with multiple hosts."""
        rows = [
            {"host": "DC01.lab.local", "type": "TASK", "reason": ""},
            {"host": "DC02.lab.local", "type": "TIER-0", "reason": ""},
            {"host": "DC01.lab.local", "type": "PRIV", "reason": ""},
        ]

        print_summary_table(rows)
        call_args = mock_table.call_args[0][0]
        assert "DC01.lab.local" in call_args
        assert "DC02.lab.local" in call_args
        assert call_args["DC01.lab.local"]["normal"] == 1
        assert call_args["DC01.lab.local"]["privileged"] == 1
        assert call_args["DC02.lab.local"]["tier0"] == 1

    @patch("taskhound.output.summary.rich_summary_table")
    def test_taskrow_objects(self, mock_table):
        """Test with TaskRow objects (has to_dict method)."""
        mock_row = MagicMock()
        mock_row.to_dict.return_value = {
            "host": "DC01.lab.local",
            "type": "TASK",
            "reason": ""
        }

        print_summary_table([mock_row])
        mock_table.assert_called_once()

    @patch("taskhound.output.summary.rich_summary_table")
    def test_with_has_tier0_detection(self, mock_table):
        """Test that has_tier0_detection flag is passed through."""
        rows = [{"host": "DC01", "type": "TASK", "reason": ""}]

        print_summary_table(rows, has_tier0_detection=True)
        mock_table.assert_called_once()
        kwargs = mock_table.call_args[1]
        assert kwargs["has_hv_data"] is True

    @patch("taskhound.output.summary.rich_summary_table")
    def test_with_hv_data_flag(self, mock_table):
        """Test that has_hv_data flag is passed through."""
        rows = [{"host": "DC01", "type": "TASK", "reason": ""}]

        print_summary_table(rows, has_hv_data=True)
        mock_table.assert_called_once()
        kwargs = mock_table.call_args[1]
        assert kwargs["has_hv_data"] is True


class TestPrintDecryptedCredentials:
    """Tests for print_decrypted_credentials function."""

    def test_empty_rows(self):
        """Test with empty rows returns 0."""
        result = print_decrypted_credentials([])
        assert result == 0

    def test_no_decrypted_passwords(self):
        """Test with rows but no decrypted passwords."""
        rows = [
            {"host": "DC01", "runas": "DOMAIN\\User", "path": "\\Task1"}
        ]
        result = print_decrypted_credentials(rows)
        assert result == 0

    @patch("taskhound.output.summary.console")
    def test_single_decrypted_password(self, mock_console):
        """Test with one decrypted password."""
        rows = [
            {
                "host": "DC01.lab.local",
                "runas": "DOMAIN\\jsmith",
                "path": "\\Tasks\\BackupTask",
                "decrypted_password": "Secret123!",
                "type": "PRIV",
            }
        ]

        result = print_decrypted_credentials(rows)
        assert result == 1

    @patch("taskhound.output.summary.console")
    def test_multiple_decrypted_passwords(self, mock_console):
        """Test with multiple decrypted passwords."""
        rows = [
            {
                "host": "DC01",
                "runas": "DOMAIN\\user1",
                "path": "\\Task1",
                "decrypted_password": "Pass1",
                "type": "TASK",
            },
            {
                "host": "DC01",
                "runas": "DOMAIN\\user2",
                "path": "\\Task2",
                "decrypted_password": "Pass2",
                "type": "TIER-0",
            },
            {
                "host": "DC02",
                "runas": "DOMAIN\\user3",
                "path": "\\Task3",
                "decrypted_password": "Pass3",
                "type": "PRIV",
            },
        ]

        result = print_decrypted_credentials(rows)
        assert result == 3

    @patch("taskhound.output.summary.console")
    def test_with_resolved_runas_sid(self, mock_console):
        """Test that resolved_runas is used for SID display."""
        rows = [
            {
                "host": "DC01",
                "runas": "S-1-5-21-123-456-789-1001",
                "resolved_runas": "DOMAIN\\jsmith",
                "path": "\\Task1",
                "decrypted_password": "Secret",
                "type": "PRIV",
            }
        ]

        result = print_decrypted_credentials(rows)
        assert result == 1
        # Check that resolved username was used in output
        # The display_runas should be "DOMAIN\\jsmith (S-1-5-21-123-456-789-1001)"

    @patch("taskhound.output.summary.console")
    def test_with_taskrow_objects(self, mock_console):
        """Test with TaskRow objects."""
        mock_row = MagicMock()
        mock_row.to_dict.return_value = {
            "host": "DC01",
            "runas": "DOMAIN\\User",
            "path": "\\Task1",
            "decrypted_password": "Password",
            "type": "TASK",
        }

        result = print_decrypted_credentials([mock_row])
        assert result == 1

    @patch("taskhound.output.summary.console")
    def test_grouped_by_host(self, mock_console):
        """Test that credentials are grouped by host."""
        rows = [
            {
                "host": "DC01",
                "runas": "user1",
                "path": "\\Task1",
                "decrypted_password": "p1",
                "type": "TASK",
            },
            {
                "host": "DC02",
                "runas": "user2",
                "path": "\\Task2",
                "decrypted_password": "p2",
                "type": "TASK",
            },
            {
                "host": "DC01",
                "runas": "user3",
                "path": "\\Task3",
                "decrypted_password": "p3",
                "type": "TASK",
            },
        ]

        result = print_decrypted_credentials(rows)
        assert result == 3


class TestMixedRows:
    """Tests with mixed rows (with and without credentials)."""

    @patch("taskhound.output.summary.console")
    def test_filters_rows_without_password(self, mock_console):
        """Test that rows without decrypted_password are filtered."""
        rows = [
            {
                "host": "DC01",
                "runas": "user1",
                "path": "\\Task1",
                "type": "TASK",
            },  # No password
            {
                "host": "DC01",
                "runas": "user2",
                "path": "\\Task2",
                "decrypted_password": "Found!",
                "type": "PRIV",
            },  # Has password
            {
                "host": "DC01",
                "runas": "user3",
                "path": "\\Task3",
                "decrypted_password": None,
                "type": "TASK",
            },  # Password is None
            {
                "host": "DC01",
                "runas": "user4",
                "path": "\\Task4",
                "decrypted_password": "",
                "type": "TASK",
            },  # Password is empty string
        ]

        result = print_decrypted_credentials(rows)
        # Only user2's row has a truthy decrypted_password
        assert result == 1
