"""
Test printer utility functions in taskhound.output.printer.
"""

from unittest.mock import MagicMock, patch

from taskhound.output.printer import format_block, format_trigger_info


class TestPrinter:
    def test_format_trigger_info_calendar(self):
        """Test formatting calendar trigger info."""
        meta = {
            "trigger_type": "Calendar",
            "start_boundary": "2023-01-01T12:00:00",
            "interval": "PT5M",
            "duration": "P1D",
        }

        result = format_trigger_info(meta)
        assert "Calendar" in result
        assert "starts 2023-01-01 12:00" in result
        assert "every 5 minutes" in result
        assert "for 1 day" in result

    def test_format_trigger_info_time(self):
        """Test formatting time trigger info."""
        meta = {"trigger_type": "Time", "start_boundary": "2023-01-01T12:00:00"}

        result = format_trigger_info(meta)
        assert "Time" in result
        assert "at 2023-01-01 12:00" in result

    def test_format_trigger_info_none(self):
        """Test formatting with no trigger type."""
        assert format_trigger_info({}) is None

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_format_block_basic(self, mock_resolve):
        """Test basic block formatting."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        lines = format_block(
            kind="TASK",
            rel_path="Tasks\\MyTask",
            runas="DOMAIN\\User",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            enabled="True",
        )

        text = "\n".join(lines)
        assert "[TASK] Tasks\\MyTask" in text
        assert "Enabled : True" in text
        assert "RunAs   : DOMAIN\\User" in text
        assert "What    : cmd.exe" in text
        assert "Author  : Admin" in text
        assert "Date    : 2023-01-01" in text

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_format_block_tier0(self, mock_resolve):
        """Test Tier-0 block formatting."""
        mock_resolve.return_value = ("DOMAIN\\Admin", "Admin")

        lines = format_block(
            kind="TIER-0",
            rel_path="Tasks\\AdminTask",
            runas="DOMAIN\\Admin",
            what="powershell.exe",
            author="Admin",
            date="2023-01-01",
            enabled="True",
        )

        text = "\n".join(lines)
        assert "[TIER-0] Tasks\\AdminTask" in text
        assert "Reason  : Tier 0 privileged group membership" in text

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_format_block_with_decrypted_creds(self, mock_resolve):
        """Test block formatting with decrypted credentials."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        # Mock credential object
        mock_cred = MagicMock()
        mock_cred.username = "DOMAIN\\User"
        mock_cred.password = "SecretPassword123!"

        lines = format_block(
            kind="PRIV",
            rel_path="Tasks\\UserTask",
            runas="DOMAIN\\User",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            enabled="True",
            extra_reason="Found saved credentials",
            decrypted_creds=[mock_cred],
        )

        text = "\n".join(lines)
        assert "[PRIV] Tasks\\UserTask" in text
        assert "Decrypted Password : SecretPassword123!" in text
