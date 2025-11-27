"""
Test printer utility functions in taskhound.output.printer.
"""

from unittest.mock import MagicMock, patch

from taskhound.output.printer import format_block, format_trigger_info, print_results


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


class TestFormatTriggerInfoExtended:
    """Extended trigger info formatting tests."""

    def test_calendar_with_hours_interval(self):
        """Test calendar trigger with hours interval."""
        meta = {
            "trigger_type": "Calendar",
            "interval": "PT2H",
        }
        result = format_trigger_info(meta)
        assert "every 2 hours" in result

    def test_calendar_with_seconds_interval(self):
        """Test calendar trigger with seconds interval."""
        meta = {
            "trigger_type": "Calendar",
            "interval": "PT30S",
        }
        result = format_trigger_info(meta)
        assert "every 30 seconds" in result

    def test_calendar_with_days_interval(self):
        """Test calendar trigger with days interval."""
        meta = {
            "trigger_type": "Calendar",
            "days_interval": "3",
        }
        result = format_trigger_info(meta)
        assert "every 3 days" in result

    def test_calendar_daily(self):
        """Test calendar trigger that runs daily."""
        meta = {
            "trigger_type": "Calendar",
            "days_interval": "1",
        }
        result = format_trigger_info(meta)
        assert "daily" in result

    def test_calendar_with_invalid_date(self):
        """Test calendar trigger with unparseable date."""
        meta = {
            "trigger_type": "Calendar",
            "start_boundary": "not-a-valid-date",
        }
        result = format_trigger_info(meta)
        assert "starts not-a-valid-date" in result

    def test_calendar_with_plural_days_duration(self):
        """Test calendar trigger with multi-day duration."""
        meta = {
            "trigger_type": "Calendar",
            "duration": "P3D",
        }
        result = format_trigger_info(meta)
        assert "for 3 days" in result

    def test_calendar_with_complex_duration(self):
        """Test calendar trigger with complex time duration."""
        meta = {
            "trigger_type": "Calendar",
            "duration": "PT12H30M",
        }
        result = format_trigger_info(meta)
        # Complex durations keep original format
        assert "PT12H30M" in result

    def test_time_with_invalid_date(self):
        """Test time trigger with unparseable date."""
        meta = {
            "trigger_type": "Time",
            "start_boundary": "invalid-date",
        }
        result = format_trigger_info(meta)
        assert "at invalid-date" in result

    def test_trigger_type_only(self):
        """Test trigger with just type, no details."""
        meta = {"trigger_type": "Logon"}
        result = format_trigger_info(meta)
        assert result == "Logon"


class TestFormatBlockConcise:
    """Tests for concise output mode."""

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_concise_basic(self, mock_resolve):
        """Test basic concise output."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        lines = format_block(
            kind="TASK",
            rel_path="Tasks\\MyTask",
            runas="DOMAIN\\User",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            concise=True,
        )

        assert len(lines) == 1
        assert "[TASK] DOMAIN\\User | Tasks\\MyTask | cmd.exe" in lines[0]

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_concise_with_reason(self, mock_resolve):
        """Test concise output with reason."""
        mock_resolve.return_value = ("DOMAIN\\Admin", "Admin")

        lines = format_block(
            kind="PRIV",
            rel_path="Tasks\\AdminTask",
            runas="DOMAIN\\Admin",
            what="powershell.exe",
            author="Admin",
            date="2023-01-01",
            extra_reason="High Value Target",
            concise=True,
        )

        assert len(lines) == 1
        assert "High Value Target" in lines[0]

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_concise_with_decrypted_creds(self, mock_resolve):
        """Test concise output shows password inline."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        mock_cred = MagicMock()
        mock_cred.username = "DOMAIN\\User"
        mock_cred.password = "P@ssw0rd!"

        lines = format_block(
            kind="PRIV",
            rel_path="Tasks\\UserTask",
            runas="DOMAIN\\User",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            decrypted_creds=[mock_cred],
            concise=True,
        )

        assert len(lines) == 1
        assert "PWD: P@ssw0rd!" in lines[0]

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_concise_cred_match_without_domain(self, mock_resolve):
        """Test concise credential matching when runas has no domain."""
        mock_resolve.return_value = ("jsmith", "jsmith")

        mock_cred = MagicMock()
        mock_cred.username = "DOMAIN\\jsmith"
        mock_cred.password = "Secret123"

        lines = format_block(
            kind="TIER-0",
            rel_path="Tasks\\Task1",
            runas="jsmith",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            decrypted_creds=[mock_cred],
            concise=True,
        )

        assert "PWD: Secret123" in lines[0]

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_concise_cred_match_reversed_domain(self, mock_resolve):
        """Test concise credential matching when cred has no domain but runas does."""
        mock_resolve.return_value = ("DOMAIN\\jsmith", "jsmith")

        mock_cred = MagicMock()
        mock_cred.username = "jsmith"
        mock_cred.password = "Secret456"

        lines = format_block(
            kind="TIER-0",
            rel_path="Tasks\\Task1",
            runas="DOMAIN\\jsmith",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            decrypted_creds=[mock_cred],
            concise=True,
        )

        assert "PWD: Secret456" in lines[0]


class TestFormatBlockWithResolvedRunas:
    """Tests for pre-resolved runas handling."""

    def test_resolved_runas_with_sid(self):
        """Test that resolved_runas is used with SID display."""
        lines = format_block(
            kind="TASK",
            rel_path="Tasks\\MyTask",
            runas="S-1-5-21-123-456-789-1001",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            resolved_runas="DOMAIN\\jsmith",
        )

        text = "\n".join(lines)
        # Should show resolved name with SID
        assert "DOMAIN\\jsmith (S-1-5-21-123-456-789-1001)" in text

    def test_resolved_runas_non_sid(self):
        """Test that resolved_runas with non-SID just shows original."""
        lines = format_block(
            kind="TASK",
            rel_path="Tasks\\MyTask",
            runas="DOMAIN\\User",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            resolved_runas="DOMAIN\\User",
        )

        text = "\n".join(lines)
        assert "RunAs   : DOMAIN\\User" in text
        # Should not show SID format
        assert "(S-1-5-" not in text


class TestFormatBlockCredValidation:
    """Tests for credential validation display."""

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_cred_validation_valid_hijackable(self, mock_resolve):
        """Test credential validation showing valid hijackable."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        lines = format_block(
            kind="PRIV",
            rel_path="Tasks\\Task1",
            runas="DOMAIN\\User",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            cred_validation={
                "cred_status": "valid",
                "cred_password_valid": True,
                "cred_hijackable": True,
            },
        )

        text = "\n".join(lines)
        assert "[+] VALID (hijackable)" in text

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_cred_validation_valid_restricted(self, mock_resolve):
        """Test credential validation showing valid but restricted."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        lines = format_block(
            kind="PRIV",
            rel_path="Tasks\\Task1",
            runas="DOMAIN\\User",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            cred_validation={
                "cred_status": "logon_as_batch",
                "cred_password_valid": True,
                "cred_hijackable": False,
                "cred_detail": "User has SeLogonAsBatchJob right",
            },
        )

        text = "\n".join(lines)
        assert "[+] VALID (restricted: logon_as_batch)" in text
        assert "Cred Detail     : User has SeLogonAsBatchJob right" in text

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_cred_validation_invalid(self, mock_resolve):
        """Test credential validation showing invalid password."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        lines = format_block(
            kind="PRIV",
            rel_path="Tasks\\Task1",
            runas="DOMAIN\\User",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            cred_validation={
                "cred_status": "invalid",
                "cred_password_valid": False,
            },
        )

        text = "\n".join(lines)
        assert "[-] INVALID (wrong password)" in text

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_cred_validation_blocked(self, mock_resolve):
        """Test credential validation showing blocked account."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        lines = format_block(
            kind="PRIV",
            rel_path="Tasks\\Task1",
            runas="DOMAIN\\User",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            cred_validation={
                "cred_status": "blocked",
            },
        )

        text = "\n".join(lines)
        assert "[-] BLOCKED (account disabled/expired)" in text

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_cred_validation_unknown_with_good_password(self, mock_resolve):
        """Test unknown validation with good password analysis falls back."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        lines = format_block(
            kind="PRIV",
            rel_path="Tasks\\Task1",
            runas="DOMAIN\\User",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            password_analysis="GOOD - saved after password change",
            cred_validation={
                "cred_status": "unknown",
                "cred_return_code": "0x80070005",
            },
        )

        text = "\n".join(lines)
        assert "[+] LIKELY VALID (task never ran, but password newer than pwdLastSet)" in text

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_cred_validation_unknown_with_bad_password(self, mock_resolve):
        """Test unknown validation with bad password analysis."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        lines = format_block(
            kind="PRIV",
            rel_path="Tasks\\Task1",
            runas="DOMAIN\\User",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            password_analysis="BAD - saved before password change",
            cred_validation={
                "cred_status": "unknown",
                "cred_return_code": "0x80070005",
            },
        )

        text = "\n".join(lines)
        assert "[-] LIKELY INVALID (task never ran, password older than pwdLastSet)" in text

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_cred_validation_unknown_no_analysis(self, mock_resolve):
        """Test unknown validation with no password analysis."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        lines = format_block(
            kind="PRIV",
            rel_path="Tasks\\Task1",
            runas="DOMAIN\\User",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            cred_validation={
                "cred_status": "unknown",
                "cred_return_code": "0x80070005",
            },
        )

        text = "\n".join(lines)
        assert "[?] UNKNOWN - task never ran (0x80070005)" in text

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_cred_validation_other_status(self, mock_resolve):
        """Test credential validation with other status."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        lines = format_block(
            kind="PRIV",
            rel_path="Tasks\\Task1",
            runas="DOMAIN\\User",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            cred_validation={
                "cred_status": "custom_status",
                "cred_return_code": "0x12345678",
            },
        )

        text = "\n".join(lines)
        assert "[?] custom_status (0x12345678)" in text


class TestFormatBlockTaskKind:
    """Tests for TASK kind specific behavior."""

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_task_with_password_analysis(self, mock_resolve):
        """Test TASK kind with password analysis."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        lines = format_block(
            kind="TASK",
            rel_path="Tasks\\RegularTask",
            runas="DOMAIN\\User",
            what="notepad.exe",
            author="Admin",
            date="2023-01-01",
            password_analysis="GOOD - password valid",
        )

        text = "\n".join(lines)
        assert "Password Analysis : GOOD - password valid" in text

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_task_with_cred_validation(self, mock_resolve):
        """Test TASK kind with credential validation."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        lines = format_block(
            kind="TASK",
            rel_path="Tasks\\RegularTask",
            runas="DOMAIN\\User",
            what="notepad.exe",
            author="Admin",
            date="2023-01-01",
            cred_validation={
                "cred_status": "valid",
                "cred_password_valid": True,
                "cred_hijackable": True,
            },
        )

        text = "\n".join(lines)
        assert "[+] VALID (hijackable)" in text


class TestFormatBlockDecryptedCredMatching:
    """Tests for credential matching in verbose mode."""

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_cred_match_with_resolved_sid(self, mock_resolve):
        """Test credential matching uses resolved_runas from SID."""
        mock_resolve.return_value = ("jsmith (S-1-5-21-123-456-789-1001)", "jsmith")

        mock_cred = MagicMock()
        mock_cred.username = "DOMAIN\\jsmith"
        mock_cred.password = "FoundPassword!"

        lines = format_block(
            kind="PRIV",
            rel_path="Tasks\\SIDTask",
            runas="S-1-5-21-123-456-789-1001",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            decrypted_creds=[mock_cred],
            resolved_runas="jsmith",
        )

        text = "\n".join(lines)
        assert "Decrypted Password : FoundPassword!" in text

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_no_creds_shows_next_step(self, mock_resolve):
        """Test that PRIV without creds shows next step message."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        lines = format_block(
            kind="PRIV",
            rel_path="Tasks\\NoCreds",
            runas="DOMAIN\\User",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
        )

        text = "\n".join(lines)
        assert "Next Step: Try DPAPI Dump / Task Manipulation" in text

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_no_saved_creds_reason_hides_next_step(self, mock_resolve):
        """Test that 'no saved credentials' reason hides next step."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        lines = format_block(
            kind="PRIV",
            rel_path="Tasks\\NoCreds",
            runas="DOMAIN\\User",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            extra_reason="No saved credentials found",
        )

        text = "\n".join(lines)
        assert "Next Step" not in text


class TestPrintResults:
    """Tests for print_results function."""

    @patch("taskhound.output.printer.log_utils._VERBOSE", True)
    @patch("taskhound.output.printer.log_utils._DEBUG", False)
    @patch("taskhound.output.printer.console")
    def test_print_results_verbose(self, mock_console):
        """Test print_results in verbose mode."""
        lines = [
            "[TIER-0] Test task",
            "[PRIV] Privileged task",
            "[TASK] Normal task",
        ]
        print_results(lines)
        assert mock_console.print.call_count == 3

    @patch("taskhound.output.printer.log_utils._VERBOSE", False)
    @patch("taskhound.output.printer.log_utils._DEBUG", False)
    @patch("taskhound.output.printer.console")
    def test_print_results_not_verbose(self, mock_console):
        """Test print_results when not verbose."""
        lines = ["[TASK] Test"]
        print_results(lines)
        mock_console.print.assert_not_called()

    @patch("taskhound.output.printer.log_utils._VERBOSE", True)
    @patch("taskhound.output.printer.console")
    def test_print_results_empty(self, mock_console):
        """Test print_results with empty list."""
        print_results([])
        mock_console.print.assert_not_called()

    @patch("taskhound.output.printer.log_utils._VERBOSE", True)
    @patch("taskhound.output.printer.console")
    def test_print_results_colorizes_tier0(self, mock_console):
        """Test that TIER-0 tags are colorized."""
        lines = ["[TIER-0] Critical task"]
        print_results(lines)
        call_args = mock_console.print.call_args[0][0]
        assert "bold red" in call_args

    @patch("taskhound.output.printer.log_utils._VERBOSE", True)
    @patch("taskhound.output.printer.console")
    def test_print_results_colorizes_priv(self, mock_console):
        """Test that PRIV tags are colorized."""
        lines = ["[PRIV] High value task"]
        print_results(lines)
        call_args = mock_console.print.call_args[0][0]
        assert "bold yellow" in call_args

    @patch("taskhound.output.printer.log_utils._VERBOSE", True)
    @patch("taskhound.output.printer.console")
    def test_print_results_colorizes_task(self, mock_console):
        """Test that TASK tags are colorized."""
        lines = ["[TASK] Regular task"]
        print_results(lines)
        call_args = mock_console.print.call_args[0][0]
        assert "bold green" in call_args


class TestFormatBlockMeta:
    """Tests for trigger metadata handling."""

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_format_block_with_trigger(self, mock_resolve):
        """Test block with trigger information."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        lines = format_block(
            kind="TASK",
            rel_path="Tasks\\ScheduledTask",
            runas="DOMAIN\\User",
            what="script.ps1",
            author="Admin",
            date="2023-01-01",
            meta={
                "trigger_type": "Calendar",
                "start_boundary": "2023-06-01T08:00:00",
            },
        )

        text = "\n".join(lines)
        assert "Trigger : Calendar (starts 2023-06-01 08:00)" in text

    @patch("taskhound.output.printer.format_runas_with_sid_resolution")
    def test_format_block_no_trigger(self, mock_resolve):
        """Test block with empty trigger metadata."""
        mock_resolve.return_value = ("DOMAIN\\User", "User")

        lines = format_block(
            kind="TASK",
            rel_path="Tasks\\RegularTask",
            runas="DOMAIN\\User",
            what="cmd.exe",
            author="Admin",
            date="2023-01-01",
            meta={},
        )

        text = "\n".join(lines)
        assert "Trigger :" not in text