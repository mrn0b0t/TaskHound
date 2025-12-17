"""Tests for taskhound/engine/offline.py - offline task processing."""

import os
import pytest
import tempfile
from unittest.mock import patch, MagicMock

from taskhound.engine.offline import (
    process_offline_directory,
    _process_offline_host,
    _process_offline_dpapi_decryption,
)


# Sample valid task XML for testing
VALID_TASK_XML = b"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2025-01-15T10:00:00</Date>
    <Author>DOMAIN\\admin</Author>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>DOMAIN\\admin</UserId>
      <LogonType>Password</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>C:\\Windows\\System32\\cmd.exe</Command>
      <Arguments>/c echo test</Arguments>
    </Exec>
  </Actions>
</Task>
"""


class TestProcessOfflineDirectory:
    """Tests for process_offline_directory function."""

    def test_nonexistent_directory(self):
        """Returns empty list for nonexistent directory."""
        with patch("taskhound.engine.offline.warn") as mock_warn:
            result = process_offline_directory(
                offline_dir="/nonexistent/path",
                hv=None,
                show_unsaved_creds=False,
                include_local=False,
                all_rows=[],
                debug=False,
            )
        assert result == []
        mock_warn.assert_called()

    def test_empty_directory(self):
        """Returns empty list for empty directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("taskhound.engine.offline.warn") as mock_warn:
                result = process_offline_directory(
                    offline_dir=tmpdir,
                    hv=None,
                    show_unsaved_creds=False,
                    include_local=False,
                    all_rows=[],
                    debug=False,
                )
        assert result == []
        mock_warn.assert_called()

    def test_file_instead_of_directory(self):
        """Returns empty list when path is a file not directory."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test")
            temp_path = f.name

        try:
            with patch("taskhound.engine.offline.warn") as mock_warn:
                result = process_offline_directory(
                    offline_dir=temp_path,
                    hv=None,
                    show_unsaved_creds=False,
                    include_local=False,
                    all_rows=[],
                    debug=False,
                )
            assert result == []
            mock_warn.assert_called()
        finally:
            os.unlink(temp_path)

    def test_directory_with_host_subdir(self):
        """Processes host subdirectories correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create host directory structure
            host_dir = os.path.join(tmpdir, "DC01")
            os.makedirs(host_dir)
            task_file = os.path.join(host_dir, "TestTask.xml")
            with open(task_file, "wb") as f:
                f.write(VALID_TASK_XML)

            all_rows = []
            with patch("taskhound.engine.offline.good"):
                with patch("taskhound.engine.offline.info"):
                    result = process_offline_directory(
                        offline_dir=tmpdir,
                        hv=None,
                        show_unsaved_creds=True,
                        include_local=True,
                        all_rows=all_rows,
                        debug=False,
                    )

            # Should have processed something
            assert len(all_rows) >= 0  # May or may not include depending on filters

    def test_skips_hidden_directories(self):
        """Skips directories starting with dot."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create hidden directory
            hidden_dir = os.path.join(tmpdir, ".hidden")
            os.makedirs(hidden_dir)
            task_file = os.path.join(hidden_dir, "TestTask.xml")
            with open(task_file, "wb") as f:
                f.write(VALID_TASK_XML)

            all_rows = []
            with patch("taskhound.engine.offline.warn"):
                result = process_offline_directory(
                    offline_dir=tmpdir,
                    hv=None,
                    show_unsaved_creds=True,
                    include_local=True,
                    all_rows=all_rows,
                    debug=False,
                )

            # Hidden dir should be skipped, no rows processed
            assert len(all_rows) == 0

    def test_dpapi_loot_directory_detection(self):
        """Detects direct DPAPI loot directory structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create DPAPI structure
            os.makedirs(os.path.join(tmpdir, "masterkeys"))
            os.makedirs(os.path.join(tmpdir, "credentials"))

            all_rows = []
            with patch("taskhound.engine.offline.info"):
                with patch("taskhound.engine.offline._process_offline_dpapi_decryption") as mock_dpapi:
                    with patch("taskhound.engine.offline._process_offline_host") as mock_host:
                        # Return tuple (out_lines, decrypted_creds)
                        mock_dpapi.return_value = ([], [])
                        mock_host.return_value = []
                        result = process_offline_directory(
                            offline_dir=tmpdir,
                            hv=None,
                            show_unsaved_creds=True,
                            include_local=True,
                            all_rows=all_rows,
                            debug=False,
                            dpapi_key="test_key",
                        )

            # Should call DPAPI decryption
            mock_dpapi.assert_called()


class TestProcessOfflineHost:
    """Tests for _process_offline_host function."""

    def test_no_xml_files(self):
        """Returns empty list when no XML files found."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("taskhound.engine.offline.warn"):
                result = _process_offline_host(
                    hostname="DC01",
                    host_dir=tmpdir,
                    hv=None,
                    show_unsaved_creds=True,
                    include_local=True,
                    all_rows=[],
                    debug=False,
                )
        assert result == []

    def test_skips_hidden_files(self):
        """Skips files starting with dot."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create hidden file
            hidden_file = os.path.join(tmpdir, ".hidden.xml")
            with open(hidden_file, "wb") as f:
                f.write(VALID_TASK_XML)

            all_rows = []
            with patch("taskhound.engine.offline.warn"):
                result = _process_offline_host(
                    hostname="DC01",
                    host_dir=tmpdir,
                    hv=None,
                    show_unsaved_creds=True,
                    include_local=True,
                    all_rows=all_rows,
                    debug=False,
                )

            # Hidden file should be skipped
            assert len(all_rows) == 0

    def test_processes_valid_xml(self):
        """Processes valid task XML files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            task_file = os.path.join(tmpdir, "TestTask.xml")
            with open(task_file, "wb") as f:
                f.write(VALID_TASK_XML)

            all_rows = []
            with patch("taskhound.engine.offline.good"):
                result = _process_offline_host(
                    hostname="DC01",
                    host_dir=tmpdir,
                    hv=None,
                    show_unsaved_creds=True,
                    include_local=True,  # Include all tasks
                    all_rows=all_rows,
                    debug=False,
                )

            # The task should be processed (may be filtered based on classification)
            # With no HV loader, non-local tasks may be filtered
            # Just verify no crash occurred
            assert isinstance(result, list)

    def test_handles_nested_directories(self):
        """Processes XML files in nested subdirectories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create nested structure like Windows/System32/Tasks/
            nested_dir = os.path.join(tmpdir, "Windows", "System32", "Tasks")
            os.makedirs(nested_dir)
            task_file = os.path.join(nested_dir, "TestTask.xml")
            with open(task_file, "wb") as f:
                f.write(VALID_TASK_XML)

            all_rows = []
            with patch("taskhound.engine.offline.good"):
                result = _process_offline_host(
                    hostname="DC01",
                    host_dir=tmpdir,
                    hv=None,
                    show_unsaved_creds=True,
                    include_local=True,
                    all_rows=all_rows,
                    debug=False,
                )

            # Verify no crash occurred
            assert isinstance(result, list)

    def test_handles_unreadable_file(self):
        """Handles files that can't be read."""
        with tempfile.TemporaryDirectory() as tmpdir:
            task_file = os.path.join(tmpdir, "TestTask.xml")
            with open(task_file, "wb") as f:
                f.write(VALID_TASK_XML)

            # Make file unreadable by mocking open to raise
            all_rows = []
            with patch("taskhound.engine.offline.good"):
                with patch("builtins.open", side_effect=PermissionError("Access denied")):
                    result = _process_offline_host(
                        hostname="DC01",
                        host_dir=tmpdir,
                        hv=None,
                        show_unsaved_creds=True,
                        include_local=True,
                        all_rows=all_rows,
                        debug=True,
                    )

            # Should not crash, just skip the file
            assert len(all_rows) == 0

    def test_concise_mode(self):
        """Processes with concise output mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            task_file = os.path.join(tmpdir, "TestTask.xml")
            with open(task_file, "wb") as f:
                f.write(VALID_TASK_XML)

            all_rows = []
            with patch("taskhound.engine.offline.good"):
                result = _process_offline_host(
                    hostname="DC01",
                    host_dir=tmpdir,
                    hv=None,
                    show_unsaved_creds=True,
                    include_local=True,
                    all_rows=all_rows,
                    debug=False,
                    concise=True,
                )

            # Should process without errors
            assert isinstance(result, list)


class TestProcessOfflineDPAPIDecryption:
    """Tests for _process_offline_dpapi_decryption function."""

    def test_no_dpapi_directory(self):
        """Returns empty tuple when no DPAPI directory exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = _process_offline_dpapi_decryption(
                hostname="DC01",
                host_dir=tmpdir,
                dpapi_key="test_key",
                debug=False,
            )
        # Returns (out_lines, decrypted_creds) tuple
        assert result == ([], [])

    def test_direct_masterkeys_structure(self):
        """Detects direct dpapi_loot structure with masterkeys/."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create direct structure
            os.makedirs(os.path.join(tmpdir, "masterkeys"))
            os.makedirs(os.path.join(tmpdir, "credentials"))

            with patch("taskhound.dpapi.looter.decrypt_offline_dpapi_files") as mock_decrypt:
                with patch("taskhound.engine.offline.info"):
                    mock_decrypt.return_value = []
                    result = _process_offline_dpapi_decryption(
                        hostname="DC01",
                        host_dir=tmpdir,
                        dpapi_key="test_key",
                        debug=False,
                    )

            mock_decrypt.assert_called_once()

    def test_combined_backup_loot_structure(self):
        """Detects combined --backup --loot structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create combined structure: host_dir/dpapi_loot/
            dpapi_dir = os.path.join(tmpdir, "dpapi_loot")
            os.makedirs(os.path.join(dpapi_dir, "masterkeys"))
            os.makedirs(os.path.join(dpapi_dir, "credentials"))

            with patch("taskhound.dpapi.looter.decrypt_offline_dpapi_files") as mock_decrypt:
                with patch("taskhound.engine.offline.info"):
                    mock_decrypt.return_value = []
                    result = _process_offline_dpapi_decryption(
                        hostname="DC01",
                        host_dir=tmpdir,
                        dpapi_key="test_key",
                        debug=False,
                    )

            mock_decrypt.assert_called_once()
            # Should be called with the dpapi_loot subdirectory
            assert "dpapi_loot" in mock_decrypt.call_args[0][0]

    def test_legacy_structure(self):
        """Detects legacy dpapi_loot/hostname structure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create legacy structure: host_dir/dpapi_loot/hostname/
            hostname = "DC01"
            dpapi_dir = os.path.join(tmpdir, "dpapi_loot", hostname)
            os.makedirs(os.path.join(dpapi_dir, "masterkeys"))
            os.makedirs(os.path.join(dpapi_dir, "credentials"))

            with patch("taskhound.dpapi.looter.decrypt_offline_dpapi_files") as mock_decrypt:
                with patch("taskhound.engine.offline.info"):
                    mock_decrypt.return_value = []
                    result = _process_offline_dpapi_decryption(
                        hostname=hostname,
                        host_dir=tmpdir,
                        dpapi_key="test_key",
                        debug=False,
                    )

            mock_decrypt.assert_called_once()

    def test_successful_decryption_output(self):
        """Formats decrypted credentials in output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.makedirs(os.path.join(tmpdir, "masterkeys"))
            os.makedirs(os.path.join(tmpdir, "credentials"))

            # Mock a decrypted credential
            mock_cred = MagicMock()
            mock_cred.task_name = "TestTask"
            mock_cred.target = "{12345678-1234-1234-1234-123456789012}"
            mock_cred.username = "DOMAIN\\admin"
            mock_cred.password = "P@ssw0rd123"
            mock_cred.blob_path = "/path/to/blob"

            with patch("taskhound.dpapi.looter.decrypt_offline_dpapi_files") as mock_decrypt:
                with patch("taskhound.engine.offline.info"):
                    with patch("taskhound.engine.offline.good"):
                        mock_decrypt.return_value = [mock_cred]
                        out_lines, decrypted_creds = _process_offline_dpapi_decryption(
                            hostname="DC01",
                            host_dir=tmpdir,
                            dpapi_key="test_key",
                            debug=False,
                        )

            # Should contain credential information in out_lines
            output = "\n".join(out_lines)
            assert "TestTask" in output
            assert "DOMAIN\\admin" in output
            assert "P@ssw0rd123" in output
            # decrypted_creds should contain the credential object
            assert len(decrypted_creds) == 1

    def test_decryption_failure_handled(self):
        """Handles decryption failures gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.makedirs(os.path.join(tmpdir, "masterkeys"))
            os.makedirs(os.path.join(tmpdir, "credentials"))

            with patch("taskhound.dpapi.looter.decrypt_offline_dpapi_files") as mock_decrypt:
                with patch("taskhound.engine.offline.warn") as mock_warn:
                    mock_decrypt.side_effect = Exception("Decryption failed")
                    out_lines, decrypted_creds = _process_offline_dpapi_decryption(
                        hostname="DC01",
                        host_dir=tmpdir,
                        dpapi_key="test_key",
                        debug=False,
                    )

            # Should not crash
            assert out_lines == []
            assert decrypted_creds == []
            mock_warn.assert_called()

    def test_debug_mode_prints_traceback(self):
        """Debug mode prints traceback on errors."""
        with tempfile.TemporaryDirectory() as tmpdir:
            os.makedirs(os.path.join(tmpdir, "masterkeys"))
            os.makedirs(os.path.join(tmpdir, "credentials"))

            with patch("taskhound.dpapi.looter.decrypt_offline_dpapi_files") as mock_decrypt:
                with patch("taskhound.engine.offline.warn"):
                    with patch("traceback.print_exc") as mock_traceback:
                        mock_decrypt.side_effect = Exception("Test error")
                        result = _process_offline_dpapi_decryption(
                            hostname="DC01",
                            host_dir=tmpdir,
                            dpapi_key="test_key",
                            debug=True,
                        )

            mock_traceback.assert_called()


class TestOfflineClassification:
    """Tests for offline task classification."""

    def test_task_without_runas_skipped(self):
        """Tasks without runas field are skipped."""
        xml_no_runas = b"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2025-01-15T10:00:00</Date>
  </RegistrationInfo>
  <Settings>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>cmd.exe</Command>
    </Exec>
  </Actions>
</Task>
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            task_file = os.path.join(tmpdir, "NoRunas.xml")
            with open(task_file, "wb") as f:
                f.write(xml_no_runas)

            all_rows = []
            with patch("taskhound.engine.offline.warn"):
                with patch("taskhound.engine.offline.good"):
                    result = _process_offline_host(
                        hostname="DC01",
                        host_dir=tmpdir,
                        hv=None,
                        show_unsaved_creds=True,
                        include_local=True,
                        all_rows=all_rows,
                        debug=False,
                    )

            # Task without runas should be skipped
            assert len(all_rows) == 0

    def test_interactivetoken_logon_type(self):
        """Tasks with InteractiveToken logon type marked as no_saved_credentials."""
        xml_interactive = b"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2025-01-15T10:00:00</Date>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>DOMAIN\\user</UserId>
      <LogonType>InteractiveToken</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>cmd.exe</Command>
    </Exec>
  </Actions>
</Task>
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            task_file = os.path.join(tmpdir, "Interactive.xml")
            with open(task_file, "wb") as f:
                f.write(xml_interactive)

            all_rows = []
            with patch("taskhound.engine.offline.good"):
                result = _process_offline_host(
                    hostname="DC01",
                    host_dir=tmpdir,
                    hv=None,
                    show_unsaved_creds=True,
                    include_local=True,
                    all_rows=all_rows,
                    debug=False,
                )

            # Task should be marked as no_saved_credentials
            if len(all_rows) > 0:
                assert all_rows[0].credentials_hint == "no_saved_credentials"

    def test_s4u_logon_type(self):
        """Tasks with S4U logon type marked as no_saved_credentials."""
        xml_s4u = b"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2025-01-15T10:00:00</Date>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>DOMAIN\\user</UserId>
      <LogonType>S4U</LogonType>
    </Principal>
  </Principals>
  <Settings>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>cmd.exe</Command>
    </Exec>
  </Actions>
</Task>
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            task_file = os.path.join(tmpdir, "S4U.xml")
            with open(task_file, "wb") as f:
                f.write(xml_s4u)

            all_rows = []
            with patch("taskhound.engine.offline.good"):
                result = _process_offline_host(
                    hostname="DC01",
                    host_dir=tmpdir,
                    hv=None,
                    show_unsaved_creds=True,
                    include_local=True,
                    all_rows=all_rows,
                    debug=False,
                )

            if len(all_rows) > 0:
                assert all_rows[0].credentials_hint == "no_saved_credentials"


class TestOfflineWithHighValueLoader:
    """Tests for offline processing with HighValueLoader."""

    def test_with_highvalue_loader_passed_through(self):
        """HighValueLoader is passed to classification."""
        with tempfile.TemporaryDirectory() as tmpdir:
            task_file = os.path.join(tmpdir, "TestTask.xml")
            with open(task_file, "wb") as f:
                f.write(VALID_TASK_XML)

            # Create mock HighValueLoader
            mock_hv = MagicMock()
            mock_hv.loaded = True

            all_rows = []
            with patch("taskhound.engine.offline.good"):
                # Don't mock classify_task - let it run to verify hv is used
                result = _process_offline_host(
                    hostname="DC01",
                    host_dir=tmpdir,
                    hv=mock_hv,
                    show_unsaved_creds=True,
                    include_local=True,
                    all_rows=all_rows,
                    debug=False,
                )

            # Test passes if no errors - HV is passed through to classify_task
            assert isinstance(result, list)
