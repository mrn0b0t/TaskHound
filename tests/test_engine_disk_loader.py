# Tests for disk_loader module (mounted Windows filesystem extraction)

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from taskhound.engine.disk_loader import (
    GUID_PATTERN,
    find_windows_root,
    extract_tasks,
    extract_masterkeys,
    extract_credentials,
    load_from_disk,
)


class TestGuidPattern:
    """Tests for GUID regex pattern."""

    def test_valid_guid_lowercase(self):
        assert GUID_PATTERN.match("12345678-1234-1234-1234-123456789abc")

    def test_valid_guid_uppercase(self):
        assert GUID_PATTERN.match("12345678-1234-1234-1234-123456789ABC")

    def test_valid_guid_mixed_case(self):
        assert GUID_PATTERN.match("12345678-AbCd-EfAb-1234-123456789AbC")

    def test_invalid_guid_too_short(self):
        assert not GUID_PATTERN.match("1234567-1234-1234-1234-123456789abc")

    def test_invalid_guid_no_dashes(self):
        assert not GUID_PATTERN.match("123456781234123412341234567890ab")

    def test_invalid_guid_wrong_chars(self):
        assert not GUID_PATTERN.match("12345678-1234-1234-1234-123456789xyz")

    def test_non_guid_filename(self):
        assert not GUID_PATTERN.match("Preferred")
        assert not GUID_PATTERN.match("something.txt")


class TestFindWindowsRoot:
    """Tests for find_windows_root function."""

    def test_direct_mount(self, tmp_path):
        """Test direct mount where Windows/ is at mount root."""
        (tmp_path / "Windows").mkdir()
        result = find_windows_root(str(tmp_path))
        assert result == tmp_path

    def test_partition_mount(self, tmp_path):
        """Test partition mount (e.g., /mnt/vhdx/C/Windows)."""
        (tmp_path / "C" / "Windows").mkdir(parents=True)
        result = find_windows_root(str(tmp_path))
        assert result == tmp_path / "C"

    def test_volume_mount(self, tmp_path):
        """Test volume mount (e.g., /mnt/vhdx/Volume1/Windows)."""
        (tmp_path / "Volume1" / "Windows").mkdir(parents=True)
        result = find_windows_root(str(tmp_path))
        assert result == tmp_path / "Volume1"

    def test_nested_mount(self, tmp_path):
        """Test two-level nested mount."""
        (tmp_path / "disk" / "partition1" / "Windows").mkdir(parents=True)
        result = find_windows_root(str(tmp_path))
        assert result == tmp_path / "disk" / "partition1"

    def test_no_windows_found(self, tmp_path):
        """Test when no Windows directory exists."""
        (tmp_path / "Linux").mkdir()
        result = find_windows_root(str(tmp_path))
        assert result is None

    def test_empty_mount(self, tmp_path):
        """Test empty mount point."""
        result = find_windows_root(str(tmp_path))
        assert result is None


class TestExtractTasks:
    """Tests for extract_tasks function."""

    def test_extract_xml_tasks(self, tmp_path):
        """Test extraction of valid XML task files."""
        # Create mock Windows structure
        windows_root = tmp_path / "windows_root"
        tasks_dir = windows_root / "Windows" / "System32" / "Tasks"
        tasks_dir.mkdir(parents=True)

        # Create a valid task XML with UTF-16 LE BOM (like Windows does)
        task_content = b'\xff\xfe' + '<?xml version="1.0" encoding="UTF-16"?>\n<Task><Actions/></Task>'.encode('utf-16-le')
        (tasks_dir / "MyTask").write_bytes(task_content)

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        count = extract_tasks(windows_root, output_dir)
        assert count == 1
        assert (output_dir / "Windows" / "System32" / "Tasks" / "MyTask").exists()

    def test_extract_utf16_task(self, tmp_path):
        """Test extraction of UTF-16 LE encoded task."""
        windows_root = tmp_path / "windows_root"
        tasks_dir = windows_root / "Windows" / "System32" / "Tasks"
        tasks_dir.mkdir(parents=True)

        # UTF-16 LE BOM + <Task
        task_content = b'\xff\xfe<\x00T\x00a\x00s\x00k\x00>\x00'
        (tasks_dir / "Utf16Task").write_bytes(task_content)

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        count = extract_tasks(windows_root, output_dir)
        assert count == 1

    def test_skip_non_xml_files(self, tmp_path):
        """Test that non-XML files are skipped."""
        windows_root = tmp_path / "windows_root"
        tasks_dir = windows_root / "Windows" / "System32" / "Tasks"
        tasks_dir.mkdir(parents=True)

        # Create a non-XML file
        (tasks_dir / "binary_file").write_bytes(b'\x00\x01\x02\x03\x04\x05')

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        count = extract_tasks(windows_root, output_dir)
        assert count == 0

    def test_skip_microsoft_folder(self, tmp_path):
        """Test that Microsoft folder is skipped by default."""
        windows_root = tmp_path / "windows_root"
        tasks_dir = windows_root / "Windows" / "System32" / "Tasks"
        ms_dir = tasks_dir / "Microsoft"
        ms_dir.mkdir(parents=True)

        # Create task in Microsoft folder
        task_content = b'<?xml version="1.0"?>\n<Task/>'
        (ms_dir / "SystemTask").write_bytes(task_content)

        # Create task outside Microsoft folder
        (tasks_dir / "CustomTask").write_bytes(task_content)

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        count = extract_tasks(windows_root, output_dir)
        assert count == 1  # Only CustomTask, not SystemTask

    def test_no_tasks_directory(self, tmp_path):
        """Test handling of missing Tasks directory."""
        windows_root = tmp_path / "windows_root"
        (windows_root / "Windows" / "System32").mkdir(parents=True)

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        count = extract_tasks(windows_root, output_dir)
        assert count == 0


class TestExtractMasterkeys:
    """Tests for extract_masterkeys function."""

    def test_extract_guid_masterkeys(self, tmp_path):
        """Test extraction of GUID-named masterkey files."""
        windows_root = tmp_path / "windows_root"
        dpapi_dir = windows_root / "Windows" / "System32" / "Microsoft" / "Protect" / "S-1-5-18" / "User"
        dpapi_dir.mkdir(parents=True)

        # Create GUID-named masterkey files
        guid1 = "12345678-1234-1234-1234-123456789abc"
        guid2 = "87654321-4321-4321-4321-cba987654321"
        (dpapi_dir / guid1).write_bytes(b"masterkey_data_1")
        (dpapi_dir / guid2).write_bytes(b"masterkey_data_2")

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        count = extract_masterkeys(windows_root, output_dir)
        assert count == 2
        assert (output_dir / "masterkeys" / guid1).exists()
        assert (output_dir / "masterkeys" / guid2).exists()

    def test_extract_preferred_file(self, tmp_path):
        """Test that Preferred file is also extracted."""
        windows_root = tmp_path / "windows_root"
        dpapi_dir = windows_root / "Windows" / "System32" / "Microsoft" / "Protect" / "S-1-5-18" / "User"
        dpapi_dir.mkdir(parents=True)

        guid = "12345678-1234-1234-1234-123456789abc"
        (dpapi_dir / guid).write_bytes(b"masterkey_data")
        (dpapi_dir / "Preferred").write_bytes(b"preferred_data")

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        count = extract_masterkeys(windows_root, output_dir)
        assert count == 1  # Only GUID counted
        assert (output_dir / "masterkeys" / "Preferred").exists()

    def test_skip_non_guid_files(self, tmp_path):
        """Test that non-GUID files are not extracted."""
        windows_root = tmp_path / "windows_root"
        dpapi_dir = windows_root / "Windows" / "System32" / "Microsoft" / "Protect" / "S-1-5-18" / "User"
        dpapi_dir.mkdir(parents=True)

        (dpapi_dir / "random_file.txt").write_bytes(b"not a masterkey")

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        count = extract_masterkeys(windows_root, output_dir)
        assert count == 0

    def test_alternate_dpapi_path(self, tmp_path):
        """Test fallback to S-1-5-18 without User subdirectory."""
        windows_root = tmp_path / "windows_root"
        # Create at S-1-5-18 level (without User)
        dpapi_dir = windows_root / "Windows" / "System32" / "Microsoft" / "Protect" / "S-1-5-18"
        dpapi_dir.mkdir(parents=True)

        guid = "12345678-1234-1234-1234-123456789abc"
        (dpapi_dir / guid).write_bytes(b"masterkey_data")

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        count = extract_masterkeys(windows_root, output_dir, verbose=True)
        assert count == 1

    def test_no_dpapi_directory(self, tmp_path):
        """Test handling of missing DPAPI directory."""
        windows_root = tmp_path / "windows_root"
        (windows_root / "Windows" / "System32").mkdir(parents=True)

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        count = extract_masterkeys(windows_root, output_dir)
        assert count == 0


class TestExtractCredentials:
    """Tests for extract_credentials function."""

    def test_extract_system_credentials(self, tmp_path):
        """Test extraction of SYSTEM credential files."""
        windows_root = tmp_path / "windows_root"
        creds_dir = windows_root / "Windows" / "System32" / "config" / "systemprofile" / "AppData" / "Local" / "Microsoft" / "Credentials"
        creds_dir.mkdir(parents=True)

        # Create credential files (typically GUID-like names)
        (creds_dir / "ABCDEF1234567890").write_bytes(b"credential_blob_1")
        (creds_dir / "1234567890ABCDEF").write_bytes(b"credential_blob_2")

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        count = extract_credentials(windows_root, output_dir)
        assert count == 2
        assert (output_dir / "credentials" / "ABCDEF1234567890").exists()
        assert (output_dir / "credentials" / "1234567890ABCDEF").exists()

    def test_no_credentials_directory(self, tmp_path):
        """Test handling of missing credentials directory."""
        windows_root = tmp_path / "windows_root"
        (windows_root / "Windows" / "System32").mkdir(parents=True)

        output_dir = tmp_path / "output"
        output_dir.mkdir()

        count = extract_credentials(windows_root, output_dir)
        assert count == 0


class TestLoadFromDisk:
    """Tests for load_from_disk function."""

    def test_full_extraction(self, tmp_path):
        """Test full extraction workflow."""
        # Create mock Windows filesystem
        mount = tmp_path / "mount"
        windows_root = mount
        
        # Tasks - use UTF-16 LE BOM like Windows does
        tasks_dir = windows_root / "Windows" / "System32" / "Tasks"
        tasks_dir.mkdir(parents=True)
        task_content = b'\xff\xfe' + '<?xml version="1.0"?>\n<Task/>'.encode('utf-16-le')
        (tasks_dir / "TestTask").write_bytes(task_content)

        # Masterkeys
        dpapi_dir = windows_root / "Windows" / "System32" / "Microsoft" / "Protect" / "S-1-5-18" / "User"
        dpapi_dir.mkdir(parents=True)
        (dpapi_dir / "12345678-1234-1234-1234-123456789abc").write_bytes(b"mk")

        # Credentials
        creds_dir = windows_root / "Windows" / "System32" / "config" / "systemprofile" / "AppData" / "Local" / "Microsoft" / "Credentials"
        creds_dir.mkdir(parents=True)
        (creds_dir / "CRED001").write_bytes(b"cred")

        # Run extraction
        hostname, backup_path = load_from_disk(
            mount_path=str(mount),
            backup_dir=str(tmp_path / "backup"),
            hostname="TESTHOST",
        )

        assert hostname == "TESTHOST"
        assert backup_path is not None
        assert Path(backup_path).exists()
        
        # Verify structure
        bp = Path(backup_path)
        assert (bp / "Windows" / "System32" / "Tasks" / "TestTask").exists()
        assert (bp / "masterkeys" / "12345678-1234-1234-1234-123456789abc").exists()
        assert (bp / "credentials" / "CRED001").exists()
        assert (bp / "extraction_info.txt").exists()

    def test_no_windows_found(self, tmp_path):
        """Test failure when Windows directory not found."""
        mount = tmp_path / "empty_mount"
        mount.mkdir()

        hostname, backup_path = load_from_disk(str(mount))
        assert hostname is None
        assert backup_path is None

    def test_no_backup_mode(self, tmp_path):
        """Test ephemeral mode (no backup saved)."""
        mount = tmp_path / "mount"
        tasks_dir = mount / "Windows" / "System32" / "Tasks"
        tasks_dir.mkdir(parents=True)
        # UTF-16 LE BOM
        task_content = b'\xff\xfe' + '<?xml version="1.0"?>\n<Task/>'.encode('utf-16-le')
        (tasks_dir / "Task1").write_bytes(task_content)

        hostname, backup_path = load_from_disk(
            mount_path=str(mount),
            no_backup=True,
            hostname="EPHEMERAL",
        )

        assert hostname == "EPHEMERAL"
        assert backup_path is not None
        # Verify temp directory was created
        assert "taskhound_EPHEMERAL_" in backup_path
        assert Path(backup_path).exists()

    def test_custom_hostname(self, tmp_path):
        """Test custom hostname override."""
        mount = tmp_path / "mount"
        (mount / "Windows" / "System32" / "Tasks").mkdir(parents=True)

        hostname, backup_path = load_from_disk(
            mount_path=str(mount),
            backup_dir=str(tmp_path / "backup"),
            hostname="CUSTOM_HOST",
        )

        assert hostname == "CUSTOM_HOST"
        assert "CUSTOM_HOST" in backup_path

    def test_default_backup_location(self, tmp_path, monkeypatch):
        """Test default backup location (dpapi_loot/)."""
        mount = tmp_path / "mount"
        (mount / "Windows" / "System32" / "Tasks").mkdir(parents=True)

        # Change to tmp_path so dpapi_loot is created there
        monkeypatch.chdir(tmp_path)

        hostname, backup_path = load_from_disk(
            mount_path=str(mount),
            hostname="DEFHOST",
        )

        assert hostname == "DEFHOST"
        assert "dpapi_loot" in backup_path
        assert "DEFHOST" in backup_path
