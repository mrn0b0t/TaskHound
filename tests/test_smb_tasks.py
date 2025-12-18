"""
Test suite for SMB task enumeration functions.

Tests cover:
- smb_listdir function
- smb_readfile function
- crawl_tasks function
"""

from unittest.mock import MagicMock, patch

import pytest

from taskhound.smb.tasks import (
    crawl_tasks,
    smb_listdir,
    smb_readfile,
)

# ============================================================================
# Test: smb_listdir
# ============================================================================


class TestSmbListdir:
    """Tests for smb_listdir function"""

    def test_returns_entries_excluding_dots(self):
        """Should return entries without . and .."""
        mock_smb = MagicMock()

        # Create mock file entries
        mock_dir = MagicMock()
        mock_dir.get_longname.return_value = "TaskFolder"
        mock_dir.is_directory.return_value = True

        mock_file = MagicMock()
        mock_file.get_longname.return_value = "task.xml"
        mock_file.is_directory.return_value = False

        mock_dot = MagicMock()
        mock_dot.get_longname.return_value = "."

        mock_dotdot = MagicMock()
        mock_dotdot.get_longname.return_value = ".."

        mock_smb.listPath.return_value = [mock_dot, mock_dotdot, mock_dir, mock_file]

        result = smb_listdir(mock_smb, "C$", "\\Tasks")

        assert len(result) == 2
        assert (True, "TaskFolder") in result
        assert (False, "task.xml") in result
        assert (True, ".") not in result
        assert (True, "..") not in result

    def test_correct_path_with_wildcard(self):
        """Should append \\* to path for listing"""
        mock_smb = MagicMock()
        mock_smb.listPath.return_value = []

        smb_listdir(mock_smb, "C$", "\\Tasks")

        mock_smb.listPath.assert_called_once_with("C$", "\\Tasks\\*")

    def test_empty_directory(self):
        """Should return empty list for empty directory"""
        mock_smb = MagicMock()
        mock_smb.listPath.return_value = []

        result = smb_listdir(mock_smb, "C$", "\\Tasks")

        assert result == []


# ============================================================================
# Test: smb_readfile
# ============================================================================


class TestSmbReadfile:
    """Tests for smb_readfile function"""

    def test_reads_file_content(self):
        """Should read file content into bytes"""
        mock_smb = MagicMock()

        def mock_getfile(share, path, callback):
            callback(b"<?xml version='1.0'?>")
            callback(b"<Task>content</Task>")

        mock_smb.getFile.side_effect = mock_getfile

        result = smb_readfile(mock_smb, "C$", "\\Tasks\\task.xml")

        assert result == b"<?xml version='1.0'?><Task>content</Task>"
        mock_smb.getFile.assert_called_once()

    def test_calls_getfile_with_correct_params(self):
        """Should call getFile with share and path"""
        mock_smb = MagicMock()
        mock_smb.getFile.side_effect = lambda s, p, c: None

        smb_readfile(mock_smb, "C$", "\\Tasks\\task.xml")

        call_args = mock_smb.getFile.call_args
        assert call_args[0][0] == "C$"
        assert call_args[0][1] == "\\Tasks\\task.xml"


# ============================================================================
# Test: crawl_tasks
# ============================================================================


class TestCrawlTasks:
    """Tests for crawl_tasks function"""

    def test_basic_task_crawl(self):
        """Should crawl and return task XMLs"""
        mock_smb = MagicMock()

        # Root listing
        task_entry = MagicMock()
        task_entry.get_longname.return_value = "BackupTask"
        task_entry.is_directory.return_value = False

        mock_smb.listPath.return_value = [task_entry]

        def mock_getfile(share, path, callback):
            callback(b"<?xml version='1.0'?><Task/>")

        mock_smb.getFile.side_effect = mock_getfile

        results = crawl_tasks(mock_smb)

        assert len(results) == 1
        assert results[0][1] == b"<?xml version='1.0'?><Task/>"

    def test_skips_microsoft_folder_by_default(self):
        """Should skip Microsoft folder unless include_ms=True"""
        mock_smb = MagicMock()

        # Create entries
        microsoft_entry = MagicMock()
        microsoft_entry.get_longname.return_value = "Microsoft"
        microsoft_entry.is_directory.return_value = True

        task_entry = MagicMock()
        task_entry.get_longname.return_value = "MyTask"
        task_entry.is_directory.return_value = False

        # First call is root validation, second is actual listing
        call_count = 0
        def mock_listpath(share, path):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return [microsoft_entry, task_entry]  # Root check
            elif "Microsoft" in path:
                # Should not be called if skipping
                return []
            return [microsoft_entry, task_entry]

        mock_smb.listPath.side_effect = mock_listpath
        mock_smb.getFile.side_effect = lambda s, p, c: c(b"<Task/>")

        results = crawl_tasks(mock_smb, include_ms=False)

        # Should only have MyTask, not anything from Microsoft
        assert len(results) == 1

    def test_includes_microsoft_folder_when_requested(self):
        """Should include Microsoft folder when include_ms=True"""
        mock_smb = MagicMock()

        microsoft_entry = MagicMock()
        microsoft_entry.get_longname.return_value = "Microsoft"
        microsoft_entry.is_directory.return_value = True

        ms_task_entry = MagicMock()
        ms_task_entry.get_longname.return_value = "WindowsUpdate"
        ms_task_entry.is_directory.return_value = False

        def mock_listpath(share, path):
            if "Microsoft" in path:
                return [ms_task_entry]
            return [microsoft_entry]

        mock_smb.listPath.side_effect = mock_listpath
        mock_smb.getFile.side_effect = lambda s, p, c: c(b"<Task/>")

        results = crawl_tasks(mock_smb, include_ms=True)

        # Should have Microsoft task
        assert len(results) == 1
        assert "Microsoft" in results[0][0]

    def test_raises_on_root_access_failure(self):
        """Should raise if cannot access root task folder"""
        mock_smb = MagicMock()
        mock_smb.listPath.side_effect = Exception("Access denied")

        with pytest.raises(Exception) as exc_info:
            crawl_tasks(mock_smb)

        assert "Failed to access" in str(exc_info.value)

    def test_continues_on_file_read_error(self):
        """Should log and continue when file read fails"""
        mock_smb = MagicMock()

        task1 = MagicMock()
        task1.get_longname.return_value = "Task1"
        task1.is_directory.return_value = False

        task2 = MagicMock()
        task2.get_longname.return_value = "Task2"
        task2.is_directory.return_value = False

        mock_smb.listPath.return_value = [task1, task2]

        call_count = 0
        def mock_getfile(share, path, callback):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise Exception("Permission denied")
            callback(b"<Task/>")

        mock_smb.getFile.side_effect = mock_getfile

        with patch('taskhound.smb.tasks.warn') as mock_warn:
            results = crawl_tasks(mock_smb)

        # Should have Task2 but not Task1
        assert len(results) == 1
        # Should have logged warning
        mock_warn.assert_called()

    def test_recursive_directory_crawl(self):
        """Should recursively crawl directories"""
        mock_smb = MagicMock()

        subdir = MagicMock()
        subdir.get_longname.return_value = "SubFolder"
        subdir.is_directory.return_value = True

        task = MagicMock()
        task.get_longname.return_value = "DeepTask"
        task.is_directory.return_value = False

        def mock_listpath(share, path):
            if "SubFolder" in path:
                return [task]
            return [subdir]

        mock_smb.listPath.side_effect = mock_listpath
        mock_smb.getFile.side_effect = lambda s, p, c: c(b"<Task/>")

        results = crawl_tasks(mock_smb)

        assert len(results) == 1
        assert "SubFolder" in results[0][0]
        assert "DeepTask" in results[0][0]

    def test_path_normalization(self):
        """Should normalize paths by removing leading backslash"""
        mock_smb = MagicMock()

        task = MagicMock()
        task.get_longname.return_value = "MyTask"
        task.is_directory.return_value = False

        mock_smb.listPath.return_value = [task]
        mock_smb.getFile.side_effect = lambda s, p, c: c(b"<Task/>")

        results = crawl_tasks(mock_smb)

        assert len(results) == 1
        # Path should not start with backslash
        assert not results[0][0].startswith("\\")

    @patch('taskhound.smb.tasks.warn')
    def test_catches_and_logs_crawl_exception(self, mock_warn):
        """Should catch exceptions during crawl and log warning."""
        mock_smb = MagicMock()

        # First listPath call for initial access check should succeed
        # Second call (in recurse) should raise an exception
        call_count = [0]
        def side_effect(*args):
            call_count[0] += 1
            if call_count[0] == 1:
                # Initial root access check succeeds
                return []
            else:
                # Subsequent call in recurse raises exception
                raise Exception("Network connection lost")

        mock_smb.listPath.side_effect = side_effect

        # Should not raise, but should log warning
        crawl_tasks(mock_smb)

        # Verify warning was logged about the crawl error
        mock_warn.assert_called()
        warn_call = mock_warn.call_args[0][0]
        assert "Crawl error" in warn_call

