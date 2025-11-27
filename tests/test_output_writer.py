"""
Test suite for output writer functions.

Tests cover:
- _rows_to_dicts helper function
- write_plain function
- write_json function
- write_csv function
"""

import csv
import json
import os
import pytest
from unittest.mock import MagicMock, patch

from taskhound.output.writer import _rows_to_dicts, write_plain, write_json, write_csv


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def temp_output_dir(tmp_path):
    """Create a temporary directory for output files"""
    return tmp_path


@pytest.fixture
def sample_task_dict():
    """Sample task as dictionary"""
    return {
        "host": "DC01.example.com",
        "path": "\\BackupTask",
        "type": "PRIV",
        "runas": "EXAMPLE\\backupuser",
        "command": "backup.exe",
        "arguments": "-full",
        "author": "Administrator",
        "date": "2024-01-15",
        "logon_type": "Password",
        "enabled": "true"
    }


@pytest.fixture
def sample_task_object():
    """Sample task as object with to_dict method"""
    task = MagicMock()
    task.to_dict.return_value = {
        "host": "WS01.example.com",
        "path": "\\MaintTask",
        "type": "TASK"
    }
    return task


# ============================================================================
# Unit Tests: _rows_to_dicts
# ============================================================================


class TestRowsToDicts:
    """Tests for _rows_to_dicts helper function"""

    def test_empty_list(self):
        """Should return empty list for empty input"""
        result = _rows_to_dicts([])
        assert result == []

    def test_dict_passthrough(self, sample_task_dict):
        """Should pass dictionaries through unchanged"""
        result = _rows_to_dicts([sample_task_dict])
        assert result == [sample_task_dict]

    def test_object_with_to_dict(self, sample_task_object):
        """Should call to_dict on objects that have it"""
        result = _rows_to_dicts([sample_task_object])
        
        sample_task_object.to_dict.assert_called_once()
        assert result == [{"host": "WS01.example.com", "path": "\\MaintTask", "type": "TASK"}]

    def test_mixed_objects_and_dicts(self, sample_task_dict, sample_task_object):
        """Should handle mixed list of dicts and objects"""
        result = _rows_to_dicts([sample_task_dict, sample_task_object])
        
        assert len(result) == 2
        assert result[0] == sample_task_dict
        assert result[1] == {"host": "WS01.example.com", "path": "\\MaintTask", "type": "TASK"}


# ============================================================================
# Unit Tests: write_plain
# ============================================================================


class TestWritePlain:
    """Tests for write_plain function"""

    @patch('taskhound.output.writer.good')
    def test_creates_output_directory(self, mock_good, temp_output_dir):
        """Should create output directory if it doesn't exist"""
        subdir = temp_output_dir / "subdir"
        lines = ["Line 1", "Line 2"]
        
        write_plain(str(subdir), "host1", lines)
        
        assert subdir.exists()

    @patch('taskhound.output.writer.good')
    def test_writes_lines_to_file(self, mock_good, temp_output_dir):
        """Should write lines to file with newlines"""
        lines = ["Line 1", "Line 2", "Line 3"]
        
        write_plain(str(temp_output_dir), "host1.example.com", lines)
        
        output_file = temp_output_dir / "host1.example.com.txt"
        assert output_file.exists()
        
        content = output_file.read_text()
        assert content == "Line 1\nLine 2\nLine 3\n"

    @patch('taskhound.output.writer.good')
    def test_empty_lines_creates_file(self, mock_good, temp_output_dir):
        """Should create file even with empty lines"""
        write_plain(str(temp_output_dir), "host1", [])
        
        output_file = temp_output_dir / "host1.txt"
        assert output_file.exists()
        content = output_file.read_text()
        assert content == ""

    @patch('taskhound.output.writer.good')
    def test_colon_replaced_in_filename(self, mock_good, temp_output_dir):
        """Should replace colons with underscores in filename"""
        write_plain(str(temp_output_dir), "host:port", ["test"])
        
        output_file = temp_output_dir / "host_port.txt"
        assert output_file.exists()

    @patch('taskhound.output.writer.good')
    def test_logs_success_message(self, mock_good, temp_output_dir):
        """Should log success message"""
        write_plain(str(temp_output_dir), "host1", ["test"])
        
        mock_good.assert_called_once()
        call_arg = mock_good.call_args[0][0]
        assert "Wrote results to" in call_arg


# ============================================================================
# Unit Tests: write_json
# ============================================================================


class TestWriteJson:
    """Tests for write_json function"""

    @patch('taskhound.output.writer.good')
    def test_writes_json_file(self, mock_good, temp_output_dir, sample_task_dict):
        """Should write JSON file with proper formatting"""
        output_file = temp_output_dir / "output.json"
        
        write_json(str(output_file), [sample_task_dict])
        
        assert output_file.exists()
        
        with open(output_file) as f:
            data = json.load(f)
        
        assert len(data) == 1
        assert data[0]["host"] == "DC01.example.com"

    @patch('taskhound.output.writer.good')
    def test_empty_list_writes_empty_array(self, mock_good, temp_output_dir):
        """Should write empty JSON array for empty input"""
        output_file = temp_output_dir / "output.json"
        
        write_json(str(output_file), [])
        
        with open(output_file) as f:
            data = json.load(f)
        
        assert data == []

    @patch('taskhound.output.writer.good')
    def test_json_indented(self, mock_good, temp_output_dir, sample_task_dict):
        """Should write indented JSON for readability"""
        output_file = temp_output_dir / "output.json"
        
        write_json(str(output_file), [sample_task_dict])
        
        content = output_file.read_text()
        # Indented JSON has newlines and spaces
        assert "\n" in content
        assert "  " in content

    @patch('taskhound.output.writer.good')
    def test_converts_objects(self, mock_good, temp_output_dir, sample_task_object):
        """Should convert objects with to_dict method"""
        output_file = temp_output_dir / "output.json"
        
        write_json(str(output_file), [sample_task_object])
        
        with open(output_file) as f:
            data = json.load(f)
        
        assert data[0]["host"] == "WS01.example.com"

    @patch('taskhound.output.writer.good')
    def test_logs_success_message(self, mock_good, temp_output_dir):
        """Should log success message"""
        output_file = temp_output_dir / "output.json"
        
        write_json(str(output_file), [])
        
        mock_good.assert_called_once()
        call_arg = mock_good.call_args[0][0]
        assert "Wrote JSON results to" in call_arg


# ============================================================================
# Unit Tests: write_csv
# ============================================================================


class TestWriteCsv:
    """Tests for write_csv function"""

    @patch('taskhound.output.writer.good')
    def test_writes_csv_file(self, mock_good, temp_output_dir, sample_task_dict):
        """Should write CSV file with headers"""
        output_file = temp_output_dir / "output.csv"
        
        write_csv(str(output_file), [sample_task_dict])
        
        assert output_file.exists()
        
        with open(output_file) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        assert len(rows) == 1
        assert rows[0]["host"] == "DC01.example.com"

    @patch('taskhound.output.writer.good')
    def test_csv_headers_present(self, mock_good, temp_output_dir):
        """Should write CSV with all expected headers"""
        output_file = temp_output_dir / "output.csv"
        
        write_csv(str(output_file), [])
        
        with open(output_file) as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames
        
        expected_fields = [
            "host", "target_ip", "computer_sid", "path", "type",
            "runas", "command", "arguments", "author", "date",
            "logon_type", "enabled", "trigger_type"
        ]
        for field in expected_fields:
            assert field in fieldnames

    @patch('taskhound.output.writer.good')
    def test_empty_list_writes_headers_only(self, mock_good, temp_output_dir):
        """Should write headers even with empty input"""
        output_file = temp_output_dir / "output.csv"
        
        write_csv(str(output_file), [])
        
        content = output_file.read_text()
        assert "host" in content
        assert "path" in content

    @patch('taskhound.output.writer.good')
    def test_converts_objects(self, mock_good, temp_output_dir, sample_task_object):
        """Should convert objects with to_dict method"""
        output_file = temp_output_dir / "output.csv"
        
        write_csv(str(output_file), [sample_task_object])
        
        with open(output_file) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        assert rows[0]["host"] == "WS01.example.com"

    @patch('taskhound.output.writer.good')
    def test_logs_success_message(self, mock_good, temp_output_dir):
        """Should log success message"""
        output_file = temp_output_dir / "output.csv"
        
        write_csv(str(output_file), [])
        
        mock_good.assert_called_once()
        call_arg = mock_good.call_args[0][0]
        assert "Wrote CSV results to" in call_arg

    @patch('taskhound.output.writer.good')
    def test_multiple_rows(self, mock_good, temp_output_dir, sample_task_dict):
        """Should handle multiple rows"""
        output_file = temp_output_dir / "output.csv"
        
        task2 = sample_task_dict.copy()
        task2["host"] = "WS02.example.com"
        
        write_csv(str(output_file), [sample_task_dict, task2])
        
        with open(output_file) as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        
        assert len(rows) == 2
        assert rows[0]["host"] == "DC01.example.com"
        assert rows[1]["host"] == "WS02.example.com"
