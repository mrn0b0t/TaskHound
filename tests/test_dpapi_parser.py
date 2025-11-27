"""
Test DPAPI blob parsing functionality.
"""

import os
import tempfile
from unittest.mock import patch

from taskhound.dpapi.parser import DPAPIBlobParser


def test_parser_initialization():
    """Test DPAPIBlobParser can be instantiated."""
    parser = DPAPIBlobParser()
    assert parser is not None
    assert parser.parsed_blobs == []


def test_parse_blob_too_small():
    """Test that blobs smaller than 16 bytes are rejected."""
    parser = DPAPIBlobParser()
    small_blob = b"\x00" * 8

    result = parser.parse_blob(small_blob)
    assert result is None


def test_parse_blob_valid_structure():
    """Test parsing a minimal valid DPAPI blob structure."""
    parser = DPAPIBlobParser()

    # Create minimal valid blob: version (4) + reserved (8) + minimal data
    blob = b"\x02\x00\x00\x00"  # version 2
    blob += b"\x00" * 8  # reserved
    blob += b"test"  # some data

    result = parser.parse_blob(blob)
    assert result is not None
    assert result["version"] == 2
    assert result["total_size"] == len(blob)


def test_algorithm_name_lookup():
    """Test algorithm ID to name conversion."""
    parser = DPAPIBlobParser()

    assert "AES_256" in parser._algorithm_name(0x6610)
    assert "3DES" in parser._algorithm_name(0x6609)
    assert "Unknown" in parser._algorithm_name(0x9999)


def test_analyze_blob_collection():
    """Test collection analysis with multiple blobs."""
    parser = DPAPIBlobParser()

    # Create test blob files list (empty for now)
    analysis = parser.analyze_blob_collection([])

    assert analysis["total_blobs"] == 0
    assert analysis["successfully_parsed"] == 0
    assert isinstance(analysis["credential_guids"], list)


class TestAlgorithmLookup:
    """Tests for algorithm name lookup."""

    def test_aes_128(self):
        """Test AES-128 algorithm lookup."""
        parser = DPAPIBlobParser()
        assert "AES_128" in parser._algorithm_name(0x660E)

    def test_aes_192(self):
        """Test AES-192 algorithm lookup."""
        parser = DPAPIBlobParser()
        assert "AES_192" in parser._algorithm_name(0x660F)

    def test_triple_des_112(self):
        """Test 3DES-112 algorithm lookup."""
        parser = DPAPIBlobParser()
        assert "3DES_112" in parser._algorithm_name(0x6603)

    def test_rc2(self):
        """Test RC2 algorithm lookup."""
        parser = DPAPIBlobParser()
        assert "RC2" in parser._algorithm_name(0x6602)

    def test_rc4(self):
        """Test RC4 algorithm lookup."""
        parser = DPAPIBlobParser()
        assert "RC4" in parser._algorithm_name(0x6801)

    def test_sha1(self):
        """Test SHA1 algorithm lookup."""
        parser = DPAPIBlobParser()
        assert "SHA1" in parser._algorithm_name(0x8003)

    def test_sha256(self):
        """Test SHA256 algorithm lookup."""
        parser = DPAPIBlobParser()
        assert "SHA256" in parser._algorithm_name(0x8004)

    def test_sha384(self):
        """Test SHA384 algorithm lookup."""
        parser = DPAPIBlobParser()
        assert "SHA384" in parser._algorithm_name(0x800C)

    def test_sha512(self):
        """Test SHA512 algorithm lookup."""
        parser = DPAPIBlobParser()
        assert "SHA512" in parser._algorithm_name(0x800D)

    def test_none_algorithm(self):
        """Test None algorithm lookup."""
        parser = DPAPIBlobParser()
        assert "None" in parser._algorithm_name(0x0000)


class TestParseBlobPath:
    """Tests for blob parsing with path context."""

    def test_parse_blob_with_path(self):
        """Test parsing blob stores path context."""
        parser = DPAPIBlobParser()

        blob = b"\x02\x00\x00\x00"  # version 2
        blob += b"\x00" * 8  # reserved
        blob += b"data"

        result = parser.parse_blob(blob, blob_path="/path/to/blob")
        assert result is not None
        assert result["blob_path"] == "/path/to/blob"

    def test_parse_blob_without_path(self):
        """Test parsing blob without path context."""
        parser = DPAPIBlobParser()

        blob = b"\x02\x00\x00\x00"
        blob += b"\x00" * 8
        blob += b"data"

        result = parser.parse_blob(blob, blob_path=None)
        assert result is not None
        assert result["blob_path"] is None


class TestParseBlobFile:
    """Tests for parsing blobs from files."""

    def test_parse_blob_file_not_found(self):
        """Test parsing non-existent file."""
        parser = DPAPIBlobParser()

        result = parser.parse_blob_file("/nonexistent/path/to/blob")
        assert result is None

    def test_parse_blob_file_valid(self):
        """Test parsing valid blob from file."""
        parser = DPAPIBlobParser()

        # Create temp file with blob data
        with tempfile.NamedTemporaryFile(delete=False) as f:
            blob = b"\x02\x00\x00\x00"  # version 2
            blob += b"\x00" * 8  # reserved
            blob += b"testdata"
            f.write(blob)
            temp_path = f.name

        try:
            result = parser.parse_blob_file(temp_path)
            assert result is not None
            assert result["version"] == 2
            assert result["blob_path"] == temp_path
        finally:
            os.unlink(temp_path)


class TestAnalyzeBlobCollection:
    """Tests for blob collection analysis."""

    def test_empty_collection(self):
        """Test analysis of empty collection."""
        parser = DPAPIBlobParser()

        analysis = parser.analyze_blob_collection([])
        assert analysis["total_blobs"] == 0
        assert analysis["successfully_parsed"] == 0
        assert len(analysis["credential_guids"]) == 0

    def test_collection_with_nonexistent_files(self):
        """Test analysis with non-existent files."""
        parser = DPAPIBlobParser()

        analysis = parser.analyze_blob_collection(["/fake/path1", "/fake/path2"])
        assert analysis["total_blobs"] == 2
        assert analysis["successfully_parsed"] == 0

    def test_collection_with_valid_files(self):
        """Test analysis with valid blob files."""
        parser = DPAPIBlobParser()

        # Create temp files with blob data
        temp_paths = []
        for i in range(2):
            with tempfile.NamedTemporaryFile(delete=False) as f:
                blob = b"\x02\x00\x00\x00" + b"\x00" * 8 + f"data{i}".encode()
                f.write(blob)
                temp_paths.append(f.name)

        try:
            analysis = parser.analyze_blob_collection(temp_paths)
            assert analysis["total_blobs"] == 2
            assert analysis["successfully_parsed"] == 2
        finally:
            for path in temp_paths:
                os.unlink(path)


class TestPrintMethods:
    """Tests for print/display methods."""

    @patch("taskhound.dpapi.parser.status")
    def test_print_blob_summary(self, mock_status):
        """Test printing blob summary."""
        parser = DPAPIBlobParser()

        blob_info = {
            "blob_path": "/path/to/blob",
            "version": 2,
            "total_size": 100,
            "parsed_successfully": True,
            "credential_guid": "test-guid-123",
        }

        # Should not raise
        parser.print_blob_summary(blob_info)

    @patch("taskhound.dpapi.parser.status")
    def test_print_collection_summary(self, mock_status):
        """Test printing collection summary."""
        parser = DPAPIBlobParser()

        analysis = {
            "total_blobs": 5,
            "successfully_parsed": 3,
            "failed_to_parse": 2,
            "credential_guids": ["guid1", "guid2"],
            "master_key_guids": ["mk1"],
            "blob_details": [],
            "cipher_algorithms": {"AES_256": 3},
            "hash_algorithms": {"SHA256": 3},
        }

        # Should not raise
        parser.print_collection_summary(analysis)


class TestBlobVersions:
    """Tests for different blob version handling."""

    def test_version_1(self):
        """Test parsing version 1 blob."""
        parser = DPAPIBlobParser()

        blob = b"\x01\x00\x00\x00"  # version 1
        blob += b"\x00" * 8
        blob += b"data"

        result = parser.parse_blob(blob)
        assert result is not None
        assert result["version"] == 1

    def test_version_2(self):
        """Test parsing version 2 blob."""
        parser = DPAPIBlobParser()

        blob = b"\x02\x00\x00\x00"  # version 2
        blob += b"\x00" * 8
        blob += b"data"

        result = parser.parse_blob(blob)
        assert result is not None
        assert result["version"] == 2

    def test_high_version(self):
        """Test parsing blob with unexpected high version."""
        parser = DPAPIBlobParser()

        blob = b"\x0A\x00\x00\x00"  # version 10
        blob += b"\x00" * 8
        blob += b"data"

        result = parser.parse_blob(blob)
        assert result is not None
        assert result["version"] == 10


class TestReservedBytes:
    """Tests for reserved bytes handling."""

    def test_reserved_bytes_extraction(self):
        """Test that reserved bytes are extracted as hex."""
        parser = DPAPIBlobParser()

        blob = b"\x02\x00\x00\x00"  # version
        blob += b"\x01\x02\x03\x04\x05\x06\x07\x08"  # reserved
        blob += b"data"

        result = parser.parse_blob(blob)
        assert result is not None
        assert result["reserved"] == "0102030405060708"
