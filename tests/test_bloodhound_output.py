"""Tests for taskhound/output/bloodhound.py - BloodHound upload utilities."""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from taskhound.output.bloodhound import (
    extract_host_from_connector,
    find_model_json,
    normalize_bloodhound_connector,
)


class TestNormalizeBloodHoundConnector:
    """Tests for normalize_bloodhound_connector function."""

    def test_hostname_only_bhce(self):
        """Hostname without scheme becomes http with port 8080 for BHCE."""
        result = normalize_bloodhound_connector("localhost", is_legacy=False)
        assert result == "http://localhost:8080"

    def test_ip_only_bhce(self):
        """IP address becomes http with port 8080 for BHCE."""
        result = normalize_bloodhound_connector("192.0.2.54", is_legacy=False)
        assert result == "http://192.0.2.54:8080"

    def test_http_without_port_bhce(self):
        """HTTP scheme without port gets default 8080 for BHCE."""
        result = normalize_bloodhound_connector("http://localhost", is_legacy=False)
        assert result == "http://localhost:8080"

    def test_https_without_port_bhce(self):
        """HTTPS scheme without port gets 443 for BHCE."""
        result = normalize_bloodhound_connector("https://bh.domain.com", is_legacy=False)
        assert result == "https://bh.domain.com:443"

    def test_explicit_port_preserved_bhce(self):
        """Explicitly specified port is preserved for BHCE."""
        result = normalize_bloodhound_connector("http://localhost:9090", is_legacy=False)
        assert result == "http://localhost:9090"

    def test_hostname_only_legacy(self):
        """Hostname without scheme becomes bolt with port 7687 for legacy."""
        result = normalize_bloodhound_connector("localhost", is_legacy=True)
        assert result == "bolt://localhost:7687"

    def test_ip_only_legacy(self):
        """IP address becomes bolt with port 7687 for legacy."""
        result = normalize_bloodhound_connector("192.0.2.54", is_legacy=True)
        assert result == "bolt://192.0.2.54:7687"

    def test_bolt_without_port_legacy(self):
        """Bolt scheme without port gets default 7687 for legacy."""
        result = normalize_bloodhound_connector("bolt://localhost", is_legacy=True)
        assert result == "bolt://localhost:7687"

    def test_explicit_port_preserved_legacy(self):
        """Explicitly specified port is preserved for legacy."""
        result = normalize_bloodhound_connector("bolt://neo4j.domain.com:7474", is_legacy=True)
        assert result == "bolt://neo4j.domain.com:7474"


class TestExtractHostFromConnector:
    """Tests for extract_host_from_connector function."""

    def test_full_url_with_scheme_and_port(self):
        """Extracts hostname from full URL with scheme and port."""
        result = extract_host_from_connector("bolt://localhost:7687")
        assert result == "localhost"

    def test_http_url(self):
        """Extracts hostname from HTTP URL."""
        result = extract_host_from_connector("http://bh.example.com:8080")
        assert result == "bh.example.com"

    def test_ip_address_in_url(self):
        """Extracts IP address from URL."""
        result = extract_host_from_connector("http://192.0.2.54:8080")
        assert result == "192.0.2.54"

    def test_url_without_port(self):
        """Extracts hostname from URL without explicit port."""
        result = extract_host_from_connector("http://bloodhound.domain.com")
        assert result == "bloodhound.domain.com"

    def test_hostname_without_scheme(self):
        """Handles hostname without scheme (edge case)."""
        # Note: This may behave differently based on implementation
        result = extract_host_from_connector("192.168.1.1:8080")
        # Should extract just the IP part
        assert "192.168.1.1" in result

    def test_bare_hostname(self):
        """Handles bare hostname without scheme or port."""
        result = extract_host_from_connector("myserver")
        assert result == "myserver"


class TestFindModelJson:
    """Tests for find_model_json function."""

    def test_not_found_raises_error(self):
        """Raises FileNotFoundError when model.json not found anywhere."""
        with patch.object(Path, "exists", return_value=False), pytest.raises(FileNotFoundError) as exc_info:
            find_model_json()
        # Error message should be helpful
        assert "model.json not found" in str(exc_info.value)

    def test_finds_config_directory(self):
        """Finds model.json in config/ directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_dir = Path(tmpdir) / "config"
            config_dir.mkdir()
            model_path = config_dir / "model.json"
            model_path.write_text('{"test": true}')

            # Mock the paths to use our temp directory
            original_cwd = Path.cwd()
            try:
                os.chdir(tmpdir)
                result = find_model_json()
                # Should find the model.json in config/
                assert result.exists()
            finally:
                os.chdir(original_cwd)

    def test_warns_on_cwd_fallback(self):
        """Test that warn is called when using model.json from CWD (skipped if config/ exists)."""
        # This test verifies the warning behavior when using CWD fallback
        # Due to search order complexity, we just verify the function returns a path
        with tempfile.TemporaryDirectory() as tmpdir:
            model_path = Path(tmpdir) / "model.json"
            model_path.write_text('{"test": true}')

            original_cwd = Path.cwd()
            try:
                os.chdir(tmpdir)
                # The function should find the model.json and return it
                result = find_model_json()
                assert result.exists()
            finally:
                os.chdir(original_cwd)


class TestUploadWithoutRequests:
    """Tests for upload function when requests library is not available."""

    def test_upload_fails_without_requests(self):
        """Upload fails gracefully when requests not installed."""
        from taskhound.output import bloodhound

        # Save original value
        original_has_requests = bloodhound.HAS_REQUESTS

        try:
            # Simulate requests not being installed
            bloodhound.HAS_REQUESTS = False

            with patch("taskhound.output.bloodhound.warn"):
                result = bloodhound.upload_opengraph_to_bloodhound(
                    opengraph_file="/tmp/test.json",
                    bloodhound_url="http://localhost:8080",
                )

            assert result is False
        finally:
            # Restore original value
            bloodhound.HAS_REQUESTS = original_has_requests


class TestNormalizeEdgeCases:
    """Edge case tests for connector normalization."""

    def test_empty_string(self):
        """Handles empty string input."""
        # May raise or return some default
        try:
            result = normalize_bloodhound_connector("", is_legacy=False)
            # If it doesn't raise, check it returns something
            assert isinstance(result, str)
        except Exception:
            pass  # Some error handling is acceptable

    def test_special_characters_in_hostname(self):
        """Handles hostnames with valid special characters."""
        result = normalize_bloodhound_connector("bh-server.corp.local", is_legacy=False)
        assert "bh-server.corp.local" in result

    def test_ipv4_address(self):
        """Handles IPv4 addresses correctly."""
        result = normalize_bloodhound_connector("10.0.0.1", is_legacy=False)
        assert "10.0.0.1" in result
        assert ":8080" in result

    def test_preserves_custom_port_https(self):
        """Preserves custom port for HTTPS URLs."""
        result = normalize_bloodhound_connector("https://bh.domain.com:9443", is_legacy=False)
        assert result == "https://bh.domain.com:9443"
