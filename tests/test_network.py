"""
Test network utility functions in taskhound.utils.network.
"""

from unittest.mock import patch

from taskhound.utils.network import verify_ldap_connection


class TestNetwork:
    @patch("taskhound.utils.network.resolve_sid_via_ldap")
    @patch("taskhound.utils.network.extract_domain_sid_from_hv")
    @patch("taskhound.utils.network.info")
    @patch("taskhound.utils.network.warn")
    @patch("taskhound.utils.network.good")
    def test_verify_ldap_connection_success(self, mock_good, mock_warn, mock_info, mock_extract, mock_resolve):
        """Test successful LDAP connection test."""
        # Setup mocks
        mock_extract.return_value = "S-1-5-21-123-456-789-500"
        mock_resolve.return_value = "Administrator"

        # Call function
        verify_ldap_connection(
            domain="corp.local",
            dc_ip="192.168.1.10",
            username="user",
            password="password",
            hashes=None,
            kerberos=False,
            no_ldap=False,
        )

        # Verify
        mock_resolve.assert_called_once()
        mock_good.assert_any_call("SID resolution initialized and ready")
        mock_warn.assert_not_called()

    @patch("taskhound.utils.network.info")
    def test_verify_ldap_connection_disabled(self, mock_info):
        """Test disabled LDAP connection test."""
        verify_ldap_connection(
            domain="corp.local",
            dc_ip=None,
            username="user",
            password="password",
            hashes=None,
            kerberos=False,
            no_ldap=True,
        )

        mock_info.assert_called_with("LDAP resolution disabled - skipping connection test")

    @patch("taskhound.utils.network.warn")
    def test_verify_ldap_connection_no_creds(self, mock_warn):
        """Test LDAP connection test with no credentials."""
        verify_ldap_connection(
            domain="corp.local", dc_ip=None, username="user", password=None, hashes=None, kerberos=False, no_ldap=False
        )

        mock_warn.assert_called_with("LDAP test skipped - no credentials available (password or hashes)")

    @patch("taskhound.utils.network.resolve_sid_via_ldap")
    @patch("taskhound.utils.network.extract_domain_sid_from_hv")
    @patch("taskhound.utils.network.warn")
    def test_verify_ldap_connection_failure(self, mock_warn, mock_extract, mock_resolve):
        """Test failed LDAP connection test."""
        # Setup mocks
        mock_extract.return_value = "S-1-5-21-123-456-789-500"
        mock_resolve.return_value = None

        # Call function
        verify_ldap_connection(
            domain="corp.local",
            dc_ip="192.168.1.10",
            username="user",
            password="password",
            hashes=None,
            kerberos=False,
            no_ldap=False,
        )

        # Verify
        mock_resolve.assert_called_once()
        mock_warn.assert_any_call("LDAP test failed: Could not resolve S-1-5-21-123-456-789-500")
