"""
Test suite for network utilities.

Tests cover:
- verify_ldap_connection function
- LDAP credential handling
- SID resolution testing
"""

import pytest
from unittest.mock import MagicMock, Mock, patch

from taskhound.utils.network import verify_ldap_connection


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def mock_hv_loader():
    """Create a mock HighValueLoader"""
    return MagicMock()


# ============================================================================
# Unit Tests: verify_ldap_connection
# ============================================================================


class TestVerifyLdapConnection:
    """Tests for verify_ldap_connection function"""

    @patch('taskhound.utils.network.info')
    def test_no_ldap_flag_skips_test(self, mock_info):
        """Should skip test when no_ldap is True"""
        verify_ldap_connection(
            domain="example.com",
            dc_ip="192.168.1.1",
            username="admin",
            password="secret",
            hashes=None,
            kerberos=False,
            no_ldap=True
        )
        
        mock_info.assert_called_once()
        assert "disabled" in mock_info.call_args[0][0]

    @patch('taskhound.utils.network.warn')
    def test_no_credentials_warns(self, mock_warn):
        """Should warn when no password or hashes provided"""
        verify_ldap_connection(
            domain="example.com",
            dc_ip="192.168.1.1",
            username="admin",
            password=None,
            hashes=None,
            kerberos=False,
            no_ldap=False
        )
        
        mock_warn.assert_called()
        assert "no credentials" in mock_warn.call_args[0][0]

    @patch('taskhound.utils.network.warn')
    def test_missing_domain_warns(self, mock_warn):
        """Should warn when domain is missing"""
        verify_ldap_connection(
            domain=None,
            dc_ip="192.168.1.1",
            username="admin",
            password="secret",
            hashes=None,
            kerberos=False,
            no_ldap=False
        )
        
        mock_warn.assert_called()
        assert "missing credentials" in mock_warn.call_args[0][0]

    @patch('taskhound.utils.network.warn')
    def test_missing_username_warns(self, mock_warn):
        """Should warn when username is missing"""
        verify_ldap_connection(
            domain="example.com",
            dc_ip="192.168.1.1",
            username=None,
            password="secret",
            hashes=None,
            kerberos=False,
            no_ldap=False
        )
        
        mock_warn.assert_called()
        assert "missing credentials" in mock_warn.call_args[0][0]

    @patch('taskhound.utils.network.info')
    @patch('taskhound.utils.network.extract_domain_sid_from_hv')
    def test_no_bloodhound_data_skips_sid_test(self, mock_extract, mock_info):
        """Should skip SID test when no BloodHound data available"""
        mock_extract.return_value = None
        
        verify_ldap_connection(
            domain="example.com",
            dc_ip="192.168.1.1",
            username="admin",
            password="secret",
            hashes=None,
            kerberos=False,
            no_ldap=False,
            hv_loader=MagicMock()
        )
        
        # Check that info was called with "No BloodHound data available"
        info_calls = [str(c) for c in mock_info.call_args_list]
        assert any("BloodHound data" in str(c) for c in info_calls)

    @patch('taskhound.utils.network.good')
    @patch('taskhound.utils.network.info')
    @patch('taskhound.utils.network.resolve_sid_via_ldap')
    @patch('taskhound.utils.network.extract_domain_sid_from_hv')
    def test_successful_sid_resolution(self, mock_extract, mock_resolve, mock_info, mock_good):
        """Should report success when SID resolution works"""
        mock_extract.return_value = "S-1-5-21-12345-67890-11111-500"
        mock_resolve.return_value = "Administrator"
        
        verify_ldap_connection(
            domain="example.com",
            dc_ip="192.168.1.1",
            username="admin",
            password="secret",
            hashes=None,
            kerberos=False,
            no_ldap=False,
            hv_loader=MagicMock()
        )
        
        # Check that good was called with success message
        good_calls = [str(c) for c in mock_good.call_args_list]
        assert any("successful" in str(c) for c in good_calls)

    @patch('taskhound.utils.network.warn')
    @patch('taskhound.utils.network.info')
    @patch('taskhound.utils.network.resolve_sid_via_ldap')
    @patch('taskhound.utils.network.extract_domain_sid_from_hv')
    def test_failed_sid_resolution(self, mock_extract, mock_resolve, mock_info, mock_warn):
        """Should warn when SID resolution fails"""
        mock_extract.return_value = "S-1-5-21-12345-67890-11111-500"
        mock_resolve.return_value = None
        
        verify_ldap_connection(
            domain="example.com",
            dc_ip="192.168.1.1",
            username="admin",
            password="secret",
            hashes=None,
            kerberos=False,
            no_ldap=False,
            hv_loader=MagicMock()
        )
        
        # Check that warn was called
        warn_calls = [str(c) for c in mock_warn.call_args_list]
        assert any("failed" in str(c).lower() for c in warn_calls)

    @patch('taskhound.utils.network.info')
    @patch('taskhound.utils.network.extract_domain_sid_from_hv')
    def test_ldap_credentials_priority(self, mock_extract, mock_info):
        """Should use dedicated LDAP credentials when provided"""
        mock_extract.return_value = None  # No BH data to avoid actual LDAP call
        
        verify_ldap_connection(
            domain="main.com",
            dc_ip="192.168.1.1",
            username="mainuser",
            password="mainpass",
            hashes=None,
            kerberos=False,
            no_ldap=False,
            ldap_domain="ldap.com",
            ldap_user="ldapuser",
            ldap_password="ldappass"
        )
        
        # Check that info was called with dedicated LDAP credentials message
        info_calls = [str(c) for c in mock_info.call_args_list]
        assert any("ldapuser" in str(c) for c in info_calls)

    @patch('taskhound.utils.network.info')
    @patch('taskhound.utils.network.extract_domain_sid_from_hv')
    def test_main_auth_credentials_fallback(self, mock_extract, mock_info):
        """Should fall back to main auth credentials when LDAP creds not set"""
        mock_extract.return_value = None  # No BH data to avoid actual LDAP call
        
        verify_ldap_connection(
            domain="example.com",
            dc_ip="192.168.1.1",
            username="admin",
            password="secret",
            hashes=None,
            kerberos=False,
            no_ldap=False,
            ldap_domain=None,
            ldap_user=None,
            ldap_password=None
        )
        
        # Check that info was called with main auth credentials
        info_calls = [str(c) for c in mock_info.call_args_list]
        assert any("main auth" in str(c) for c in info_calls)

    @patch('taskhound.utils.network.warn')
    @patch('taskhound.utils.network.info')
    @patch('taskhound.utils.network.extract_domain_sid_from_hv')
    def test_import_error_handled(self, mock_extract, mock_info, mock_warn):
        """Should handle ImportError gracefully"""
        mock_extract.side_effect = ImportError("Missing ldap module")
        
        verify_ldap_connection(
            domain="example.com",
            dc_ip="192.168.1.1",
            username="admin",
            password="secret",
            hashes=None,
            kerberos=False,
            no_ldap=False,
            hv_loader=MagicMock()
        )
        
        mock_warn.assert_called()
        assert any("Missing dependencies" in str(c) for c in mock_warn.call_args_list)

    @patch('taskhound.utils.network.warn')
    @patch('taskhound.utils.network.info')
    @patch('taskhound.utils.network.extract_domain_sid_from_hv')
    def test_generic_exception_handled(self, mock_extract, mock_info, mock_warn):
        """Should handle generic exceptions gracefully"""
        mock_extract.side_effect = Exception("Unexpected error")
        
        verify_ldap_connection(
            domain="example.com",
            dc_ip="192.168.1.1",
            username="admin",
            password="secret",
            hashes=None,
            kerberos=False,
            no_ldap=False,
            hv_loader=MagicMock()
        )
        
        mock_warn.assert_called()
        assert any("Unexpected" in str(c) or "failed" in str(c) for c in mock_warn.call_args_list)

    @patch('taskhound.utils.network.warn')
    def test_hashes_accepted_without_password(self, mock_warn):
        """Should accept NTLM hashes without password"""
        with patch('taskhound.utils.network.info') as mock_info, \
             patch('taskhound.utils.network.extract_domain_sid_from_hv') as mock_extract:
            mock_extract.return_value = None  # No BH data
            
            # Should not warn about missing credentials when hashes are provided
            verify_ldap_connection(
                domain="example.com",
                dc_ip="192.168.1.1",
                username="admin",
                password=None,
                hashes="aad3b435b51404eeaad3b435b51404ee:hash",
                kerberos=False,
                no_ldap=False
            )
            
            # Should not see "no credentials" warning
            warn_calls = [str(c) for c in mock_warn.call_args_list]
            assert not any("no credentials" in str(c) for c in warn_calls)
