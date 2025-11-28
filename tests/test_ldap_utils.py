"""
Test suite for LDAP utility functions.

Tests cover:
- parse_ntlm_hashes function
- resolve_dc_hostname function
- get_ldap_connection function
"""

import pytest
import socket
from unittest.mock import MagicMock, patch

from taskhound.utils.ldap import (
    parse_ntlm_hashes,
    resolve_dc_hostname,
    get_ldap_connection,
    LDAPConnectionError,
)


# ============================================================================
# Test: parse_ntlm_hashes
# ============================================================================


class TestParseNtlmHashes:
    """Tests for parse_ntlm_hashes function"""

    def test_none_input(self):
        """Should return empty strings for None input"""
        lmhash, nthash = parse_ntlm_hashes(None)
        assert lmhash == ""
        assert nthash == ""

    def test_empty_string_input(self):
        """Should return empty strings for empty string"""
        lmhash, nthash = parse_ntlm_hashes("")
        assert lmhash == ""
        assert nthash == ""

    def test_nt_hash_only(self):
        """Should parse NT hash when no colon"""
        lmhash, nthash = parse_ntlm_hashes("aad3b435b51404eeaad3b435b51404ee")
        assert lmhash == ""
        assert nthash == "aad3b435b51404eeaad3b435b51404ee"

    def test_lm_nt_hash_format(self):
        """Should parse LM:NT format correctly"""
        lmhash, nthash = parse_ntlm_hashes(
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        )
        assert lmhash == "aad3b435b51404eeaad3b435b51404ee"
        assert nthash == "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_empty_lm_with_nt_hash(self):
        """Should handle empty LM hash with colon prefix"""
        lmhash, nthash = parse_ntlm_hashes(":31d6cfe0d16ae931b73c59d7e0c089c0")
        assert lmhash == ""
        assert nthash == "31d6cfe0d16ae931b73c59d7e0c089c0"


# ============================================================================
# Test: resolve_dc_hostname
# ============================================================================


class TestResolveDcHostname:
    """Tests for resolve_dc_hostname function"""

    @patch('taskhound.utils.ldap.socket.gethostbyaddr')
    def test_socket_reverse_dns_success(self, mock_gethostbyaddr):
        """Should use socket reverse DNS lookup"""
        mock_gethostbyaddr.return_value = ("dc01.example.com", [], [])
        
        result = resolve_dc_hostname("192.168.1.1", "example.com")
        
        assert result == "dc01.example.com"

    @patch('taskhound.utils.ldap.socket.gethostbyaddr')
    def test_socket_returns_domain_name_tries_fqdn(self, mock_gethostbyaddr):
        """Should skip result if it matches domain name"""
        mock_gethostbyaddr.return_value = ("example.com", [], [])
        
        with patch('taskhound.utils.ldap.socket.getfqdn') as mock_fqdn:
            mock_fqdn.return_value = "dc01.example.com"
            result = resolve_dc_hostname("192.168.1.1", "example.com")
            
            assert result == "dc01.example.com"

    @patch('taskhound.utils.ldap.socket.gethostbyaddr')
    def test_socket_herror_returns_none(self, mock_gethostbyaddr):
        """Should return None when socket.herror occurs"""
        mock_gethostbyaddr.side_effect = socket.herror("Reverse lookup failed")
        
        with patch('taskhound.utils.ldap.socket.getfqdn') as mock_fqdn:
            mock_fqdn.return_value = "192.168.1.1"  # Returns IP, not hostname
            result = resolve_dc_hostname("192.168.1.1", "example.com")
            
            assert result is None

    @patch('taskhound.utils.ldap.socket.gethostbyaddr')
    def test_all_methods_fail_returns_none(self, mock_gethostbyaddr):
        """Should return None when all methods fail"""
        mock_gethostbyaddr.side_effect = socket.herror()
        
        with patch('taskhound.utils.ldap.socket.getfqdn') as mock_fqdn:
            mock_fqdn.side_effect = Exception("FQDN lookup failed")
            result = resolve_dc_hostname("192.168.1.1", "example.com")
            
            assert result is None

    @patch('taskhound.utils.ldap.socket.getfqdn')
    @patch('taskhound.utils.ldap.socket.gethostbyaddr')
    def test_getfqdn_fallback_success(self, mock_gethostbyaddr, mock_getfqdn):
        """Should use getfqdn as fallback when reverse DNS fails"""
        mock_gethostbyaddr.side_effect = socket.herror()
        mock_getfqdn.return_value = "dc02.example.com"
        
        result = resolve_dc_hostname("192.168.1.1", "example.com")
        
        assert result == "dc02.example.com"

    @patch('taskhound.utils.ldap.socket.getfqdn')
    @patch('taskhound.utils.ldap.socket.gethostbyaddr')
    def test_getfqdn_returns_ip_no_hostname(self, mock_gethostbyaddr, mock_getfqdn):
        """Should return None when getfqdn just returns the IP"""
        mock_gethostbyaddr.side_effect = socket.herror()
        mock_getfqdn.return_value = "192.168.1.1"  # Returns same IP
        
        result = resolve_dc_hostname("192.168.1.1", "example.com")
        
        assert result is None

    def test_use_tcp_parameter_accepted(self):
        """Should accept use_tcp parameter without error"""
        # Just verify the function accepts the parameter (actual DNS lookup will fail/be mocked)
        with patch('taskhound.utils.ldap.socket.gethostbyaddr') as mock_gethostbyaddr:
            mock_gethostbyaddr.return_value = ("dc01.example.com", [], [])
            result = resolve_dc_hostname("192.168.1.1", "example.com", use_tcp=True)
            assert result == "dc01.example.com"

    @patch('dns.reversename.from_address')
    @patch('dns.resolver.Resolver')
    def test_use_tcp_passes_to_resolver(self, mock_resolver_class, mock_from_address):
        """Should pass tcp=True to resolver.resolve() when use_tcp=True"""
        mock_resolver = MagicMock()
        mock_resolver_class.return_value = mock_resolver
        mock_from_address.return_value = "1.1.168.192.in-addr.arpa"
        
        mock_answer = MagicMock()
        mock_answer.__str__ = MagicMock(return_value="dc01.example.com.")
        mock_resolver.resolve.return_value = [mock_answer]
        
        result = resolve_dc_hostname("192.168.1.1", "example.com", use_tcp=True)
        
        # Verify resolve was called with tcp=True
        mock_resolver.resolve.assert_called_once()
        call_args = mock_resolver.resolve.call_args
        assert call_args[1].get('tcp') is True
        assert result == "dc01.example.com"


# ============================================================================
# Test: get_ldap_connection
# ============================================================================


class TestGetLdapConnection:
    """Tests for get_ldap_connection function"""

    @patch('taskhound.utils.ldap.ldap_impacket.LDAPConnection')
    def test_ldaps_connection_success(self, mock_ldap_class):
        """Should connect via LDAPS successfully"""
        mock_conn = MagicMock()
        mock_ldap_class.return_value = mock_conn
        
        result = get_ldap_connection(
            dc_ip="192.168.1.1",
            domain="example.com",
            username="admin",
            password="password123"
        )
        
        assert result == mock_conn
        mock_conn.login.assert_called_once()
        call_kwargs = mock_conn.login.call_args[1]
        assert call_kwargs["user"] == "admin"
        assert call_kwargs["password"] == "password123"
        assert call_kwargs["domain"] == "example.com"

    @patch('taskhound.utils.ldap.ldap_impacket.LDAPConnection')
    def test_ldaps_fails_falls_back_to_ldap(self, mock_ldap_class):
        """Should fallback to LDAP if LDAPS fails"""
        mock_conn = MagicMock()
        call_count = 0
        
        def ldap_side_effect(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if "ldaps" in url:
                raise Exception("SSL certificate error")
            return mock_conn
        
        mock_ldap_class.side_effect = ldap_side_effect
        
        result = get_ldap_connection(
            dc_ip="192.168.1.1",
            domain="example.com",
            username="admin",
            password="pass"
        )
        
        assert result == mock_conn
        assert call_count == 2

    @patch('taskhound.utils.ldap.ldap_impacket.LDAPConnection')
    def test_both_protocols_fail_raises_error(self, mock_ldap_class):
        """Should raise LDAPConnectionError when both protocols fail"""
        mock_ldap_class.side_effect = Exception("Connection refused")
        
        with pytest.raises(LDAPConnectionError) as exc_info:
            get_ldap_connection(
                dc_ip="192.168.1.1",
                domain="example.com",
                username="admin",
                password="pass"
            )
        
        assert "Connection refused" in str(exc_info.value)

    @patch('taskhound.utils.ldap.ldap_impacket.LDAPConnection')
    def test_ntlm_hash_authentication(self, mock_ldap_class):
        """Should authenticate with NTLM hashes"""
        mock_conn = MagicMock()
        mock_ldap_class.return_value = mock_conn
        
        result = get_ldap_connection(
            dc_ip="192.168.1.1",
            domain="example.com",
            username="admin",
            hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        )
        
        assert result == mock_conn
        call_kwargs = mock_conn.login.call_args[1]
        assert call_kwargs["lmhash"] == "aad3b435b51404eeaad3b435b51404ee"
        assert call_kwargs["nthash"] == "31d6cfe0d16ae931b73c59d7e0c089c0"

    @patch('taskhound.utils.ldap.resolve_dc_hostname')
    @patch('taskhound.utils.ldap.ldap_impacket.LDAPConnection')
    def test_kerberos_authentication(self, mock_ldap_class, mock_resolve):
        """Should use Kerberos authentication when specified"""
        mock_conn = MagicMock()
        mock_ldap_class.return_value = mock_conn
        mock_resolve.return_value = "dc01.example.com"
        
        result = get_ldap_connection(
            dc_ip="192.168.1.1",
            domain="example.com",
            username="admin",
            password="pass",
            kerberos=True
        )
        
        assert result == mock_conn
        mock_conn.kerberosLogin.assert_called_once()
        call_kwargs = mock_conn.kerberosLogin.call_args[1]
        assert call_kwargs["user"] == "admin"
        assert call_kwargs["domain"] == "example.com"

    @patch('taskhound.utils.ldap.ldap_impacket.LDAPConnection')
    def test_kerberos_with_explicit_dc_host(self, mock_ldap_class):
        """Should use provided dc_host for Kerberos SPN"""
        mock_conn = MagicMock()
        mock_ldap_class.return_value = mock_conn
        
        result = get_ldap_connection(
            dc_ip="192.168.1.1",
            domain="example.com",
            username="admin",
            password="pass",
            kerberos=True,
            dc_host="dc01.example.com"
        )
        
        assert result == mock_conn
        mock_conn.kerberosLogin.assert_called_once()
        # Check that URL contains the hostname
        call_args = mock_ldap_class.call_args
        assert "dc01.example.com" in call_args[0][0]

    @patch('taskhound.utils.ldap.ldap_impacket.LDAPConnection')
    def test_base_dn_constructed_from_domain(self, mock_ldap_class):
        """Should construct correct base DN from domain"""
        mock_conn = MagicMock()
        mock_ldap_class.return_value = mock_conn
        
        get_ldap_connection(
            dc_ip="192.168.1.1",
            domain="sub.example.com",
            username="admin",
            password="pass"
        )
        
        call_kwargs = mock_ldap_class.call_args[1]
        assert call_kwargs["baseDN"] == "DC=sub,DC=example,DC=com"

    @patch('taskhound.utils.ldap.ldap_impacket.LDAPConnection')
    def test_stronger_auth_required_error(self, mock_ldap_class):
        """Should handle strongerAuthRequired error"""
        mock_conn = MagicMock()
        
        def ldap_side_effect(url, **kwargs):
            if "ldaps" in url:
                raise Exception("SSL error")
            mock_conn.login.side_effect = Exception("strongerAuthRequired")
            return mock_conn
        
        mock_ldap_class.side_effect = ldap_side_effect
        
        with pytest.raises(LDAPConnectionError):
            get_ldap_connection(
                dc_ip="192.168.1.1",
                domain="example.com",
                username="admin",
                password="pass"
            )

    @patch('taskhound.utils.ldap.ldap_impacket.LDAPConnection')
    def test_no_password_uses_empty_string(self, mock_ldap_class):
        """Should use empty string when password is None"""
        mock_conn = MagicMock()
        mock_ldap_class.return_value = mock_conn
        
        get_ldap_connection(
            dc_ip="192.168.1.1",
            domain="example.com",
            username="admin",
            password=None
        )
        
        call_kwargs = mock_conn.login.call_args[1]
        assert call_kwargs["password"] == ""
