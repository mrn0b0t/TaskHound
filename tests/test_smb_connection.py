"""
Test suite for SMB connection functions.

Tests cover:
- _parse_hashes function
- smb_connect function
- smb_negotiate function
- smb_login function
- smb_connect_with_laps function
"""

from unittest.mock import MagicMock, patch

import pytest

from taskhound.smb.connection import (
    _parse_hashes,
    smb_connect,
    smb_connect_with_laps,
    smb_login,
    smb_negotiate,
)

# ============================================================================
# Test: _parse_hashes
# ============================================================================


class TestParseHashes:
    """Tests for _parse_hashes function"""

    def test_none_input(self):
        """Should return empty password and hashes for None"""
        pwd, lm, nt = _parse_hashes(None)
        assert pwd is None
        assert lm == ""
        assert nt == ""

    def test_empty_string_input(self):
        """Should return empty values for empty string"""
        pwd, lm, nt = _parse_hashes("")
        assert pwd is None
        assert lm == ""
        assert nt == ""

    def test_lm_nt_hash_format(self):
        """Should parse LM:NT format correctly"""
        pwd, lm, nt = _parse_hashes(
            "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        )
        assert pwd is None
        assert lm == "aad3b435b51404eeaad3b435b51404ee"
        assert nt == "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_nt_hash_only_32_hex(self):
        """Should recognize 32-char hex as NT hash"""
        pwd, lm, nt = _parse_hashes("31d6cfe0d16ae931b73c59d7e0c089c0")
        assert pwd is None
        assert lm == ""
        assert nt == "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_cleartext_password(self):
        """Should treat non-hash strings as cleartext password"""
        pwd, lm, nt = _parse_hashes("MySecretP@ssw0rd!")
        assert pwd == "MySecretP@ssw0rd!"
        assert lm == ""
        assert nt == ""

    def test_empty_lm_with_nt_hash(self):
        """Should handle empty LM with NT hash"""
        pwd, lm, nt = _parse_hashes(":31d6cfe0d16ae931b73c59d7e0c089c0")
        assert pwd is None
        assert lm == ""
        assert nt == "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_password_with_colon(self):
        """Should handle passwords containing colon after first split"""
        pwd, lm, nt = _parse_hashes("abc:def:ghi")
        # Splits on first colon only
        assert pwd is None
        assert lm == "abc"
        assert nt == "def:ghi"

    def test_short_hex_as_password(self):
        """Should treat short hex strings as passwords"""
        pwd, lm, nt = _parse_hashes("abcdef12345")  # Not 32 chars
        assert pwd == "abcdef12345"
        assert lm == ""
        assert nt == ""

    def test_whitespace_trimmed(self):
        """Should trim whitespace from hashes"""
        pwd, lm, nt = _parse_hashes(" aad3b435b51404eeaad3b435b51404ee : 31d6cfe0d16ae931b73c59d7e0c089c0 ")
        assert pwd is None
        assert lm == "aad3b435b51404eeaad3b435b51404ee"
        assert nt == "31d6cfe0d16ae931b73c59d7e0c089c0"


# ============================================================================
# Test: smb_connect
# ============================================================================


class TestSmbConnect:
    """Tests for smb_connect function"""

    @patch('taskhound.smb.connection.SMBConnection')
    def test_basic_password_auth(self, mock_smb_class):
        """Should connect with basic password authentication"""
        mock_smb = MagicMock()
        mock_smb_class.return_value = mock_smb

        result = smb_connect(
            target="192.168.1.1",
            domain="EXAMPLE",
            username="admin",
            password="password123"
        )

        assert result == mock_smb
        mock_smb.login.assert_called_once_with("admin", "password123", "EXAMPLE")

    @patch('taskhound.smb.connection.SMBConnection')
    def test_ntlm_hash_auth(self, mock_smb_class):
        """Should connect with NTLM hash authentication"""
        mock_smb = MagicMock()
        mock_smb_class.return_value = mock_smb

        result = smb_connect(
            target="192.168.1.1",
            domain="EXAMPLE",
            username="admin",
            password="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        )

        assert result == mock_smb
        mock_smb.login.assert_called_once_with(
            "admin", "", "EXAMPLE",
            lmhash="aad3b435b51404eeaad3b435b51404ee",
            nthash="31d6cfe0d16ae931b73c59d7e0c089c0"
        )

    @patch('taskhound.smb.connection.SMBConnection')
    def test_kerberos_auth(self, mock_smb_class):
        """Should connect with Kerberos authentication"""
        mock_smb = MagicMock()
        mock_smb_class.return_value = mock_smb

        result = smb_connect(
            target="192.168.1.1",
            domain="EXAMPLE",
            username="admin",
            password="password123",
            kerberos=True,
            dc_ip="192.168.1.10"
        )

        assert result == mock_smb
        mock_smb.kerberosLogin.assert_called_once()
        call_kwargs = mock_smb.kerberosLogin.call_args[1]
        assert call_kwargs["user"] == "admin"
        assert call_kwargs["password"] == "password123"
        assert call_kwargs["domain"] == "EXAMPLE"
        assert call_kwargs["kdcHost"] == "192.168.1.10"

    @patch('taskhound.smb.connection.SMBConnection')
    def test_custom_timeout(self, mock_smb_class):
        """Should use custom timeout"""
        mock_smb = MagicMock()
        mock_smb_class.return_value = mock_smb

        smb_connect(
            target="192.168.1.1",
            domain="EXAMPLE",
            username="admin",
            password="pass",
            timeout=120
        )

        call_kwargs = mock_smb_class.call_args[1]
        assert call_kwargs["timeout"] == 120


# ============================================================================
# Test: smb_negotiate
# ============================================================================


class TestSmbNegotiate:
    """Tests for smb_negotiate function"""

    @patch('taskhound.smb.connection.SMBConnection')
    def test_creates_connection_without_auth(self, mock_smb_class):
        """Should create connection without authenticating"""
        mock_smb = MagicMock()
        mock_smb_class.return_value = mock_smb

        result = smb_negotiate("192.168.1.1", timeout=30)

        assert result == mock_smb
        mock_smb_class.assert_called_once_with(
            remoteName="192.168.1.1",
            remoteHost="192.168.1.1",
            sess_port=445,
            timeout=30
        )
        # Should NOT call login or kerberosLogin
        mock_smb.login.assert_not_called()
        mock_smb.kerberosLogin.assert_not_called()


# ============================================================================
# Test: smb_login
# ============================================================================


class TestSmbLogin:
    """Tests for smb_login function"""

    def test_password_auth(self):
        """Should authenticate with password"""
        mock_smb = MagicMock()

        smb_login(mock_smb, domain="EXAMPLE", username="admin", password="pass123")

        mock_smb.login.assert_called_once_with("admin", "pass123", "EXAMPLE")

    def test_hash_auth(self):
        """Should authenticate with hashes"""
        mock_smb = MagicMock()

        smb_login(
            mock_smb,
            domain="EXAMPLE",
            username="admin",
            password="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        )

        mock_smb.login.assert_called_once_with(
            "admin", "", "EXAMPLE",
            lmhash="aad3b435b51404eeaad3b435b51404ee",
            nthash="31d6cfe0d16ae931b73c59d7e0c089c0"
        )

    def test_kerberos_auth(self):
        """Should authenticate with Kerberos"""
        mock_smb = MagicMock()

        smb_login(
            mock_smb,
            domain="EXAMPLE",
            username="admin",
            password="pass123",
            kerberos=True,
            dc_ip="192.168.1.10"
        )

        mock_smb.kerberosLogin.assert_called_once()
        call_kwargs = mock_smb.kerberosLogin.call_args[1]
        assert call_kwargs["user"] == "admin"
        assert call_kwargs["kdcHost"] == "192.168.1.10"


# ============================================================================
# Test: smb_connect_with_laps
# ============================================================================


class TestSmbConnectWithLaps:
    """Tests for smb_connect_with_laps function"""

    @patch('taskhound.smb.connection.smb_negotiate')
    @patch('taskhound.smb.connection.smb_login')
    def test_uses_laps_credentials(self, mock_login, mock_negotiate):
        """Should use LAPS credentials when available"""
        mock_smb = MagicMock()
        mock_smb.getServerName.return_value = "WS01"
        mock_negotiate.return_value = mock_smb

        mock_laps_cache = MagicMock()
        mock_laps_cred = MagicMock()
        mock_laps_cred.encrypted = False
        mock_laps_cred.username = "Administrator"
        mock_laps_cred.password = "LapsPassword123"
        mock_laps_cred.laps_type = "legacy"
        mock_laps_cache.get.return_value = mock_laps_cred

        smb, hostname, laps_type, used_laps = smb_connect_with_laps(
            target="192.168.1.1",
            laps_cache=mock_laps_cache,
            fallback_domain="EXAMPLE",
            fallback_username="user",
            fallback_password="pass"
        )

        assert smb == mock_smb
        assert hostname == "WS01"
        assert laps_type == "legacy"
        assert used_laps is True
        mock_login.assert_called_once_with(
            mock_smb,
            domain=".",
            username="Administrator",
            password="LapsPassword123",
            kerberos=False
        )

    @patch('taskhound.smb.connection.smb_negotiate')
    @patch('taskhound.smb.connection.smb_login')
    def test_falls_back_to_provided_creds(self, mock_login, mock_negotiate):
        """Should use fallback credentials when LAPS not available"""
        mock_smb = MagicMock()
        mock_smb.getServerName.return_value = "WS01"
        mock_negotiate.return_value = mock_smb

        mock_laps_cache = MagicMock()
        mock_laps_cache.get.return_value = None

        smb, hostname, laps_type, used_laps = smb_connect_with_laps(
            target="192.168.1.1",
            laps_cache=mock_laps_cache,
            fallback_domain="EXAMPLE",
            fallback_username="user",
            fallback_password="pass123"
        )

        assert smb == mock_smb
        assert hostname == "WS01"
        assert laps_type is None
        assert used_laps is False
        mock_login.assert_called_once_with(
            mock_smb,
            domain="EXAMPLE",
            username="user",
            password="pass123",
            kerberos=False,
            dc_ip=None
        )

    @patch('taskhound.smb.connection.smb_negotiate')
    @patch('taskhound.smb.connection.smb_login')
    def test_encrypted_laps_uses_fallback(self, mock_login, mock_negotiate):
        """Should fallback when LAPS password is encrypted"""
        mock_smb = MagicMock()
        mock_smb.getServerName.return_value = "WS01"
        mock_negotiate.return_value = mock_smb

        mock_laps_cache = MagicMock()
        mock_laps_cred = MagicMock()
        mock_laps_cred.encrypted = True  # Encrypted LAPS - cannot use
        mock_laps_cache.get.return_value = mock_laps_cred

        smb, hostname, laps_type, used_laps = smb_connect_with_laps(
            target="192.168.1.1",
            laps_cache=mock_laps_cache,
            fallback_domain="EXAMPLE",
            fallback_username="user",
            fallback_password="pass"
        )

        assert used_laps is False
        assert laps_type is None

    @patch('taskhound.smb.connection.smb_negotiate')
    @patch('taskhound.smb.connection.smb_login')
    def test_no_laps_cache_uses_fallback(self, mock_login, mock_negotiate):
        """Should use fallback when no LAPS cache provided"""
        mock_smb = MagicMock()
        mock_smb.getServerName.return_value = "WS01"
        mock_negotiate.return_value = mock_smb

        smb, hostname, laps_type, used_laps = smb_connect_with_laps(
            target="192.168.1.1",
            laps_cache=None,
            fallback_domain="EXAMPLE",
            fallback_username="user",
            fallback_password="pass"
        )

        assert used_laps is False

    @patch('taskhound.smb.connection.smb_negotiate')
    @patch('taskhound.smb.connection.smb_login')
    def test_hostname_not_available_uses_target(self, mock_login, mock_negotiate):
        """Should use target as hostname when not available from SMB"""
        mock_smb = MagicMock()
        mock_smb.getServerName.return_value = None
        mock_negotiate.return_value = mock_smb

        smb, hostname, laps_type, used_laps = smb_connect_with_laps(
            target="192.168.1.1",
            laps_cache=None,
            fallback_domain="EXAMPLE",
            fallback_username="user",
            fallback_password="pass"
        )

        assert hostname == "192.168.1.1"

    @patch('taskhound.smb.connection.smb_negotiate')
    @patch('taskhound.smb.connection.smb_login')
    def test_laps_auth_failure_reraises(self, mock_login, mock_negotiate):
        """Should re-raise exception when LAPS auth fails"""
        mock_smb = MagicMock()
        mock_smb.getServerName.return_value = "WS01"
        mock_negotiate.return_value = mock_smb

        mock_laps_cache = MagicMock()
        mock_laps_cred = MagicMock()
        mock_laps_cred.encrypted = False
        mock_laps_cred.username = "Administrator"
        mock_laps_cred.password = "WrongPassword"
        mock_laps_cred.laps_type = "legacy"
        mock_laps_cache.get.return_value = mock_laps_cred

        mock_login.side_effect = Exception("Authentication failed")

        with pytest.raises(Exception) as exc_info:
            smb_connect_with_laps(
                target="192.168.1.1",
                laps_cache=mock_laps_cache,
                fallback_domain="EXAMPLE",
                fallback_username="user",
                fallback_password="pass"
            )

        assert "Authentication failed" in str(exc_info.value)

    @patch('taskhound.smb.connection.smb_negotiate')
    @patch('taskhound.smb.connection.smb_login')
    def test_fallback_uses_hashes(self, mock_login, mock_negotiate):
        """Should prefer hashes over password in fallback"""
        mock_smb = MagicMock()
        mock_smb.getServerName.return_value = "WS01"
        mock_negotiate.return_value = mock_smb

        smb_connect_with_laps(
            target="192.168.1.1",
            laps_cache=None,
            fallback_domain="EXAMPLE",
            fallback_username="user",
            fallback_password="pass",
            fallback_hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        )

        call_kwargs = mock_login.call_args[1]
        assert call_kwargs["password"] == "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"

    @patch('taskhound.smb.connection.smb_negotiate')
    @patch('taskhound.smb.connection.smb_login')
    def test_fallback_kerberos(self, mock_login, mock_negotiate):
        """Should use Kerberos for fallback when specified"""
        mock_smb = MagicMock()
        mock_smb.getServerName.return_value = "WS01"
        mock_negotiate.return_value = mock_smb

        smb_connect_with_laps(
            target="192.168.1.1",
            laps_cache=None,
            fallback_domain="EXAMPLE",
            fallback_username="user",
            fallback_password="pass",
            fallback_kerberos=True,
            dc_ip="192.168.1.10"
        )

        call_kwargs = mock_login.call_args[1]
        assert call_kwargs["kerberos"] is True
        assert call_kwargs["dc_ip"] == "192.168.1.10"
