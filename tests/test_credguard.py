"""
Test suite for Credential Guard detection functionality.

Tests cover:
- check_credential_guard function
- Registry key checking (LsaCfgFlags, IsolatedUserMode)
- Error handling for SMB/registry operations
"""

from unittest.mock import MagicMock, patch

import pytest

from taskhound.smb.credguard import check_credential_guard

# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def mock_smb_connection():
    """Create a mock SMB connection"""
    mock = MagicMock()
    return mock


# ============================================================================
# Unit Tests: check_credential_guard
# ============================================================================


class TestCheckCredentialGuard:
    """Tests for check_credential_guard function"""

    @patch('taskhound.smb.credguard.transport')
    @patch('taskhound.smb.credguard.rrp')
    def test_credential_guard_enabled_via_lsacfgflags(self, mock_rrp, mock_transport, mock_smb_connection):
        """Should return True when LsaCfgFlags is 1"""
        # Setup mocks
        mock_dce = MagicMock()
        mock_transport.DCERPCTransportFactory.return_value.get_dce_rpc.return_value = mock_dce

        mock_rrp.hOpenLocalMachine.return_value = {"phKey": MagicMock()}
        mock_rrp.hBaseRegOpenKey.return_value = {"phkResult": MagicMock()}
        # LsaCfgFlags = 1 (enabled)
        mock_rrp.hBaseRegQueryValue.return_value = {"lpData": (1).to_bytes(4, "little")}
        mock_rrp.KEY_READ = 0x20019

        result = check_credential_guard(mock_smb_connection, "DC01")

        assert result is True

    @patch('taskhound.smb.credguard.transport')
    @patch('taskhound.smb.credguard.rrp')
    def test_credential_guard_enabled_via_isolatedusermode(self, mock_rrp, mock_transport, mock_smb_connection):
        """Should return True when IsolatedUserMode is 1"""
        # Setup mocks
        mock_dce = MagicMock()
        mock_transport.DCERPCTransportFactory.return_value.get_dce_rpc.return_value = mock_dce

        mock_rrp.hOpenLocalMachine.return_value = {"phKey": MagicMock()}
        mock_rrp.hBaseRegOpenKey.return_value = {"phkResult": MagicMock()}
        mock_rrp.KEY_READ = 0x20019

        # LsaCfgFlags throws exception (not found), IsolatedUserMode = 1
        from impacket.dcerpc.v5.rpcrt import DCERPCException
        mock_rrp.hBaseRegQueryValue.side_effect = [
            DCERPCException(),  # LsaCfgFlags not found
            {"lpData": (1).to_bytes(4, "little")}  # IsolatedUserMode = 1
        ]

        result = check_credential_guard(mock_smb_connection, "DC01")

        assert result is True

    @patch('taskhound.smb.credguard.transport')
    @patch('taskhound.smb.credguard.rrp')
    def test_credential_guard_disabled(self, mock_rrp, mock_transport, mock_smb_connection):
        """Should return False when both keys are 0"""
        # Setup mocks
        mock_dce = MagicMock()
        mock_transport.DCERPCTransportFactory.return_value.get_dce_rpc.return_value = mock_dce

        mock_rrp.hOpenLocalMachine.return_value = {"phKey": MagicMock()}
        mock_rrp.hBaseRegOpenKey.return_value = {"phkResult": MagicMock()}
        mock_rrp.KEY_READ = 0x20019

        # Both keys return 0
        mock_rrp.hBaseRegQueryValue.side_effect = [
            {"lpData": (0).to_bytes(4, "little")},  # LsaCfgFlags = 0
            {"lpData": (0).to_bytes(4, "little")}   # IsolatedUserMode = 0
        ]

        result = check_credential_guard(mock_smb_connection, "DC01")

        assert result is False

    @patch('taskhound.smb.credguard.transport')
    @patch('taskhound.smb.credguard.rrp')
    def test_credential_guard_keys_not_found(self, mock_rrp, mock_transport, mock_smb_connection):
        """Should return False when registry keys don't exist"""
        # Setup mocks
        mock_dce = MagicMock()
        mock_transport.DCERPCTransportFactory.return_value.get_dce_rpc.return_value = mock_dce

        mock_rrp.hOpenLocalMachine.return_value = {"phKey": MagicMock()}
        mock_rrp.hBaseRegOpenKey.return_value = {"phkResult": MagicMock()}
        mock_rrp.KEY_READ = 0x20019

        # Both keys throw exception
        from impacket.dcerpc.v5.rpcrt import DCERPCException
        mock_rrp.hBaseRegQueryValue.side_effect = DCERPCException()

        result = check_credential_guard(mock_smb_connection, "DC01")

        assert result is False

    @patch('taskhound.smb.credguard.transport')
    def test_connection_error_returns_false(self, mock_transport, mock_smb_connection):
        """Should return False on connection error"""
        # Make transport factory throw an exception
        mock_transport.DCERPCTransportFactory.side_effect = Exception("Connection failed")

        result = check_credential_guard(mock_smb_connection, "DC01")

        assert result is False

    @patch('taskhound.smb.credguard.transport')
    @patch('taskhound.smb.credguard.rrp')
    def test_registry_open_error_returns_false(self, mock_rrp, mock_transport, mock_smb_connection):
        """Should return False when cannot open registry"""
        mock_dce = MagicMock()
        mock_transport.DCERPCTransportFactory.return_value.get_dce_rpc.return_value = mock_dce

        # Opening local machine fails
        mock_rrp.hOpenLocalMachine.side_effect = Exception("Access denied")

        result = check_credential_guard(mock_smb_connection, "DC01")

        assert result is False

    @patch('taskhound.smb.credguard.transport')
    @patch('taskhound.smb.credguard.rrp')
    def test_lsa_key_open_error_returns_false(self, mock_rrp, mock_transport, mock_smb_connection):
        """Should return False when cannot open LSA key"""
        mock_dce = MagicMock()
        mock_transport.DCERPCTransportFactory.return_value.get_dce_rpc.return_value = mock_dce

        mock_rrp.hOpenLocalMachine.return_value = {"phKey": MagicMock()}
        mock_rrp.KEY_READ = 0x20019
        # Opening LSA key fails
        mock_rrp.hBaseRegOpenKey.side_effect = Exception("Key not found")

        result = check_credential_guard(mock_smb_connection, "DC01")

        assert result is False

    @patch('taskhound.smb.credguard.transport')
    @patch('taskhound.smb.credguard.rrp')
    def test_lsacfgflags_other_values(self, mock_rrp, mock_transport, mock_smb_connection):
        """Should handle LsaCfgFlags values other than 0 or 1"""
        mock_dce = MagicMock()
        mock_transport.DCERPCTransportFactory.return_value.get_dce_rpc.return_value = mock_dce

        mock_rrp.hOpenLocalMachine.return_value = {"phKey": MagicMock()}
        mock_rrp.hBaseRegOpenKey.return_value = {"phkResult": MagicMock()}
        mock_rrp.KEY_READ = 0x20019

        # LsaCfgFlags = 2 (not exactly 1, but not 0)
        mock_rrp.hBaseRegQueryValue.side_effect = [
            {"lpData": (2).to_bytes(4, "little")},  # LsaCfgFlags = 2
            {"lpData": (0).to_bytes(4, "little")}   # IsolatedUserMode = 0
        ]

        result = check_credential_guard(mock_smb_connection, "DC01")

        # Should return False since value is not exactly 1
        assert result is False

    @patch('taskhound.smb.credguard.transport')
    @patch('taskhound.smb.credguard.rrp')
    def test_transport_string_binding_format(self, mock_rrp, mock_transport, mock_smb_connection):
        """Should use correct transport string binding format"""
        mock_dce = MagicMock()
        mock_transport.DCERPCTransportFactory.return_value.get_dce_rpc.return_value = mock_dce

        mock_rrp.hOpenLocalMachine.return_value = {"phKey": MagicMock()}
        mock_rrp.hBaseRegOpenKey.return_value = {"phkResult": MagicMock()}
        mock_rrp.KEY_READ = 0x20019
        mock_rrp.hBaseRegQueryValue.return_value = {"lpData": (0).to_bytes(4, "little")}

        check_credential_guard(mock_smb_connection, "DC01.example.com")

        # Verify transport factory was called with correct binding string
        mock_transport.DCERPCTransportFactory.assert_called_once()
        call_arg = mock_transport.DCERPCTransportFactory.call_args[0][0]
        assert "DC01.example.com" in call_arg
        assert "winreg" in call_arg
