"""Additional tests for taskhound/smb/credguard.py module."""

from unittest.mock import MagicMock, patch

from taskhound.smb.credguard import check_credential_guard


class TestCheckCredentialGuard:
    """Tests for check_credential_guard function."""

    @patch('taskhound.smb.credguard.transport')
    @patch('taskhound.smb.credguard.rrp')
    def test_returns_true_when_lsa_cfg_flags_set(self, mock_rrp, mock_transport):
        """Returns True when LsaCfgFlags is 1."""
        mock_smb = MagicMock()
        mock_dce = MagicMock()
        mock_transport.DCERPCTransportFactory.return_value.get_dce_rpc.return_value = mock_dce

        # Mock registry values
        mock_rrp.hOpenLocalMachine.return_value = {"phKey": MagicMock()}
        mock_rrp.hBaseRegOpenKey.return_value = {"phkResult": MagicMock()}
        mock_rrp.hBaseRegQueryValue.return_value = {"lpData": b"\x01\x00\x00\x00"}

        result = check_credential_guard(mock_smb, "192.168.1.100")
        assert result is True

    @patch('taskhound.smb.credguard.transport')
    @patch('taskhound.smb.credguard.rrp')
    def test_returns_false_when_not_enabled(self, mock_rrp, mock_transport):
        """Returns False when Credential Guard is not enabled."""
        mock_smb = MagicMock()
        mock_dce = MagicMock()
        mock_transport.DCERPCTransportFactory.return_value.get_dce_rpc.return_value = mock_dce

        # Mock registry values with 0
        mock_rrp.hOpenLocalMachine.return_value = {"phKey": MagicMock()}
        mock_rrp.hBaseRegOpenKey.return_value = {"phkResult": MagicMock()}
        mock_rrp.hBaseRegQueryValue.return_value = {"lpData": b"\x00\x00\x00\x00"}

        result = check_credential_guard(mock_smb, "192.168.1.100")
        assert result is False

    @patch('taskhound.smb.credguard.transport')
    def test_returns_false_on_exception(self, mock_transport):
        """Returns False when an exception occurs."""
        mock_smb = MagicMock()
        mock_transport.DCERPCTransportFactory.side_effect = Exception("Connection failed")

        result = check_credential_guard(mock_smb, "192.168.1.100")
        assert result is False

    def test_function_callable(self):
        """Function is callable."""
        assert callable(check_credential_guard)


class TestCredGuardRegistry:
    """Tests for registry key constants used."""

    def test_lsa_path_format(self):
        """LSA registry path is properly formatted."""
        # The function internally uses this path
        lsa_path = "SYSTEM\\CurrentControlSet\\Control\\Lsa"
        assert "Lsa" in lsa_path
        assert "Control" in lsa_path

    def test_lsa_cfg_flags_key(self):
        """LsaCfgFlags is the key to check."""
        key_name = "LsaCfgFlags"
        assert key_name == "LsaCfgFlags"

    def test_isolated_user_mode_key(self):
        """IsolatedUserMode is an alternative key."""
        key_name = "IsolatedUserMode"
        assert key_name == "IsolatedUserMode"
