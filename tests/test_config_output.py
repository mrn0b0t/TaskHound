from unittest.mock import mock_open, patch, MagicMock

import pytest

from taskhound.config import load_config, build_parser, validate_args


@pytest.fixture
def mock_tomllib():
    with patch("taskhound.config.tomllib") as mock:
        yield mock


def test_load_output_config(mock_tomllib):
    toml_content = {
        "output": {
            "plain": "./out/plain",
            "json": "./out/results.json",
            "csv": "./out/results.csv",
            "backup": "./out/backup",
            "no_summary": True,
            "debug": True,
        }
    }

    mock_tomllib.load.return_value = toml_content

    with patch("builtins.open", mock_open(read_data=b"mock data")), patch("os.path.exists", return_value=True):
        config = load_config()

    assert config["plain"] == "./out/plain"
    assert config["json"] == "./out/results.json"
    assert config["csv"] == "./out/results.csv"
    assert config["backup"] == "./out/backup"
    assert config["no_summary"] is True
    assert config["debug"] is True


class TestLoadConfigAuthentication:
    """Tests for authentication config loading."""

    def test_load_auth_username(self, mock_tomllib):
        """Test loading authentication username."""
        mock_tomllib.load.return_value = {
            "authentication": {"username": "admin"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["username"] == "admin"

    def test_load_auth_password(self, mock_tomllib):
        """Test loading authentication password."""
        mock_tomllib.load.return_value = {
            "authentication": {"password": "secret123"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["password"] == "secret123"

    def test_load_auth_domain(self, mock_tomllib):
        """Test loading authentication domain."""
        mock_tomllib.load.return_value = {
            "authentication": {"domain": "CORP.LOCAL"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["domain"] == "CORP.LOCAL"

    def test_load_auth_hashes(self, mock_tomllib):
        """Test loading NTLM hashes."""
        mock_tomllib.load.return_value = {
            "authentication": {"hashes": "aad3b435b51404eeaad3b435b51404ee:hash"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert "hash" in config["hashes"]

    def test_load_auth_kerberos(self, mock_tomllib):
        """Test loading Kerberos flag."""
        mock_tomllib.load.return_value = {
            "authentication": {"kerberos": True}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["kerberos"] is True


class TestLoadConfigTarget:
    """Tests for target config loading."""

    def test_load_dc_ip(self, mock_tomllib):
        """Test loading DC IP."""
        mock_tomllib.load.return_value = {
            "target": {"dc_ip": "192.168.1.1"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["dc_ip"] == "192.168.1.1"

    def test_load_timeout(self, mock_tomllib):
        """Test loading timeout."""
        mock_tomllib.load.return_value = {
            "target": {"timeout": 30}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["timeout"] == 30

    def test_load_target(self, mock_tomllib):
        """Test loading target."""
        mock_tomllib.load.return_value = {
            "target": {"target": "dc01.corp.local"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["target"] == "dc01.corp.local"


class TestLoadConfigScanning:
    """Tests for scanning config loading."""

    def test_load_offline(self, mock_tomllib):
        """Test loading offline mode."""
        mock_tomllib.load.return_value = {
            "scanning": {"offline": True}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["offline"] is True

    def test_load_include_local(self, mock_tomllib):
        """Test loading include_local flag."""
        mock_tomllib.load.return_value = {
            "scanning": {"include_local": True}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["include_local"] is True

    def test_load_opsec(self, mock_tomllib):
        """Test loading opsec mode."""
        mock_tomllib.load.return_value = {
            "scanning": {"opsec": True}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["opsec"] is True

    def test_load_bh_data(self, mock_tomllib):
        """Test loading BloodHound data path."""
        mock_tomllib.load.return_value = {
            "scanning": {"bh_data": "/path/to/bh.json"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["bh_data"] == "/path/to/bh.json"


class TestLoadConfigCache:
    """Tests for cache config loading."""

    def test_load_cache_ttl(self, mock_tomllib):
        """Test loading cache TTL."""
        mock_tomllib.load.return_value = {
            "cache": {"ttl": 24}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["cache_ttl"] == 24

    def test_load_cache_disabled(self, mock_tomllib):
        """Test loading cache disabled state."""
        mock_tomllib.load.return_value = {
            "cache": {"enabled": False}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["no_cache"] is True

    def test_load_cache_file(self, mock_tomllib):
        """Test loading cache file path."""
        mock_tomllib.load.return_value = {
            "cache": {"file": "/tmp/cache.db"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["cache_file"] == "/tmp/cache.db"


class TestLoadConfigBloodHound:
    """Tests for BloodHound config loading."""

    def test_load_bh_live(self, mock_tomllib):
        """Test loading BH live mode."""
        mock_tomllib.load.return_value = {
            "bloodhound": {"live": True}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["bh_live"] is True

    def test_load_bh_connector(self, mock_tomllib):
        """Test loading BH connector."""
        mock_tomllib.load.return_value = {
            "bloodhound": {"connector": "https://localhost:8080"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert "localhost" in config["bh_connector"]

    def test_load_bh_type_bhce(self, mock_tomllib):
        """Test loading BH type BHCE."""
        mock_tomllib.load.return_value = {
            "bloodhound": {"type": "bhce"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["bhce"] is True

    def test_load_bh_type_legacy(self, mock_tomllib):
        """Test loading BH type legacy."""
        mock_tomllib.load.return_value = {
            "bloodhound": {"type": "legacy"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["legacy"] is True


class TestLoadConfigLDAP:
    """Tests for LDAP config loading."""

    def test_load_ldap_disabled(self, mock_tomllib):
        """Test loading no_ldap flag."""
        mock_tomllib.load.return_value = {
            "ldap": {"no_ldap": True}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["no_ldap"] is True

    def test_load_ldap_user(self, mock_tomllib):
        """Test loading LDAP user."""
        mock_tomllib.load.return_value = {
            "ldap": {"user": "ldap_admin"}
        }
        with patch("builtins.open", mock_open()), patch("os.path.exists", return_value=True):
            config = load_config()
        assert config["ldap_user"] == "ldap_admin"


class TestLoadConfigNoFile:
    """Tests when no config file exists."""

    def test_no_config_file(self, mock_tomllib):
        """Test that empty dict is returned when no config file."""
        with patch("os.path.exists", return_value=False):
            config = load_config()
        assert config == {}

    def test_no_tomllib(self):
        """Test that empty dict is returned when tomllib not available."""
        with patch("taskhound.config.tomllib", None):
            config = load_config()
        assert config == {}


class TestBuildParser:
    """Tests for build_parser function."""

    def test_parser_creation(self):
        """Test that parser is created successfully."""
        parser = build_parser()
        assert parser is not None
        assert parser.prog == "taskhound"

    def test_parser_has_auth_options(self):
        """Test that parser has authentication arguments."""
        parser = build_parser()
        # Parse with offline mode (doesn't need username/password)
        args = parser.parse_args(["--offline", "/some/path"])
        assert args.offline == "/some/path"

    def test_parser_offline_mode(self):
        """Test offline mode argument."""
        parser = build_parser()
        args = parser.parse_args(["--offline", "/path/to/xml"])
        assert args.offline == "/path/to/xml"

    def test_parser_bh_data(self):
        """Test bh-data argument."""
        parser = build_parser()
        args = parser.parse_args(["--offline", "/path", "--bh-data", "/path/to/bh.json"])
        assert args.bh_data == "/path/to/bh.json"


class TestValidateArgs:
    """Tests for validate_args function."""

    # Note: validate_args() performs many checks and may exit, so we only test
    # cases that should pass validation cleanly

    @patch("taskhound.config.sys.exit")
    def test_validate_laps_without_dc_ip(self, mock_exit):
        """Test validation catches LAPS without DC IP."""
        parser = build_parser()
        args = parser.parse_args(["--offline", "/path", "--laps", "-d", "corp.local"])
        validate_args(args)
        # Should have called sys.exit because LAPS needs --dc-ip
        mock_exit.assert_called()

    @patch("taskhound.config.sys.exit")
    def test_validate_creds_with_opsec_exits(self, mock_exit):
        """Test that --validate-creds with --opsec exits with error."""
        parser = build_parser()
        args = parser.parse_args([
            "--offline", "/path",
            "--validate-creds",
            "--opsec",
        ])
        validate_args(args)
        # Should have called sys.exit because validate-creds is incompatible with opsec
        mock_exit.assert_called_with(1)

    @patch("taskhound.config.os.path.isdir", return_value=True)
    @patch("taskhound.config.os.path.exists", return_value=True)
    @patch("taskhound.config.sys.exit")
    def test_opsec_disables_credguard_detect(self, mock_exit, mock_exists, mock_isdir):
        """Test that --opsec disables --credguard-detect."""
        parser = build_parser()
        args = parser.parse_args([
            "--offline", "/path",
            "--opsec",
            "--credguard-detect",
        ])
        validate_args(args)
        # credguard_detect should be set to False
        assert args.credguard_detect is False
        # Should not exit (no incompatible flags)
        mock_exit.assert_not_called()

    @patch("taskhound.config.os.path.isdir", return_value=True)
    @patch("taskhound.config.os.path.exists", return_value=True)
    def test_opsec_without_validate_creds_passes(self, mock_exists, mock_isdir):
        """Test that --opsec without --validate-creds passes validation."""
        parser = build_parser()
        args = parser.parse_args([
            "--offline", "/path",
            "--opsec",
        ])
        # Should not raise or exit
        validate_args(args)
        assert args.opsec is True

    @patch("taskhound.config.os.path.isdir", return_value=True)
    @patch("taskhound.config.os.path.exists", return_value=True)
    def test_validate_creds_without_opsec_passes(self, mock_exists, mock_isdir):
        """Test that --validate-creds without --opsec passes validation."""
        parser = build_parser()
        args = parser.parse_args([
            "--offline", "/path",
            "--validate-creds",
        ])
        # Should not raise or exit
        validate_args(args)
        assert args.validate_creds is True