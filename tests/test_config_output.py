from unittest.mock import mock_open, patch

import pytest

from taskhound.config import load_config


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
            "opengraph": "./out/og",
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
    assert config["opengraph"] == "./out/og"
    assert config["backup"] == "./out/backup"
    assert config["no_summary"] is True
    assert config["debug"] is True
