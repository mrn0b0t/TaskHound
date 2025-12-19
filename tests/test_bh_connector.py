"""
Tests for BloodHound connector module.
"""
from unittest.mock import MagicMock, patch

from taskhound.connectors.bloodhound import (
    BloodHoundConnector,
    _safe_get_sam,
    _sanitize_string_value,
)


class TestSafeGetSam:
    """Tests for _safe_get_sam helper function"""

    def test_returns_lowercase_value(self):
        """Should return lowercase SAM account name"""
        data = {"SamAccountName": "ADMIN"}
        result = _safe_get_sam(data, "SamAccountName")

        assert result == "admin"

    def test_handles_none_value(self):
        """Should return empty string for None value"""
        data = {"SamAccountName": None}
        result = _safe_get_sam(data, "SamAccountName")

        assert result == ""

    def test_handles_missing_key(self):
        """Should return empty string for missing key"""
        data = {}
        result = _safe_get_sam(data, "SamAccountName")

        assert result == ""

    def test_handles_non_string_value(self):
        """Should convert non-string to lowercase string"""
        data = {"SamAccountName": 123}
        result = _safe_get_sam(data, "SamAccountName")

        assert result == "123"

    def test_handles_already_lowercase(self):
        """Should keep already lowercase value"""
        data = {"samaccountname": "user"}
        result = _safe_get_sam(data, "samaccountname")

        assert result == "user"

    def test_handles_empty_string(self):
        """Should return empty string for empty string value"""
        data = {"SamAccountName": ""}
        result = _safe_get_sam(data, "SamAccountName")

        assert result == ""


class TestSanitizeStringValue:
    """Tests for _sanitize_string_value helper function"""

    def test_returns_string_unchanged(self):
        """Should return string as-is"""
        result = _sanitize_string_value("test value")

        assert result == "test value"

    def test_handles_non_string(self):
        """Should return non-string values unchanged"""
        result = _sanitize_string_value(123)

        assert result == 123

    def test_handles_none(self):
        """Should return None unchanged"""
        result = _sanitize_string_value(None)

        assert result is None

    def test_handles_backslashes(self):
        """Should handle strings with backslashes"""
        result = _sanitize_string_value("C:\\Windows\\System32")

        assert "Windows" in result


class TestBloodHoundConnectorInit:
    """Tests for BloodHoundConnector initialization"""

    def test_init_bhce(self):
        """Should initialize BHCE connector"""
        connector = BloodHoundConnector(
            bh_type="bhce",
            ip="192.168.1.1",
            username="admin",
            password="password"
        )

        assert connector.bh_type == "bhce"
        assert connector.ip == "192.168.1.1"
        assert connector.username == "admin"

    def test_init_legacy(self):
        """Should initialize legacy connector"""
        connector = BloodHoundConnector(
            bh_type="legacy",
            ip="192.168.1.1",
            username="neo4j",
            password="neo4jpassword"
        )

        assert connector.bh_type == "legacy"

    def test_init_with_api_key(self):
        """Should initialize with API key"""
        connector = BloodHoundConnector(
            bh_type="bhce",
            ip="192.168.1.1",
            api_key="test_api_key",
            api_key_id="test_key_id"
        )

        assert connector.api_key == "test_api_key"
        assert connector.api_key_id == "test_key_id"

    def test_init_with_custom_timeout(self):
        """Should set custom timeout"""
        connector = BloodHoundConnector(
            bh_type="bhce",
            ip="192.168.1.1",
            timeout=300
        )

        assert connector.timeout == 300

    def test_init_default_timeout(self):
        """Should set default timeout of 120"""
        connector = BloodHoundConnector(
            bh_type="bhce",
            ip="192.168.1.1",
        )

        assert connector.timeout == 120

    def test_init_with_url_scheme(self):
        """Should handle URL with scheme"""
        connector = BloodHoundConnector(
            bh_type="bhce",
            ip="https://bloodhound.domain.lab",
            username="admin",
            password="password"
        )

        assert "bloodhound.domain.lab" in connector.ip


class TestBloodHoundConnectorRunCypherQuery:
    """Tests for run_cypher_query method"""

    def test_rejects_non_bhce(self):
        """Should reject non-BHCE connector"""
        connector = BloodHoundConnector(
            bh_type="legacy",
            ip="192.168.1.1",
            username="neo4j",
            password="password"
        )

        result = connector.run_cypher_query("MATCH (n) RETURN n")

        assert result is None

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    def test_successful_query(self):
        """Should execute successful cypher query"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"
        connector.authenticator = MagicMock()

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": {"nodes": []}}
        connector.authenticator.request.return_value = mock_response

        result = connector.run_cypher_query("MATCH (n) RETURN n")

        assert result == {"data": {"nodes": []}}

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    def test_failed_query_returns_none(self):
        """Should return None on failed query"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"
        connector.authenticator = MagicMock()

        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Bad Request"
        connector.authenticator.request.return_value = mock_response

        result = connector.run_cypher_query("INVALID QUERY")

        assert result is None

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    def test_handles_request_exception(self):
        """Should handle request exceptions gracefully"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"
        connector.authenticator = MagicMock()
        connector.authenticator.request.side_effect = Exception("Connection failed")

        result = connector.run_cypher_query("MATCH (n) RETURN n")

        assert result is None


class TestBloodHoundConnectorConnectAndQuery:
    """Tests for connect_and_query method"""

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    @patch.object(BloodHoundConnector, '_query_bhce')
    def test_routes_to_bhce(self, mock_query_bhce):
        """Should route to BHCE query method"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"
        mock_query_bhce.return_value = True

        result = connector.connect_and_query()

        assert result is True
        mock_query_bhce.assert_called_once()

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    @patch.object(BloodHoundConnector, '_query_legacy')
    def test_routes_to_legacy(self, mock_query_legacy):
        """Should route to legacy query method"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "legacy"
        mock_query_legacy.return_value = True

        result = connector.connect_and_query()

        assert result is True
        mock_query_legacy.assert_called_once()

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    def test_rejects_unknown_type(self):
        """Should return False for unknown bh_type"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "unknown"

        result = connector.connect_and_query()

        assert result is False

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    @patch.object(BloodHoundConnector, '_query_bhce')
    def test_handles_exception(self, mock_query_bhce):
        """Should handle exceptions gracefully"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"
        mock_query_bhce.side_effect = Exception("Connection failed")

        result = connector.connect_and_query()

        assert result is False


class TestBloodHoundConnectorQueryBHCE:
    """Tests for _query_bhce method"""

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    def test_connection_refused(self):
        """Should handle connection refused"""
        import requests

        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"
        connector.ip = "192.168.1.1"
        connector.authenticator = MagicMock()
        connector.authenticator.request.side_effect = requests.exceptions.ConnectionError()

        result = connector._query_bhce()

        assert result is False

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    def test_timeout_error(self):
        """Should handle timeout"""
        import requests

        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"
        connector.ip = "192.168.1.1"
        connector.authenticator = MagicMock()
        connector.authenticator.request.side_effect = requests.exceptions.Timeout()

        result = connector._query_bhce()

        assert result is False

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    def test_version_check_failure(self):
        """Should return False if version check fails"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.bh_type = "bhce"
        connector.ip = "192.168.1.1"
        connector.authenticator = MagicMock()

        # First call for version check returns error
        mock_response = MagicMock()
        mock_response.status_code = 401
        connector.authenticator.request.return_value = mock_response

        result = connector._query_bhce()

        assert result is False


class TestBloodHoundConnectorGetUsersData:
    """Tests for get_users_data method"""

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    def test_returns_users_data(self):
        """Should return users data dict"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.users_data = {"admin": {"sid": "S-1-5-21-xxx"}}

        result = connector.get_users_data()

        assert result == {"admin": {"sid": "S-1-5-21-xxx"}}

    @patch.object(BloodHoundConnector, '__init__', lambda x, **kwargs: None)
    def test_returns_empty_dict_when_no_data(self):
        """Should return empty dict when no data"""
        connector = BloodHoundConnector.__new__(BloodHoundConnector)
        connector.users_data = {}

        result = connector.get_users_data()

        assert result == {}
