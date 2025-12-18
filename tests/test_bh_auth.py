"""
Test suite for BloodHound authentication utilities.

Tests cover:
- BloodHoundAuthenticator initialization
- get_token method
- request method (GET, POST)
- API key vs username/password authentication
- Error handling for network errors
"""

from unittest.mock import Mock, patch

import pytest

from taskhound.utils.bh_auth import BloodHoundAuthenticator

# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def auth_with_creds():
    """Create authenticator with username/password"""
    return BloodHoundAuthenticator(
        base_url="http://localhost:8080",
        username="admin",
        password="password123"
    )


@pytest.fixture
def auth_with_api_key():
    """Create authenticator with API key"""
    return BloodHoundAuthenticator(
        base_url="http://localhost:8080",
        api_key="secret_api_key",
        api_key_id="key_id_123"
    )


@pytest.fixture
def auth_no_creds():
    """Create authenticator with no credentials"""
    return BloodHoundAuthenticator(
        base_url="http://localhost:8080"
    )


# ============================================================================
# Unit Tests: Initialization
# ============================================================================


class TestBloodHoundAuthenticatorInit:
    """Tests for BloodHoundAuthenticator initialization"""

    def test_init_with_username_password(self):
        """Should store username and password"""
        auth = BloodHoundAuthenticator(
            base_url="http://localhost:8080",
            username="admin",
            password="secret"
        )

        assert auth.base_url == "http://localhost:8080"
        assert auth.username == "admin"
        assert auth.password == "secret"
        assert auth.api_key is None
        assert auth.api_key_id is None

    def test_init_with_api_key(self):
        """Should store API key credentials"""
        auth = BloodHoundAuthenticator(
            base_url="http://localhost:8080",
            api_key="api_key_123",
            api_key_id="id_456"
        )

        assert auth.api_key == "api_key_123"
        assert auth.api_key_id == "id_456"

    def test_init_strips_trailing_slash(self):
        """Should remove trailing slash from base_url"""
        auth = BloodHoundAuthenticator(
            base_url="http://localhost:8080/",
            username="admin",
            password="secret"
        )

        assert auth.base_url == "http://localhost:8080"

    def test_init_default_timeout(self):
        """Should have default timeout of 30"""
        auth = BloodHoundAuthenticator(base_url="http://localhost:8080")

        assert auth.timeout == 30

    def test_init_custom_timeout(self):
        """Should accept custom timeout"""
        auth = BloodHoundAuthenticator(
            base_url="http://localhost:8080",
            timeout=60
        )

        assert auth.timeout == 60


# ============================================================================
# Unit Tests: get_token
# ============================================================================


class TestGetToken:
    """Tests for get_token method"""

    def test_api_key_returns_none(self, auth_with_api_key):
        """Should return None when using API key (no token needed)"""
        result = auth_with_api_key.get_token()

        assert result is None

    def test_no_credentials_returns_none(self, auth_no_creds):
        """Should return None when no credentials configured"""
        result = auth_no_creds.get_token()

        assert result is None

    @patch('taskhound.utils.bh_auth.get_bloodhound_token')
    def test_successful_token_fetch(self, mock_get_token, auth_with_creds):
        """Should fetch and cache token on success"""
        mock_get_token.return_value = "test_token_123"

        result = auth_with_creds.get_token()

        assert result == "test_token_123"
        mock_get_token.assert_called_once_with(
            "http://localhost:8080",
            "admin",
            "password123",
            30
        )

    @patch('taskhound.utils.bh_auth.get_bloodhound_token')
    def test_cached_token_returned(self, mock_get_token, auth_with_creds):
        """Should return cached token on subsequent calls"""
        mock_get_token.return_value = "test_token_123"

        # First call fetches token
        result1 = auth_with_creds.get_token()
        # Second call should use cached token
        result2 = auth_with_creds.get_token()

        assert result1 == "test_token_123"
        assert result2 == "test_token_123"
        # Should only call get_bloodhound_token once
        assert mock_get_token.call_count == 1

    @patch('taskhound.utils.bh_auth.get_bloodhound_token')
    def test_timeout_error_returns_none(self, mock_get_token, auth_with_creds):
        """Should return None on timeout"""
        import requests
        mock_get_token.side_effect = requests.Timeout()

        result = auth_with_creds.get_token()

        assert result is None

    @patch('taskhound.utils.bh_auth.get_bloodhound_token')
    def test_request_exception_returns_none(self, mock_get_token, auth_with_creds):
        """Should return None on network error"""
        import requests
        mock_get_token.side_effect = requests.RequestException("Connection failed")

        result = auth_with_creds.get_token()

        assert result is None

    @patch('taskhound.utils.bh_auth.get_bloodhound_token')
    def test_key_error_returns_none(self, mock_get_token, auth_with_creds):
        """Should return None on invalid response format"""
        mock_get_token.side_effect = KeyError("session_token")

        result = auth_with_creds.get_token()

        assert result is None

    @patch('taskhound.utils.bh_auth.get_bloodhound_token')
    def test_value_error_returns_none(self, mock_get_token, auth_with_creds):
        """Should return None on invalid response value"""
        mock_get_token.side_effect = ValueError("Invalid token")

        result = auth_with_creds.get_token()

        assert result is None

    @patch('taskhound.utils.bh_auth.get_bloodhound_token')
    def test_generic_exception_returns_none(self, mock_get_token, auth_with_creds):
        """Should return None on unexpected error"""
        mock_get_token.side_effect = Exception("Unexpected")

        result = auth_with_creds.get_token()

        assert result is None


# ============================================================================
# Unit Tests: request
# ============================================================================


class TestRequest:
    """Tests for request method"""

    @patch('taskhound.utils.bh_auth.bhce_signed_request')
    def test_api_key_uses_signed_request(self, mock_signed, auth_with_api_key):
        """Should use bhce_signed_request for API key auth"""
        mock_response = Mock()
        mock_signed.return_value = mock_response

        result = auth_with_api_key.request("GET", "/api/test")

        assert result == mock_response
        mock_signed.assert_called_once()

    @patch('taskhound.utils.bh_auth.get_bloodhound_token')
    @patch('requests.request')
    def test_bearer_token_with_password_auth(self, mock_request, mock_get_token, auth_with_creds):
        """Should use bearer token for password auth"""
        mock_get_token.return_value = "test_token"
        mock_response = Mock()
        mock_request.return_value = mock_response

        result = auth_with_creds.request("GET", "/api/test")

        assert result == mock_response
        mock_request.assert_called_once()
        # Check Authorization header
        call_kwargs = mock_request.call_args[1]
        assert "Authorization" in call_kwargs["headers"]
        assert call_kwargs["headers"]["Authorization"] == "Bearer test_token"

    @patch('taskhound.utils.bh_auth.get_bloodhound_token')
    @patch('requests.request')
    def test_dict_body_serialized(self, mock_request, mock_get_token, auth_with_creds):
        """Should serialize dict body to JSON"""
        mock_get_token.return_value = "test_token"
        mock_response = Mock()
        mock_request.return_value = mock_response

        auth_with_creds.request("POST", "/api/test", body={"key": "value"})

        call_kwargs = mock_request.call_args[1]
        assert call_kwargs["data"] == b'{"key":"value"}'

    @patch('taskhound.utils.bh_auth.get_bloodhound_token')
    @patch('requests.request')
    def test_bytes_body_passed_directly(self, mock_request, mock_get_token, auth_with_creds):
        """Should pass bytes body directly"""
        mock_get_token.return_value = "test_token"
        mock_response = Mock()
        mock_request.return_value = mock_response

        auth_with_creds.request("POST", "/api/test", body=b"raw bytes")

        call_kwargs = mock_request.call_args[1]
        assert call_kwargs["data"] == b"raw bytes"

    @patch('taskhound.utils.bh_auth.get_bloodhound_token')
    @patch('requests.request')
    def test_string_body_encoded(self, mock_request, mock_get_token, auth_with_creds):
        """Should encode string body to bytes"""
        mock_get_token.return_value = "test_token"
        mock_response = Mock()
        mock_request.return_value = mock_response

        auth_with_creds.request("POST", "/api/test", body="string body")

        call_kwargs = mock_request.call_args[1]
        assert call_kwargs["data"] == b"string body"

    @patch('taskhound.utils.bh_auth.get_bloodhound_token')
    @patch('requests.request')
    def test_endpoint_without_leading_slash(self, mock_request, mock_get_token, auth_with_creds):
        """Should add leading slash to endpoint if missing"""
        mock_get_token.return_value = "test_token"
        mock_response = Mock()
        mock_request.return_value = mock_response

        auth_with_creds.request("GET", "api/test")

        call_kwargs = mock_request.call_args[1]
        assert call_kwargs["url"] == "http://localhost:8080/api/test"

    @patch('taskhound.utils.bh_auth.get_bloodhound_token')
    @patch('requests.request')
    def test_custom_headers_merged(self, mock_request, mock_get_token, auth_with_creds):
        """Should merge custom headers with defaults"""
        mock_get_token.return_value = "test_token"
        mock_response = Mock()
        mock_request.return_value = mock_response

        auth_with_creds.request("GET", "/api/test", headers={"X-Custom": "value"})

        call_kwargs = mock_request.call_args[1]
        assert call_kwargs["headers"]["X-Custom"] == "value"
        assert call_kwargs["headers"]["Authorization"] == "Bearer test_token"

    def test_no_token_returns_none(self, auth_no_creds):
        """Should return None when cannot get token"""
        result = auth_no_creds.request("GET", "/api/test")

        assert result is None

    @patch('taskhound.utils.bh_auth.get_bloodhound_token')
    @patch('requests.request')
    def test_exception_returns_none(self, mock_request, mock_get_token, auth_with_creds):
        """Should return None on request exception"""
        mock_get_token.return_value = "test_token"
        mock_request.side_effect = Exception("Request failed")

        result = auth_with_creds.request("GET", "/api/test")

        assert result is None

    @patch('taskhound.utils.bh_auth.get_bloodhound_token')
    @patch('requests.request')
    def test_timeout_used(self, mock_request, mock_get_token):
        """Should use configured timeout"""
        auth = BloodHoundAuthenticator(
            base_url="http://localhost:8080",
            username="admin",
            password="secret",
            timeout=60
        )
        mock_get_token.return_value = "test_token"
        mock_response = Mock()
        mock_request.return_value = mock_response

        auth.request("GET", "/api/test")

        call_kwargs = mock_request.call_args[1]
        assert call_kwargs["timeout"] == 60
