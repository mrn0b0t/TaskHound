from unittest.mock import Mock

from taskhound.output.bloodhound import _set_custom_icon
from taskhound.utils.bh_auth import BloodHoundAuthenticator


class TestBloodHoundOutput:
    """Unit tests for BloodHound output module."""

    def test_set_custom_icon_payload_casing(self):
        """Verify that _set_custom_icon sends 'ScheduledTask' (CamelCase) in the payload."""

        # Mock Authenticator
        mock_auth = Mock(spec=BloodHoundAuthenticator)

        # Mock GET response (icon doesn't exist)
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {"data": []}

        # Mock POST response (success)
        mock_post_response = Mock()
        mock_post_response.status_code = 200

        # Configure request side effects
        def request_side_effect(method, endpoint, body=None, headers=None):
            if method == "GET":
                return mock_get_response
            if method == "POST":
                return mock_post_response
            return None

        mock_auth.request.side_effect = request_side_effect

        # Call the function
        _set_custom_icon(
            authenticator=mock_auth,
            icon_name="clock",
            icon_color="#8B5CF6",
            force=False
        )

        # Verify POST was called
        # We expect 2 calls: GET (check) and POST (create)
        assert mock_auth.request.call_count == 2

        # Inspect the second call (POST)
        call_args = mock_auth.request.call_args_list[1]
        method, endpoint, payload = call_args[0]

        assert method == "POST"
        assert endpoint == "/api/v2/custom-nodes"

        # Assert the structure and casing
        assert "custom_types" in payload
        assert "ScheduledTask" in payload["custom_types"]
        assert "scheduledtask" not in payload["custom_types"]
        assert payload["custom_types"]["ScheduledTask"]["icon"]["name"] == "clock"
