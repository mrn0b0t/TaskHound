import json
from unittest.mock import Mock, patch

from taskhound.output.bloodhound import _set_custom_icon


class TestBloodHoundOutput:
    """Unit tests for BloodHound output module."""

    @patch("requests.get")
    @patch("requests.post")
    def test_set_custom_icon_payload_casing(self, mock_post, mock_get):
        """Verify that _set_custom_icon sends 'ScheduledTask' (CamelCase) in the payload."""

        # Mock GET response (icon doesn't exist)
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.json.return_value = {"data": []}
        mock_get.return_value = mock_get_response

        # Mock POST response (success)
        mock_post_response = Mock()
        mock_post_response.status_code = 200
        mock_post.return_value = mock_post_response

        # Call the function
        _set_custom_icon(
            bloodhound_url="http://localhost:8080",
            headers={},
            icon_name="clock",
            icon_color="#8B5CF6"
        )

        # Verify POST was called
        assert mock_post.called

        # Inspect the JSON payload sent to POST
        args, kwargs = mock_post.call_args
        payload = kwargs.get("json")

        # If payload is not in kwargs, check if it was passed as data
        if not payload and "data" in kwargs:
             payload = json.loads(kwargs["data"])

        # Assert the structure and casing
        assert "custom_types" in payload
        assert "ScheduledTask" in payload["custom_types"]
        assert "scheduledtask" not in payload["custom_types"]
        assert payload["custom_types"]["ScheduledTask"]["icon"]["name"] == "clock"
