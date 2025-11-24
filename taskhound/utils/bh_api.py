import base64
import datetime
import hashlib
import hmac
from typing import Optional

import requests


def bhce_signed_request(
    method: str, uri: str, base_url: str, api_key: str, api_key_id: str, body: Optional[bytes] = None, timeout: int = 30
) -> requests.Response:
    """
    Make a signed request to BloodHound CE API using HMAC-SHA256 authentication.

    According to BloodHound CE API documentation, API key authentication uses
    hash-based message authentication code (HMAC) with the following signature chain:
    1. OperationKey: HMAC(api_key, method + uri)
    2. DateKey: HMAC(OperationKey, RFC3339_datetime[:13])  # truncated to hour
    3. Signature: HMAC(DateKey, body)  # body can be empty

    Args:
        method: HTTP method (GET, POST, etc.)
        uri: API endpoint path (e.g., '/api/version')
        base_url: Base URL of BloodHound CE instance
        api_key: API key for HMAC signing
        api_key_id: API key ID for Authorization header
        body: Optional request body as bytes
        timeout: Request timeout in seconds

    Returns:
        requests.Response object
    """
    # Initialize HMAC digester with API key as secret
    digester = hmac.new(api_key.encode(), None, hashlib.sha256)

    # OperationKey: HMAC digest of method + URI (no delimiter)
    digester.update(f"{method}{uri}".encode())
    digester = hmac.new(digester.digest(), None, hashlib.sha256)

    # DateKey: HMAC digest of RFC3339 datetime truncated to hour
    datetime_formatted = datetime.datetime.now().astimezone().isoformat("T")
    digester.update(datetime_formatted[:13].encode())
    digester = hmac.new(digester.digest(), None, hashlib.sha256)

    # Body signing: HMAC digest of request body (or empty)
    if body is not None:
        digester.update(body)

    # Build headers with HMAC signature
    headers = {
        "Authorization": f"bhesignature {api_key_id}",
        "RequestDate": datetime_formatted,
        "Signature": base64.b64encode(digester.digest()).decode(),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    # Make the signed request
    return requests.request(method=method, url=f"{base_url}{uri}", headers=headers, data=body, timeout=timeout)


def get_bloodhound_token(base_url: str, username: str, password: str, timeout: int = 30) -> str:
    """
    Get session token from BloodHound CE.
    Raises requests.RequestException or ValueError on failure.
    """
    response = requests.post(
        f"{base_url}/api/v2/login",
        json={"login_method": "secret", "secret": password, "username": username},
        timeout=timeout,
    )
    response.raise_for_status()
    data = response.json()
    if "data" not in data or "session_token" not in data["data"]:
        raise ValueError("Invalid response format: missing session_token")
    return data["data"]["session_token"]
