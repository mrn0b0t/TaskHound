"""
BloodHound OpenGraph Upload Module

Handles upload of OpenGraph files to BloodHound CE via API.
"""

import contextlib
import json
import time
from pathlib import Path
from typing import Dict, Optional

from ..utils.bh_api import bhce_signed_request, get_bloodhound_token
from ..utils.logging import good, info, warn

try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# HTTP timeout for all requests (seconds)
TIMEOUT = 30


def normalize_bloodhound_connector(connector: str, is_legacy: bool = False) -> str:
    """
    Normalize BloodHound connector URI to include scheme and port.

    Handles various input formats for both BHCE and Legacy:

    BHCE (is_legacy=False):
    - localhost -> http://localhost:8080
    - 192.0.2.54 -> http://192.0.2.54:8080
    - http://localhost -> http://localhost:8080
    - https://bh.domain.com -> https://bh.domain.com:443
    - http://localhost:8080 -> http://localhost:8080 (no change)

    Legacy (is_legacy=True):
    - localhost -> bolt://localhost:7687
    - 192.0.2.54 -> bolt://192.0.2.54:7687
    - bolt://localhost -> bolt://localhost:7687
    - bolt://neo4j.domain.com:7474 -> bolt://neo4j.domain.com:7474 (no change)

    Args:
        connector: BloodHound connector URI in various formats
        is_legacy: True if connecting to Legacy BloodHound (Neo4j), False for BHCE

    Returns:
        Normalized URI with scheme and port
    """
    from urllib.parse import urlparse

    # Parse the connector URI
    parsed = urlparse(connector)

    # If no scheme, assume default based on type
    if not parsed.scheme:
        # Check if it looks like just a hostname or IP
        connector = f"bolt://{connector}" if is_legacy else f"http://{connector}"
        parsed = urlparse(connector)

    # Determine default port based on scheme
    if parsed.scheme == "bolt":
        default_port = 7687
    elif parsed.scheme == "https":
        default_port = 443
    else:  # http
        default_port = 8080

    # If port is already specified, use it
    port = parsed.port or default_port

    # Reconstruct URI with explicit port
    netloc = parsed.hostname or parsed.netloc
    normalized = f"{parsed.scheme}://{netloc}:{port}"

    return normalized


def extract_host_from_connector(connector: str) -> str:
    """
    Extract just the hostname/IP from a connector URI.

    Used for legacy connectors that need just the hostname.

    Args:
        connector: Full connector URI (e.g., "bolt://localhost:7687", "http://bh.example.com:8080")

    Returns:
        Just the hostname/IP (e.g., "localhost", "bh.example.com")
    """
    from urllib.parse import urlparse

    parsed = urlparse(connector)

    # If no scheme was provided, the hostname might be in netloc or path
    if parsed.hostname:
        return parsed.hostname
    elif parsed.netloc:
        # Handle case like "192.168.1.1:8080" without scheme
        return parsed.netloc.split(":")[0]
    else:
        # Fallback: assume the whole thing is a hostname
        return connector.split(":")[0]


def find_model_json() -> Path:
    """
    Find model.json in multiple possible locations.

    Search order:
    1. config/model.json (primary - new location)
    2. ~/.config/taskhound/model.json (XDG standard - Linux/macOS)
    3. ~/.taskhound/model.json (legacy location)
    4. Current working directory (last resort with warning)

    Returns:
        Path to model.json

    Raises:
        FileNotFoundError: If model.json is not found in any location
    """
    search_paths = [
        # 1. Project config directory (relative to this file or CWD)
        Path(__file__).parent.parent.parent / "config" / "model.json",
        Path.cwd() / "config" / "model.json",
        # 2. User config directory (XDG standard for Linux/macOS)
        Path.home() / ".config" / "taskhound" / "model.json",
        # 3. Legacy home directory location
        Path.home() / ".taskhound" / "model.json",
        # 4. Current working directory (last resort)
        Path.cwd() / "model.json",
    ]

    for path in search_paths:
        if path.exists():
            # Warn if using CWD (security concern)
            if path == Path.cwd() / "model.json":
                warn("WARNING: Using model.json from current directory")
                warn("This can be a security risk - consider moving to config/model.json")
            return path

    # None found - provide helpful error message
    raise FileNotFoundError(
        "model.json not found. Searched locations:\n"
        + "\n".join(f"  - {p}" for p in search_paths)
        + "\n\nCreate config/model.json in your project directory or ~/.config/taskhound/model.json"
    )


def upload_opengraph_to_bloodhound(
    opengraph_file: str,
    bloodhound_url: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    api_key: Optional[str] = None,
    api_key_id: Optional[str] = None,
    set_icon: bool = False,
    force_icon: bool = False,
    icon_name: str = "heart",
    icon_color: str = "#8B5CF6",
) -> bool:
    """
    Upload OpenGraph file to BloodHound Community Edition.

    Args:
        opengraph_file: Path to the OpenGraph JSON file (contains both nodes and edges)
        bloodhound_url: BloodHound connector URI (various formats supported)
        username: BloodHound username (not needed if api_key/api_key_id provided)
        password: BloodHound password (not needed if api_key/api_key_id provided)
        api_key: BloodHound API key for HMAC authentication (requires api_key_id)
        api_key_id: BloodHound API key ID for HMAC authentication (requires api_key)
        set_icon: Whether to set custom icon for ScheduledTask nodes
        force_icon: Force icon update even if already exists (requires set_icon=True)
        icon_name: Icon name (if set_icon=True)
        icon_color: Icon color in hex format (if set_icon=True)

    Returns:
        True if upload succeeded, False otherwise
    """
    # Normalize URL to include scheme and port (BHCE only)
    bloodhound_url = normalize_bloodhound_connector(bloodhound_url, is_legacy=False)

    if not HAS_REQUESTS:
        warn("ERROR: 'requests' library not installed")
        warn("Install with: pip install requests")
        return False

    # Authenticate
    try:
        use_api_key = api_key and api_key_id

        if use_api_key:
            # Use HMAC-signed API key authentication (no login needed)
            info(f"Using API key authentication for BloodHound at {bloodhound_url}")
            # We'll use bhce_signed_request for all API calls
            headers = None  # Will be generated per-request with HMAC signature
            token = None
        else:
            # Use username/password authentication
            if not username or not password:
                warn("BloodHound authentication requires either API key/ID pair or username/password")
                return False

            token = get_bloodhound_token(bloodhound_url, username, password, timeout=TIMEOUT)

            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

            good(f"Authenticated to BloodHound at {bloodhound_url}")
    except requests.Timeout:
        warn(f"Timeout authenticating to BloodHound (request took longer than {TIMEOUT}s)")
        return False
    except requests.RequestException as e:
        warn(f"Network error during authentication: {e}")
        return False
    except (KeyError, ValueError) as e:
        warn(f"Invalid authentication response from BloodHound: {e}")
        return False
    except Exception as e:
        warn(f"Unexpected authentication error: {e}")
        return False

    # Set custom icon if requested
    if set_icon:
        _set_custom_icon(bloodhound_url, headers, icon_name, icon_color, force_icon, api_key, api_key_id)

    # Upload the OpenGraph file
    info("Uploading OpenGraph data...")
    success = _upload_file(bloodhound_url, headers, opengraph_file, "OpenGraph", api_key, api_key_id)

    return success


def _wait_for_job_completion(
    bloodhound_url: str,
    headers: Optional[Dict],
    job_id: int,
    api_key: Optional[str] = None,
    api_key_id: Optional[str] = None,
    max_wait_time: int = 300,  # 5 minutes
    initial_delay: float = 1.0,
    max_delay: float = 10.0,
) -> bool:
    """
    Poll BloodHound for job completion with exponential backoff.

    Args:
        bloodhound_url: BloodHound base URL
        headers: Authentication headers (for username/password auth)
        job_id: Upload job ID to check
        api_key: Optional API key for HMAC-signed authentication
        api_key_id: Optional API key ID for HMAC-signed authentication
        max_wait_time: Maximum time to wait for job completion (seconds)
        initial_delay: Initial delay between polls (will increase exponentially)
        max_delay: Maximum delay between polls (seconds)

    Returns:
        True if job completed successfully, False otherwise
    """
    use_api_key = api_key and api_key_id
    retry_delay = initial_delay
    max_retries = int(max_wait_time / initial_delay)  # Calculate max retries from wait time

    for attempt in range(max_retries):
        time.sleep(retry_delay)

        try:
            if use_api_key:
                status_response = bhce_signed_request(
                    "GET", "/api/v2/file-upload?skip=0&limit=100", bloodhound_url, api_key, api_key_id, timeout=TIMEOUT
                )
            else:
                status_response = requests.get(
                    f"{bloodhound_url}/api/v2/file-upload?skip=0&limit=100", headers=headers, timeout=TIMEOUT
                )
            status_response.raise_for_status()

            jobs = status_response.json().get("data", [])
            job_found = False
            for job in jobs:
                if job["id"] == job_id:
                    job_found = True
                    status = job.get("status", "")

                    # BloodHound API returns integer status codes, not strings
                    # Map known status codes to readable names
                    status_map = {
                        0: "running",
                        1: "completed",
                        2: "completed",  # success/completed
                        3: "failed",
                        4: "canceled",
                        5: "timeout",
                        6: "ingesting",  # Still processing
                        7: "analyzing",  # Still processing
                    }

                    # Convert integer status to string
                    if isinstance(status, int):
                        status_name = status_map.get(status, f"unknown_{status}")
                    else:
                        status_name = str(status).lower() if status else "unknown"

                    if status_name in ["completed", "success"] or status == 2:
                        # Check for failed files
                        failed = job.get("failed_files_count", job.get("failed_files", 0))
                        if failed == 0:
                            good(f"Upload job {job_id} completed successfully")
                            return True
                        else:
                            warn(f"Job {job_id} completed with {failed} failed files")
                            # Try to get error details
                            if "errors" in job:
                                for error in job["errors"][:3]:  # Show first 3 errors
                                    warn(f"  Error: {error}")
                            return False

                    elif status_name in ["failed", "error"] or status == 3:
                        error_msg = job.get("error", "Unknown error")
                        warn(f"Job {job_id} failed: {error_msg}")
                        return False

                    elif status_name in ["running", "ingesting", "analyzing"] or status in [0, 6, 7]:
                        # Still processing, continue polling
                        info(f"Job {job_id} status: {status_name} (attempt {attempt + 1}/{max_retries})")
                        break

                    else:
                        # Unknown status - log but don't fail immediately
                        info(
                            f"Job {job_id} status: {status} ({status_name}) (attempt {attempt + 1}/{max_retries})"
                        )
                        # Continue polling in case it transitions to a known state

                    break

            if not job_found:
                info(f"Job {job_id} not found in recent jobs list (attempt {attempt + 1}/{max_retries})")

        except requests.Timeout:
            warn(f"Timeout checking job status (attempt {attempt + 1}/{max_retries})")
        except requests.RequestException as e:
            warn(f"Error checking job status (attempt {attempt + 1}/{max_retries}): {e}")

        # Exponential backoff, cap at 10 seconds
        retry_delay = min(retry_delay * 1.5, 10.0)

    warn(f"Timeout waiting for job {job_id} after {max_retries} attempts")
    return False


def _upload_file(
    bloodhound_url: str,
    headers: Optional[Dict],
    file_path: str,
    file_type: str,
    api_key: Optional[str] = None,
    api_key_id: Optional[str] = None,
) -> bool:
    """
    Upload a single file to BloodHound with proper error handling and job polling.

    Args:
        bloodhound_url: BloodHound base URL
        headers: Authentication headers (for username/password auth)
        file_path: Path to file to upload
        file_type: Description of file type for logging
        api_key: Optional API key for HMAC-signed authentication
        api_key_id: Optional API key ID for HMAC-signed authentication

    Returns:
        True if upload and processing succeeded, False otherwise
    """
    use_api_key = api_key and api_key_id
    try:
        # Start upload job
        if use_api_key:
            job_response = bhce_signed_request(
                "POST", "/api/v2/file-upload/start", bloodhound_url, api_key, api_key_id, b"{}", timeout=TIMEOUT
            )
        else:
            job_response = requests.post(
                f"{bloodhound_url}/api/v2/file-upload/start", headers=headers, json={}, timeout=TIMEOUT
            )
        job_response.raise_for_status()
        job_id = job_response.json()["data"]["id"]
        info(f"Started upload job {job_id}")

        # Upload file
        with open(file_path) as f:
            file_data = f.read()

        info(f"Uploading {file_type} data ({len(file_data)} bytes)...")
        if use_api_key:
            upload_response = bhce_signed_request(
                "POST",
                f"/api/v2/file-upload/{job_id}",
                bloodhound_url,
                api_key,
                api_key_id,
                file_data.encode(),
                timeout=TIMEOUT,
            )
        else:
            upload_response = requests.post(
                f"{bloodhound_url}/api/v2/file-upload/{job_id}",
                headers={**headers, "Content-Type": "application/json"},
                data=file_data,
                timeout=TIMEOUT,
            )
        upload_response.raise_for_status()

        # End job
        if use_api_key:
            end_response = bhce_signed_request(
                "POST", f"/api/v2/file-upload/{job_id}/end", bloodhound_url, api_key, api_key_id, b"", timeout=TIMEOUT
            )
        else:
            end_response = requests.post(
                f"{bloodhound_url}/api/v2/file-upload/{job_id}/end", headers=headers, timeout=TIMEOUT
            )
        end_response.raise_for_status()

        # Wait for processing with exponential backoff
        info("Waiting for BloodHound to process the upload...")
        return _wait_for_job_completion(bloodhound_url, headers, job_id, api_key, api_key_id)

    except requests.Timeout:
        warn(f"Timeout uploading {file_type} file (request took longer than {TIMEOUT}s)")
        return False
    except requests.RequestException as e:
        warn(f"Network error uploading {file_type} file: {e}")
        return False
    except FileNotFoundError:
        warn(f"File not found: {file_path}")
        return False
    except Exception as e:
        warn(f"Unexpected error uploading {file_type} file: {e}")
        return False


def _set_custom_icon(
    bloodhound_url: str,
    headers: Optional[Dict],
    icon_name: str,
    icon_color: str,
    force: bool = False,
    api_key: Optional[str] = None,
    api_key_id: Optional[str] = None,
):
    """
    Set custom icon for ScheduledTask nodes by uploading model.json.

    Args:
        bloodhound_url: BloodHound base URL
        headers: Authentication headers (for username/password auth)
        icon_name: Font Awesome icon name
        icon_color: Hex color code
        force: If True, delete existing icon before creating new one
        api_key: Optional API key for HMAC-signed authentication
        api_key_id: Optional API key ID for HMAC-signed authentication
    """
    use_api_key = api_key and api_key_id

    try:
        # First, check if icon already exists
        if use_api_key:
            check_response = bhce_signed_request(
                "GET", "/api/v2/custom-nodes", bloodhound_url, api_key, api_key_id, timeout=TIMEOUT
            )
        else:
            check_response = requests.get(f"{bloodhound_url}/api/v2/custom-nodes", headers=headers, timeout=TIMEOUT)

        if check_response.status_code == 200:
            response_data = check_response.json()
            existing = response_data.get("data") if response_data else None

            if existing:
                for node in existing:
                    # Case-insensitive check for scheduledtask kind
                    kind_name = node.get("kindName", "").lower()
                    if kind_name == "scheduledtask":
                        node_id = node.get("id")
                        existing_icon = node.get("config", {}).get("icon", {})

                        # Check if icon matches what we want
                        if existing_icon.get("name") == icon_name and existing_icon.get("color") == icon_color:
                            print(f"[*] scheduledtask icon already configured ({icon_name}, {icon_color})")
                            return

                        # Icon exists but is different
                        if force:
                            # Delete existing icon configuration
                            print("[*] scheduledtask icon exists with different settings - forcing update")
                            print(f"[*] Current: {existing_icon.get('name')} {existing_icon.get('color')}")
                            print(f"[*] Requested: {icon_name} {icon_color}")
                            info("Deleting existing icon configuration...")

                            try:
                                if use_api_key:
                                    delete_response = bhce_signed_request(
                                        "DELETE",
                                        f"/api/v2/custom-nodes/{node_id}",
                                        bloodhound_url,
                                        api_key,
                                        api_key_id,
                                        timeout=TIMEOUT,
                                    )
                                else:
                                    delete_response = requests.delete(
                                        f"{bloodhound_url}/api/v2/custom-nodes/{node_id}",
                                        headers=headers,
                                        timeout=TIMEOUT,
                                    )

                                if delete_response.status_code in [200, 204]:
                                    good("Deleted existing icon configuration")
                                else:
                                    warn(f"Failed to delete icon (status {delete_response.status_code})")
                                    warn("Will attempt to create new icon anyway...")
                            except requests.Timeout:
                                warn(f"Timeout deleting icon (request took longer than {TIMEOUT}s)")
                                warn("Will attempt to create new icon anyway...")
                            except Exception as e:
                                warn(f"Error deleting icon: {e}")
                                warn("Will attempt to create new icon anyway...")
                        else:
                            info("ScheduledTask icon exists but with different settings")
                            info(f"Current: {existing_icon.get('name')} {existing_icon.get('color')}")
                            info(f"Requested: {icon_name} {icon_color}")
                            info("Keeping existing configuration (use --bh-force-icon to override)")
                            return

        # Icon doesn't exist (or was just deleted), upload model.json file
        # Find model.json in standard locations
        try:
            model_file = find_model_json()
            info(f"Loading icon configuration from: {model_file}")
        except FileNotFoundError as e:
            warn(f"{e}")
            # Fallback to hardcoded structure
            model_data = {
                "custom_types": {
                    "ScheduledTask": {"icon": {"type": "font-awesome", "name": icon_name, "color": icon_color}}
                }
            }
        else:
            # Load model.json (NetworkHound approach)
            with open(model_file, encoding="utf-8") as f:
                model_data = json.load(f)

        if use_api_key:
            response = bhce_signed_request(
                "POST",
                "/api/v2/custom-nodes",
                bloodhound_url,
                api_key,
                api_key_id,
                json.dumps(model_data).encode(),
                timeout=TIMEOUT,
            )
        else:
            response = requests.post(
                f"{bloodhound_url}/api/v2/custom-nodes",
                headers={**headers, "Content-Type": "application/json"},
                json=model_data,
                timeout=TIMEOUT,
            )

        if response.status_code in [200, 201]:
            good(f"Custom icon set for 'ScheduledTask': {icon_name} ({icon_color})")
        elif response.status_code == 409:
            info("ScheduledTask icon already configured")
        else:
            # Non-critical error - print response for debugging
            warn(f"Could not set custom icon (status {response.status_code})")
            with contextlib.suppress(Exception):
                warn(f"Response: {response.text}")

    except requests.Timeout:
        warn(f"Timeout setting custom icon (request took longer than {TIMEOUT}s) (non-critical)")
    except Exception as e:
        # Non-critical - don't fail the whole upload
        warn(f"Failed to set custom icon: {e} (non-critical)")
