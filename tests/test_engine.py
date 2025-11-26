"""
Test engine functionality and merged feature integration.
"""

import inspect

from taskhound.engine import process_target
from taskhound.output.printer import format_block


def test_process_target_signature_has_dpapi_params():
    """Test that process_target has DPAPI parameters."""
    sig = inspect.signature(process_target)
    params = list(sig.parameters.keys())

    assert "loot" in params, "Missing 'loot' parameter"
    assert "dpapi_key" in params, "Missing 'dpapi_key' parameter"


def test_process_target_signature_has_bloodhound_params():
    """Test that process_target has BloodHound/LDAP parameters via AuthContext."""
    sig = inspect.signature(process_target)
    params = list(sig.parameters.keys())

    # AuthContext bundles LDAP params (ldap_domain, ldap_user, ldap_password, ldap_hashes)
    assert "auth" in params, "Missing 'auth' parameter (AuthContext)"


def test_format_block_signature_has_all_params():
    """Test that format_block has parameters from both features."""
    sig = inspect.signature(format_block)
    params = list(sig.parameters.keys())

    # DPAPI parameter
    assert "decrypted_creds" in params, "Missing 'decrypted_creds' parameter"

    # BloodHound parameters
    assert "ldap_domain" in params, "Missing 'ldap_domain' parameter"
    assert "meta" in params, "Missing 'meta' parameter"


def test_process_target_parameter_count():
    """Test that process_target has expected number of parameters."""
    sig = inspect.signature(process_target)
    params = list(sig.parameters.keys())

    # After AuthContext refactor: 18 params (11 auth params bundled into AuthContext)
    # target, all_rows, auth, include_ms, include_local, hv, debug, show_unsaved_creds,
    # backup_dir, credguard_detect, no_ldap, loot, dpapi_key, bh_connector, concise,
    # opsec, laps_cache, validate_creds
    assert len(params) >= 18, f"Expected at least 18 parameters, got {len(params)}"


def test_format_block_parameter_count():
    """Test that format_block has expected number of parameters."""
    sig = inspect.signature(format_block)
    params = list(sig.parameters.keys())

    # Should have parameters from both features merged
    assert len(params) >= 20, f"Expected at least 20 parameters, got {len(params)}"
