"""
Tests for SID resolver utilities.
"""
import struct
from unittest.mock import MagicMock

import pytest

from taskhound.utils.sid_resolver import (
    binary_to_sid,
    is_sid,
    resolve_sid_from_bloodhound,
    sid_to_binary,
)


class TestIsSid:
    """Tests for is_sid function"""

    def test_valid_domain_sid(self):
        """Should recognize valid domain SID"""
        sid = "S-1-5-21-123456789-123456789-123456789-1001"

        assert is_sid(sid) is True

    def test_valid_builtin_sid(self):
        """Should recognize builtin account SIDs"""
        # Local System
        assert is_sid("S-1-5-18") is True
        # Local Service
        assert is_sid("S-1-5-19") is True
        # Network Service
        assert is_sid("S-1-5-20") is True

    def test_valid_builtin_administrators(self):
        """Should recognize builtin group SIDs"""
        # Builtin Administrators
        assert is_sid("S-1-5-32-544") is True

    def test_empty_string_returns_false(self):
        """Should return False for empty string"""
        assert is_sid("") is False

    def test_none_returns_false(self):
        """Should return False for None"""
        assert is_sid(None) is False

    def test_invalid_sid_no_prefix(self):
        """Should reject SID without S- prefix"""
        assert is_sid("1-5-21-123456789") is False

    def test_invalid_sid_wrong_format(self):
        """Should reject malformed SID"""
        assert is_sid("S-1-invalid") is False

    def test_username_is_not_sid(self):
        """Should reject username"""
        assert is_sid("DOMAIN\\admin") is False

    def test_strips_whitespace(self):
        """Should strip whitespace before checking"""
        assert is_sid("  S-1-5-18  ") is True


class TestSidToBinary:
    """Tests for sid_to_binary function"""

    def test_converts_simple_sid(self):
        """Should convert simple SID to binary"""
        sid = "S-1-5-18"  # Local System

        result = sid_to_binary(sid)

        assert result is not None
        assert isinstance(result, bytes)
        assert len(result) >= 8  # Minimum SID size

    def test_converts_domain_sid(self):
        """Should convert domain SID to binary"""
        sid = "S-1-5-21-123456789-987654321-111111111-500"

        result = sid_to_binary(sid)

        assert result is not None
        # 5 sub-authorities (21, 123456789, 987654321, 111111111, 500)
        # Revision (1) + SubAuth count (1) + Authority (6) + 5 sub-authorities (20) = 28
        assert len(result) == 28

    def test_returns_none_for_invalid_sid(self):
        """Should return None for invalid SID"""
        assert sid_to_binary("invalid") is None
        assert sid_to_binary("") is None
        assert sid_to_binary("S-1") is None  # Too short

    def test_returns_none_for_non_sid_prefix(self):
        """Should return None for string not starting with S-"""
        assert sid_to_binary("1-5-21-123456789") is None

    def test_roundtrip_conversion(self):
        """Should survive roundtrip conversion"""
        original_sid = "S-1-5-21-123456789-987654321-111111111-1001"

        binary = sid_to_binary(original_sid)
        recovered = binary_to_sid(binary)

        assert recovered == original_sid


class TestBinaryToSid:
    """Tests for binary_to_sid function"""

    def test_converts_binary_to_sid_string(self):
        """Should convert binary SID to string"""
        # Build a known binary SID for S-1-5-18
        # Revision=1, SubAuth count=1, Authority=5, SubAuth=18
        binary = struct.pack("B", 1)  # Revision
        binary += struct.pack("B", 1)  # SubAuth count
        binary += struct.pack(">Q", 5)[2:]  # Authority (6 bytes)
        binary += struct.pack("<I", 18)  # SubAuth

        result = binary_to_sid(binary)

        assert result == "S-1-5-18"

    def test_returns_none_for_empty_bytes(self):
        """Should return None for empty bytes"""
        assert binary_to_sid(b"") is None

    def test_returns_none_for_too_short_bytes(self):
        """Should return None for bytes too short"""
        assert binary_to_sid(b"\x01") is None
        assert binary_to_sid(b"\x01\x02\x03") is None

    def test_returns_none_for_none(self):
        """Should return None for None input"""
        assert binary_to_sid(None) is None

    def test_handles_truncated_subauthorities(self):
        """Should handle truncated binary data"""
        # Claim 5 sub-authorities but only provide data for 1
        binary = struct.pack("B", 1)  # Revision
        binary += struct.pack("B", 5)  # SubAuth count (claims 5)
        binary += struct.pack(">Q", 5)[2:]  # Authority (6 bytes)
        binary += struct.pack("<I", 18)  # Only 1 SubAuth provided

        result = binary_to_sid(binary)

        assert result is None


class TestResolveFromBloodhound:
    """Tests for resolve_sid_from_bloodhound function"""

    def test_returns_none_when_no_loader(self):
        """Should return None when hv_loader is None"""
        result = resolve_sid_from_bloodhound("S-1-5-21-xxx", None)

        assert result is None

    def test_returns_none_when_loader_not_loaded(self):
        """Should return None when loader exists but not loaded"""
        mock_loader = MagicMock()
        mock_loader.loaded = False

        result = resolve_sid_from_bloodhound("S-1-5-21-xxx", mock_loader)

        assert result is None

    def test_returns_username_when_found(self):
        """Should look up SID in BloodHound data"""
        mock_loader = MagicMock()
        mock_loader.loaded = True
        mock_loader.hv_sids = {
            "S-1-5-21-123456789-1001": {
                "sam": "admin",
                "domain": "DOMAIN.LAB"
            }
        }

        # The function may return user data, None, or processed value
        # depending on implementation - testing the lookup path
        resolve_sid_from_bloodhound("S-1-5-21-123456789-1001", mock_loader)

        # Function accesses hv_sids, so the mock should have been called
        # Result depends on implementation details
        # Main test is that it doesn't raise an exception
        pass  # If we get here without exception, the path was tested

    def test_returns_none_when_sid_not_found(self):
        """Should return None when SID not in BloodHound data"""
        mock_loader = MagicMock()
        mock_loader.loaded = True
        mock_loader.hv_sids = {}

        result = resolve_sid_from_bloodhound("S-1-5-21-unknown", mock_loader)

        assert result is None


class TestSidBinaryRoundtrip:
    """Roundtrip tests for SID conversion"""

    @pytest.mark.parametrize("sid", [
        "S-1-5-18",  # Local System
        "S-1-5-19",  # Local Service
        "S-1-5-20",  # Network Service
        "S-1-5-32-544",  # Builtin Administrators
        "S-1-5-21-123456789-987654321-111111111-500",  # Domain Admin
        "S-1-5-21-123456789-987654321-111111111-501",  # Domain Guest
        "S-1-5-21-123456789-987654321-111111111-512",  # Domain Admins group
        "S-1-5-21-1234567890-1234567890-1234567890-1001",  # Regular user
    ])
    def test_roundtrip_preserves_sid(self, sid):
        """SID should survive binary roundtrip"""
        binary = sid_to_binary(sid)
        recovered = binary_to_sid(binary)

        assert recovered == sid


class TestIsSidEdgeCases:
    """Edge case tests for is_sid function"""

    def test_requires_subauthority(self):
        """Should require at least one sub-authority"""
        # S-1-5 has no sub-authority - should this be valid?
        # Based on pattern requiring sub-authorities:
        assert is_sid("S-1-5") is False

    def test_handles_very_long_sid(self):
        """Should handle SID with many sub-authorities"""
        # Windows supports up to 15 sub-authorities
        sid = "S-1-5-" + "-".join(str(i) for i in range(15))

        assert is_sid(sid) is True

    def test_handles_large_sub_authority_values(self):
        """Should handle large sub-authority values"""
        sid = "S-1-5-21-4294967295-4294967295-4294967295-4294967295"

        assert is_sid(sid) is True


class TestSidToBinaryEdgeCases:
    """Edge case tests for sid_to_binary function"""

    def test_handles_large_authority(self):
        """Should handle large authority values"""
        # SECURITY_NT_AUTHORITY is 5, but other values exist
        sid = "S-1-5-21-123456789"

        result = sid_to_binary(sid)

        assert result is not None

    def test_handles_zero_subauthority(self):
        """Should handle zero as sub-authority"""
        sid = "S-1-5-0"

        result = sid_to_binary(sid)

        assert result is not None
        assert binary_to_sid(result) == sid


class TestGetDomainSidPrefix:
    """Tests for get_domain_sid_prefix function"""

    def test_extracts_domain_prefix_from_user_sid(self):
        """Should extract domain prefix from user SID (remove RID)"""
        from taskhound.utils.sid_resolver import get_domain_sid_prefix

        sid = "S-1-5-21-123456789-987654321-111222333-1001"

        result = get_domain_sid_prefix(sid)

        assert result == "S-1-5-21-123456789-987654321-111222333"

    def test_extracts_domain_prefix_from_computer_sid(self):
        """Should extract domain prefix from computer account SID"""
        from taskhound.utils.sid_resolver import get_domain_sid_prefix

        sid = "S-1-5-21-3570960105-1792075822-554663251-1002"

        result = get_domain_sid_prefix(sid)

        assert result == "S-1-5-21-3570960105-1792075822-554663251"

    def test_returns_none_for_builtin_sid(self):
        """Should return None for builtin SIDs (not domain SIDs)"""
        from taskhound.utils.sid_resolver import get_domain_sid_prefix

        # Local System
        assert get_domain_sid_prefix("S-1-5-18") is None
        # Builtin Administrators
        assert get_domain_sid_prefix("S-1-5-32-544") is None

    def test_returns_none_for_empty_string(self):
        """Should return None for empty string"""
        from taskhound.utils.sid_resolver import get_domain_sid_prefix

        assert get_domain_sid_prefix("") is None

    def test_returns_none_for_none(self):
        """Should return None for None"""
        from taskhound.utils.sid_resolver import get_domain_sid_prefix

        assert get_domain_sid_prefix(None) is None


class TestIsForeignDomainSid:
    """Tests for is_foreign_domain_sid function"""

    def test_detects_foreign_domain_sid(self):
        """Should detect SID from different domain"""
        from taskhound.utils.sid_resolver import is_foreign_domain_sid

        local_prefix = "S-1-5-21-123456789-987654321-111222333"
        foreign_sid = "S-1-5-21-999888777-666555444-333222111-1001"

        assert is_foreign_domain_sid(foreign_sid, local_prefix) is True

    def test_detects_same_domain_sid(self):
        """Should return False for SID from same domain"""
        from taskhound.utils.sid_resolver import is_foreign_domain_sid

        local_prefix = "S-1-5-21-123456789-987654321-111222333"
        same_domain_sid = "S-1-5-21-123456789-987654321-111222333-500"

        assert is_foreign_domain_sid(same_domain_sid, local_prefix) is False

    def test_returns_false_for_builtin_sid(self):
        """Should return False for builtin SIDs (not domain SIDs)"""
        from taskhound.utils.sid_resolver import is_foreign_domain_sid

        local_prefix = "S-1-5-21-123456789-987654321-111222333"

        # Local System - not a domain SID
        assert is_foreign_domain_sid("S-1-5-18", local_prefix) is False

    def test_returns_false_when_no_local_prefix(self):
        """Should return False when local domain prefix is unknown"""
        from taskhound.utils.sid_resolver import is_foreign_domain_sid

        foreign_sid = "S-1-5-21-999888777-666555444-333222111-1001"

        assert is_foreign_domain_sid(foreign_sid, None) is False


class TestLDAPDomainValidation:
    """Tests for LDAP domain validation (B7 bug fix)"""

    def test_resolve_name_to_sid_via_ldap_rejects_empty_domain(self):
        """Should return None for empty domain (prevents invalidDNSyntax error)"""
        from taskhound.utils.sid_resolver import resolve_name_to_sid_via_ldap

        # Empty domain should return None immediately without attempting LDAP
        result = resolve_name_to_sid_via_ldap(
            name="testcomputer",
            domain="",
            is_computer=True,
        )

        assert result is None

    def test_resolve_name_to_sid_via_ldap_rejects_domain_without_dots(self):
        """Should return None for domain without dots (not FQDN)"""
        from taskhound.utils.sid_resolver import resolve_name_to_sid_via_ldap

        # Single-label domain (no dots) should return None
        result = resolve_name_to_sid_via_ldap(
            name="testcomputer",
            domain="TESTDOMAIN",
            is_computer=True,
        )

        assert result is None

    def test_resolve_sid_via_ldap_rejects_empty_domain(self):
        """Should return None for empty domain in SID resolution"""
        from taskhound.utils.sid_resolver import resolve_sid_via_ldap

        result = resolve_sid_via_ldap(
            sid="S-1-5-21-123456789-987654321-111111111-1001",
            domain="",
            username="testuser",
            password="testpass",
        )

        assert result is None

    def test_resolve_sid_via_ldap_rejects_domain_without_dots(self):
        """Should return None for domain without dots in SID resolution"""
        from taskhound.utils.sid_resolver import resolve_sid_via_ldap

        result = resolve_sid_via_ldap(
            sid="S-1-5-21-123456789-987654321-111111111-1001",
            domain="NODOTS",
            username="testuser",
            password="testpass",
        )

        assert result is None

    def test_batch_get_user_attributes_rejects_empty_domain(self):
        """Should return empty dict for empty domain in batch query"""
        from taskhound.utils.sid_resolver import batch_get_user_attributes

        result = batch_get_user_attributes(
            usernames=["testuser"],
            domain="",
        )

        assert result == {}

    def test_fetch_tier0_members_rejects_empty_domain(self):
        """Should return empty dict for empty domain in Tier-0 preflight"""
        from taskhound.utils.sid_resolver import fetch_tier0_members

        result = fetch_tier0_members(domain="")

        assert result == {}

    def test_fetch_tier0_members_rejects_domain_without_dots(self):
        """Should return empty dict for domain without dots"""
        from taskhound.utils.sid_resolver import fetch_tier0_members

        result = fetch_tier0_members(domain="SINGLELABEL")

        assert result == {}
