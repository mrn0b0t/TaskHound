"""Tests for taskhound/utils/credentials.py - Credential matching utilities."""

import pytest

from taskhound.dpapi.decryptor import ScheduledTaskCredential
from taskhound.utils.credentials import find_password_for_user, match_username


class TestMatchUsername:
    """Tests for match_username function."""

    def test_exact_match(self):
        """Exact username match returns True."""
        assert match_username("jdoe", "jdoe") is True

    def test_case_insensitive(self):
        """Match is case insensitive."""
        assert match_username("JDoe", "jdoe") is True
        assert match_username("JDOE", "jdoe") is True

    def test_domain_prefix_match(self):
        """Domain\\user matches bare username."""
        assert match_username("CORP\\jdoe", "jdoe") is True
        assert match_username("jdoe", "CORP\\jdoe") is True

    def test_different_domains_same_user(self):
        """Different domains but same username match."""
        assert match_username("CORP\\jdoe", "OTHERDOMAIN\\jdoe") is True

    def test_no_match_different_users(self):
        """Different usernames do not match."""
        assert match_username("jdoe", "admin") is False

    def test_no_match_partial(self):
        """Partial matches do not count."""
        assert match_username("jdoe", "jdoe2") is False
        assert match_username("jdoe2", "jdoe") is False

    def test_domain_with_domain(self):
        """Two domain\\user with different users don't match."""
        assert match_username("CORP\\jdoe", "CORP\\admin") is False


class TestFindPasswordForUser:
    """Tests for find_password_for_user function."""

    @pytest.fixture
    def sample_creds(self):
        """Sample credentials for testing."""
        return [
            ScheduledTaskCredential(
                task_name="Task1", blob_path="/path/1",
                username="CORP\\jdoe", password="Password123!"
            ),
            ScheduledTaskCredential(
                task_name="Task2", blob_path="/path/2",
                username="admin", password="AdminPass!"
            ),
            ScheduledTaskCredential(
                task_name="Task3", blob_path="/path/3",
                username="DOMAIN\\svc_backup", password="BackupPass!"
            ),
        ]

    def test_exact_match(self, sample_creds):
        """Find password with exact username match."""
        result = find_password_for_user("admin", sample_creds)
        assert result == "AdminPass!"

    def test_domain_match(self, sample_creds):
        """Find password when credential has domain prefix."""
        result = find_password_for_user("jdoe", sample_creds)
        assert result == "Password123!"

    def test_user_with_domain_finds_bare_cred(self, sample_creds):
        """Username with domain finds credential without domain."""
        result = find_password_for_user("CORP\\admin", sample_creds)
        assert result == "AdminPass!"

    def test_not_found(self, sample_creds):
        """Returns None when no match found."""
        result = find_password_for_user("nonexistent", sample_creds)
        assert result is None

    def test_empty_creds(self):
        """Returns None with empty credentials list."""
        result = find_password_for_user("jdoe", [])
        assert result is None

    def test_none_creds(self):
        """Returns None with None credentials."""
        result = find_password_for_user("jdoe", None)
        assert result is None

    def test_resolved_username_fallback(self, sample_creds):
        """Uses resolved_username as fallback."""
        # Primary doesn't match, but resolved does
        result = find_password_for_user("S-1-5-21-xxx", sample_creds, resolved_username="jdoe")
        assert result == "Password123!"

    def test_sid_suffix_stripped(self, sample_creds):
        """SID suffix is stripped from username."""
        result = find_password_for_user("jdoe (S-1-5-21-xxx)", sample_creds)
        assert result == "Password123!"

    def test_cred_without_username_skipped(self):
        """Credentials without username are skipped."""
        creds = [
            ScheduledTaskCredential(
                task_name="Task1", blob_path="/path/1",
                username=None, password="NoUser"
            ),
            ScheduledTaskCredential(
                task_name="Task2", blob_path="/path/2",
                username="jdoe", password="HasUser"
            ),
        ]
        result = find_password_for_user("jdoe", creds)
        assert result == "HasUser"
