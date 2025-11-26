# Tests for AuthContext dataclass.


from taskhound.auth import AuthContext


class TestAuthContext:
    """Test AuthContext dataclass functionality."""

    def test_basic_creation(self):
        """Test basic AuthContext creation with minimal params."""
        auth = AuthContext(username="admin", domain="CORP")
        assert auth.username == "admin"
        assert auth.domain == "CORP"
        assert auth.password is None
        assert auth.hashes is None
        assert auth.kerberos is False

    def test_full_creation(self):
        """Test AuthContext creation with all params."""
        auth = AuthContext(
            username="admin",
            password="secret",
            domain="CORP",
            hashes=None,
            kerberos=False,
            dc_ip="192.168.1.1",
            timeout=30,
            ldap_domain="LDAP.CORP",
            ldap_user="ldap_admin",
            ldap_password="ldap_secret",
            ldap_hashes=None,
        )
        assert auth.username == "admin"
        assert auth.password == "secret"
        assert auth.domain == "CORP"
        assert auth.dc_ip == "192.168.1.1"
        assert auth.timeout == 30
        assert auth.ldap_domain == "LDAP.CORP"
        assert auth.ldap_user == "ldap_admin"
        assert auth.ldap_password == "ldap_secret"

    def test_has_credentials_with_password(self):
        """Test has_credentials with password auth."""
        auth = AuthContext(username="admin", password="secret", domain="CORP")
        assert auth.has_credentials is True

    def test_has_credentials_with_hashes(self):
        """Test has_credentials with hash auth."""
        auth = AuthContext(username="admin", hashes="aad3b435b51404ee:8846f7eaee8fb117", domain="CORP")
        assert auth.has_credentials is True

    def test_has_credentials_with_kerberos(self):
        """Test has_credentials with Kerberos auth."""
        auth = AuthContext(username="admin", kerberos=True, domain="CORP")
        assert auth.has_credentials is True

    def test_has_credentials_false_no_auth(self):
        """Test has_credentials returns False without auth."""
        auth = AuthContext(username="admin", domain="CORP")
        assert auth.has_credentials is False

    def test_has_credentials_false_no_username(self):
        """Test has_credentials returns False without username."""
        auth = AuthContext(password="secret", domain="CORP")
        assert auth.has_credentials is False

    def test_ldap_effective_domain_override(self):
        """Test LDAP domain override."""
        auth = AuthContext(domain="CORP", ldap_domain="LDAP.CORP")
        assert auth.ldap_effective_domain == "LDAP.CORP"

    def test_ldap_effective_domain_fallback(self):
        """Test LDAP domain falls back to main domain."""
        auth = AuthContext(domain="CORP")
        assert auth.ldap_effective_domain == "CORP"

    def test_ldap_effective_user_override(self):
        """Test LDAP user override."""
        auth = AuthContext(username="admin", ldap_user="ldap_admin")
        assert auth.ldap_effective_user == "ldap_admin"

    def test_ldap_effective_user_fallback(self):
        """Test LDAP user falls back to main user."""
        auth = AuthContext(username="admin")
        assert auth.ldap_effective_user == "admin"

    def test_ldap_effective_password_override(self):
        """Test LDAP password override."""
        auth = AuthContext(password="secret", ldap_password="ldap_secret")
        assert auth.ldap_effective_password == "ldap_secret"

    def test_ldap_effective_password_fallback(self):
        """Test LDAP password falls back to main password."""
        auth = AuthContext(password="secret")
        assert auth.ldap_effective_password == "secret"

    def test_ldap_effective_hashes_override(self):
        """Test LDAP hashes override."""
        auth = AuthContext(
            hashes="aad3b435b51404ee:main",
            ldap_hashes="aad3b435b51404ee:ldap"
        )
        assert auth.ldap_effective_hashes == "aad3b435b51404ee:ldap"

    def test_ldap_effective_hashes_fallback(self):
        """Test LDAP hashes falls back to main hashes."""
        auth = AuthContext(hashes="aad3b435b51404ee:main")
        assert auth.ldap_effective_hashes == "aad3b435b51404ee:main"

    def test_get_lm_hash(self):
        """Test LM hash extraction."""
        auth = AuthContext(hashes="aad3b435b51404ee:8846f7eaee8fb117")
        assert auth.get_lm_hash() == "aad3b435b51404ee"

    def test_get_nt_hash(self):
        """Test NT hash extraction."""
        auth = AuthContext(hashes="aad3b435b51404ee:8846f7eaee8fb117")
        assert auth.get_nt_hash() == "8846f7eaee8fb117"

    def test_get_lm_hash_empty(self):
        """Test LM hash extraction with no hashes."""
        auth = AuthContext()
        assert auth.get_lm_hash() == ""

    def test_get_nt_hash_empty(self):
        """Test NT hash extraction with no hashes."""
        auth = AuthContext()
        assert auth.get_nt_hash() == ""

    def test_get_nt_hash_single_part(self):
        """Test NT hash extraction with single hash (NT only)."""
        auth = AuthContext(hashes=":8846f7eaee8fb117")
        assert auth.get_nt_hash() == "8846f7eaee8fb117"

    def test_repr_hides_credentials(self):
        """Test repr doesn't expose actual credentials."""
        auth = AuthContext(
            username="admin",
            password="supersecret",
            hashes="aad3b435b51404ee:8846f7eaee8fb117",
            domain="CORP",
        )
        repr_str = repr(auth)
        assert "supersecret" not in repr_str
        assert "8846f7eaee8fb117" not in repr_str
        assert "has_password=True" in repr_str
        assert "has_hashes=True" in repr_str
        assert "admin" in repr_str
        assert "CORP" in repr_str

    def test_default_timeout(self):
        """Test default timeout value."""
        auth = AuthContext()
        assert auth.timeout == 60
