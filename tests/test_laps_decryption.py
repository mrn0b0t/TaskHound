"""
Tests for LAPS decryption module.
"""

from taskhound.laps.decryption import (
    LAPSDecryptionContext,
)


class TestLAPSDecryptionContextInit:
    """Tests for LAPSDecryptionContext dataclass"""

    def test_basic_creation(self):
        """Should create context with required fields"""
        ctx = LAPSDecryptionContext(
            domain="DOMAIN.LAB",
            username="admin"
        )

        assert ctx.domain == "DOMAIN.LAB"
        assert ctx.username == "admin"
        assert ctx.password is None

    def test_creation_with_password(self):
        """Should create context with password"""
        ctx = LAPSDecryptionContext(
            domain="DOMAIN.LAB",
            username="admin",
            password="P@ssw0rd!"
        )

        assert ctx.password == "P@ssw0rd!"

    def test_creation_with_hashes(self):
        """Should create context with NTLM hashes"""
        ctx = LAPSDecryptionContext(
            domain="DOMAIN.LAB",
            username="admin",
            lmhash="aad3b435b51404eeaad3b435b51404ee",
            nthash="31d6cfe0d16ae931b73c59d7e0c089c0"
        )

        assert ctx.lmhash == "aad3b435b51404eeaad3b435b51404ee"
        assert ctx.nthash == "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_creation_with_kerberos(self):
        """Should create context with Kerberos enabled"""
        ctx = LAPSDecryptionContext(
            domain="DOMAIN.LAB",
            username="admin",
            kerberos=True,
            kdc_host="dc01.domain.lab"
        )

        assert ctx.kerberos is True
        assert ctx.kdc_host == "dc01.domain.lab"

    def test_defaults(self):
        """Should have correct default values"""
        ctx = LAPSDecryptionContext(
            domain="DOMAIN.LAB",
            username="admin"
        )

        assert ctx.lmhash == ""
        assert ctx.nthash == ""
        assert ctx.kerberos is False
        assert ctx.kdc_host is None
        assert ctx.dns_server is None

    def test_gke_cache_initialized(self):
        """Should initialize empty GKE cache"""
        ctx = LAPSDecryptionContext(
            domain="DOMAIN.LAB",
            username="admin"
        )

        assert ctx._gke_cache == {}


class TestLAPSDecryptionContextFromCredentials:
    """Tests for from_credentials factory method"""

    def test_basic_creation(self):
        """Should create context from basic credentials"""
        ctx = LAPSDecryptionContext.from_credentials(
            domain="DOMAIN.LAB",
            username="admin",
            password="P@ssw0rd!"
        )

        assert ctx.domain == "DOMAIN.LAB"
        assert ctx.username == "admin"
        assert ctx.password == "P@ssw0rd!"

    def test_parses_lm_nt_hashes(self):
        """Should parse LM:NT hash format"""
        ctx = LAPSDecryptionContext.from_credentials(
            domain="DOMAIN.LAB",
            username="admin",
            hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
        )

        assert ctx.lmhash == "aad3b435b51404eeaad3b435b51404ee"
        assert ctx.nthash == "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_parses_nt_hash_only(self):
        """Should parse NT hash only"""
        ctx = LAPSDecryptionContext.from_credentials(
            domain="DOMAIN.LAB",
            username="admin",
            hashes="31d6cfe0d16ae931b73c59d7e0c089c0"
        )

        assert ctx.lmhash == ""
        assert ctx.nthash == "31d6cfe0d16ae931b73c59d7e0c089c0"

    def test_handles_no_hashes(self):
        """Should handle None hashes"""
        ctx = LAPSDecryptionContext.from_credentials(
            domain="DOMAIN.LAB",
            username="admin",
            password="P@ssw0rd!",
            hashes=None
        )

        assert ctx.lmhash == ""
        assert ctx.nthash == ""

    def test_with_kerberos(self):
        """Should set Kerberos options"""
        ctx = LAPSDecryptionContext.from_credentials(
            domain="DOMAIN.LAB",
            username="admin",
            password="P@ssw0rd!",
            kerberos=True,
            kdc_host="dc01.domain.lab"
        )

        assert ctx.kerberos is True
        assert ctx.kdc_host == "dc01.domain.lab"

    def test_with_dns_server(self):
        """Should set DNS server"""
        ctx = LAPSDecryptionContext.from_credentials(
            domain="DOMAIN.LAB",
            username="admin",
            password="P@ssw0rd!",
            dns_server="192.168.1.1"
        )

        assert ctx.dns_server == "192.168.1.1"


class TestLAPSDecryptionContextCaching:
    """Tests for GKE cache functionality"""

    def test_cache_starts_empty(self):
        """Should start with empty cache"""
        ctx = LAPSDecryptionContext(
            domain="DOMAIN.LAB",
            username="admin"
        )

        assert len(ctx._gke_cache) == 0

    def test_cache_can_store_values(self):
        """Should be able to store values in cache"""
        ctx = LAPSDecryptionContext(
            domain="DOMAIN.LAB",
            username="admin"
        )

        key = b"test_key_id"
        value = {"test": "data"}
        ctx._gke_cache[key] = value

        assert ctx._gke_cache[key] == value

    def test_separate_instances_have_separate_caches(self):
        """Each context instance should have its own cache"""
        ctx1 = LAPSDecryptionContext(
            domain="DOMAIN1.LAB",
            username="admin1"
        )
        ctx2 = LAPSDecryptionContext(
            domain="DOMAIN2.LAB",
            username="admin2"
        )

        ctx1._gke_cache[b"key1"] = "value1"

        assert b"key1" not in ctx2._gke_cache
