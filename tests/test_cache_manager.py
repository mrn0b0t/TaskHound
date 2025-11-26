import json
import shutil
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from taskhound.utils.cache_manager import CacheManager


class TestCacheManager(unittest.TestCase):

    def setUp(self):
        # Create temp dir for cache
        self.test_dir = tempfile.mkdtemp()
        self.cache_path = Path(self.test_dir) / "test_cache.db"
        self.cache = CacheManager(cache_file=self.cache_path, ttl_hours=1, enabled=True)

    def tearDown(self):
        if self.cache.conn:
            self.cache.conn.close()
        shutil.rmtree(self.test_dir)

    def test_session_cache(self):
        """Test in-memory session cache."""
        self.cache.set("test", "key1", "value1")

        # Check internal session dict
        self.assertIn("test:key1", self.cache.session)
        self.assertEqual(self.cache.session["test:key1"], "value1")

        # Check get method
        self.assertEqual(self.cache.get("test", "key1"), "value1")
        self.assertEqual(self.cache.stats["session_hits"], 1)

    def test_persistent_cache(self):
        """Test persistent SQLite cache."""
        self.cache.set("test", "key2", {"complex": "data", "id": 123})

        # Verify it's in DB
        conn = sqlite3.connect(self.cache_path)
        cursor = conn.execute("SELECT value FROM cache WHERE category='test' AND key='key2'")
        row = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(json.loads(row[0]), {"complex": "data", "id": 123})

    def test_persistence_across_instances(self):
        """Test that data persists across CacheManager instances."""
        # Set in first instance
        self.cache.set("test", "key3", "persistent_value")
        self.cache.conn.close() # Close first instance connection

        # Create second instance pointing to same DB
        cache2 = CacheManager(cache_file=self.cache_path, ttl_hours=1, enabled=True)

        # Should miss session cache but hit persistent cache
        value = cache2.get("test", "key3")
        self.assertEqual(value, "persistent_value")
        self.assertEqual(cache2.stats["session_misses"], 1)
        self.assertEqual(cache2.stats["persistent_hits"], 1)

        # Second access should hit session cache (promoted)
        value2 = cache2.get("test", "key3")
        self.assertEqual(value2, "persistent_value")
        self.assertEqual(cache2.stats["session_hits"], 1)

        cache2.conn.close()

    def test_expiration(self):
        """Test TTL expiration."""
        # Set with very short TTL (0.0001 hours ~= 0.36 seconds)
        # Using a small float for hours
        self.cache.set("test", "expired_key", "value", ttl_hours=0.0001)

        # Should be available immediately
        self.assertEqual(self.cache.get("test", "expired_key"), "value")

        # Wait for expiration
        time.sleep(0.5)

        # Clear session cache to force DB check
        self.cache.session.clear()

        # Should be expired and removed
        self.assertIsNone(self.cache.get("test", "expired_key"))
        self.assertEqual(self.cache.stats["expired"], 1)

    def test_disabled_persistence(self):
        """Test behavior when persistence is disabled."""
        cache_disabled = CacheManager(cache_file=self.cache_path, enabled=False)

        cache_disabled.set("test", "no_persist", "value")

        # Should be in session
        self.assertEqual(cache_disabled.get("test", "no_persist"), "value")

        # Should NOT be in DB (file might not even exist if init skipped, but let's check DB if it exists)
        if self.cache_path.exists():
            conn = sqlite3.connect(self.cache_path)
            cursor = conn.execute("SELECT value FROM cache WHERE category='test' AND key='no_persist'")
            row = cursor.fetchone()
            conn.close()
            self.assertIsNone(row)

    def test_host_deduplication(self):
        """Test dual-homed host deduplication tracking with atomic operation."""
        # First call should succeed (was_first=True)
        was_first, previous = self.cache.try_mark_host_processed("DC.domain.lab", "192.168.1.10")
        self.assertTrue(was_first)
        self.assertIsNone(previous)
        
        # Second call with same host but different IP should fail (was_first=False)
        was_first, previous = self.cache.try_mark_host_processed("DC.domain.lab", "192.168.1.11")
        self.assertFalse(was_first)
        self.assertEqual(previous, "192.168.1.10")
        
        # Case-insensitive check
        was_first, previous = self.cache.try_mark_host_processed("dc.DOMAIN.LAB", "10.0.0.1")
        self.assertFalse(was_first)
        self.assertEqual(previous, "192.168.1.10")
        
        # Different host should succeed
        was_first, previous = self.cache.try_mark_host_processed("SERVER.domain.lab", "192.168.1.20")
        self.assertTrue(was_first)
        self.assertIsNone(previous)
        
    def test_host_deduplication_multiple_hosts(self):
        """Test that multiple hosts are tracked independently."""
        # Mark all hosts - all should be first
        w1, _ = self.cache.try_mark_host_processed("DC.domain.lab", "192.168.1.10")
        w2, _ = self.cache.try_mark_host_processed("SERVER.domain.lab", "192.168.1.20")
        w3, _ = self.cache.try_mark_host_processed("WS01.domain.lab", "10.0.0.5")
        
        self.assertTrue(w1)
        self.assertTrue(w2)
        self.assertTrue(w3)
        
        # Re-mark should all fail with original targets
        w1, p1 = self.cache.try_mark_host_processed("DC.domain.lab", "10.10.10.1")
        w2, p2 = self.cache.try_mark_host_processed("SERVER.domain.lab", "10.10.10.2")
        w3, p3 = self.cache.try_mark_host_processed("WS01.domain.lab", "10.10.10.3")
        
        self.assertFalse(w1)
        self.assertFalse(w2)
        self.assertFalse(w3)
        self.assertEqual(p1, "192.168.1.10")
        self.assertEqual(p2, "192.168.1.20")
        self.assertEqual(p3, "10.0.0.5")

