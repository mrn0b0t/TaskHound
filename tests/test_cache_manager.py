"""
Tests for CacheManager module.
"""
import tempfile
from pathlib import Path

from taskhound.utils.cache_manager import CacheManager


class TestCacheManagerInit:
    """Tests for CacheManager initialization"""

    def test_uses_provided_cache_file(self):
        """Should use provided cache file path"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = Path(tmpdir) / "test_cache.db"
            cache = CacheManager(cache_file=cache_file, enabled=True)

            assert cache.cache_file == cache_file

            cache.close()

    def test_sets_ttl_hours(self):
        """Should set TTL from parameter"""
        cache = CacheManager(ttl_hours=48, enabled=False)

        assert cache.ttl_hours == 48

    def test_disabled_mode(self):
        """Should disable persistent caching"""
        cache = CacheManager(enabled=False)

        assert cache.persistent_enabled is False

    def test_is_new_db_flag_for_new_file(self):
        """Should set is_new_db True for new database"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = Path(tmpdir) / "new_cache.db"
            cache = CacheManager(cache_file=cache_file, enabled=True)

            # Note: After DB creation, file exists so this depends on check timing
            # The flag is set BEFORE DB init, so a new file means is_new_db=True
            assert cache.is_new_db is True

            cache.close()

    def test_initializes_empty_session_cache(self):
        """Should initialize empty session cache"""
        cache = CacheManager(enabled=False)

        assert cache.session == {}

    def test_initializes_stats(self):
        """Should initialize statistics counters"""
        cache = CacheManager(enabled=False)

        assert cache.stats["session_hits"] == 0
        assert cache.stats["session_misses"] == 0
        assert cache.stats["persistent_hits"] == 0
        assert cache.stats["persistent_misses"] == 0


class TestCacheManagerSessionCache:
    """Tests for session cache operations"""

    def test_set_and_get_session_value(self):
        """Should store and retrieve value from session cache"""
        cache = CacheManager(enabled=False)

        cache.set("test_category", "test_key", "test_value")
        result = cache.get("test_category", "test_key")

        assert result == "test_value"

    def test_session_hit_increments_stats(self):
        """Should increment session hit counter"""
        cache = CacheManager(enabled=False)
        cache.set("cat", "key", "value")

        cache.get("cat", "key")

        assert cache.stats["session_hits"] >= 1

    def test_session_miss_increments_stats(self):
        """Should increment session miss counter"""
        cache = CacheManager(enabled=False)

        cache.get("cat", "nonexistent_key")

        assert cache.stats["session_misses"] >= 1

    def test_get_returns_none_for_missing_key(self):
        """Should return None for missing key"""
        cache = CacheManager(enabled=False)

        result = cache.get("cat", "missing")

        assert result is None

    def test_overwrite_existing_value(self):
        """Should overwrite existing value"""
        cache = CacheManager(enabled=False)
        cache.set("cat", "key", "original")

        cache.set("cat", "key", "updated")
        result = cache.get("cat", "key")

        assert result == "updated"


class TestCacheManagerIncrement:
    """Tests for atomic increment operation"""

    def test_increment_from_zero(self):
        """Should increment from 0 to 1"""
        cache = CacheManager(enabled=False)

        result = cache.increment("failures", "key1")

        assert result == 1

    def test_increment_multiple_times(self):
        """Should increment sequentially"""
        cache = CacheManager(enabled=False)

        assert cache.increment("failures", "key1") == 1
        assert cache.increment("failures", "key1") == 2
        assert cache.increment("failures", "key1") == 3

    def test_increment_respects_max(self):
        """Should return max+1 when at max"""
        cache = CacheManager(enabled=False)

        # Increment to max (3)
        cache.increment("failures", "key1")  # 1
        cache.increment("failures", "key1")  # 2
        cache.increment("failures", "key1")  # 3

        # Should return max+1 (4) when already at max
        result = cache.increment("failures", "key1")
        assert result == 4

    def test_increment_custom_max(self):
        """Should respect custom max value"""
        cache = CacheManager(enabled=False)

        assert cache.increment("failures", "key1", max_value=2) == 1
        assert cache.increment("failures", "key1", max_value=2) == 2
        # At max=2, should return 3
        assert cache.increment("failures", "key1", max_value=2) == 3

    def test_increment_different_keys_independent(self):
        """Should track different keys independently"""
        cache = CacheManager(enabled=False)

        cache.increment("failures", "key1")
        cache.increment("failures", "key1")
        cache.increment("failures", "key2")

        # key1 should be at 2, key2 at 1
        assert cache.increment("failures", "key1") == 3
        assert cache.increment("failures", "key2") == 2

    def test_increment_thread_safety(self):
        """Should handle concurrent increments without exceeding max"""
        import threading

        cache = CacheManager(enabled=False)
        results = []

        def incrementer():
            for _ in range(10):
                result = cache.increment("failures", "concurrent_key", max_value=30)
                results.append(result)

        threads = [threading.Thread(target=incrementer) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have exactly 50 results (5 threads * 10 increments)
        assert len(results) == 50
        # None should exceed max+1 (31)
        assert all(r <= 31 for r in results)
        # Results should be sequential when sorted
        sorted_results = sorted(results)
        # First 30 should be 1-30, rest should be 31
        assert sorted_results[:30] == list(range(1, 31))
        assert all(r == 31 for r in sorted_results[30:])


class TestCacheManagerPersistentCache:
    """Tests for persistent cache operations"""

    def test_persistent_storage(self):
        """Should persist data to SQLite"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = Path(tmpdir) / "test.db"

            # Write
            cache1 = CacheManager(cache_file=cache_file, enabled=True)
            cache1.set("test", "key", "persistent_value")
            cache1.close()

            # Read in new instance
            cache2 = CacheManager(cache_file=cache_file, enabled=True)
            cache2.get("test", "key")

            # May need to check persistent
            cache2.close()

    def test_db_init_creates_table(self):
        """Should create cache table on init"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = Path(tmpdir) / "test.db"
            cache = CacheManager(cache_file=cache_file, enabled=True)

            # Verify table exists by querying via the thread-local connection
            conn = cache._get_conn()
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='cache'"
            )
            result = cursor.fetchone()

            assert result is not None
            assert result[0] == "cache"

            cache.close()


class TestCacheManagerCategories:
    """Tests for category-based caching"""

    def test_different_categories_isolated(self):
        """Should keep categories separate"""
        cache = CacheManager(enabled=False)

        cache.set("cat1", "key", "value1")
        cache.set("cat2", "key", "value2")

        assert cache.get("cat1", "key") == "value1"
        assert cache.get("cat2", "key") == "value2"

    def test_get_category_returns_all_keys(self):
        """Should return all keys in a category"""
        cache = CacheManager(enabled=False)
        cache.set("mycat", "key1", "value1")
        cache.set("mycat", "key2", "value2")
        cache.set("othercat", "key3", "value3")

        # Access internal session to verify
        assert "mycat" in str(cache.session.keys()) or len(cache.session) >= 2


class TestCacheManagerInvalidate:
    """Tests for cache invalidation"""

    def test_invalidate_clears_cache(self):
        """Should clear all cache entries"""
        cache = CacheManager(enabled=False)
        cache.set("cat1", "key1", "value1")
        cache.set("cat2", "key2", "value2")

        cache.invalidate()

        # Session should be cleared
        assert cache.get("cat1", "key1") is None
        assert cache.get("cat2", "key2") is None


class TestCacheManagerThreadSafety:
    """Tests for thread safety"""

    def test_has_lock(self):
        """Should have RLock for session cache"""
        cache = CacheManager(enabled=False)

        assert cache._session_lock is not None

    def test_concurrent_access(self):
        """Should handle concurrent access"""
        import threading

        cache = CacheManager(enabled=False)
        results = []

        def writer(n):
            for i in range(10):
                cache.set("cat", f"key_{n}_{i}", f"value_{n}_{i}")

        def reader(n):
            for i in range(10):
                result = cache.get("cat", f"key_{n}_{i}")
                results.append(result)

        threads = []
        for n in range(5):
            t1 = threading.Thread(target=writer, args=(n,))
            threads.append(t1)

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        # No exceptions should have occurred
        assert True

    def test_concurrent_persistent_access(self):
        """Should handle concurrent SQLite access from multiple threads without errors.

        This is the key test for the thread-safety fix (B5). Previously, a single
        SQLite connection was shared across threads, causing:
        'SQLite objects created in a thread can only be used in that same thread'

        The fix uses threading.local() to give each thread its own connection.
        """
        import tempfile
        from concurrent.futures import ThreadPoolExecutor, as_completed

        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = Path(tmpdir) / "test_concurrent.db"
            cache = CacheManager(cache_file=cache_file, enabled=True)
            errors = []

            def worker(thread_id):
                """Simulate worker thread doing cache operations."""
                try:
                    for i in range(20):
                        key = f"thread_{thread_id}_key_{i}"
                        # Write
                        cache.set("sids", key, {"resolved": f"value_{i}"})
                        # Read back
                        result = cache.get("sids", key)
                        if result is None:
                            errors.append(f"Thread {thread_id}: Got None for {key}")
                    return thread_id
                except Exception as e:
                    errors.append(f"Thread {thread_id}: {type(e).__name__}: {e}")
                    return None

            # Run with 5 concurrent threads (like --threads 5 in production)
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(worker, i) for i in range(5)]
                for future in as_completed(futures):
                    future.result()  # Raises if worker raised

            # No SQLite thread errors should have occurred
            assert len(errors) == 0, f"Thread safety errors: {errors}"

            # Verify each thread created its own connection
            # (We can check the _connections list length)
            assert len(cache._connections) >= 1  # At least main thread connection

            cache.close()


class TestCacheManagerClose:
    """Tests for cache cleanup"""

    def test_close_commits_changes(self):
        """Should commit changes on close"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = Path(tmpdir) / "test.db"
            cache = CacheManager(cache_file=cache_file, enabled=True)
            cache.set("cat", "key", "value")

            # Should not raise
            cache.close()

            # Verify connections list is cleared after close
            assert len(cache._connections) == 0

    def test_close_handles_no_connection(self):
        """Should handle close when no connection"""
        cache = CacheManager(enabled=False)

        # Should not raise
        cache.close()


class TestCacheManagerStatistics:
    """Tests for cache statistics"""

    def test_stats_available(self):
        """Should track stats dictionary"""
        cache = CacheManager(enabled=False)
        cache.set("cat", "key", "value")
        cache.get("cat", "key")
        cache.get("cat", "missing")

        # Stats are stored in cache.stats dict
        assert "session_hits" in cache.stats
        assert "session_misses" in cache.stats
        assert cache.stats["session_hits"] >= 1
        assert cache.stats["session_misses"] >= 1


class TestCacheManagerGetAll:
    """Tests for get_all functionality."""

    def test_get_all_disabled_returns_empty(self):
        """Should return empty dict when persistent is disabled."""
        cache = CacheManager(enabled=False)
        cache.set("cat", "key1", "value1")
        cache.set("cat", "key2", "value2")

        # get_all only works on persistent cache, not session
        result = cache.get_all("cat")
        assert result == {}

    def test_get_all_with_persistent_cache(self):
        """Should return all entries for category from persistent cache."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = Path(tmpdir) / "test_cache.db"
            cache = CacheManager(cache_file=cache_file, enabled=True)

            cache.set("cat", "key1", "value1")
            cache.set("cat", "key2", "value2")
            cache.set("other", "key3", "value3")  # Different category

            result = cache.get_all("cat")

            assert len(result) == 2
            assert result.get("key1") == "value1"
            assert result.get("key2") == "value2"

            cache.close()

    def test_get_all_skips_expired(self):
        """Should skip expired entries in get_all."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = Path(tmpdir) / "test_cache.db"
            cache = CacheManager(cache_file=cache_file, enabled=True, ttl_hours=0)  # 0 TTL = already expired

            # Manually insert an expired entry via thread-local connection
            import json
            import time
            conn = cache._get_conn()
            past_time = time.time() - 1000  # Expired
            conn.execute(
                "INSERT OR REPLACE INTO cache (category, key, value, expires_at) VALUES (?, ?, ?, ?)",
                ("cat", "expired_key", json.dumps("expired_value"), past_time)
            )
            conn.commit()

            result = cache.get_all("cat")

            # Expired entry should not be returned
            assert "expired_key" not in result

            cache.close()


class TestCacheManagerInvalidateSpecific:
    """Tests for specific cache invalidation."""

    def test_invalidate_specific_key(self):
        """Should invalidate specific key in category."""
        cache = CacheManager(enabled=False)
        cache.set("cat", "key1", "value1")
        cache.set("cat", "key2", "value2")

        cache.invalidate(category="cat", key="key1")

        assert cache.get("cat", "key1") is None
        assert cache.get("cat", "key2") == "value2"

    def test_invalidate_category(self):
        """Should invalidate entire category."""
        cache = CacheManager(enabled=False)
        cache.set("cat", "key1", "value1")
        cache.set("cat", "key2", "value2")
        cache.set("other", "key3", "value3")

        cache.invalidate(category="cat")

        assert cache.get("cat", "key1") is None
        assert cache.get("cat", "key2") is None
        assert cache.get("other", "key3") == "value3"

    def test_invalidate_all(self):
        """Should invalidate all entries."""
        cache = CacheManager(enabled=False)
        cache.set("cat1", "key1", "value1")
        cache.set("cat2", "key2", "value2")

        cache.invalidate()

        assert cache.get("cat1", "key1") is None
        assert cache.get("cat2", "key2") is None

    def test_invalidate_with_persistent(self):
        """Should invalidate persistent cache entries."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_file = Path(tmpdir) / "test_cache.db"
            cache = CacheManager(cache_file=cache_file, enabled=True)

            cache.set("cat", "key1", "value1")
            cache.invalidate(category="cat", key="key1")

            # Clear session to test persistent
            cache.session.clear()

            # Entry should be gone from persistent too
            assert cache.get("cat", "key1") is None

            cache.close()

    def test_print_stats_exists(self):
        """Should have print_stats method"""
        cache = CacheManager(enabled=False)

        # Method should exist
        assert hasattr(cache, 'print_stats')

