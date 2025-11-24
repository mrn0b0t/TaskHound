"""
Session-level and persistent caching for TaskHound using SQLite.

This module provides a three-tier caching system:
1. Session cache (in-memory, single run)
2. Persistent cache (SQLite database, across runs)
3. Live queries (fallback)
"""

import contextlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Optional

from ..utils.logging import debug, info, warn


class CacheManager:
    """
    Manages session and persistent caching for TaskHound using SQLite.

    Thread-safe via SQLite's internal locking.
    """

    def __init__(self, cache_file: Optional[Path] = None, ttl_hours: int = 24, enabled: bool = True):
        """
        Initialize cache manager.

        Args:
            cache_file: Path to persistent cache DB (default: ~/.taskhound/cache.db)
            ttl_hours: Default TTL for new entries (hours)
            enabled: Enable persistent caching (session cache always active)
        """
        self.ttl_hours = ttl_hours
        self.persistent_enabled = enabled
        self.conn = None

        # Default cache location
        if cache_file is None:
            cache_dir = Path.home() / ".taskhound"
            cache_dir.mkdir(parents=True, exist_ok=True)
            cache_file = cache_dir / "cache.db"

        self.cache_file = cache_file
        self.is_new_db = not cache_file.exists() if cache_file else True

        # Tier 1: Session cache (in-memory, cleared on exit)
        self.session: Dict[str, Any] = {}

        # Statistics for reporting
        self.stats = {
            "session_hits": 0,
            "session_misses": 0,
            "persistent_hits": 0,
            "persistent_misses": 0,
            "expired": 0,
        }

        # Initialize persistent cache if enabled
        if self.persistent_enabled:
            self._init_db()

    def _init_db(self):
        """Initialize SQLite database and schema."""
        try:
            self.conn = sqlite3.connect(self.cache_file, timeout=10.0)
            # Enable WAL mode for better concurrency
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")

            # Create table if not exists
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    category TEXT,
                    key TEXT,
                    value TEXT,
                    expires_at REAL,
                    PRIMARY KEY (category, key)
                )
            """)

            # Create index for expiration cleanup
            self.conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_expires_at ON cache(expires_at)
            """)

            self.conn.commit()

            # Opportunistic cleanup of expired entries (1% chance on init to avoid thundering herd)
            # Or just do it always since it's fast with an index
            self._prune_expired()

        except Exception as e:
            warn(f"Failed to initialize cache database: {e}")
            self.persistent_enabled = False

    def _prune_expired(self):
        """Remove expired entries from database."""
        if not self.conn:
            return

        try:
            now = time.time()
            cursor = self.conn.execute("DELETE FROM cache WHERE expires_at < ?", (now,))
            if cursor.rowcount > 0:
                debug(f"Pruned {cursor.rowcount} expired cache entries")
                self.stats["expired"] += cursor.rowcount
            self.conn.commit()
        except Exception as e:
            debug(f"Error pruning cache: {e}")

    def get(self, category: str, key: str) -> Optional[Any]:
        """
        Get cached value (checks session first, then persistent).

        Args:
            category: Cache category ("computers", "users", "sids")
            key: Cache key (e.g., "DC.CORP.LOCAL", "S-1-5-21-...", etc.)

        Returns:
            Cached value or None if miss/expired
        """
        # Tier 1: Check session cache first (fastest)
        session_key = f"{category}:{key}"
        if session_key in self.session:
            self.stats["session_hits"] += 1
            debug(f"Cache hit (session): {category}:{key}")
            return self.session[session_key]

        self.stats["session_misses"] += 1

        # Tier 2: Check persistent cache
        if self.persistent_enabled and self.conn:
            try:
                now = time.time()
                cursor = self.conn.execute(
                    "SELECT value, expires_at FROM cache WHERE category=? AND key=?", (category, key)
                )
                row = cursor.fetchone()

                if row:
                    value_json, expires_at = row

                    # Check expiration
                    if expires_at < now:
                        debug(f"Cache expired: {category}:{key}")
                        self.stats["expired"] += 1
                        # Lazy delete
                        self.conn.execute("DELETE FROM cache WHERE category=? AND key=?", (category, key))
                        self.conn.commit()
                        return None

                    # Valid hit
                    try:
                        value = json.loads(value_json)
                        self.stats["persistent_hits"] += 1
                        debug(f"Cache hit (persistent): {category}:{key}")

                        # Promote to session cache
                        self.session[session_key] = value
                        return value
                    except json.JSONDecodeError:
                        warn(f"Corrupt cache entry: {category}:{key}")
                        return None
            except Exception as e:
                debug(f"Cache read error: {e}")

        self.stats["persistent_misses"] += 1
        return None

    def set(self, category: str, key: str, value: Any, ttl_hours: Optional[int] = None):
        """
        Store value in both session and persistent caches.

        Args:
            category: Cache category ("computers", "users", "sids")
            key: Cache key
            value: Value to store (must be JSON serializable)
            ttl_hours: Override default TTL (optional)
        """
        session_key = f"{category}:{key}"

        # Always store in session cache
        self.session[session_key] = value

        # Store in persistent cache if enabled
        if self.persistent_enabled and self.conn:
            try:
                ttl = ttl_hours if ttl_hours is not None else self.ttl_hours
                expires_at = time.time() + (ttl * 3600)
                value_json = json.dumps(value)

                self.conn.execute(
                    "INSERT OR REPLACE INTO cache (category, key, value, expires_at) VALUES (?, ?, ?, ?)",
                    (category, key, value_json, expires_at),
                )
                self.conn.commit()
                debug(f"Cache store: {category}:{key}")
            except Exception as e:
                debug(f"Cache write error: {e}")

    def delete(self, category: str, key: str):
        """
        Remove value from both session and persistent caches.

        Args:
            category: Cache category
            key: Cache key
        """
        session_key = f"{category}:{key}"

        # Remove from session cache
        if session_key in self.session:
            del self.session[session_key]

        # Remove from persistent cache
        if self.persistent_enabled and self.conn:
            try:
                self.conn.execute("DELETE FROM cache WHERE category=? AND key=?", (category, key))
                self.conn.commit()
            except Exception as e:
                debug(f"Cache delete error: {e}")

    def invalidate(self, category: Optional[str] = None, key: Optional[str] = None):
        """
        Invalidate cache entries.

        Args:
            category: If provided, invalidate entire category
            key: If provided (with category), invalidate specific entry
                 If category is None, invalidates from all categories
        """
        # Clear session cache
        if category is None and key is None:
            self.session.clear()
        elif category is not None and key is None:
            self.session = {k: v for k, v in self.session.items() if not k.startswith(f"{category}:")}
        elif category is not None and key is not None:
            session_key = f"{category}:{key}"
            self.session.pop(session_key, None)

        # Clear persistent cache
        if self.persistent_enabled and self.conn:
            try:
                if category is None and key is None:
                    self.conn.execute("DELETE FROM cache")
                    info("Cache cleared (all entries)")
                elif category is not None and key is None:
                    self.conn.execute("DELETE FROM cache WHERE category=?", (category,))
                    info(f"Cache cleared (category: {category})")
                elif category is not None and key is not None:
                    self.conn.execute("DELETE FROM cache WHERE category=? AND key=?", (category, key))
                    debug(f"Cache invalidated: {category}:{key}")

                self.conn.commit()
            except Exception as e:
                warn(f"Cache invalidation error: {e}")

    def close(self):
        """Close database connection."""
        if self.conn:
            with contextlib.suppress(Exception):
                self.conn.close()
            self.conn = None

    def print_stats(self):
        """Print cache performance statistics."""
        total_requests = self.stats["session_hits"] + self.stats["session_misses"]

        if total_requests == 0:
            info("Cache: No requests made")
            return

        session_hit_rate = (self.stats["session_hits"] / total_requests) * 100
        persistent_hit_rate = (self.stats["persistent_hits"] / total_requests) * 100

        info("Cache Statistics:")
        info(f"  Session hits: {self.stats['session_hits']} ({session_hit_rate:.1f}%)")
        info(f"  Persistent hits: {self.stats['persistent_hits']} ({persistent_hit_rate:.1f}%)")
        info(f"  Misses: {self.stats['persistent_misses']}")
        info(f"  Expired: {self.stats['expired']}")

        if self.persistent_enabled and self.conn:
            try:
                cursor = self.conn.execute("SELECT COUNT(*) FROM cache")
                total_cached = cursor.fetchone()[0]
                info(f"  Persistent cache size: {total_cached} entries")
            except Exception:
                pass


# Global cache instance
_cache: Optional[CacheManager] = None


def get_cache() -> Optional[CacheManager]:
    """Get global cache instance."""
    return _cache


def init_cache(ttl_hours: int = 24, enabled: bool = True, cache_file: Optional[Path] = None):
    """Initialize global cache instance."""
    global _cache
    _cache = CacheManager(cache_file=cache_file, ttl_hours=ttl_hours, enabled=enabled)
    return _cache
