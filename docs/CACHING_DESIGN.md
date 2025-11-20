# TaskHound Caching System Design
**Version:** 1.0  
**Created:** November 19, 2025  
**Status:** 🔵 BRAINSTORM - Not Yet Implemented  
**Roadmap Reference:** ROADMAP_BATTLEPLAN.md Phase 1.2

---

## 🎯 Executive Summary

This document outlines the comprehensive caching strategy for TaskHound to dramatically improve performance in multi-host/multi-run scenarios. The design implements a **three-tier caching hierarchy** that balances speed, persistence, and accuracy.

**Key Goals:**
1. **Runtime deduplication**: Don't query the same SID/node multiple times in a single run
2. **Persistent caching**: Reuse lookups across runs (with TTL expiration)
3. **Selective invalidation**: Re-query stale data while keeping fresh entries
4. **Minimal complexity**: Simple JSON storage, no database overhead

**Performance Impact Estimate:**
- First run (cold cache): 0% improvement (baseline)
- Second run (warm cache): 60-80% faster (node lookups only)
- Rescanning same host <24h: 90%+ faster (full cache hit)
- Large environments (100+ hosts): Savings compound exponentially

---

## 📊 Current Performance Bottlenecks

### Problem 1: Runtime Duplication
**Scenario:** Host has 10 tasks, all running as `DOMAIN\Administrator`

**Current Behavior:**
```
Task 1: resolve_sid("DOMAIN\Administrator") → LDAP query (200ms)
Task 2: resolve_sid("DOMAIN\Administrator") → LDAP query (200ms)
Task 3: resolve_sid("DOMAIN\Administrator") → LDAP query (200ms)
...
Total: 10 × 200ms = 2000ms wasted on duplicate queries
```

**Root Cause:** No in-memory deduplication within a single run

---

### Problem 2: OpenGraph Node Resolution Duplication
**Scenario:** 50 hosts all have tasks running as same 3 domain users

**Current Behavior:**
```python
# taskhound/output/opengraph.py:resolve_object_ids_chunked()
computer_names = {"DC1.CORP.LOCAL", "DC2.CORP.LOCAL", ...}  # 50 hosts
user_names = {"ADMIN@CORP.LOCAL", "SERVICE@CORP.LOCAL", "BACKUP@CORP.LOCAL"}

# Chunks computers into groups of 10, queries BloodHound API
for chunk in _chunk_list(computer_names, chunk_size=10):
    # 5 API calls for 50 computers
    
# Queries all users (small set, but still API call)
for chunk in _chunk_list(user_names, chunk_size=10):
    # 1 API call for 3 users
```

**Impact:**
- 6 BloodHound API calls **every single run**
- Even if scanning same hosts repeatedly
- BloodHound API can be slow (200-500ms per query)
- Network latency adds up

**Root Cause:** No persistent cache of node ID lookups across runs

---

### Problem 3: Offline Mode SID Resolution
**Scenario:** Offline task analysis with LDAP available

**Current Behavior:**
```python
# taskhound/engine.py:_process_offline_host()
for task in tasks:
    display_runas, resolved = format_runas_with_sid_resolution(
        task["runas_user"], hv, domain, dc_ip, username, password, hashes, kerberos
    )
    # Every task triggers SID lookup, no deduplication
```

**Root Cause:** `format_runas_with_sid_resolution()` has no caching layer

---

## 🏗️ Proposed Architecture: Three-Tier Caching

```
┌─────────────────────────────────────────────────────────────┐
│                    TIER 1: SESSION CACHE                    │
│                    (In-Memory, Single Run)                  │
├─────────────────────────────────────────────────────────────┤
│  • Python dict: {key → value}                               │
│  • Cleared on exit                                          │
│  • Deduplicates within current run                          │
│  • No persistence                                           │
│                                                             │
│  Use Cases:                                                 │
│  - Same SID appears in 10 tasks → Only resolve once        │
│  - Dual-homed host scanned twice → Reuse first lookup      │
│                                                             │
│  Stored Data:                                               │
│  - SID → Username mappings                                  │
│  - Computer FQDN → (node_id, objectId) pairs               │
│  - User principal → (node_id, objectId) pairs               │
└─────────────────────────────────────────────────────────────┘
                            ↓ Cache Miss
┌─────────────────────────────────────────────────────────────┐
│                   TIER 2: PERSISTENT CACHE                  │
│                  (JSON File, Across Runs)                   │
├─────────────────────────────────────────────────────────────┤
│  • Location: ~/.taskhound/cache.json                        │
│  • TTL: 24 hours (configurable via --cache-ttl)            │
│  • Survives tool restarts                                  │
│  • Auto-prunes expired entries on load                     │
│                                                             │
│  Use Cases:                                                 │
│  - Daily scheduled scans → Reuse yesterday's lookups       │
│  - Re-scan failed host → Don't re-query BloodHound         │
│  - Large sweep → Save results for incremental follow-ups   │
│                                                             │
│  Stored Data:                                               │
│  {                                                          │
│    "computers": {                                           │
│      "DC.CORP.LOCAL": {                                     │
│        "node_id": "123",                                    │
│        "object_id": "S-1-5-21-...-1000",                    │
│        "timestamp": "2025-11-19T14:30:00Z",                 │
│        "ttl_hours": 24                                      │
│      }                                                      │
│    },                                                       │
│    "users": { ... },                                        │
│    "sids": { ... }  # SID → Username mappings              │
│  }                                                          │
└─────────────────────────────────────────────────────────────┘
                            ↓ Cache Miss or Expired
┌─────────────────────────────────────────────────────────────┐
│                TIER 3: LIVE QUERIES (Fallback)              │
├─────────────────────────────────────────────────────────────┤
│  • BloodHound API queries                                   │
│  • LDAP SID lookups                                         │
│  • SMB connection SID extraction                            │
│                                                             │
│  After successful query:                                    │
│  1. Store in Tier 1 (session cache)                         │
│  2. Store in Tier 2 (persistent cache)                      │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔧 Implementation Plan

### Phase 1: Session Cache (Runtime Deduplication)
**Goal:** Eliminate duplicate queries within a single run  
**Effort:** 2-3 hours  
**Priority:** 🔴 HIGH (Quick win, immediate impact)

#### 1.1 Create Cache Manager Class

**New File:** `taskhound/utils/cache_manager.py`

```python
"""
Session-level and persistent caching for TaskHound.

This module provides a three-tier caching system:
1. Session cache (in-memory, single run)
2. Persistent cache (JSON file, across runs)
3. Live queries (fallback)
"""

from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Tuple, Any
import json
from dataclasses import dataclass, asdict
from ..utils.logging import debug, info, warn


@dataclass
class CacheEntry:
    """Single cache entry with TTL tracking."""
    value: Any  # Could be str, tuple, dict, etc.
    timestamp: str  # ISO 8601 format
    ttl_hours: int = 24
    
    def is_expired(self) -> bool:
        """Check if entry has exceeded TTL."""
        entry_time = datetime.fromisoformat(self.timestamp)
        expiry_time = entry_time + timedelta(hours=self.ttl_hours)
        return datetime.now() > expiry_time
    
    def to_dict(self) -> dict:
        """Serialize for JSON storage."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict) -> 'CacheEntry':
        """Deserialize from JSON."""
        return cls(**data)


class CacheManager:
    """
    Manages session and persistent caching for TaskHound.
    
    Thread-safe for single-threaded use (future: add locks for async).
    """
    
    def __init__(
        self,
        cache_file: Optional[Path] = None,
        ttl_hours: int = 24,
        enabled: bool = True
    ):
        """
        Initialize cache manager.
        
        Args:
            cache_file: Path to persistent cache JSON (default: ~/.taskhound/cache.json)
            ttl_hours: Default TTL for new entries (hours)
            enabled: Enable persistent caching (session cache always active)
        """
        self.ttl_hours = ttl_hours
        self.persistent_enabled = enabled
        
        # Default cache location
        if cache_file is None:
            cache_dir = Path.home() / ".taskhound"
            cache_dir.mkdir(parents=True, exist_ok=True)
            cache_file = cache_dir / "cache.json"
        
        self.cache_file = cache_file
        
        # Tier 1: Session cache (in-memory, cleared on exit)
        self.session: Dict[str, Any] = {}
        
        # Tier 2: Persistent cache (loaded from disk, written on save)
        self.persistent: Dict[str, Dict[str, CacheEntry]] = {
            "computers": {},
            "users": {},
            "sids": {}
        }
        
        # Statistics for reporting
        self.stats = {
            "session_hits": 0,
            "session_misses": 0,
            "persistent_hits": 0,
            "persistent_misses": 0,
            "expired": 0
        }
        
        # Load persistent cache if enabled
        if self.persistent_enabled:
            self._load_persistent_cache()
    
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
        if self.persistent_enabled and category in self.persistent:
            if key in self.persistent[category]:
                entry = self.persistent[category][key]
                
                # Check if expired
                if entry.is_expired():
                    debug(f"Cache expired: {category}:{key} (age: {self._get_age_hours(entry)}h)")
                    self.stats["expired"] += 1
                    # Remove expired entry
                    del self.persistent[category][key]
                    return None
                
                # Valid hit - promote to session cache
                self.stats["persistent_hits"] += 1
                debug(f"Cache hit (persistent): {category}:{key}")
                self.session[session_key] = entry.value
                return entry.value
        
        self.stats["persistent_misses"] += 1
        return None
    
    def set(self, category: str, key: str, value: Any, ttl_hours: Optional[int] = None):
        """
        Store value in both session and persistent caches.
        
        Args:
            category: Cache category ("computers", "users", "sids")
            key: Cache key
            value: Value to store
            ttl_hours: Override default TTL (optional)
        """
        session_key = f"{category}:{key}"
        
        # Always store in session cache
        self.session[session_key] = value
        
        # Store in persistent cache if enabled
        if self.persistent_enabled:
            entry = CacheEntry(
                value=value,
                timestamp=datetime.now().isoformat(),
                ttl_hours=ttl_hours or self.ttl_hours
            )
            
            if category not in self.persistent:
                self.persistent[category] = {}
            
            self.persistent[category][key] = entry
            debug(f"Cache store: {category}:{key}")
    
    def invalidate(self, category: Optional[str] = None, key: Optional[str] = None):
        """
        Invalidate cache entries.
        
        Args:
            category: If provided, invalidate entire category
            key: If provided (with category), invalidate specific entry
                 If category is None, invalidates from all categories
        """
        if category is None and key is None:
            # Clear everything
            self.session.clear()
            for cat in self.persistent.keys():
                self.persistent[cat].clear()
            info("Cache cleared (all entries)")
        
        elif category is not None and key is None:
            # Clear entire category
            self.session = {k: v for k, v in self.session.items() if not k.startswith(f"{category}:")}
            if category in self.persistent:
                self.persistent[category].clear()
            info(f"Cache cleared (category: {category})")
        
        elif category is not None and key is not None:
            # Clear specific entry
            session_key = f"{category}:{key}"
            self.session.pop(session_key, None)
            if category in self.persistent:
                self.persistent[category].pop(key, None)
            debug(f"Cache invalidated: {category}:{key}")
    
    def save(self):
        """Persist cache to disk (call on exit)."""
        if not self.persistent_enabled:
            return
        
        try:
            # Convert CacheEntry objects to dicts for JSON
            serializable = {}
            for category, entries in self.persistent.items():
                serializable[category] = {
                    key: entry.to_dict() for key, entry in entries.items()
                }
            
            with open(self.cache_file, 'w') as f:
                json.dump(serializable, f, indent=2)
            
            total_entries = sum(len(entries) for entries in self.persistent.values())
            info(f"Cache saved: {total_entries} entries → {self.cache_file}")
        
        except Exception as e:
            warn(f"Failed to save cache: {e}")
    
    def _load_persistent_cache(self):
        """Load cache from disk (called on init)."""
        if not self.cache_file.exists():
            debug(f"No cache file found: {self.cache_file}")
            return
        
        try:
            with open(self.cache_file, 'r') as f:
                data = json.load(f)
            
            # Reconstruct CacheEntry objects
            for category, entries in data.items():
                self.persistent[category] = {
                    key: CacheEntry.from_dict(entry_dict)
                    for key, entry_dict in entries.items()
                }
            
            # Prune expired entries immediately
            self._prune_expired()
            
            total_entries = sum(len(entries) for entries in self.persistent.values())
            info(f"Cache loaded: {total_entries} entries from {self.cache_file}")
        
        except Exception as e:
            warn(f"Failed to load cache: {e}")
            # Reset to empty cache
            self.persistent = {"computers": {}, "users": {}, "sids": {}}
    
    def _prune_expired(self):
        """Remove expired entries from persistent cache."""
        pruned_count = 0
        
        for category in list(self.persistent.keys()):
            expired_keys = [
                key for key, entry in self.persistent[category].items()
                if entry.is_expired()
            ]
            
            for key in expired_keys:
                del self.persistent[category][key]
                pruned_count += 1
        
        if pruned_count > 0:
            debug(f"Pruned {pruned_count} expired cache entries")
    
    def _get_age_hours(self, entry: CacheEntry) -> float:
        """Calculate age of cache entry in hours."""
        entry_time = datetime.fromisoformat(entry.timestamp)
        age = datetime.now() - entry_time
        return age.total_seconds() / 3600
    
    def print_stats(self):
        """Print cache performance statistics."""
        total_requests = (
            self.stats["session_hits"] +
            self.stats["session_misses"]
        )
        
        if total_requests == 0:
            info("Cache: No requests made")
            return
        
        session_hit_rate = (self.stats["session_hits"] / total_requests) * 100
        persistent_hit_rate = (self.stats["persistent_hits"] / total_requests) * 100
        
        info(f"Cache Statistics:")
        info(f"  Session hits: {self.stats['session_hits']} ({session_hit_rate:.1f}%)")
        info(f"  Persistent hits: {self.stats['persistent_hits']} ({persistent_hit_rate:.1f}%)")
        info(f"  Misses: {self.stats['persistent_misses']}")
        info(f"  Expired: {self.stats['expired']}")
        
        total_cached = sum(len(entries) for entries in self.persistent.values())
        info(f"  Persistent cache size: {total_cached} entries")


# Global cache instance (initialized in cli.py)
_cache: Optional[CacheManager] = None


def get_cache() -> Optional[CacheManager]:
    """Get global cache instance."""
    return _cache


def init_cache(ttl_hours: int = 24, enabled: bool = True, cache_file: Optional[Path] = None):
    """Initialize global cache instance (called from cli.py)."""
    global _cache
    _cache = CacheManager(cache_file=cache_file, ttl_hours=ttl_hours, enabled=enabled)
    return _cache
```

---

#### 1.2 Integrate Cache into SID Resolution

**File:** `taskhound/utils/sid_resolver.py`

**Changes:**
```python
from .cache_manager import get_cache

def format_runas_with_sid_resolution(...):
    """Existing function - ADD caching layer"""
    
    # NEW: Check cache first
    cache = get_cache()
    if cache:
        cached_username = cache.get("sids", runas_user)
        if cached_username:
            debug(f"Using cached SID resolution: {runas_user} → {cached_username}")
            return cached_username, cached_username
    
    # EXISTING: Proceed with BloodHound/LDAP lookups
    ...
    
    # NEW: Store result in cache
    if cache and resolved_username:
        cache.set("sids", runas_user, resolved_username)
    
    return display_runas, resolved_username
```

---

#### 1.3 Integrate Cache into OpenGraph Node Resolution

**File:** `taskhound/output/opengraph.py`

**Changes:**
```python
from ..utils.cache_manager import get_cache

def resolve_object_ids_chunked(...):
    """Existing function - ADD caching layer"""
    
    cache = get_cache()
    
    # NEW: Check cache for computers
    if cache:
        cached_computers = {}
        uncached_computers = set()
        
        for hostname in computer_names:
            cached = cache.get("computers", hostname)
            if cached:
                cached_computers[hostname] = cached
                debug(f"Using cached computer: {hostname}")
            else:
                uncached_computers.add(hostname)
        
        # Only query BloodHound for uncached hosts
        computer_names = uncached_computers
    
    # EXISTING: Query BloodHound API for remaining computers
    ...
    
    # NEW: Store results in cache
    if cache:
        for hostname, (node_id, object_id) in computer_sid_map.items():
            cache.set("computers", hostname, (node_id, object_id))
    
    # Same pattern for users...
```

---

### Phase 2: CLI Integration & Configuration
**Effort:** 1-2 hours

#### 2.1 Add CLI Flags

**File:** `taskhound/config.py`

```python
# Add new argument group
cache_group = parser.add_argument_group("Caching Options")
cache_group.add_argument(
    "--cache-ttl",
    type=int,
    default=24,
    help="Cache TTL in hours (default: 24). Set to 0 to disable persistent cache."
)
cache_group.add_argument(
    "--no-cache",
    action="store_true",
    help="Disable persistent caching (session cache still active)"
)
cache_group.add_argument(
    "--clear-cache",
    action="store_true",
    help="Clear persistent cache before running"
)
cache_group.add_argument(
    "--cache-file",
    type=Path,
    help="Custom cache file location (default: ~/.taskhound/cache.json)"
)
cache_group.add_argument(
    "--cache-stats",
    action="store_true",
    help="Print detailed cache statistics after run"
)
```

---

#### 2.2 Initialize Cache in CLI

**File:** `taskhound/cli.py`

```python
from .utils.cache_manager import init_cache, get_cache

def main():
    args = parse_args()
    
    # Initialize cache early
    cache_enabled = not args.no_cache and args.cache_ttl > 0
    cache = init_cache(
        ttl_hours=args.cache_ttl,
        enabled=cache_enabled,
        cache_file=args.cache_file
    )
    
    # Handle --clear-cache
    if args.clear_cache:
        cache.invalidate()
        print("[*] Cache cleared")
    
    # ... existing code ...
    
    # Save cache on exit
    try:
        # ... run TaskHound ...
    finally:
        if cache:
            cache.save()
            if args.cache_stats:
                cache.print_stats()
```

---

### Phase 3: Advanced Features (Optional)
**Effort:** 2-3 hours

#### 3.1 Selective Cache Invalidation

**Use Case:** User knows a specific host changed, wants to re-query just that host

**CLI Flag:**
```python
parser.add_argument(
    "--invalidate-host",
    action="append",
    help="Invalidate cache for specific hostname (can specify multiple times)"
)
```

**Implementation:**
```python
if args.invalidate_host:
    for hostname in args.invalidate_host:
        cache.invalidate("computers", hostname)
        info(f"Invalidated cache for: {hostname}")
```

---

#### 3.2 Cache Export/Import

**Use Case:** Share cache with team, backup cache, transfer between machines

**CLI Flags:**
```python
parser.add_argument("--export-cache", type=Path, help="Export cache to JSON file")
parser.add_argument("--import-cache", type=Path, help="Import cache from JSON file")
```

---

#### 3.3 Cache Compression

**Use Case:** Large environments (1000+ hosts) produce big cache files

**Implementation:** Use gzip compression for cache file

```python
import gzip

def save(self):
    with gzip.open(f"{self.cache_file}.gz", 'wt') as f:
        json.dump(serializable, f, indent=2)
```

---

## 📈 Expected Performance Improvements

### Scenario 1: Single Host, Multiple Tasks
**Setup:** 1 host, 20 tasks, 5 unique users

**Before:**
- 20 SID lookups (duplicate resolution)
- Time: 20 × 200ms = 4000ms

**After (Session Cache):**
- 5 SID lookups (deduplicated)
- Time: 5 × 200ms = 1000ms
- **Improvement: 75% faster**

---

### Scenario 2: Daily Rescans
**Setup:** Scan 50 hosts every day

**Before:**
- Day 1: 50 hosts × 500ms (BloodHound query) = 25s
- Day 2: 50 hosts × 500ms = 25s
- Total: 50s

**After (Persistent Cache):**
- Day 1: 50 hosts × 500ms = 25s (cold cache)
- Day 2: 50 hosts × 0ms = 0s (cache hit, TTL not expired)
- Total: 25s
- **Improvement: 50% faster over 2 days**

---

### Scenario 3: Large Environment Sweep
**Setup:** Scan 500 hosts, many share same users (domain admins, service accounts)

**Before:**
- 500 hosts × 500ms (node lookup) = 250s
- 500 hosts × 10 tasks × 200ms (SID lookup) = 1000s
- Total: ~21 minutes

**After (Full Caching):**
- First run: 21 minutes (cold cache)
- Second run (same day): ~2 minutes (only new hosts/tasks)
- **Improvement: 90% faster on subsequent runs**

---

## 🔒 Cache Consistency & Safety

### TTL Strategy
**Default: 24 hours** - Balances freshness with performance

**Reasoning:**
- BloodHound data doesn't change frequently (computer/user nodes stable)
- Active Directory changes (password changes, account deletions) are rare
- Security: If account deleted, max 24h window before cache expires

**Configurable:** Use `--cache-ttl` to adjust for your environment
- High-security: `--cache-ttl 1` (1 hour)
- Stable environments: `--cache-ttl 168` (1 week)
- Testing: `--cache-ttl 0` (disable persistent cache)

---

### Cache Invalidation Triggers

**Automatic:**
1. TTL expiration (checked on load + every get)
2. Failed BloodHound queries (don't cache errors)
3. `--clear-cache` flag

**Manual:**
1. Delete `~/.taskhound/cache.json`
2. `--invalidate-host HOSTNAME` (selective)

---

### Stale Data Handling

**Q: What if cached node deleted from BloodHound?**  
**A:** BloodHound edge creation will fail gracefully. Next run after TTL expires will re-query and detect missing node.

**Q: What if user password changed?**  
**A:** SID mappings don't include passwords. Cache only stores username ↔ SID relationship, which doesn't change.

**Q: What if computer rejoins domain (new SID)?**  
**A:** Computer name → SID mapping will be stale. TTL expiration forces re-query. Consider shorter TTL for dynamic environments.

---

## 🧪 Testing Strategy

### Unit Tests
```python
# tests/test_cache_manager.py

def test_session_cache_hit():
    cache = CacheManager(enabled=False)  # Disable persistent
    cache.set("sids", "S-1-5-21-123", "Administrator")
    assert cache.get("sids", "S-1-5-21-123") == "Administrator"
    assert cache.stats["session_hits"] == 1

def test_persistent_cache_expiry():
    cache = CacheManager(ttl_hours=0)  # Immediate expiry
    cache.set("computers", "DC.CORP.LOCAL", ("123", "S-1-5-..."))
    time.sleep(1)
    assert cache.get("computers", "DC.CORP.LOCAL") is None
    assert cache.stats["expired"] == 1

def test_cache_promotion():
    # Store in persistent, retrieve (should promote to session)
    cache = CacheManager()
    cache.set("users", "admin@corp.local", ("42", "S-1-5-..."))
    cache.session.clear()  # Clear session
    
    value = cache.get("users", "admin@corp.local")
    assert value == ("42", "S-1-5-...")
    assert cache.stats["persistent_hits"] == 1
    
    # Second get should hit session
    value = cache.get("users", "admin@corp.local")
    assert cache.stats["session_hits"] == 1
```

---

### Integration Tests
```python
# tests/test_cache_integration.py

def test_opengraph_caching(live_config):
    """Verify OpenGraph node resolution uses cache"""
    # First run - should populate cache
    run_taskhound(["--bh-opengraph", ...])
    cache = get_cache()
    assert cache.stats["persistent_misses"] > 0
    
    # Second run - should hit cache
    cache.stats = reset_stats()
    run_taskhound(["--bh-opengraph", ...])
    assert cache.stats["persistent_hits"] > 0

def test_sid_resolution_caching():
    """Verify SID lookups are cached"""
    # Process same SID twice in one run
    sid = "S-1-5-21-123-456-789-500"
    resolve_sid(sid)  # Cold
    resolve_sid(sid)  # Should hit session cache
    
    cache = get_cache()
    assert cache.stats["session_hits"] >= 1
```

---

## 🚀 Migration Path

### Phase 1: Session Cache Only (Quick Win)
**Timeline:** Week 1  
**Effort:** 2-3 hours  
**Risk:** Low (no persistence, no breaking changes)

1. Implement `CacheManager` (session cache only)
2. Integrate into `sid_resolver.py`
3. Integrate into `opengraph.py`
4. Test thoroughly

**Outcome:** Immediate performance boost for multi-task hosts

---

### Phase 2: Persistent Cache (Major Win)
**Timeline:** Week 2  
**Effort:** 3-4 hours  
**Risk:** Low (opt-in with `--cache-ttl`, default enabled)

1. Add JSON persistence to `CacheManager`
2. Add CLI flags (`--cache-ttl`, `--no-cache`, etc.)
3. Add cache save/load logic in `cli.py`
4. Test cache expiry, TTL logic

**Outcome:** Dramatic speedup for rescans, daily operations

---

### Phase 3: Advanced Features (Optional)
**Timeline:** Week 3+  
**Effort:** 2-3 hours  
**Risk:** Low (nice-to-have features)

1. Selective invalidation
2. Cache export/import
3. Compression (if needed)

---

## 🎨 User Experience Examples

### Example 1: First Run (Cold Cache)
```bash
$ taskhound -u admin -p pass -d CORP.LOCAL -t DC01 --bh-opengraph

[*] Cache loaded: 0 entries from /Users/admin/.taskhound/cache.json
[*] Scanning DC01.CORP.LOCAL...
[*] Found 15 scheduled tasks
[*] Extracted 1 unique computer, 8 unique users
[*] Found 1 computer with SID from SMB connection
[*] Querying BloodHound for node IDs...
[*] Chunk 1/1: 1/1 computers resolved via API
[*] Chunk 1/1: 8/8 users resolved via API
[*] Created 30 relationships (HasTask + RunsAs)
[*] Cache saved: 9 entries → /Users/admin/.taskhound/cache.json

Cache Statistics:
  Session hits: 7 (46.7%)
  Persistent hits: 0 (0.0%)
  Misses: 8
  Expired: 0
  Persistent cache size: 9 entries
```

---

### Example 2: Second Run (Warm Cache)
```bash
$ taskhound -u admin -p pass -d CORP.LOCAL -t DC01 --bh-opengraph

[*] Cache loaded: 9 entries from /Users/admin/.taskhound/cache.json
[*] Scanning DC01.CORP.LOCAL...
[*] Found 15 scheduled tasks
[*] Extracted 1 unique computer, 8 unique users
[*] Using cached computer: DC01.CORP.LOCAL
[*] Using cached user: ADMIN@CORP.LOCAL
[*] Using cached user: SERVICE@CORP.LOCAL
... (all users cached)
[*] Skipped BloodHound queries (all nodes cached)
[*] Created 30 relationships (HasTask + RunsAs)
[*] Cache saved: 9 entries → /Users/admin/.taskhound/cache.json

Cache Statistics:
  Session hits: 7 (46.7%)
  Persistent hits: 9 (60.0%)  ← Much faster!
  Misses: 0
  Expired: 0
  Persistent cache size: 9 entries
```

---

### Example 3: Cache Expired After 24h
```bash
$ taskhound -u admin -p pass -d CORP.LOCAL -t DC01 --bh-opengraph

[*] Cache loaded: 9 entries from /Users/admin/.taskhound/cache.json
[*] Pruned 9 expired cache entries  ← TTL reached
[*] Scanning DC01.CORP.LOCAL...
[*] Querying BloodHound for node IDs... (re-querying)
...
```

---

### Example 4: Selective Invalidation
```bash
# User knows DC01 was rebuilt with new SID
$ taskhound --invalidate-host DC01.CORP.LOCAL -t DC01 --bh-opengraph

[*] Cache loaded: 9 entries from /Users/admin/.taskhound/cache.json
[*] Invalidated cache for: DC01.CORP.LOCAL
[*] Scanning DC01.CORP.LOCAL...
[*] Querying BloodHound for node IDs...
[*] Chunk 1/1: 1/1 computers resolved via API  ← Re-queried DC01
[*] Using cached user: ADMIN@CORP.LOCAL  ← Users still cached
...
```

---

## 📝 Configuration Examples

### Minimal (Defaults)
```bash
# Default: 24h TTL, persistent cache enabled
taskhound -t HOST --bh-opengraph
```

---

### High Security (Short TTL)
```bash
# Re-query every hour
taskhound -t HOST --bh-opengraph --cache-ttl 1
```

---

### Testing (No Persistent Cache)
```bash
# Session cache only, no file writes
taskhound -t HOST --bh-opengraph --no-cache
```

---

### Custom Cache Location
```bash
# Store cache in project directory
taskhound -t HOST --bh-opengraph --cache-file ./project_cache.json
```

---

### Detailed Diagnostics
```bash
# Print full cache statistics
taskhound -t HOST --bh-opengraph --cache-stats --debug
```

---

## 🔍 Alternative Approaches Considered

### Option 1: SQLite Database
**Pros:**
- Fast queries
- Proper indexing
- Concurrent access

**Cons:**
- Added dependency
- Overkill for simple key-value storage
- Harder to inspect/debug

**Verdict:** ❌ Too complex for current needs

---

### Option 2: Redis/Memcached
**Pros:**
- Very fast
- Built-in TTL
- Shared across processes

**Cons:**
- External dependency (requires server)
- Overkill for single-user tool
- Network overhead

**Verdict:** ❌ Not suitable for CLI tool

---

### Option 3: Pickle (Python serialization)
**Pros:**
- Native Python
- Can serialize complex objects

**Cons:**
- Security risk (arbitrary code execution)
- Not human-readable
- Version compatibility issues

**Verdict:** ❌ JSON is safer and more inspectable

---

### Option 4: No Persistent Cache (Session Only)
**Pros:**
- Simple
- No file I/O overhead
- No stale data issues

**Cons:**
- Loses all benefits of cross-run caching
- Daily scans still slow

**Verdict:** ❌ Persistent cache is core requirement

---

## ✅ Selected Approach: JSON + Three-Tier Caching
**Why:**
- Simple to implement and debug
- Human-readable (can inspect with `cat ~/.taskhound/cache.json`)
- No external dependencies
- Balances performance with complexity
- Extensible (can add compression/encryption later)

---

## 🎯 Success Metrics

### Performance Targets
- [ ] First run: Baseline (0% improvement)
- [ ] Second run (warm cache): 60-80% faster node lookups
- [ ] Rescanning same host <24h: 90%+ faster overall
- [ ] Session cache hit rate: >50% for multi-task hosts

### Code Quality Targets
- [ ] No breaking changes to existing functionality
- [ ] Comprehensive unit tests (>80% coverage for `cache_manager.py`)
- [ ] Clear logging (debug for cache hits, info for statistics)
- [ ] Graceful degradation (tool works if cache fails)

### User Experience Targets
- [ ] Cache transparent by default (no config needed)
- [ ] Clear statistics (`--cache-stats` shows impact)
- [ ] Easy troubleshooting (`--debug` shows cache operations)
- [ ] Flexible control (`--no-cache`, `--cache-ttl`, etc.)

---

## 📚 References

- **Original Roadmap:** `ROADMAP_BATTLEPLAN.md` Phase 1.2
- **Related Code:**
  - `taskhound/utils/sid_resolver.py` (SID lookup logic)
  - `taskhound/output/opengraph.py` (node resolution logic)
  - `taskhound/cli.py` (CLI entry point)
- **Similar Implementations:**
  - BloodHound.py (caches LDAP queries)
  - Impacket (caches Kerberos tickets)

---

## 🚧 Open Questions for Tomorrow

1. **Cache key format for users:** Use `USER@DOMAIN.TLD` or normalize to `DOMAIN\USER`?
   - **Recommendation:** Keep as-is from input to avoid normalization bugs

2. **Cache storage format for node tuples:** Store as `[node_id, object_id]` or `{"node_id": "...", "object_id": "..."}`?
   - **Recommendation:** Dict for clarity: `{"node_id": "123", "object_id": "S-1-5-..."}`

3. **Handle multi-domain environments:** Single cache file or per-domain?
   - **Recommendation:** Single file, key includes domain (e.g., `DC.CORP.LOCAL` vs `DC.CHILD.CORP.LOCAL`)

4. **Cache version migrations:** What if we change cache format in future version?
   - **Recommendation:** Add `"version": 1` field, handle upgrades gracefully

5. **Offline mode caching:** Should offline SID lookups be cached?
   - **Recommendation:** Yes, same cache, separate category: `"offline_sids"`

---

## 🎉 Conclusion

This three-tier caching design provides:
- ✅ **Immediate wins** (session cache deduplication)
- ✅ **Long-term benefits** (persistent cache across runs)
- ✅ **Low complexity** (simple JSON storage)
- ✅ **User control** (TTL, invalidation, disable flags)
- ✅ **Transparent operation** (works out-of-the-box)

**Estimated Total Effort:** 8-10 hours (matches roadmap estimate)  
**Risk Level:** Low (opt-in, graceful degradation)  
**Performance Impact:** 60-90% improvement in multi-run scenarios

Ready to implement tomorrow! 🚀
