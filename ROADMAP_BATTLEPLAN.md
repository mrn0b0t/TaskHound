# TaskHound Development Roadmap & Battle Plan
**Version:** 1.0  
**Created:** October 31, 2025  
**Status:** ✅ APPROVED - BLOCKED PENDING MERGE  
**Current Version:** 0.9.5 (post-OpenGraph integration)

> ⚠️ **IMPLEMENTATION HOLD**: This roadmap is approved but implementation is **BLOCKED** until the `feature/opengraph-integration` branch is merged to `main`. Do not begin work on any features in this document until the merge is complete.

---

## 🎯 Executive Summary

This roadmap outlines the development plan for TaskHound based on community feedback and real-world usage. The focus is on:
1. **Optimizing OpenGraph implementation** (performance, reliability, UX)
2. **Enhancing core logic** (SID resolution, error handling)
3. **Adding new offensive/defensive features** (LAPS, async processing, audit mode)
4. **Quality of life improvements** (colored output, better logging, refactoring)

**Estimated Total Effort:** 60-80 hours across 4 phases  
**Target Completion:** Q1 2026

---

## 📊 Priority Matrix

### 🔴 CRITICAL (Blockers / High Impact, Low Effort)
- OpenGraph: Switch from name matching to ID matching
- OpenGraph: Caching solution for node lookups
- OpenGraph: API Key authentication
- Core: Enhanced SID lookup chain

### 🟡 HIGH PRIORITY (High Impact, Medium Effort)
- OpenGraph: Allow orphaned nodes option
- Core: Include unreachable hosts in summary
- Feature: Asynchronous processing/multithreading
- Feature: OPSEC mode (disable noisy operations)
- Feature: LAPS support
- Feature: Cross-domain trust authentication
- QoL: Colored terminal output

### 🟢 MEDIUM PRIORITY (Nice to Have)
- OpenGraph: Shortened output with --verbose flag
- Feature: WMI-based password validation
- Feature: Automatic script file grabbing
- QoL: Refactoring (engine.py split, naming standardization)

### 🔵 LOW PRIORITY (Future Enhancements)
- Feature: Blue Team audit mode with HTML export
- OpenGraph: Abuse info & OPSEC notes
- Documentation: Extensive OpenGraph guide

---

## 🗺️ PHASE 1: OpenGraph Optimization (CRITICAL PATH)
> ⚠️ **BLOCKED**: Cannot begin until OpenGraph merge to main
**Goal:** Fix performance issues and improve reliability  
**Timeline:** 2-3 weeks  
**Estimated Effort:** 20-25 hours

### 1.1 Switch from Name Matching to ID Matching 🔴 CRITICAL
**Problem:** Current implementation uses name-based matching which is unreliable
**Solution:** Use BloodHound search API to find node ID (not objectid property!)

**Implementation Details:**
```python
# CURRENT (taskhound/output/opengraph.py):
Node(
    label="ScheduledTask",
    kind="ScheduledTask", 
    properties=Properties(
        name=task_name,  # ❌ Name-based matching
        ...
    )
)

# PROPOSED:
# 1. Query BloodHound search API to get node ID
node_id = search_bloodhound_for_node_id(computer_name, node_type="Computer")

# 2. Use ID in edge relationships
Edge(
    source=node_id,  # ✅ ID-based matching
    target=task_node_id,
    kind="HasTask"
)
```

**Tasks:**
- [ ] Research BloodHound search API endpoint structure
- [ ] Implement `search_node_by_name()` function in `output/bloodhound.py`
- [ ] Update `resolve_object_ids_chunked()` to use search API
- [ ] Add fallback to name-based if search fails
- [ ] Add `--prefer-name-matching` flag for backward compatibility
- [ ] Update OpenGraph file generation to use IDs
- [ ] Test with BHCE instance

**Files to Modify:**
- `taskhound/output/opengraph.py` (resolve_object_ids_chunked)
- `taskhound/output/bloodhound.py` (add search_node_by_name)
- `taskhound/config.py` (add --prefer-name-matching flag)

**Estimated Effort:** 6-8 hours

---

### 1.2 Implement Node Caching System 🔴 CRITICAL
**Problem:** Multiple API queries for the same nodes (e.g., dual-homed hosts)  
**Solution:** Multi-tier caching strategy

**Architecture:**
```
┌─────────────────────────────────────────┐
│  1. In-Memory Cache (current run)      │
│     - Hostname → Node ID mapping        │
│     - Deduplicates within single run    │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│  2. Persistent Cache (across runs)      │
│     - SQLite or JSON file               │
│     - Hostname, ObjectID, Node ID       │
│     - TTL: 24 hours (configurable)      │
└─────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────┐
│  3. BloodHound API (fallback)           │
│     - Only if cache miss                │
└─────────────────────────────────────────┘
```

**Implementation Details:**
```python
# taskhound/output/opengraph_cache.py (NEW FILE)
from functools import lru_cache
from pathlib import Path
import json
from datetime import datetime, timedelta

class OpenGraphNodeCache:
    """Caches BloodHound node lookups to minimize API calls"""
    
    def __init__(self, cache_file: Path = Path.home() / ".taskhound" / "node_cache.json"):
        self.cache_file = cache_file
        self.cache: Dict[str, CacheEntry] = {}
        self.session_cache: Dict[str, str] = {}  # In-memory only
        self._load_cache()
    
    @lru_cache(maxsize=1000)
    def get_node_id(self, hostname: str, object_id: str = None) -> Optional[str]:
        """Get cached node ID or None if cache miss"""
        # 1. Check session cache first (in-memory)
        if hostname in self.session_cache:
            return self.session_cache[hostname]
        
        # 2. Check persistent cache
        cache_key = f"{hostname}:{object_id}" if object_id else hostname
        if cache_key in self.cache:
            entry = self.cache[cache_key]
            if not entry.is_expired():
                self.session_cache[hostname] = entry.node_id
                return entry.node_id
        
        return None  # Cache miss
    
    def set_node_id(self, hostname: str, node_id: str, object_id: str = None):
        """Cache a node ID lookup result"""
        cache_key = f"{hostname}:{object_id}" if object_id else hostname
        self.session_cache[hostname] = node_id
        self.cache[cache_key] = CacheEntry(
            hostname=hostname,
            node_id=node_id,
            object_id=object_id,
            timestamp=datetime.now()
        )
    
    def save(self):
        """Persist cache to disk"""
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.cache_file, 'w') as f:
            json.dump({k: v.to_dict() for k, v in self.cache.items()}, f)
```

**Configuration:**
```ini
# bh_connector.config (new section)
[Cache]
enabled = true
ttl_hours = 24
cache_file = ~/.taskhound/node_cache.json
```

**Tasks:**
- [ ] Create `taskhound/output/opengraph_cache.py`
- [ ] Implement CacheEntry dataclass with TTL
- [ ] Add session-level deduplication (warn on duplicates)
- [ ] Add persistent cache (JSON file in ~/.taskhound/)
- [ ] Add cache statistics logging (hits/misses)
- [ ] Add `--clear-cache` flag to CLI
- [ ] Add `--no-cache` flag to disable caching
- [ ] Integrate into `resolve_object_ids_chunked()`

**Files to Create:**
- `taskhound/output/opengraph_cache.py`

**Files to Modify:**
- `taskhound/output/opengraph.py` (integrate cache)
- `taskhound/config.py` (add cache flags)
- `taskhound/config_model.py` (add cache config)

**Estimated Effort:** 8-10 hours

---

### 1.3 Allow Orphaned Nodes Option 🟡 HIGH
**Problem:** Tasks referencing non-existent users/computers fail ingestion  
**Solution:** Add `--allow-orphaned-nodes` flag

**Implementation Details:**
```python
# When creating edges, allow orphan nodes if flag is set
def _create_relationship_edges(task, computer_id, principal_id, allow_orphans=False):
    edges = []
    
    # Computer → Task edge
    if computer_id or allow_orphans:
        edges.append(Edge(
            source=computer_id or "UNKNOWN",  # Create orphan if needed
            target=task_id,
            kind="HasTask"
        ))
    
    # Task → User edge
    if principal_id or allow_orphans:
        edges.append(Edge(
            source=task_id,
            target=principal_id or "UNKNOWN",
            kind="RunsAs"
        ))
    
    return edges
```

**Tasks:**
- [ ] Add `--allow-orphaned-nodes` CLI flag
- [ ] Modify edge creation logic to handle None IDs when flag enabled
- [ ] Add warning log when orphan nodes are created
- [ ] Document orphan node risks in README
- [ ] Test with deleted user accounts

**Files to Modify:**
- `taskhound/output/opengraph.py` (_create_relationship_edges)
- `taskhound/config.py` (add flag)

**Estimated Effort:** 3-4 hours

---

### 1.4 API Key Authentication for BHCE 🔴 CRITICAL
**Problem:** Only username/password auth supported  
**Solution:** Support BHCE API keys

**Implementation Details:**
```python
# taskhound/config_model.py
@dataclass
class BloodHoundConfig:
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None  # NEW
    
    def get_auth_headers(self) -> Dict[str, str]:
        """Return appropriate auth headers"""
        if self.api_key:
            return {"Authorization": f"Bearer {self.api_key}"}
        else:
            # Use token-based auth
            token = self._get_token()
            return {"Authorization": f"Bearer {token}"}
```

**Configuration:**
```ini
# bh_connector.config
[BloodHound]
ip = 127.0.0.1
api_key = ${BH_API_KEY}  # From environment variable
type = bhce
```

**Tasks:**
- [ ] Add `api_key` field to BloodHoundConfig
- [ ] Add `--bh-api-key` CLI flag
- [ ] Modify authentication logic to prefer API key
- [ ] Update all API calls to use new auth headers
- [ ] Test with BHCE API key
- [ ] Document API key generation in README

**Files to Modify:**
- `taskhound/config_model.py`
- `taskhound/config.py`
- `taskhound/output/bloodhound.py`
- `taskhound/connectors/bloodhound.py`

**Estimated Effort:** 4-5 hours

---

### 1.5 Shortened Output Mode 🟡 HIGH
**Problem:** Too verbose during OpenGraph operations  
**Solution:** Concise output by default, `--verbose` for details

**Current Output:**
```
[*] Resolving Computer objectIds...
[+] Resolved DC01.domain.local → 8f3a2b...
[+] Resolved WS01.domain.local → 7e1c9d...
[*] Generating OpenGraph files...
[+] Created 150 task nodes
[+] Created 300 relationship edges
[+] Upload successful!
```

**Proposed Output (default):**
```
[OpenGraph] DC01.domain.local ✓
[OpenGraph] WS01.domain.local ✓
[OpenGraph] WS02.domain.local ✗ (Node not found)
[+] Generated OpenGraph: 150 tasks, 300 edges → Upload ✓
```

**Proposed Output (--verbose):**
```
[*] Resolving Computer objectIds for 3 hosts...
[+] DC01.domain.local → objectId: 8f3a2b..., nodeId: abc123
[+] WS01.domain.local → objectId: 7e1c9d..., nodeId: def456
[!] WS02.domain.local → Not found in BloodHound
[*] Generating OpenGraph files...
[+] Created 150 ScheduledTask nodes
[+] Created 300 relationship edges (150 HasTask, 150 RunsAs)
[*] Uploading to BloodHound CE...
[+] Upload successful! Job ID: 5f7e3a...
```

**Tasks:**
- [ ] Add `--verbose` flag to CLI
- [ ] Create progress indicator class (spinner or progress bar)
- [ ] Modify logging in opengraph.py to respect verbosity
- [ ] Use rich/colorama for cleaner output
- [ ] Add summary line at end

**Files to Modify:**
- `taskhound/output/opengraph.py`
- `taskhound/output/bloodhound.py`
- `taskhound/config.py`
- `requirements.txt` (add rich or colorama)

**Estimated Effort:** 3-4 hours

---

### 1.6 Add Abuse Info & OPSEC Notes 🔵 LOW
**Problem:** No guidance on exploiting discovered tasks  
**Solution:** Add metadata to OpenGraph nodes

**Implementation:**
```python
# Add to ScheduledTask properties
properties = Properties(
    name=task_name,
    # ... existing properties ...
    abuse_info="""
    1. Modify task executable path to malicious binary
    2. Hijack DLL loaded by task (if writable)
    3. Manipulate task arguments or environment variables
    4. Wait for next execution (check trigger schedule)
    """,
    opsec_notes="""
    - Task modifications logged in Security Event 4698/4702
    - Check if SIEM monitors ScheduledTask changes
    - Consider existing task EDR coverage
    - Backup original task XML before modification
    """,
    references=[
        "https://attack.mitre.org/techniques/T1053/005/",
        "https://www.elastic.co/guide/en/security/current/scheduled-task-created-by-a-suspicious-process.html"
    ]
)
```

**Tasks:**
- [ ] Research common scheduled task abuse techniques
- [ ] Create abuse_info template for different scenarios
- [ ] Add OPSEC considerations based on task properties
- [ ] Test if bhopengraph accepts custom properties
- [ ] Document in BloodHound UI

**Estimated Effort:** 4-5 hours

---

### 1.7 Extensive OpenGraph Documentation 🔵 LOW
**Goal:** Comprehensive guide for users

**Documentation Structure:**
```
docs/
└── opengraph/
    ├── README.md                  # Overview
    ├── SETUP.md                   # Installation & config
    ├── USAGE.md                   # CLI examples
    ├── CYPHER_QUERIES.md          # Useful Cypher queries
    ├── TROUBLESHOOTING.md         # Common issues
    └── ARCHITECTURE.md            # Technical deep dive
```

**Content to Include:**
- Setup guide (BHCE configuration, API keys)
- Usage examples with screenshots
- Cypher query collection for finding attack paths
- BloodHound UI navigation guide
- Troubleshooting common errors
- Performance tuning guide
- Integration with other tools

**Tasks:**
- [ ] Create docs/opengraph/ directory
- [ ] Write comprehensive setup guide
- [ ] Create Cypher query cookbook
- [ ] Add screenshots/diagrams
- [ ] Create video walkthrough (optional)

**Estimated Effort:** 8-10 hours

---

## 🗺️ PHASE 2: Core Logic Enhancements
**Goal:** Improve reliability and accuracy  
**Timeline:** 2-3 weeks  
**Estimated Effort:** 15-20 hours

### 2.1 Enhanced SID Lookup Chain 🔴 CRITICAL
**Current:** BloodHound Data → LDAP  
**Proposed:** BloodHound Data → Live BloodHound DB → LDAP

**Implementation:**
```python
# taskhound/utils/sid_resolver.py
def resolve_sid(sid: str, 
                hv_loader: Optional[HighValueLoader] = None,
                bh_connector: Optional[BloodHoundConnector] = None,
                ldap_conn: Optional[LDAPConnection] = None,
                no_ldap: bool = False) -> Optional[str]:
    """
    Resolve SID to username using cascading lookup strategy:
    1. Local BloodHound export data (fastest, offline)
    2. Live BloodHound database connection (fresh data)
    3. LDAP query (most authoritative, slowest)
    """
    
    # Level 1: Check local BloodHound data
    if hv_loader:
        username = resolve_sid_from_bloodhound_export(sid, hv_loader)
        if username:
            debug(f"Resolved {sid} via BloodHound export")
            return username
    
    # Level 2: Query live BloodHound database
    if bh_connector and bh_connector.is_connected():
        username = resolve_sid_from_live_bloodhound(sid, bh_connector)
        if username:
            info(f"Resolved {sid} via live BloodHound query")
            return username
    
    # Level 3: LDAP fallback
    if ldap_conn and not no_ldap:
        username = resolve_sid_from_ldap(sid, ldap_conn)
        if username:
            info(f"Resolved {sid} via LDAP")
            return username
    
    return None
```

**Tasks:**
- [ ] Add `resolve_sid_from_live_bloodhound()` function
- [ ] Implement Cypher query for SID lookup
- [ ] Add BloodHoundConnector instance to engine context
- [ ] Update all SID resolution calls to use new chain
- [ ] Add caching for resolved SIDs (LRU cache)
- [ ] Add metrics logging (source of resolution)

**Files to Modify:**
- `taskhound/utils/sid_resolver.py`
- `taskhound/engine.py`
- `taskhound/cli.py`

**Estimated Effort:** 6-8 hours

---

### 2.2 Include Unreachable Hosts in Summary 🟡 HIGH
**Problem:** Failed hosts silently disappear from summary  
**Solution:** Show them with "N/A [Unreachable]" status

**Current Summary:**
```
HOSTNAME                | TIER-0_TASKS | PRIVILEGED_TASKS | NORMAL_TASKS
------------------------------------------------------------------------
dc01.domain.local       | 2            | 5                | 10
```

**Proposed Summary:**
```
HOSTNAME                | TIER-0_TASKS | PRIVILEGED_TASKS | NORMAL_TASKS | STATUS
----------------------------------------------------------------------------------
dc01.domain.local       | 2            | 5                | 10           | ✓
ws01.domain.local       | N/A          | N/A              | N/A          | Unreachable (SMB)
ws02.domain.local       | N/A          | N/A              | N/A          | Unreachable (Auth Failed)
192.168.1.50            | N/A          | N/A              | N/A          | Unreachable (DNS Failed)
```

**Implementation:**
```python
# taskhound/engine.py
def process_target(...):
    try:
        # ... existing logic ...
    except SMBConnectionError as e:
        return {
            'hostname': target,
            'status': 'unreachable',
            'reason': 'SMB connection failed',
            'error': str(e),
            'tier0_tasks': 'N/A',
            'privileged_tasks': 'N/A',
            'normal_tasks': 'N/A'
        }
```

**LDAP FQDN Resolution:**
```python
# For IP addresses, resolve to FQDN via LDAP
if is_ipv4(target):
    fqdn = resolve_ip_to_fqdn_via_ldap(target, ldap_conn)
    if fqdn:
        hostname = fqdn
    else:
        hostname = target  # Keep IP if resolution fails
```

**Tasks:**
- [ ] Add error tracking to process_target()
- [ ] Create UnreachableHost dataclass
- [ ] Modify summary table to show unreachable hosts
- [ ] Add LDAP reverse lookup function
- [ ] Add retry logic with exponential backoff
- [ ] Log detailed error messages to debug log
- [ ] Add connection timeout detection and reporting
- [ ] Add configurable timeout value (--timeout flag)
- [ ] Show 'Timeout' status in summary table for hosts that don't respond
- [ ] Handle graceful timeout in SMB operations

**Files to Modify:**
- `taskhound/engine.py`
- `taskhound/output/summary.py`
- `taskhound/utils/sid_resolver.py` (add reverse lookup)
- `taskhound/smb/connection.py` (add timeout handling)

**Estimated Effort:** 6-8 hours

---

## 🗺️ PHASE 3: New Features
**Goal:** Add powerful new capabilities  
**Timeline:** 4-6 weeks  
**Estimated Effort:** 31-43 hours

### 3.1 Asynchronous Processing / Multithreading 🟡 HIGH
**Problem:** Slow when scanning many targets sequentially  
**Solution:** Process targets in parallel using asyncio

**Architecture:**
```python
# taskhound/engine_async.py (NEW FILE)
import asyncio
from concurrent.futures import ThreadPoolExecutor

async def process_targets_async(targets: List[str], 
                                 max_workers: int = 10,
                                 **kwargs) -> List[Dict]:
    """Process multiple targets concurrently"""
    
    # Use ThreadPoolExecutor for SMB I/O (not async-native)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        loop = asyncio.get_event_loop()
        
        # Create tasks for all targets
        tasks = [
            loop.run_in_executor(
                executor,
                process_target,
                target,
                **kwargs
            )
            for target in targets
        ]
        
        # Wait for all tasks with progress bar
        results = []
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            # Update progress bar
            print(f"[{len(results)}/{len(targets)}] {result['hostname']}")
        
        return results
```

**CLI Usage:**
```bash
# Sequential (current)
taskhound -t targets.txt -u admin -p pass

# Parallel (new)
taskhound -t targets.txt -u admin -p pass --threads 20

# With rate limiting
taskhound -t targets.txt -u admin -p pass --threads 10 --rate-limit 5/sec
```

**Tasks:**
- [ ] Create `taskhound/engine_async.py`
- [ ] Implement async wrapper for process_target()
- [ ] Add `--threads` / `--workers` CLI flag
- [ ] Add `--rate-limit` to prevent overwhelming network
- [ ] Add progress bar (tqdm or rich)
- [ ] Handle graceful shutdown (Ctrl+C)
- [ ] Add timeout per target
- [ ] Thread-safe logging

**Files to Create:**
- `taskhound/engine_async.py`

**Files to Modify:**
- `taskhound/cli.py`
- `taskhound/config.py`
- `requirements.txt` (add tqdm or rich)

**Estimated Effort:** 10-12 hours

---

### 3.2 WMI-Based Password Validation 🟢 MEDIUM
**Problem:** Password age heuristic is unreliable  
**Solution:** Query last successful task run via WMI

**Implementation:**
```python
# taskhound/smb/wmi.py (NEW FILE)
def get_task_last_run(smb_conn, task_path: str) -> Optional[datetime]:
    """
    Query WMI for last successful execution of scheduled task.
    
    WMI Class: Win32_ScheduledJob or MSFT_ScheduledTask
    Property: LastRunTime
    """
    try:
        # Execute WMI query via impacket
        query = f"SELECT LastRunTime FROM MSFT_ScheduledTask WHERE TaskPath='{task_path}'"
        result = execute_wmi_query(smb_conn, query)
        
        if result and result[0].LastRunTime:
            return parse_wmi_datetime(result[0].LastRunTime)
    except Exception as e:
        debug(f"WMI query failed for {task_path}: {e}")
    
    return None

def validate_password_via_wmi(smb_conn, task_path: str, 
                               runas: str, pwd_last_set: datetime) -> str:
    """
    Determine if task password is valid by comparing:
    - Last successful task run time
    - Password last set time
    
    Logic:
    If last_run > pwd_last_set:
        Password was valid at last_run → Likely still valid
    Else:
        Password may be stale
    """
    last_run = get_task_last_run(smb_conn, task_path)
    
    if not last_run:
        return "Unknown (WMI query failed)"
    
    if last_run > pwd_last_set:
        return f"Valid (last ran {last_run.strftime('%Y-%m-%d')}, password unchanged)"
    else:
        return f"Possibly stale (password changed after last run)"
```

**Tasks:**
- [ ] Research WMI scheduled task classes
- [ ] Create `taskhound/smb/wmi.py`
- [ ] Implement WMI query execution via impacket
- [ ] Parse WMI datetime format
- [ ] Integrate into password analysis logic
- [ ] Add `--wmi-validation` flag
- [ ] Handle WMI access denied errors gracefully

**Files to Create:**
- `taskhound/smb/wmi.py`

**Files to Modify:**
- `taskhound/engine.py` (integrate WMI check)
- `taskhound/config.py` (add flag)

**Estimated Effort:** 8-10 hours

---

### 3.3 OPSEC Mode 🟡 HIGH
**Problem:** Multiple TaskHound features create high-signal network activity that can be detected by EDR/SIEM  
**Solution:** Add `--opsec` flag that automatically disables all OPSEC-unsafe operations

**Background:**
Red team operators need a way to enumerate scheduled tasks with minimal detection risk. Several TaskHound features generate network activity that security tools actively monitor:

1. **LDAP SID Resolution**: LDAP queries to Domain Controllers are logged and can trigger alerts
2. **SAMR RPC Queries**: SAM Remote Protocol calls are unusual and may be monitored
3. **Remote Registry (Credential Guard)**: RemoteRegistry access is high-signal behavior
4. **Verbose Logging**: Debug output may expose operational details

**OPSEC-Safe Approach:**
- Use only SMB file access (blend with normal file operations)
- Skip all SID validation (accept name-based matching risks)
- Disable Credential Guard detection (skip RemoteRegistry)
- Minimal logging (no debug, reduced verbosity)

**Implementation:**
```python
# taskhound/config.py
@dataclass
class TaskHoundArgs:
    # ... existing fields ...
    opsec: bool = False  # NEW: Enable OPSEC mode
    
    def __post_init__(self):
        """Apply OPSEC restrictions if --opsec is enabled"""
        if self.opsec:
            # Disable OPSEC-unsafe features
            self.skip_sid_resolution = True      # No LDAP queries
            self.skip_samr_sid_lookup = True     # No SAMR RPC
            self.skip_credguard_check = True     # No RemoteRegistry
            self.verbose = False                 # Minimal output
            self.debug = False                   # No debug logging
            
            # Log OPSEC mode activation
            warn("[OPSEC] OPSEC mode enabled - disabling noisy features")
            warn("[OPSEC] SID validation: DISABLED (name-only matching)")
            warn("[OPSEC] Credential Guard detection: DISABLED")
            warn("[OPSEC] LDAP queries: DISABLED")
```

**CLI Usage:**
```bash
# OPSEC mode - minimal footprint
taskhound -u user -p pass -d domain.local -t 10.10.10.5 --opsec

# Equivalent to:
taskhound -u user -p pass -d domain.local -t 10.10.10.5 \
  --skip-sid-resolution \
  --skip-samr-sid-lookup \
  --skip-credguard-check \
  --no-debug

# Can still enable BloodHound integration (only uses SMB data)
taskhound -u user -p pass -d domain.local -t 10.10.10.5 \
  --opsec --bh-opengraph
```

**Output Comparison:**

*Normal Mode:*
```
[*] 172.17.1.11: Testing Credential Guard via Remote Registry...
[+] 172.17.1.11: Credential Guard: Disabled
[DEBUG] 172.17.1.11: Computer SID: S-1-5-21-29307702-767405025-1897820487-1002
[*] Using SID validation for 1 computers (from SMB connection)
[*] Resolving SIDs via LDAP for 2 users...
```

*OPSEC Mode:*
```
[*] 172.17.1.11: Found 3 scheduled tasks
[*] Credential Guard status: Unknown (OPSEC mode)
[*] SID validation: Skipped (OPSEC mode)
```

**Disabled Features in OPSEC Mode:**

| Feature | Protocol/Method | Detection Risk | OPSEC Status |
|---------|----------------|----------------|--------------|
| SAMR SID Lookup | SAMR RPC (`\samr` pipe) | HIGH - Unusual RPC call | ❌ DISABLED |
| LDAP SID Resolution | LDAP queries to DC | MEDIUM - Common but logged | ❌ DISABLED |
| Credential Guard Check | RemoteRegistry access | HIGH - Privileged access | ❌ DISABLED |
| Debug Logging | N/A | LOW - Info disclosure | ❌ DISABLED |
| SMB Task Enumeration | SMB file access | LOW - Normal file ops | ✅ ENABLED |
| Task XML Parsing | Local parsing | NONE - Offline | ✅ ENABLED |

**Trade-offs:**
- ✅ **Pros**: Significantly reduced detection surface, blend with normal SMB traffic
- ⚠️ **Cons**: No SID validation (risk of wrong node matching), no Credential Guard info, name-only BloodHound matching

**Tasks:**
- [ ] Add `--opsec` flag to CLI arguments
- [ ] Implement `__post_init__` logic to set OPSEC restrictions
- [ ] Update `get_server_sid()` to check `skip_samr_sid_lookup` flag
- [ ] Update `resolve_name_to_sid_via_ldap()` to check `skip_sid_resolution` flag
- [ ] Update Credential Guard check to respect `skip_credguard_check` flag
- [ ] Add OPSEC mode indicators to output
- [ ] Document detection risks in README
- [ ] Create OPSEC best practices guide
- [ ] Add test cases for OPSEC mode

**Files to Modify:**
- `taskhound/config.py` (add --opsec flag and logic)
- `taskhound/cli.py` (parse --opsec argument)
- `taskhound/smb/connection.py` (check flags in get_server_sid)
- `taskhound/smb/credguard.py` (check flag before registry access)
- `taskhound/utils/sid_resolver.py` (check flag before LDAP)
- `taskhound/output/opengraph.py` (handle missing SIDs gracefully)
- `taskhound/utils/logging.py` (respect OPSEC mode verbosity)

**Documentation to Create:**
- `docs/OPSEC_GUIDE.md` - Detection risks and mitigation strategies
- `docs/DETECTION_MATRIX.md` - What defenders can see

**Estimated Effort:** 6-8 hours

---

### 3.4 Cross-Domain Trust Authentication 🟡 HIGH
**Problem:** Cannot authenticate across trust boundaries (auth domain ≠ target domain)  
**Solution:** Support separate authentication and target domains like BloodHound CE

**Use Case:**
```
# Authenticate as user from thesimpsons.springfield.local
# Target computers in ogdenville.local (trusting domain)
# Assumes trust relationship allows cross-domain authentication
```

**Implementation:**
```python
# taskhound/cli.py
def main():
    # Parse authentication domain from username if in UPN format
    auth_domain = args.domain
    auth_user = args.username
    
    if '@' in args.username:
        # Extract domain from UPN (user@domain.com)
        auth_user, auth_domain = args.username.split('@', 1)
        info(f"Detected UPN format: authenticating as {auth_user}@{auth_domain}")
    
    # Target domain can be different
    target_domain = args.target_domain or args.domain
    
    if auth_domain != target_domain:
        info(f"Cross-domain authentication: {auth_domain} → {target_domain}")
        info(f"Ensure trust relationship allows this authentication path")
```

**Authentication Flow:**
```python
# taskhound/engine.py
def process_target(target: str, 
                   domain: str,              # Target domain
                   username: str,            # Can be UPN or simple format
                   auth_domain: str = None,  # Authentication domain (NEW)
                   ...):
    """
    Process target with cross-domain trust support.
    
    Args:
        target: Target hostname/IP
        domain: Target domain (computers being scanned)
        username: Authentication username (can be UPN: user@auth.domain.com)
        auth_domain: Explicit authentication domain (overrides UPN)
    """
    
    # Determine actual authentication domain
    if '@' in username:
        auth_user, detected_auth_domain = username.split('@', 1)
        final_auth_domain = auth_domain or detected_auth_domain
    else:
        auth_user = username
        final_auth_domain = auth_domain or domain
    
    # For SMB connection, use auth domain for credentials
    # But resolve target in target domain
    smb_conn = smb_connect(
        target=target,
        domain=final_auth_domain,  # Auth domain for credentials
        username=auth_user,
        password=password,
        ...
    )
    
    # For LDAP SID resolution, prioritize dedicated LDAP domain
    # Otherwise fall back to target domain (NOT auth domain)
    ldap_domain = args.ldap_domain or domain  # Target domain by default
```

**CLI Usage:**
```bash
# Option 1: UPN format (automatic detection)
taskhound -t DC01.ogdenville.local \
  -u krustytheclown@thesimpsons.springfield.local \
  -p krustytheclown \
  -d ogdenville.local \
  --dc-ip 172.17.1.11

# Option 2: Explicit auth domain
taskhound -t DC01.ogdenville.local \
  -u krustytheclown \
  -d ogdenville.local \
  --auth-domain thesimpsons.springfield.local \
  -p krustytheclown \
  --dc-ip 172.17.1.11

# Option 3: With NTLM hashes
taskhound -t DC01.ogdenville.local \
  -u krustytheclown@thesimpsons.springfield.local \
  --hashes :2D0AA42EB9B24A64E5427A65552AE1F4 \
  -d ogdenville.local \
  --dc-ip 172.17.1.11

# Option 4: Separate LDAP domain for SID resolution
taskhound -t DC01.ogdenville.local \
  -u localadmin \
  -p localpass \
  -d ogdenville.local \
  --ldap-user krustytheclown \
  --ldap-password krustytheclown \
  --ldap-domain thesimpsons.springfield.local
```

**Trust Validation:**
```python
# taskhound/smb/trust.py (NEW FILE)
def validate_trust_relationship(auth_domain: str, 
                                target_domain: str,
                                dc_ip: str,
                                username: str,
                                password: str) -> bool:
    """
    Validate that trust relationship exists and allows authentication.
    
    Uses LDAP to query trustedDomain objects.
    """
    try:
        # Query trustedDomain objects in target domain
        ldap_conn = connect_ldap(target_domain, username, password, dc_ip)
        
        search_filter = f"(trustedDomain=*{auth_domain}*)"
        results = ldap_conn.search(
            searchBase=f"CN=System,DC={target_domain.replace('.', ',DC=')}",
            searchFilter=search_filter,
            attributes=['trustDirection', 'trustType', 'trustAttributes']
        )
        
        if results:
            trust_info = results[0]
            direction = trust_info.get('trustDirection')
            
            # Check if trust allows authentication from auth_domain
            if direction in ['Bidirectional', 'Inbound']:
                info(f"Trust validated: {auth_domain} → {target_domain}")
                return True
            else:
                warn(f"Trust exists but wrong direction: {direction}")
                return False
        else:
            warn(f"No trust relationship found: {auth_domain} ↔ {target_domain}")
            return False
            
    except Exception as e:
        warn(f"Trust validation failed: {e}")
        return False
```

**Error Handling:**
```python
# Detect authentication failures due to trust issues
try:
    smb_conn = smb_connect(...)
except SessionError as e:
    if "STATUS_TRUSTED_DOMAIN_FAILURE" in str(e):
        error(f"Trust relationship broken between {auth_domain} and {target_domain}")
        error("Possible causes:")
        error("  - Trust does not exist")
        error("  - Trust is disabled")
        error("  - Trust password is stale")
        error("  - Firewall blocking cross-domain authentication")
```

**Tasks:**
- [ ] Add `--auth-domain` CLI flag
- [ ] Add `--target-domain` alias for `--domain` (clarity)
- [ ] Implement UPN parsing (user@domain.com)
- [ ] Update SMB connection to use auth domain
- [ ] Update LDAP resolution to use target domain
- [ ] Create trust validation function
- [ ] Add trust relationship checks
- [ ] Handle STATUS_TRUSTED_DOMAIN_FAILURE errors
- [ ] Update documentation with trust examples
- [ ] Test with real forest trust scenarios

**Files to Create:**
- `taskhound/smb/trust.py`

**Files to Modify:**
- `taskhound/cli.py`
- `taskhound/config.py`
- `taskhound/engine.py`
- `taskhound/smb/connection.py`

**Estimated Effort:** 8-10 hours

**References:**
- BloodHound CE Python: Uses `-d` for target domain, `-u` with UPN for auth domain
- Impacket examples: Support domain\user and user@domain.com formats
- Trust types: Parent/Child, External, Forest, Shortcut

---

### 3.5 LAPS Support 🟡 HIGH
**Problem:** Can't leverage LAPS for automatic credential rotation  
**Solution:** Implement LAPS password lookup like NetExec

**Implementation:**
```python
# taskhound/laps.py (NEW FILE)
from impacket.ldap import ldap, ldapasn1

def get_laps_password(target: str, 
                      domain: str,
                      username: str,
                      password: str,
                      dc_ip: Optional[str] = None) -> Optional[Tuple[str, str]]:
    """
    Retrieve LAPS password for target computer.
    
    Args:
        target: Hostname or IP of target computer
        domain: Domain name
        username: LDAP authentication username
        password: LDAP authentication password
        dc_ip: Domain controller IP (optional)
    
    Returns:
        Tuple of (laps_username, laps_password) or None
    """
    # Resolve target to FQDN if needed
    if is_ipv4(target):
        fqdn = resolve_ip_to_fqdn(target, domain, dc_ip)
    else:
        fqdn = target
    
    # Connect to LDAP
    ldap_conn = connect_ldap(domain, username, password, dc_ip)
    
    # Query LAPS attribute
    search_filter = f"(cn={fqdn.split('.')[0]})"
    attributes = ['ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime']
    
    results = ldap_conn.search(
        searchBase=f"DC={domain.replace('.', ',DC=')}",
        searchFilter=search_filter,
        attributes=attributes
    )
    
    if results and 'ms-Mcs-AdmPwd' in results[0]:
        laps_password = results[0]['ms-Mcs-AdmPwd'][0]
        return ('Administrator', laps_password)  # Default LAPS user
    
    return None
```

**CLI Usage:**
```bash
# Use LAPS with default Administrator user
taskhound --targets-file hosts.txt -u domain_admin -p pass --laps

# Use LAPS with custom username
taskhound --targets-file hosts.txt -u domain_admin -p pass --laps --laps-user LocalAdmin

# LAPS with Kerberos
taskhound --targets-file hosts.txt -u admin -k --laps
```

**Tasks:**
- [ ] Create `taskhound/laps.py`
- [ ] Implement LDAP query for ms-Mcs-AdmPwd
- [ ] Add `--laps` flag
- [ ] Add `--laps-user` flag (default: Administrator)
- [ ] Handle LAPS not configured error
- [ ] Handle expired LAPS passwords
- [ ] Add LAPS to authentication priority chain
- [ ] Log LAPS usage for audit trail

**Files to Create:**
- `taskhound/laps.py`

**Files to Modify:**
- `taskhound/cli.py`
- `taskhound/config.py`
- `taskhound/engine.py`

**Estimated Effort:** 8-10 hours

---

### 3.6 Blue Team Audit Mode 🔵 LOW
**Goal:** Comprehensive security audit with HTML reporting

**Features:**
- Enterprise-wide scan with LAPS or Domain Admin creds
- OpenGraph export for attack path analysis
- HTML report with severity ratings
- Remediation recommendations

**HTML Report Structure:**
```html
<!DOCTYPE html>
<html>
<head>
    <title>TaskHound Security Audit Report</title>
    <style>
        /* Bootstrap-like styling */
        .severity-critical { background: #dc3545; color: white; }
        .severity-high { background: #fd7e14; color: white; }
        .severity-medium { background: #ffc107; }
        .severity-low { background: #28a745; color: white; }
    </style>
</head>
<body>
    <h1>Scheduled Task Security Audit</h1>
    <div class="summary">
        <h2>Executive Summary</h2>
        <table>
            <tr>
                <th>Total Hosts Scanned</th><td>150</td>
            </tr>
            <tr>
                <th>Critical Issues</th><td class="severity-critical">25</td>
            </tr>
            <tr>
                <th>High Issues</th><td class="severity-high">50</td>
            </tr>
        </table>
    </div>
    
    <div class="findings">
        <h2>Critical Findings</h2>
        <div class="finding severity-critical">
            <h3>TIER-0 Account with Valid Password</h3>
            <p><strong>Host:</strong> DC01.domain.local</p>
            <p><strong>Task:</strong> \BackupTask</p>
            <p><strong>Runs As:</strong> DOMAIN\Administrator</p>
            <p><strong>Risk:</strong> Domain Admin credentials stored, password unchanged since task creation</p>
            <p><strong>Remediation:</strong> Remove stored credentials, use Group Managed Service Account (gMSA)</p>
        </div>
    </div>
</body>
</html>
```

**Severity Rating Logic:**
```python
def calculate_severity(task: Dict) -> str:
    """
    Calculate risk severity based on multiple factors:
    - CRITICAL: Tier-0 + Valid Password + Enabled
    - HIGH: Privileged + Valid Password + Enabled
    - MEDIUM: Privileged + Stale Password
    - LOW: Normal user account
    """
    score = 0
    
    if task.get('is_tier0'):
        score += 40
    elif task.get('is_privileged'):
        score += 20
    
    if task.get('password_valid'):
        score += 30
    
    if task.get('enabled'):
        score += 20
    
    if task.get('writable_executable'):
        score += 10
    
    if score >= 70:
        return 'CRITICAL'
    elif score >= 50:
        return 'HIGH'
    elif score >= 30:
        return 'MEDIUM'
    else:
        return 'LOW'
```

**Tasks:**
- [ ] Create `taskhound/output/html_report.py`
- [ ] Design HTML template with Jinja2
- [ ] Implement severity calculation logic
- [ ] Add remediation recommendations database
- [ ] Add `--audit-mode` flag
- [ ] Add `--html-report` output option
- [ ] Include charts/graphs (optional, with Chart.js)
- [ ] Add executive summary section
- [ ] Test with large datasets

**Estimated Effort:** 12-15 hours

---

### 3.7 Automatic Script File Grabbing 🟢 MEDIUM
**Goal:** Download task executables for offline analysis

**Implementation:**
```python
# taskhound/smb/file_grabber.py (NEW FILE)
SCRIPT_EXTENSIONS = ['.ps1', '.bat', '.cmd', '.vbs', '.js', '.py', '.exe', '.dll']

def grab_task_files(smb_conn, task: Dict, output_dir: Path) -> List[Path]:
    """
    Download executables/scripts referenced by scheduled task.
    
    Returns list of downloaded file paths.
    """
    downloaded = []
    executable = task.get('executable', '')
    
    # Check if file extension matches script types
    if not any(executable.lower().endswith(ext) for ext in SCRIPT_EXTENSIONS):
        debug(f"Skipping {executable} (not a script)")
        return downloaded
    
    # Convert Windows path to SMB path
    share, path = parse_windows_path(executable)
    
    try:
        # Download file
        local_path = output_dir / task['hostname'] / Path(path).name
        local_path.parent.mkdir(parents=True, exist_ok=True)
        
        smb_download_file(smb_conn, share, path, local_path)
        good(f"Downloaded {executable} → {local_path}")
        downloaded.append(local_path)
        
        # Create restore metadata
        create_restore_metadata(local_path, task)
        
    except Exception as e:
        warn(f"Failed to download {executable}: {e}")
    
    return downloaded

def create_restore_metadata(local_path: Path, task: Dict):
    """Save metadata for --restore functionality"""
    metadata = {
        'hostname': task['hostname'],
        'task_path': task['path'],
        'executable': task['executable'],
        'original_hash': hashlib.sha256(local_path.read_bytes()).hexdigest(),
        'downloaded_at': datetime.now().isoformat()
    }
    
    with open(local_path.with_suffix('.meta.json'), 'w') as f:
        json.dump(metadata, f, indent=2)
```

**Restore Functionality:**
```python
def restore_task_file(metadata_file: Path, smb_conn):
    """Restore original file back to target"""
    with open(metadata_file) as f:
        meta = json.load(f)
    
    original_file = metadata_file.with_suffix('')
    
    # Verify file hasn't been tampered with
    current_hash = hashlib.sha256(original_file.read_bytes()).hexdigest()
    if current_hash != meta['original_hash']:
        warn(f"File hash mismatch! Skipping restore for safety")
        return False
    
    # Upload back to original location
    share, path = parse_windows_path(meta['executable'])
    smb_upload_file(smb_conn, share, path, original_file)
    
    good(f"Restored {meta['executable']} on {meta['hostname']}")
    return True
```

**CLI Usage:**
```bash
# Grab all script files
taskhound -t dc01.domain.local -u admin -p pass --grab-files --grab-output ./loot/

# Restore modified file
taskhound -t dc01.domain.local -u admin -p pass --restore ./loot/dc01/backup.ps1.meta.json
```

**Tasks:**
- [ ] Create `taskhound/smb/file_grabber.py`
- [ ] Implement file download logic
- [ ] Add `--grab-files` flag
- [ ] Add `--grab-output` directory flag
- [ ] Implement restore functionality
- [ ] Add `--restore` flag
- [ ] Create metadata files for tracking
- [ ] Add hash verification
- [ ] Handle UNC paths

**Estimated Effort:** 6-8 hours

---

### 3.8 Colorful Terminal Output 🟡 HIGH (QoL)
**Goal:** Modern, readable output with colors

**Implementation:**
```python
# taskhound/utils/logging.py (REFACTOR)
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich import print as rprint

console = Console()

def good(msg: str):
    console.print(f"[green][+][/green] {msg}")

def warn(msg: str):
    console.print(f"[yellow][!][/yellow] {msg}")

def info(msg: str):
    console.print(f"[blue][*][/blue] {msg}")

def error(msg: str):
    console.print(f"[red][-][/red] {msg}")

def tier0_task(msg: str):
    console.print(f"[bold red on white][TIER-0][/bold red on white] {msg}")

def privileged_task(msg: str):
    console.print(f"[bold yellow][PRIV][/bold yellow] {msg}")
```

**Rich Summary Table:**
```python
def print_summary_table_rich(all_rows: List[Dict]):
    table = Table(title="TaskHound Summary", show_header=True, header_style="bold magenta")
    
    table.add_column("Hostname", style="cyan")
    table.add_column("TIER-0", justify="center")
    table.add_column("Privileged", justify="center")
    table.add_column("Normal", justify="center")
    table.add_column("Status", justify="center")
    
    for row in all_rows:
        status_color = "green" if row['status'] == 'success' else "red"
        table.add_row(
            row['hostname'],
            f"[red]{row['tier0_tasks']}[/red]" if row['tier0_tasks'] > 0 else "0",
            f"[yellow]{row['priv_tasks']}[/yellow]" if row['priv_tasks'] > 0 else "0",
            str(row['normal_tasks']),
            f"[{status_color}]{row['status']}[/{status_color}]"
        )
    
    console.print(table)
```

**Tasks:**
- [ ] Add rich to requirements.txt
- [ ] Refactor logging.py to use rich
- [ ] Update summary table to use Rich Table
- [ ] Add progress bars for long operations
- [ ] Add syntax highlighting for task details
- [ ] Add `--no-color` flag for piping
- [ ] Test on different terminals

**Files to Modify:**
- `taskhound/utils/logging.py`
- `taskhound/output/summary.py`
- `taskhound/output/printer.py`
- `requirements.txt`

**Estimated Effort:** 4-5 hours

---

## 🗺️ PHASE 4: Quality of Life & Refactoring
> ⚠️ **BLOCKED**: Cannot begin until OpenGraph merge to main
**Goal:** Code quality and maintainability  
**Timeline:** 2-3 weeks  
**Estimated Effort:** 15-20 hours

### 4.1 Code Refactoring (from REFACTORING_ANALYSIS.md)

#### 4.1.1 Split engine.py 🟢 MEDIUM
```
taskhound/engine/
├── __init__.py
├── online.py      # process_target() - SMB collection
├── offline.py     # process_offline_directory() - XML parsing
├── formatting.py  # _format_block(), _sort_tasks_by_priority()
└── dpapi.py       # _process_offline_dpapi_decryption()
```

**Estimated Effort:** 3-4 hours

#### 4.1.2 Standardize Variable Names 🟢 MEDIUM
```python
# Global standards:
bh_url          # BloodHound base URL
bh_username     # BloodHound username
bh_password     # BloodHound password
hv              # HighValueLoader instance
smb_conn        # SMBConnection instance
```

**Estimated Effort:** 1-2 hours (find-replace)

#### 4.1.3 Extract Constants 🟢 MEDIUM
Create `taskhound/constants.py`:
```python
# Task classification labels
TIER_ZERO_LABEL = "TIER-0"
PRIVILEGED_LABEL = "PRIV"
NORMAL_LABEL = "TASK"

# Paths
MICROSOFT_TASKS_PATH = r"\Microsoft\"
TASKS_ROOT = r"Windows\System32\Tasks"

# Cache settings
DEFAULT_CACHE_TTL_HOURS = 24
CACHE_DIR = Path.home() / ".taskhound"

# API settings
DEFAULT_CHUNK_SIZE = 100
DEFAULT_TIMEOUT = 30
```

**Estimated Effort:** 2 hours

---

## 📋 Implementation Priority Order

### Sprint 1 (Week 1-2): Critical OpenGraph Fixes
1. ✅ Switch to ID matching
2. ✅ Implement caching system
3. ✅ API Key authentication
4. ✅ Allow orphaned nodes

### Sprint 2 (Week 3-4): Core Improvements
1. ✅ Enhanced SID lookup chain
2. ✅ Unreachable hosts in summary
3. ✅ Colored output
4. ✅ Shortened output mode

### Sprint 3 (Week 5-7): Performance & Usability
1. ✅ Async processing
2. ✅ Cross-domain trust authentication
3. ✅ LAPS support
4. ✅ Script file grabbing
5. ✅ Code refactoring

### Sprint 4 (Week 8-10): Advanced Features
1. ✅ WMI password validation
2. ✅ Audit mode with HTML reports
3. ✅ Abuse info & OPSEC notes
4. ✅ Extensive documentation

---

## 🧪 Testing Strategy

### Unit Tests
- [ ] OpenGraph cache (hit/miss rates)
- [ ] SID resolver cascade
- [ ] LAPS password retrieval
- [ ] WMI query execution
- [ ] File grabber/restore

### Integration Tests
- [ ] End-to-end OpenGraph workflow
- [ ] Async processing with 100+ targets
- [ ] LAPS integration with real AD
- [ ] HTML report generation

### Performance Tests
- [ ] Benchmark async vs sequential (100 hosts)
- [ ] Cache effectiveness (hit rate >80%)
- [ ] Memory usage with large datasets

---

## 📊 Success Metrics

### Performance Targets
- [ ] Reduce API calls by 80% with caching
- [ ] 10x speedup with async processing (100 hosts: 10min → 1min)
- [ ] <1% error rate on SID resolution

### Quality Targets
- [ ] 80% code coverage
- [ ] Zero critical bugs in production
- [ ] All features documented

### Adoption Targets
- [ ] 50+ GitHub stars
- [ ] Featured in offensive security blogs
- [ ] Integrated into red team toolkits

---

## ❓ Open Questions & Clarifications Needed

### ✅ RESOLVED (2025-10-31)

#### OpenGraph Implementation
1. **✅ ID Matching API Endpoint**: `/api/v2/search` confirmed
   - Reference: https://bloodhound.specterops.io/reference/search/search-for-objects
   
2. **✅ Cache Storage Format**: **SQLite database** (recommended for performance)
   - Better performance for lookups and updates
   - ACID compliance ensures cache consistency
   - Supports concurrent access patterns
   - Natural fit for key-value lookups with TTL
   
3. **✅ Threading Default**: **10 threads** (conservative approach)
   - Safe default to avoid overwhelming BloodHound API
   - Users can increase with `--threads` flag if needed

4. **✅ Priority Weights**: Severity scoring confirmed as appropriate
   - TIER-0=40, HIGH-PRIV=20, MEDIUM-PRIV=10, LOW-PRIV=5

### 🔄 PENDING USER CLARIFICATION

#### OpenGraph Implementation
5. **Orphaned Nodes:** Should we log orphan creation to a separate file for review?

#### LAPS Support
6. **LAPS Attribute:** Is `ms-Mcs-AdmPwd` the only attribute or are there others?
7. **LAPS Fallback:** If LAPS fails, should we fall back to provided credentials?

#### Audit Mode
8. **Remediation DB:** Should remediation recommendations be hardcoded or external JSON?

#### Performance
9. **Rate Limiting:** Should rate limiting be per-target or global?

---

## 📚 Dependencies & Prerequisites

### New Python Dependencies
```txt
# requirements.txt additions
rich>=13.0.0           # Colored output, tables, progress bars
aiofiles>=23.0.0       # Async file I/O
tqdm>=4.66.0           # Progress bars (alternative to rich)
jinja2>=3.1.0          # HTML report templating
```

### External Requirements
- BloodHound CE 5.0+ (for OpenGraph features)
- Domain Admin or LAPS credentials (for audit mode)
- Python 3.11+ (already required)

---

## 🚀 Getting Started

### For Developers
1. Read this roadmap thoroughly
2. Review `REFACTORING_ANALYSIS.md` for code structure
3. Set up development environment:
   ```bash
   git checkout -b feature/opengraph-optimizations
   pip install -r requirements-dev.txt
   pytest tests/ -v
   ```
4. Pick a task from Sprint 1
5. Create feature branch: `feature/opengraph-caching`
6. Implement, test, document, PR

### For Contributors
- **Low Effort, High Impact:** Colored output, constants extraction
- **Medium Effort:** Caching system, LAPS support
- **High Effort:** Async processing, audit mode

---

## 📞 Contact & Collaboration

**Slack Channel:** #taskhound-dev (BloodHound Slack)  
**GitHub Issues:** Tag with `roadmap` label  
**Questions:** Ask in this document or create Discussion

---

**Last Updated:** October 31, 2025  
**Next Review:** Post-merge to main branch  
**Status:** ✅ APPROVED - BLOCKED PENDING OPENGRAPH MERGE  
**Blocking Issue:** Waiting for `feature/opengraph-integration` → `main` merge

---

## 🎉 Conclusion

This roadmap represents a comprehensive plan to evolve TaskHound from a solid tool into an **enterprise-grade offensive security platform**. The phased approach ensures:

- ✅ **Quick wins first** (caching, colored output)
- ✅ **Stability maintained** (no breaking changes)
- ✅ **Gradual complexity** (simple → advanced features)
- ✅ **User feedback loop** (test after each sprint)

**Let's build something amazing! 🐕🔍**
