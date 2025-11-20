# Orphaned Nodes Problem Analysis

## Problem Statement

TaskHound currently creates edges to Computer and User nodes that may not exist in the BloodHound graph database, resulting in orphaned edges that reference non-existent nodes.

## Current Implementation

### Flow Overview
```
1. Extract Names          → {computers, users} from task data
2. Resolve via BH API     → Query: MATCH (n:Type) WHERE n.name IN [...]
3. Build Mapping          → {"HOST": ("node_id", "SID")} for found nodes
4. Create Edges           → Check if name in map, otherwise use name matching
```

### Current Logic in `opengraph.py`

```python
# resolve_object_ids_chunked() returns:
computer_map = {"DC01.CORP.LOCAL": ("19", "S-1-5-21-...")}  # Found
user_map = {}  # Empty if ADMIN@CORP.LOCAL not found

# _create_relationship_edges() checks:
if computer_map and hostname in computer_map:
    node_id, object_id = computer_map[hostname]
    if node_id:
        use_node_id()  # Preferred path
    else:
        use_name_matching()  # LDAP fallback - no node_id
else:
    use_name_matching()  # Node not found - CREATES ORPHANED EDGE!
```

### The Issue

**Missing nodes fall through to name matching:**
- `resolve_object_ids_chunked()` only returns entries for **found** nodes
- Missing entries (not in dict) are treated as "use name matching"
- Name matching assumes the node exists in BloodHound → **broken assumption**

## Example Scenarios

### Scenario 1: Computer Not in BloodHound
```
Task Data:
  host: "WORKSTATION01.CORP.LOCAL"
  runas: "ADMIN@CORP.LOCAL"

BloodHound Database:
  Computers: [DC01, DC02, FILESERVER01]  ❌ No WORKSTATION01
  Users: [ADMIN@CORP.LOCAL]

Current Behavior:
  1. Query API for WORKSTATION01 → Returns empty {}
  2. computer_map = {} (no entry)
  3. Edge creation checks: hostname NOT in computer_map
  4. Falls back to name matching
  5. Creates: Computer(name="WORKSTATION01") -[HasTask]-> Task
  6. Result: ❌ ORPHANED EDGE - Computer node doesn't exist

Expected Behavior:
  1. Detect that WORKSTATION01 doesn't exist in BloodHound
  2. Either:
     a) Skip the edge (conservative)
     b) Create stub Computer node (permissive)
  3. Log warning about missing node
```

### Scenario 2: Service Account Not in BloodHound
```
Task Data:
  host: "DC01.CORP.LOCAL"  ✅ Exists in BH
  runas: "SVC_BACKUP@CORP.LOCAL"  ❌ Not in BH

BloodHound Database:
  Computers: [DC01.CORP.LOCAL]
  Users: [ADMIN, USER01, USER02]  ❌ No SVC_BACKUP

Current Behavior:
  1. HasTask edge created successfully (DC01 exists)
  2. RunsAs edge: SVC_BACKUP not in user_map
  3. Falls back to name matching
  4. Creates: Task -[RunsAs]-> User(name="SVC_BACKUP@CORP.LOCAL")
  5. Result: ❌ ORPHANED EDGE - User node doesn't exist

Expected Behavior:
  1. Detect that SVC_BACKUP doesn't exist in BloodHound
  2. Skip RunsAs edge OR create stub User node
  3. Log warning: "Skipped RunsAs edge to SVC_BACKUP@CORP.LOCAL (not found in BloodHound)"
```

## Root Cause

**Absence of evidence ≠ Evidence of absence**

The current code treats "not in map" as "use fallback" rather than "doesn't exist".

```python
# Current (incorrect assumption):
if hostname in computer_map:
    # Node definitely exists
    use_node_id()
else:
    # Could mean:
    # A) Node exists, but API query failed
    # B) Node doesn't exist in BloodHound
    # We assume A, but it might be B!
    use_name_matching()  # ❌ Creates orphaned edge if B
```

## Solution Design

### Core Change: Explicit Existence Tracking

Instead of "not in dict = use name matching", track three states:
1. **Found with node_id**: Resolved via API → Use node_id
2. **Found without node_id**: Resolved via LDAP → Use name matching (risky)
3. **Not found**: Missing from BloodHound → Skip OR create stub node

### Updated Return Signature

```python
# Current:
resolve_object_ids_chunked() -> (
    Dict[str, Tuple[str, str]],  # computer_map
    Dict[str, Tuple[str, str]]   # user_map
)

# Proposed:
resolve_object_ids_chunked() -> (
    Dict[str, Optional[Tuple[str, str]]],  # computer_map
    Dict[str, Optional[Tuple[str, str]]]   # user_map
)

# Now explicitly marks missing nodes:
computer_map = {
    "DC01.CORP.LOCAL": ("19", "S-1-5-21-..."),     # Found via API
    "DC02.CORP.LOCAL": ("", "S-1-5-21-..."),       # Found via LDAP only
    "WORKSTATION01.CORP.LOCAL": None               # ✨ NOT FOUND - explicitly marked
}
```

### Updated Edge Creation Logic

```python
def _create_relationship_edges(task, computer_map, user_map, allow_orphaned=False):
    # ...
    
    # Check if computer exists in BloodHound
    if hostname in computer_map:
        node_info = computer_map[hostname]
        
        if node_info is None:
            # Node explicitly marked as NOT FOUND
            if not allow_orphaned:
                warn(f"Skipping HasTask edge to {hostname} (not found in BloodHound)")
                # Don't create edge
            else:
                # Create stub node + edge (opt-in behavior)
                create_stub_computer_node(hostname)
                create_edge_with_name_matching()
        else:
            # Node exists - use node_id or name matching
            node_id, object_id = node_info
            if node_id:
                create_edge_with_node_id(node_id)
            else:
                # LDAP fallback - node exists but we only have SID
                create_edge_with_name_matching()
    else:
        # Node not queried (shouldn't happen in normal flow)
        warn(f"Node {hostname} not in resolution map - skipping edge")
```

## Implementation Plan

### Phase 1: Update Resolution Logic
1. Modify `resolve_object_ids_chunked()` to return `Dict[str, Optional[Tuple]]`
2. Explicitly mark missing nodes as `None` in the mapping
3. Update all code that reads from these maps to handle `None` values

### Phase 2: Update Edge Creation
1. Modify `_create_relationship_edges()` to check for `None` values
2. Add `allow_orphaned` parameter (default `False`)
3. Skip edges when node is `None` (unless `allow_orphaned=True`)
4. Log warnings for skipped edges

### Phase 3: Add CLI Flags
1. Add `--allow-orphaned-nodes` flag (opt-in permissive mode)
2. Pass flag through to `generate_opengraph_file()`
3. Update documentation

### Phase 4: Stub Node Creation (Optional - Future)
1. Add function to create minimal stub Computer/User nodes
2. Mark stubs with `source: "TaskHound"` property
3. Include warning in node properties: `incomplete_data: true`

## Testing Strategy

### Test Cases

1. **All nodes exist**: Verify normal behavior unchanged
2. **Computer missing**: Verify edge skipped, warning logged
3. **User missing**: Verify edge skipped, warning logged
4. **Both missing**: Verify no edges created for that task
5. **With --allow-orphaned-nodes**: Verify stub nodes created

### Test Data Setup

```cypher
// BloodHound database state
CREATE (:Computer {name: "DC01.CORP.LOCAL", objectId: "S-1-5-21-...-1000"})
CREATE (:User {name: "ADMIN@CORP.LOCAL", objectId: "S-1-5-21-...-500"})
// Note: WORKSTATION01 and SVC_BACKUP intentionally missing

// Task data
Task 1: DC01.CORP.LOCAL → ADMIN@CORP.LOCAL (both exist) ✅
Task 2: WORKSTATION01.CORP.LOCAL → ADMIN@CORP.LOCAL (computer missing) ❌
Task 3: DC01.CORP.LOCAL → SVC_BACKUP@CORP.LOCAL (user missing) ❌
Task 4: WORKSTATION01.CORP.LOCAL → SVC_BACKUP@CORP.LOCAL (both missing) ❌

// Expected results (conservative mode):
Task 1: 2 edges created ✅
Task 2: 1 edge created (RunsAs only), HasTask skipped ⚠️
Task 3: 1 edge created (HasTask only), RunsAs skipped ⚠️
Task 4: 0 edges created ⚠️
```

## Roadmap Integration

This work aligns with:
- **Phase 1.3**: Allow Orphaned Nodes in OpenGraph Output (Option)
  - Add explicit tracking of missing nodes
  - Add `--allow-orphaned-nodes` flag
  - Default to conservative behavior (skip orphaned edges)

## Metrics & Reporting

Add summary statistics to output:
```
OpenGraph Generation Summary:
  Tasks processed: 150
  Nodes created: 150 ScheduledTask nodes
  Edges created: 285 edges (143 HasTask, 142 RunsAs)
  Skipped edges: 15 edges (7 to missing computers, 8 to missing users)
  
  Missing BloodHound nodes:
    Computers: WORKSTATION01.CORP.LOCAL, WORKSTATION02.CORP.LOCAL (7 edges skipped)
    Users: SVC_BACKUP@CORP.LOCAL, SVC_MAINT@CORP.LOCAL (8 edges skipped)
```

## References

- ROADMAP_BATTLEPLAN.md - Phase 1.3
- taskhound/output/opengraph.py - Main implementation file
- taskhound/connectors/bloodhound.py - API query functions
