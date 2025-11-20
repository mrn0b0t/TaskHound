"""
BloodHound OpenGraph Data Generator

This module is responsible for converting TaskHound's internal data structures
into JSON files that are ingestible by BloodHound's OpenGraph feature.

Now using the official bhopengraph library (https://github.com/p0dalirius/bhopengraph)
for type-safe, schema-validated graph generation.

It will generate two main files:
- scheduled_tasks_nodes.json: Contains the custom 'ScheduledTask' nodes.
- scheduled_tasks_edges.json: Contains the custom 'HasTask' and 'RunsAs' relationships.
"""

import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from bhopengraph import OpenGraph, Node, Edge, Properties
from ..utils.logging import good, info, warn, debug
from ..utils.sid_resolver import resolve_name_to_sid_via_ldap


def _get_bloodhound_token(api_url: str, username: str, password: str) -> Optional[str]:
    """
    Authenticate to BloodHound CE API and get session token.
    
    Args:
        api_url: BloodHound API base URL (e.g., "http://127.0.0.1:8080")
        username: BloodHound username
        password: BloodHound password
        
    Returns:
        Session token string, or None if authentication fails
    """
    import requests
    
    try:
        response = requests.post(
            f"{api_url}/api/v2/login",
            json={"login_method": "secret", "secret": password, "username": username},
            timeout=30
        )
        
        if response.status_code != 200:
            warn(f"BloodHound authentication failed - HTTP {response.status_code}")
            return None
        
        token = response.json()["data"]["session_token"]
        debug(f"Successfully authenticated to BloodHound at {api_url}")
        return token
        
    except requests.Timeout:
        warn(f"Timeout authenticating to BloodHound (>30s)")
        return None
    except requests.RequestException as e:
        warn(f"Network error during authentication: {e}")
        return None
    except (KeyError, ValueError) as e:
        warn(f"Invalid authentication response from BloodHound: {e}")
        return None
    except Exception as e:
        warn(f"Unexpected authentication error: {e}")
        return None


def resolve_object_ids_chunked(
    computer_names: Set[str],
    user_names: Set[str],
    bh_connector,  # BloodHoundConnector instance
    ldap_config: Optional[Dict] = None,
    chunk_size: int = 10,
    computer_sids: Optional[Dict[str, str]] = None
) -> Tuple[Dict[str, Tuple[str, str]], Dict[str, Tuple[str, str]]]:
    """
    Resolve computer and user names to their node IDs and objectIds (SIDs) using BloodHound API.
    Falls back to LDAP if API queries fail (LDAP only provides objectId, not node_id).
    
    Workflow (optimized for SID-based lookup):
    1. If computer_sids provided: Query by objectId (SID) - most reliable!
    2. Otherwise: Query by name using WHERE IN clause
    3. Build name→(node_id, objectId) mappings from results
    4. If API fails, fallback to LDAP for missing entries (provides objectId only)
    
    Args:
        computer_names: Set of computer FQDNs (e.g., {"DC.CORP.LOCAL", "WEB01.CORP.LOCAL"})
        user_names: Set of user names in USER@DOMAIN.TLD format (e.g., {"ADMIN@CORP.LOCAL"})
        bh_connector: BloodHoundConnector instance for API queries
        ldap_config: Optional LDAP configuration for fallback
                    Expected keys: domain, dc_ip, username, password, hashes, kerberos
        chunk_size: Number of items per WHERE IN clause (default: 10)
        computer_sids: Optional mapping of FQDN→SID from SMB connections (preferred!)
                      Example: {"DC.CORP.LOCAL": "S-1-5-21-...-1000"}
        
    Returns:
        Tuple of (computer_map, user_map) where:
        - computer_map: {"DC.CORP.LOCAL": ("19", "S-1-5-21-...-1000")}
        - user_map: {"ADMIN@CORP.LOCAL": ("42", "S-1-5-21-...-500")}
        
        Note: If resolved via LDAP fallback, node_id will be empty string: ("", "S-1-5-21-...")
    """
    
    computer_sid_map = {}
    user_sid_map = {}
    
    def _chunk_list(items: Set[str], size: int) -> List[List[str]]:
        """Split set into chunks of specified size."""
        items_list = sorted(list(items))  # Sort for consistent ordering
        return [items_list[i:i + size] for i in range(0, len(items_list), size)]
    
    def _query_bloodhound_with_sid_validation(names_with_sids: Dict[str, str], node_type: str) -> Dict[str, Tuple[str, str]]:
        """
        Query BloodHound API by name but VALIDATE with SID for correctness.
        
        This hybrid approach:
        - Queries by name (works reliably in BloodHound CE)
        - Validates returned node has matching SID (prevents wrong node)
        - Detects duplicate names (multiple nodes with same name)
        
        Args:
            names_with_sids: Dict mapping name→SID (e.g., {"DC.CORP.LOCAL": "S-1-5-21-...-1000"})
            node_type: "Computer" or "User"
            
        Returns:
            Mapping of name→(node_id, objectId)
            Example: {"DC.CORP.LOCAL": ("19", "S-1-5-21-...-1000")}
        """
        import json
        mapping = {}
        
        if not names_with_sids:
            return {}
        
        # Build Cypher query with WHERE IN clause for names
        names_list = list(names_with_sids.keys())
        names_list_str = ', '.join([f'"{name}"' for name in names_list])
        query = f'MATCH (n:{node_type}) WHERE n.name IN [{names_list_str}] RETURN n'
        
        try:
            debug(f"Querying {node_type} chunk with SID validation: {len(names_with_sids)} items")
            
            # Use the connector's _bhce_signed_request method directly
            base_url = bh_connector.ip if "://" in bh_connector.ip else f"http://{bh_connector.ip}:8080"
            body = json.dumps({"query": query}, separators=(',', ':')).encode()
            response = bh_connector._bhce_signed_request('POST', '/api/v2/graphs/cypher', base_url, body)
            
            if response.status_code == 200:
                data = response.json()
                nodes = data.get("data", {}).get("nodes", {})
                
                # Group nodes by name to detect duplicates
                nodes_by_name = {}
                for node_id, node in nodes.items():
                    name = node.get("label")
                    object_id = node.get("objectId")
                    
                    if name not in nodes_by_name:
                        nodes_by_name[name] = []
                    nodes_by_name[name].append((node_id, object_id))
                
                # Process each name and validate SID
                for name, expected_sid in names_with_sids.items():
                    node_list = nodes_by_name.get(name, [])
                    
                    if len(node_list) == 0:
                        debug(f"No {node_type} node found for {name}")
                        continue
                    
                    if len(node_list) > 1:
                        # DUPLICATE NAMES DETECTED!
                        warn(f"⚠️  Duplicate {node_type} nodes found for {name}: {len(node_list)} nodes")
                        warn(f"   Node IDs: {[n[0] for n in node_list]}")
                        warn(f"   SIDs: {[n[1] for n in node_list]}")
                    
                    # Find node with matching SID
                    matched_node = None
                    for node_id, object_id in node_list:
                        if object_id == expected_sid:
                            matched_node = (node_id, object_id)
                            break
                    
                    if matched_node:
                        mapping[name] = matched_node
                        debug(f"✓ Validated {name} → node_id={matched_node[0]}, SID={matched_node[1]}")
                    else:
                        # SID mismatch - wrong computer!
                        warn(f"⚠️  SID mismatch for {name}:")
                        warn(f"   Expected SID: {expected_sid}")
                        warn(f"   BloodHound returned: {[n[1] for n in node_list]}")
                        warn(f"   Skipping this node (possible stale data or wrong computer)")
                
                return mapping
            else:
                warn(f"BloodHound API returned status {response.status_code}: {response.text}")
                return {}
        except Exception as e:
            warn(f"Error querying BloodHound with SID validation: {e}")
            if debug:
                import traceback
                traceback.print_exc()
            return {}
    
    def _query_bloodhound_chunk(names: List[str], node_type: str) -> Dict[str, Tuple[str, str]]:
        """
        Query BloodHound API for a chunk of names using the connector.
        
        Args:
            names: List of names to query
            node_type: "Computer" or "User"
            
        Returns:
            Mapping of name→(node_id, objectId)
            Example: {"DC01.DOMAIN.LOCAL": ("19", "S-1-5-21-...-1000")}
        """
        import json
        mapping = {}
        
        # Build Cypher query with WHERE IN clause
        names_list_str = ', '.join([f'"{name}"' for name in names])
        query = f'MATCH (n:{node_type}) WHERE n.name IN [{names_list_str}] RETURN n'
        
        try:
            debug(f"Querying {node_type} chunk: {len(names)} items")
            
            # Use the connector's _bhce_signed_request method directly
            base_url = bh_connector.ip if "://" in bh_connector.ip else f"http://{bh_connector.ip}:8080"
            body = json.dumps({"query": query}, separators=(',', ':')).encode()
            response = bh_connector._bhce_signed_request('POST', '/api/v2/graphs/cypher', base_url, body)
            
            if response.status_code == 200:
                data = response.json()
                nodes = data.get("data", {}).get("nodes", {})
                
                # Nodes are returned as dict keyed by node ID (THIS is the graph database ID!)
                for node_id, node in nodes.items():
                    # Properties are at top level of node, not nested
                    name = node.get("label")  # 'label' contains the name
                    object_id = node.get("objectId")  # 'objectId' not 'objectid'
                    
                    if name and object_id:
                        mapping[name] = (node_id, object_id)  # Return BOTH IDs
                        debug(f"Resolved {name} → node_id={node_id}, objectId={object_id}")
                
                return mapping
            else:
                warn(f"BloodHound API returned status {response.status_code}: {response.text}")
                return {}
                
        except Exception as e:
            warn(f"BloodHound API query failed: {e}")
            import traceback
            debug(traceback.format_exc())
            return {}
    
    def _ldap_fallback(names: List[str], is_computer: bool) -> Dict[str, Tuple[str, str]]:
        """
        Fallback to LDAP for resolving names to SIDs.
        Note: LDAP can only provide objectId (SID), not the BloodHound node_id.
        
        Args:
            names: List of names that couldn't be resolved via API
            is_computer: True for computers, False for users
            
        Returns:
            Mapping of name→("", SID)  # Empty node_id since LDAP doesn't provide it
        """
        mapping = {}
        
        if not ldap_config:
            warn(f"LDAP fallback requested but no LDAP config provided")
            return {}
        
        domain = ldap_config.get("domain")
        if not domain:
            warn(f"LDAP config missing 'domain' key")
            return {}
        
        for name in names:
            try:
                sid = resolve_name_to_sid_via_ldap(
                    name=name,
                    domain=domain,
                    is_computer=is_computer,
                    dc_ip=ldap_config.get("dc_ip"),
                    username=ldap_config.get("username"),
                    password=ldap_config.get("password"),
                    hashes=ldap_config.get("hashes"),
                    kerberos=ldap_config.get("kerberos", False)
                )
                
                if sid:
                    mapping[name] = ("", sid)  # Empty node_id, only objectId from LDAP
                    info(f"LDAP fallback resolved {name} → {sid}")
                else:
                    debug(f"LDAP fallback failed for {name}")
                    
            except Exception as e:
                warn(f"LDAP fallback error for {name}: {e}")
        
        return mapping
    
    # Process computers in chunks
    if computer_names:
        info(f"Resolving {len(computer_names)} computer names to objectIds...")
        
        # OPTIMIZATION: Use SID validation if available (captured from SMB connection)
        if computer_sids:
            # Split into: computers with known SIDs vs computers without SIDs
            computers_with_sids = {name: sid for name, sid in computer_sids.items() if name in computer_names and sid}
            computers_without_sids = computer_names - set(computers_with_sids.keys())
            
            if computers_with_sids:
                info(f"Using SID validation for {len(computers_with_sids)} computers (from SMB connection)")
                
                # Chunk the computers with SIDs
                computers_list = list(computers_with_sids.keys())
                name_chunks = [computers_list[i:i + chunk_size] for i in range(0, len(computers_list), chunk_size)]
                
                for i, chunk in enumerate(name_chunks, 1):
                    debug(f"Processing computer chunk {i}/{len(name_chunks)} with SID validation")
                    
                    # Build name→SID mapping for this chunk
                    chunk_name_sid_map = {name: computers_with_sids[name] for name in chunk}
                    
                    # Query by name BUT validate with SID
                    chunk_mapping = _query_bloodhound_with_sid_validation(chunk_name_sid_map, "Computer")
                    computer_sid_map.update(chunk_mapping)
                    
                    info(f"[*] Chunk {i}/{len(name_chunks)}: {len(chunk_mapping)}/{len(chunk)} resolved and validated")
            
            # Fall back to name-based lookup WITHOUT validation for computers without SIDs
            if computers_without_sids:
                info(f"Using name-based lookup for {len(computers_without_sids)} computers (no SID for validation)")
                computer_chunks = _chunk_list(computers_without_sids, chunk_size)
            else:
                computer_chunks = []
        else:
            # No SIDs available, use traditional name-based lookup
            info("No computer SIDs available - using name-based lookup (may have duplicates)")
            computer_chunks = _chunk_list(computer_names, chunk_size)
        
        # Process any remaining computers via name-based lookup
        for i, chunk in enumerate(computer_chunks, 1):
            debug(f"Processing computer name chunk {i}/{len(computer_chunks)}")
            
            # Try BloodHound API by name
            chunk_mapping = _query_bloodhound_chunk(chunk, "Computer")
            computer_sid_map.update(chunk_mapping)
            
            # Find missing entries
            resolved_names = set(chunk_mapping.keys())
            missing_names = set(chunk) - resolved_names
            
            if missing_names:
                info(f"Chunk {i}/{len(computer_chunks)}: {len(chunk_mapping)}/{len(chunk)} resolved via API, {len(missing_names)} missing")
                
                # Try LDAP fallback for missing entries
                if ldap_config:
                    fallback_mapping = _ldap_fallback(list(missing_names), is_computer=True)
                    computer_sid_map.update(fallback_mapping)
                    
                    still_missing = missing_names - set(fallback_mapping.keys())
                    if still_missing:
                        warn(f"Could not resolve computers: {', '.join(sorted(still_missing))}")
                        # Mark missing computers as None so we can detect them later
                        for missing_name in still_missing:
                            computer_sid_map[missing_name] = None
                else:
                    warn(f"No LDAP config for fallback. Missing computers: {', '.join(sorted(missing_names))}")
                    # Mark missing computers as None so we can detect them later
                    for missing_name in missing_names:
                        computer_sid_map[missing_name] = None
            else:
                info(f"Chunk {i}/{len(computer_chunks)}: {len(chunk_mapping)}/{len(chunk)} resolved via API")
    
    # Process users in chunks
    if user_names:
        info(f"Resolving {len(user_names)} user names to objectIds...")
        user_chunks = _chunk_list(user_names, chunk_size)
        
        for i, chunk in enumerate(user_chunks, 1):
            debug(f"Processing user chunk {i}/{len(user_chunks)}")
            
            # Try BloodHound API first
            chunk_mapping = _query_bloodhound_chunk(chunk, "User")
            user_sid_map.update(chunk_mapping)
            
            # Find missing entries
            resolved_names = set(chunk_mapping.keys())
            missing_names = set(chunk) - resolved_names
            
            if missing_names:
                info(f"Chunk {i}/{len(user_chunks)}: {len(chunk_mapping)}/{len(chunk)} resolved via API, {len(missing_names)} missing")
                
                # Try LDAP fallback for missing entries
                if ldap_config:
                    fallback_mapping = _ldap_fallback(list(missing_names), is_computer=False)
                    user_sid_map.update(fallback_mapping)
                    
                    still_missing = missing_names - set(fallback_mapping.keys())
                    if still_missing:
                        warn(f"Could not resolve users: {', '.join(sorted(still_missing))}")
                        # Mark missing users as None so we can detect them later
                        for missing_name in still_missing:
                            user_sid_map[missing_name] = None
                else:
                    warn(f"No LDAP config for fallback. Missing users: {', '.join(sorted(missing_names))}")
                    # Mark missing users as None so we can detect them later
                    for missing_name in missing_names:
                        user_sid_map[missing_name] = None
            else:
                info(f"Chunk {i}/{len(user_chunks)}: {len(chunk_mapping)}/{len(chunk)} resolved via API")
    
    good(f"Resolution complete: {len(computer_sid_map)} computers, {len(user_sid_map)} users")
    return computer_sid_map, user_sid_map


def generate_opengraph_files(output_dir: str, tasks: List[Dict],
                            bh_api_url: Optional[str] = None,
                            bh_username: Optional[str] = None,
                            bh_password: Optional[str] = None,
                            bh_api_key: Optional[str] = None,
                            bh_api_key_id: Optional[str] = None,
                            ldap_config: Optional[Dict] = None,
                            allow_orphans: bool = False) -> str:
    """
    Main function to generate OpenGraph file using bhopengraph library.

    :param output_dir: The directory to write the JSON file to.
    :param tasks: A list of task dictionaries from the TaskHound engine.
    :param bh_api_url: BloodHound API URL for objectId resolution (optional)
    :param bh_username: BloodHound username for API authentication (optional)
    :param bh_password: BloodHound password for API authentication (optional)
    :param bh_api_key: BloodHound API key for HMAC authentication (optional)
    :param bh_api_key_id: BloodHound API key ID for HMAC authentication (optional)
    :param ldap_config: LDAP configuration for fallback resolution (optional)
    :param allow_orphans: If True, create edges even when nodes are missing from BloodHound (optional)
    :return: Path to the generated OpenGraph file
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Create a single OpenGraph instance for both nodes and edges
    # Don't use source_kind to avoid adding it to stub Computer/User nodes
    graph = OpenGraph()

    # Create and add task nodes
    skipped_nodes = 0
    for task in tasks:
        try:
            node = _create_task_node(task)
            graph.add_node(node)
        except ValueError as e:
            warn(f"Skipping invalid task: {e}")
            skipped_nodes += 1
    
    if skipped_nodes > 0:
        warn(f"Skipped {skipped_nodes} invalid tasks (missing host/path)")
    
    info(f"Created {graph.get_node_count()} ScheduledTask nodes")

    # Resolve objectIds if BloodHound API is available
    computer_sid_map = {}
    user_sid_map = {}
    computer_map = {}
    user_map = {}
    
    # Check if BloodHound credentials are available (either username/password or API key)
    has_bh_credentials = bh_api_url and ((bh_username and bh_password) or (bh_api_key and bh_api_key_id))
    
    # Initialize connector early so it can be used for cross-domain validation
    connector = None
    if has_bh_credentials:
        # Use BloodHoundConnector for API queries (supports both username/password and API key auth)
        from ..connectors.bloodhound import BloodHoundConnector
        
        try:
            connector = BloodHoundConnector(
                bh_type='bhce',  # OpenGraph is only for BHCE
                ip=bh_api_url,
                username=bh_username,
                password=bh_password,
                api_key=bh_api_key,
                api_key_id=bh_api_key_id,
                timeout=getattr(args, 'bh_timeout', 120)
            )
            info("BloodHound connector initialized for cross-domain validation")
        except Exception as e:
            warn(f"Failed to initialize BloodHound connector: {e}")
            warn("Cross-domain tasks will be skipped")
            connector = None
    
    if has_bh_credentials and connector:
        # Extract unique computer names, user names, AND computer SIDs from tasks
        computer_names = set()
        user_names = set()
        computer_sids_map = {}  # FQDN → SID mapping from SMB connections
        
        for task in tasks:
            hostname = task.get("host", "").strip().upper()
            if hostname and hostname not in ("UNKNOWN_HOST", "UNKNOWN", ""):
                computer_names.add(hostname)
                
                # OPTIMIZATION: Capture computer SID if available (from SMB connection)
                computer_sid = task.get("computer_sid")
                if computer_sid and hostname not in computer_sids_map:
                    computer_sids_map[hostname] = computer_sid
                    debug(f"Captured SID for {hostname}: {computer_sid}")
            
            runas_user = task.get("runas", "").strip()
            if runas_user and runas_user not in ("N/A", "", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"):
                # Extract domain from hostname for principal ID construction
                def _extract_domain_from_fqdn(fqdn: str) -> str:
                    if "." in fqdn:
                        parts = fqdn.split(".")
                        if len(parts) >= 2:
                            return ".".join(parts[1:]).upper()
                    return "WORKGROUP"
                
                fqdn_domain = _extract_domain_from_fqdn(hostname)
                # Pass connector for cross-domain validation
                principal_id = _create_principal_id(runas_user, fqdn_domain, task, connector)
                
                if principal_id:  # Only add if it passed filtering
                    user_names.add(principal_id)
        
        info(f"Extracted {len(computer_names)} unique computers and {len(user_names)} unique users")
        
        try:
            
            # Resolve names to node IDs and objectIds using chunked queries
            # OPTIMIZATION: Pass computer_sids_map for SID-based lookup (faster & more reliable!)
            if computer_sids_map:
                info(f"Found {len(computer_sids_map)} computers with SIDs from SMB connections")
            
            computer_map, user_map = resolve_object_ids_chunked(
                computer_names=computer_names,
                user_names=user_names,
                bh_connector=connector,
                ldap_config=ldap_config,
                chunk_size=10,
                computer_sids=computer_sids_map  # Pass SIDs for optimized lookup!
            )
        except Exception as e:
            warn(f"Failed to initialize BloodHound connector: {e}")
            warn("Edges will use name matching (may create duplicates)")
            computer_map = {}
            user_map = {}
    
    # Create and add relationship edges with node ID-based matching
    total_skipped = {"computers": 0, "users": 0}
    for task in tasks:
        task_edges, skipped = _create_relationship_edges(task, computer_map, user_map, connector, allow_orphans)
        total_skipped["computers"] += skipped["computers"]
        total_skipped["users"] += skipped["users"]
        for edge in task_edges:
            # Use add_edge_without_validation to allow edges to reference
            # Computer/User nodes that exist in BloodHound but not in our local graph
            graph.add_edge_without_validation(edge)
    
    info(f"Created {graph.get_edge_count()} relationships (HasTask + RunsAs)")
    
    # Report skipped edges if any
    if total_skipped["computers"] > 0 or total_skipped["users"] > 0:
        warn(f"Skipped edges due to missing nodes:")
        if total_skipped["computers"] > 0:
            warn(f"  - {total_skipped['computers']} edges to missing Computer nodes")
        if total_skipped["users"] > 0:
            warn(f"  - {total_skipped['users']} edges to missing User nodes")
        info(f"Tip: Use --allow-orphans to create edges to missing nodes (may create orphaned edges)")

    # Export to single file - bhopengraph includes both nodes and edges automatically
    output_file = output_path / "taskhound_opengraph.json"
    graph.export_to_file(str(output_file))
    
    good(f"OpenGraph file: {output_file}")
    
    return str(output_file)


def _create_task_object_id(hostname: str, task_path: str) -> str:
    """
    Create unique, deterministic object ID for scheduled task.
    
    Format: HOSTNAME_HASH_TASKNAME
    
    Uses MD5 hash to prevent collisions between similar paths:
    - \\Tasks\\My_Task vs \\Tasks_My\\Task would collide with simple replacement
    - Hash ensures uniqueness while keeping ID somewhat readable
    
    :param hostname: FQDN hostname (e.g., DC01.DOMAIN.LAB)
    :param task_path: Full task path (e.g., \\Microsoft\\Windows\\UpdateTask)
    :return: Unique object ID (e.g., DC01.DOMAIN.LAB_A3F2B1C8_UPDATETASK)
    """
    # Create deterministic identifier from hostname and full path
    identifier = f"{hostname.upper()}|{task_path.upper()}"
    
    # Generate short hash for uniqueness (8 chars is enough for collision resistance)
    hash_short = hashlib.md5(identifier.encode()).hexdigest()[:8].upper()
    
    # Extract task name from path for readability
    task_name = task_path.split("\\")[-1].upper()  # Get last part
    task_name = task_name.replace(" ", "_")[:40]  # Limit length, replace spaces
    
    # Combine into final ID
    return f"{hostname}_{hash_short}_{task_name}"


def _create_task_node(task: Dict) -> Node:
    """
    Creates a single ScheduledTask node using bhopengraph.
    
    :param task: Task dictionary from TaskHound engine
    :return: Node instance
    :raises ValueError: If required fields are missing or invalid
    """
    hostname = task.get("host", "").strip().upper()
    task_path = task.get("path", "").strip()
    
    # Validate required fields
    if not hostname:
        raise ValueError(f"Task missing 'host' field: {task}")
    if not task_path:
        raise ValueError(f"Task missing 'path' field: {task}")
    
    # Validate hostname is not empty/unknown
    if hostname.upper() in ("UNKNOWN_HOST", "UNKNOWN", ""):
        raise ValueError(f"Invalid hostname '{hostname}' for task: {task_path}")
    
    # Create a unique object ID using hash to prevent collisions
    object_id = _create_task_object_id(hostname, task_path)

    # Build command string
    command = task.get("command", "N/A")
    arguments = task.get("arguments")
    if arguments:
        command = f"{command} {arguments}"

    # Determine credentials status
    credentials_hint = task.get("credentials_hint", "unknown")
    logon_type = task.get("logon_type") or "Unknown"  # Handle None/null values
    
    # Build properties dict - bhopengraph Properties class validates schema compliance
    properties_dict = {
        "name": task_path,
        "hostname": hostname,
        "objectid": object_id,
        "runas": task.get("runas") or "N/A",
        "enabled": str(task.get("enabled", "false")).lower() == "true",
        "command": command,
        "logontype": logon_type,
        "credentialsstored": credentials_hint == "stored_credentials",
    }

    # Add optional properties only if they have non-null values
    author = task.get("author")
    if author:
        properties_dict["author"] = author
    
    date = task.get("date")
    if date:
        properties_dict["date"] = date

    # Add trigger information if available
    trigger_type = task.get("trigger_type")
    if trigger_type:
        properties_dict["triggertype"] = trigger_type
        
        # Add schedule-specific details (only if non-null)
        start_boundary = task.get("start_boundary")
        if start_boundary:
            properties_dict["startboundary"] = start_boundary
        
        interval = task.get("interval")
        if interval:
            properties_dict["interval"] = interval
        
        duration = task.get("duration")
        if duration:
            properties_dict["duration"] = duration
        
        days_interval = task.get("days_interval")
        if days_interval:
            properties_dict["daysinterval"] = days_interval

    # Add password age analysis if available
    password_analysis = task.get("password_analysis")
    if password_analysis:
        properties_dict["passwordanalysis"] = password_analysis
    
    # Add classification (TIER-0, PRIV, TASK)
    task_type = task.get("type")
    if task_type:
        properties_dict["tasktype"] = task_type
    
    reason = task.get("reason")
    if reason:
        properties_dict["classification"] = reason

    # Create Node using bhopengraph (automatically validates schema)
    # Add TaskHound as custom kind for filtering in BloodHound
    # NOTE: First kind in array becomes "Primary Kind" in BloodHound UI
    node = Node(
        id=object_id,
        kinds=["scheduledtask", "Base", "TaskHound"],
        properties=Properties(**properties_dict)
    )
    
    return node


def _create_principal_id(runas_user: str, local_domain: str, task: Dict, bh_connector=None) -> Optional[str]:
    """
    Create BloodHound-compatible principal ID from RunAs user.
    
    Handles various formats and filters out accounts that should not have edges:
    - Built-in accounts (NT AUTHORITY\\SYSTEM, etc.)
    - SID format (S-1-5-*)
    - Cross-domain users (validates domain exists in BloodHound)
    
    Supported input formats:
    - UPN: user@domain.lab
    - NETBIOS: DOMAIN\\user
    - samAccountName: user
    
    :param runas_user: RunAs user from task (various formats)
    :param local_domain: FQDN domain of the computer (e.g., DOMAIN.LAB)
    :param task: Full task dict for logging context
    :param bh_connector: Optional BloodHoundConnector for cross-domain validation
    :return: Principal ID in BloodHound format (USER@DOMAIN.LAB) or None if should skip
    """
    # Skip empty/invalid
    if not runas_user or runas_user.upper() == "N/A":
        return None
    
    # Skip SIDs (start with S-1-5-)
    if runas_user.startswith("S-1-5-"):
        return None
    
    # Skip built-in accounts that shouldn't have attack paths
    BUILTIN_ACCOUNTS = {
        'NT AUTHORITY\\SYSTEM',
        'NT AUTHORITY\\LOCAL SERVICE',
        'NT AUTHORITY\\NETWORK SERVICE',
        'NT AUTHORITY\\LOCALSERVICE',
        'NT AUTHORITY\\NETWORKSERVICE',
        'BUILTIN\\ADMINISTRATORS',
        'BUILTIN\\USERS',
        'NT AUTHORITY\\ANONYMOUS LOGON',
        'NT AUTHORITY\\AUTHENTICATED USERS',
        'SYSTEM',  # Sometimes appears without prefix
        'LOCAL SERVICE',
        'NETWORK SERVICE',
    }
    
    if runas_user.upper() in BUILTIN_ACCOUNTS:
        return None
    
    # Check if already in UPN format (user@domain.tld)
    if "@" in runas_user:
        # Already in UPN format - validate domain matches
        user_part, domain_part = runas_user.rsplit("@", 1)
        user_part = user_part.strip().upper()
        domain_part = domain_part.strip().upper()
        
        # Check if domain matches local domain (case-insensitive)
        if domain_part != local_domain.upper():
            # Cross-domain UPN - validate both domain and user exist in BloodHound
            if bh_connector:
                # Extract first component of FQDN for NETBIOS lookup
                netbios_name = domain_part.split(".")[0] if "." in domain_part else domain_part
                
                # Use complete validation workflow: domain + user
                user_info = bh_connector.validate_and_resolve_cross_domain_user(netbios_name, user_part)
                
                if user_info and not user_info.get('error_reason'):
                    # Both domain and user exist! Create edge with validated UPN
                    task_path = task.get("path", "unknown")
                    hostname = task.get("host", "unknown")
                    info(f"Cross-domain task on {hostname}: {task_path}")
                    info(f"  RunAs: {user_part}@{domain_part} → {user_info['name']} (validated in BH)")
                    info(f"  Domain: {user_info['domain_fqdn']}, User SID: {user_info['objectid']}")
                    return user_info['name']
                else:
                    # Domain or user doesn't exist in BloodHound
                    task_path = task.get("path", "unknown")
                    hostname = task.get("host", "unknown")
                    error_reason = user_info.get('error_reason') if user_info else 'unknown'
                    
                    if error_reason == 'domain_not_found':
                        warn(f"Cross-domain task on {hostname}: {task_path}")
                        warn(f"  RunAs: {runas_user}")
                        warn(f"  ✗ Domain '{netbios_name}' not found in BloodHound")
                        warn(f"  → Import '{netbios_name}' domain data to BloodHound to enable this edge")
                    elif error_reason == 'user_not_found':
                        warn(f"Cross-domain task on {hostname}: {task_path}")
                        warn(f"  RunAs: {runas_user}")
                        warn(f"  ✓ Domain '{user_info['domain_fqdn']}' exists")
                        warn(f"  ✗ User '{user_info['username']}' not found in domain")
                        warn(f"  → Likely orphaned task (user deleted) - enable orphaned node creation to capture")
                    else:
                        warn(f"Cross-domain task on {hostname}: {task_path}")
                        warn(f"  RunAs: {runas_user} (validation failed)")
                    
                    return None
            else:
                # No connector - can't validate, skip for safety
                warn(f"Cross-domain UPN {runas_user} - skipping (no BloodHound connector)")
                return None
        
        # UPN domain matches - return normalized format
        return f"{user_part}@{local_domain}"
    
    # Parse NETBIOS domain\user format
    if "\\" in runas_user:
        domain_prefix, user = runas_user.split("\\", 1)
        domain_prefix = domain_prefix.strip().upper()
        user = user.strip().upper()
        
        # Extract first part of FQDN for comparison (e.g., DOMAIN.LAB -> DOMAIN)
        local_domain_short = local_domain.split(".")[0].upper() if "." in local_domain else local_domain.upper()
        
        # Extract first part of domain_prefix for comparison (may be FQDN like THESIMPSONS.SPRINGFIELD.LOCAL)
        domain_prefix_short = domain_prefix.split(".")[0] if "." in domain_prefix else domain_prefix
        
        # Extract hostname from FQDN for local account detection (e.g., CLIENT01.DOMAIN.LAB -> CLIENT01)
        hostname_fqdn = task.get("host", "")
        hostname_short = hostname_fqdn.split(".")[0].upper() if "." in hostname_fqdn else hostname_fqdn.upper()
        
        # Check if it's a local account (NETBIOS domain matches hostname)
        is_local_account = (domain_prefix_short == hostname_short)
        
        # Check if cross-domain (domain doesn't match local domain AND not a local account)
        if domain_prefix_short != local_domain_short and not is_local_account:
            # Cross-domain task - validate both domain and user exist in BloodHound
            if bh_connector:
                # Use complete validation workflow: domain + user
                user_info = bh_connector.validate_and_resolve_cross_domain_user(domain_prefix_short, user)
                
                if user_info and not user_info.get('error_reason'):
                    # Both domain and user exist! Create edge with validated UPN
                    task_path = task.get("path", "unknown")
                    hostname = task.get("host", "unknown")
                    info(f"Cross-domain task on {hostname}: {task_path}")
                    info(f"  RunAs: {domain_prefix_short}\\{user} → {user_info['name']} (validated in BH)")
                    info(f"  Domain: {user_info['domain_fqdn']}, User SID: {user_info['objectid']}")
                    return user_info['name']
                else:
                    # Domain or user doesn't exist in BloodHound
                    task_path = task.get("path", "unknown")
                    hostname = task.get("host", "unknown")
                    error_reason = user_info.get('error_reason') if user_info else 'unknown'
                    
                    if error_reason == 'domain_not_found':
                        warn(f"Cross-domain task on {hostname}: {task_path}")
                        warn(f"  RunAs: {runas_user}")
                        warn(f"  ✗ Domain '{domain_prefix_short}' not found in BloodHound")
                        warn(f"  → Import '{domain_prefix_short}' domain data to BloodHound to enable this edge")
                    elif error_reason == 'user_not_found':
                        warn(f"Cross-domain task on {hostname}: {task_path}")
                        warn(f"  RunAs: {runas_user}")
                        warn(f"  ✓ Domain '{user_info['domain_fqdn']}' exists")
                        warn(f"  ✗ User '{user_info['username']}' not found in domain")
                        warn(f"  → Likely orphaned task (user deleted) - enable orphaned node creation to capture")
                    else:
                        warn(f"Cross-domain task on {hostname}: {task_path}")
                        warn(f"  RunAs: {runas_user} (validation failed)")
                    
                    return None
            else:
                # No connector - can't validate, skip for safety
                warn(f"Cross-domain task {runas_user} - skipping (no BloodHound connector)")
                return None
        
        # If it's a local account, skip creating edge (local accounts aren't in BloodHound)
        if is_local_account:
            debug(f"Skipping local account: {runas_user} on {hostname_fqdn}")
            return None
        
        # Use full FQDN format
        return f"{user}@{local_domain}"
    else:
        # No domain prefix and no @ - assume local domain
        user = runas_user.strip().upper()
        return f"{user}@{local_domain}"


def _create_relationship_edges(task: Dict, 
                              computer_map: Dict[str, Optional[Tuple[str, str]]] = None,
                              user_map: Dict[str, Optional[Tuple[str, str]]] = None,
                              bh_connector=None,
                              allow_orphans: bool = False) -> Tuple[List[Edge], Dict[str, int]]:
    """
    Creates HasTask and RunsAs edges for a single task using bhopengraph.
    
    Uses BloodHound node IDs (graph database IDs) for reliable edge creation.
    Falls back to name matching if node IDs are not available.
    
    :param task: Task dictionary from TaskHound engine
    :param computer_map: Optional mapping of computer FQDN → (node_id, objectId) or None if not found
                        Example: {"DC01.DOMAIN.LAB": ("19", "S-1-5-21-...-1000"), "MISSING.LAB": None}
    :param user_map: Optional mapping of user principal → (node_id, objectId) or None if not found
                    Example: {"ADMIN@DOMAIN.LAB": ("42", "S-1-5-21-...-500"), "GHOST@LAB": None}
    :param bh_connector: Optional BloodHoundConnector for cross-domain validation
    :param allow_orphans: If True, create edges even when nodes are missing from BloodHound
    :return: Tuple of (List of Edge instances, Dict with skip statistics)
    """
    edges = []
    skipped = {"computers": 0, "users": 0}
    hostname = task.get("host", "UNKNOWN_HOST").upper()
    task_path = task.get("path", "UNKNOWN_PATH")
    runas_user = task.get("runas", "N/A")

    # Extract domain from hostname FQDN (e.g., DC01.DOMAIN.LAB -> DOMAIN.LAB)
    # Note: hostname is already resolved to FQDN via SMB in engine.py:630 (get_server_fqdn)
    def _extract_domain_from_fqdn(fqdn: str) -> str:
        """Extract domain from FQDN hostname."""
        if "." in fqdn:
            parts = fqdn.split(".")
            if len(parts) >= 2:
                return ".".join(parts[1:]).upper()
        return "WORKGROUP"  # Fallback for non-domain systems
    
    fqdn_domain = _extract_domain_from_fqdn(hostname)

    # Create task object ID using hash-based function (same as in _create_task_node)
    task_object_id = _create_task_object_id(hostname, task_path)

    # 1. Create (Computer)-[HasTask]->(ScheduledTask) edge
    # Differentiate edge type based on whether credentials are stored
    credentials_hint = task.get("credentials_hint", "unknown")
    has_stored_creds = credentials_hint == "stored_credentials"
    
    # Use different edge kind based on credential storage
    edge_kind = "HasTaskWithStoredCreds" if has_stored_creds else "HasTask"
    
    # Prefer id (objectid/SID) matching, fall back to name matching
    # Note: In BloodHound, a node's 'id' property IS the objectid (SID for users/computers)
    computer_object_id = None
    computer_match_by = "name"  # Default fallback
    
    if computer_map and hostname in computer_map:
        node_info = computer_map[hostname]
        
        if node_info is None:
            # Node was queried but not found in BloodHound
            if not allow_orphans:
                warn(f"Skipping {edge_kind} edge: Computer '{hostname}' not found in BloodHound")
                warn(f"  Task: {task_path}")
                warn(f"  Use --allow-orphans to create edges to missing nodes")
                skipped["computers"] += 1
                # Don't create this edge - skip to user edge
            else:
                # User opted in to orphaned edges - use name matching
                debug(f"Creating orphaned edge for missing computer: {hostname}")
                has_task_edge = Edge(
                    start_node=hostname,
                    end_node=task_object_id,
                    kind=edge_kind,
                    start_match_by="name",
                    end_match_by="id"
                )
                edges.append(has_task_edge)
        else:
            # Node exists in BloodHound
            node_id, object_id = node_info
            if object_id:  # If we have an objectid (SID)
                computer_object_id = object_id
                computer_match_by = "id"  # match_by='id' looks for node where id property == object_id (SID)
                debug(f"Using id (objectid) for Computer: {hostname} → {object_id}")
            else:
                debug(f"No objectid for {hostname}, falling back to name matching")
            
            has_task_edge = Edge(
                start_node=computer_object_id if computer_object_id else hostname,
                end_node=task_object_id,
                kind=edge_kind,
                start_match_by=computer_match_by,
                end_match_by="id"
            )
            debug(f"Created {edge_kind} edge: {hostname} → {task_path} (match_by={computer_match_by})")
            edges.append(has_task_edge)
    else:
        # Computer not in map - wasn't queried (shouldn't happen in normal flow)
        if not allow_orphans:
            warn(f"Computer '{hostname}' not in resolution map - skipping {edge_kind} edge")
            skipped["computers"] += 1
        else:
            # Fallback for orphaned mode
            has_task_edge = Edge(
                start_node=hostname,
                end_node=task_object_id,
                kind=edge_kind,
                start_match_by="name",
                end_match_by="id"
            )
            edges.append(has_task_edge)

    # 2. Create (ScheduledTask)-[RunsAs]->(Principal) edge
    # Use helper function to create principal ID with proper filtering
    principal_id = _create_principal_id(runas_user, fqdn_domain, task, bh_connector)
    
    if principal_id:
        # Prefer id (objectid/SID) matching, fall back to name matching
        # Note: In BloodHound, a node's 'id' property IS the objectid (SID for users/computers)
        user_object_id = None
        user_match_by = "name"  # Default fallback
        
        if user_map and principal_id in user_map:
            node_info = user_map[principal_id]
            
            if node_info is None:
                # User was queried but not found in BloodHound
                if not allow_orphans:
                    warn(f"Skipping RunsAs edge: User '{principal_id}' not found in BloodHound")
                    warn(f"  Task: {task_path}")
                    warn(f"  Use --allow-orphans to create edges to missing nodes")
                    skipped["users"] += 1
                    # Don't create this edge
                else:
                    # User opted in to orphaned edges - use name matching
                    debug(f"Creating orphaned edge for missing user: {principal_id}")
                    runs_as_edge = Edge(
                        start_node=task_object_id,
                        end_node=principal_id,
                        kind="RunsAs",
                        start_match_by="id",
                        end_match_by="name"
                    )
                    edges.append(runs_as_edge)
            else:
                # User exists in BloodHound
                node_id, object_id = node_info
                if object_id:  # If we have an objectid (SID)
                    user_object_id = object_id
                    user_match_by = "id"  # match_by='id' looks for node where id property == object_id (SID)
                    debug(f"Using id (objectid) for User: {principal_id} → {object_id}")
                else:
                    debug(f"No objectid for {principal_id}, falling back to name matching")
                
                runs_as_edge = Edge(
                    start_node=task_object_id,
                    end_node=user_object_id if user_object_id else principal_id,
                    kind="RunsAs",
                    start_match_by="id",
                    end_match_by=user_match_by
                )
                debug(f"Created RunsAs edge: {task_path} → {principal_id} (match_by={user_match_by})")
                edges.append(runs_as_edge)
        else:
            # User not in map - wasn't queried (shouldn't happen in normal flow)
            if not allow_orphans:
                warn(f"User '{principal_id}' not in resolution map - skipping RunsAs edge")
                skipped["users"] += 1
            else:
                # Fallback for orphaned mode
                runs_as_edge = Edge(
                    start_node=task_object_id,
                    end_node=principal_id,
                    kind="RunsAs",
                    start_match_by="id",
                    end_match_by="name"
                )
                edges.append(runs_as_edge)

    return edges, skipped
