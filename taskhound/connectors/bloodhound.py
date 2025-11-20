#!/usr/bin/env python3
"""
Simple BloodHound Connector for TaskHound

Provides basic connectivity to BloodHound instances for real-time high-value user data.
Supports both BHCE (API) and Legacy (Neo4j Bolt) connections.

Author: 0xr0BIT
"""

import base64
import datetime
import hashlib
import hmac
import json
import re
from typing import Any, Dict, Optional

import requests

try:
    from neo4j import GraphDatabase
except ImportError:
    GraphDatabase = None
from ..utils.logging import good, info, warn


def _safe_get_sam(data: dict, key: str) -> str:
    """
    Safely extract SAM account name from data, handling None values.
    
    Args:
        data: Dictionary containing user data
        key: Key to look up ('SamAccountName', 'samaccountname', etc.)
        
    Returns:
        Lowercase SAM account name as string, empty string if None/missing
    """
    value = data.get(key, '')
    if value is None:
        return ''
    return str(value).lower()


def _sanitize_string_value(value: str) -> str:
    """
    Sanitize individual string values that might contain problematic backslashes.
    This is for processing individual field values from databases/APIs.
    """
    if not isinstance(value, str):
        return value

    # For individual string values, we just need to ensure they're properly handled
    # when converting to JSON later. The main issue is with JSON parsing, not storage.
    return value


def _sanitize_json_response(response_text: str) -> str:
    """
    Sanitize JSON response text to handle unescaped backslashes that break JSON parsing.
    
    This commonly occurs in Active Directory Distinguished Names like:
    "CN=LASTNAME\\, FIRSTNAME,OU=..."
    
    Args:
        response_text: Raw JSON response text that may contain unescaped backslashes
        
    Returns:
        Sanitized JSON string with properly escaped backslashes
    """
    # Replace single backslashes with double backslashes, but be careful not to
    # double-escape already escaped sequences

    # First, temporarily replace already properly escaped sequences
    import uuid
    placeholder = str(uuid.uuid4())

    # Protect already escaped sequences (\\, \", \n, \r, \t, \/, \b, \f, \u)
    protected = response_text.replace('\\\\', placeholder + 'BACKSLASH')
    protected = protected.replace('\\"', placeholder + 'QUOTE')
    protected = protected.replace('\\n', placeholder + 'NEWLINE')
    protected = protected.replace('\\r', placeholder + 'RETURN')
    protected = protected.replace('\\t', placeholder + 'TAB')
    protected = protected.replace('\\/', placeholder + 'SLASH')
    protected = protected.replace('\\b', placeholder + 'BACKSPACE')
    protected = protected.replace('\\f', placeholder + 'FORMFEED')

    # Protect unicode escapes (\uXXXX)
    import re
    unicode_pattern = r'\\u[0-9a-fA-F]{4}'
    unicode_matches = re.findall(unicode_pattern, protected)
    for i, match in enumerate(unicode_matches):
        protected = protected.replace(match, f'{placeholder}UNICODE{i}')

    # Now escape any remaining single backslashes
    protected = protected.replace('\\', '\\\\')

    # Restore the protected sequences
    protected = protected.replace(placeholder + 'BACKSLASH', '\\\\')
    protected = protected.replace(placeholder + 'QUOTE', '\\"')
    protected = protected.replace(placeholder + 'NEWLINE', '\\n')
    protected = protected.replace(placeholder + 'RETURN', '\\r')
    protected = protected.replace(placeholder + 'TAB', '\\t')
    protected = protected.replace(placeholder + 'SLASH', '\\/')
    protected = protected.replace(placeholder + 'BACKSPACE', '\\b')
    protected = protected.replace(placeholder + 'FORMFEED', '\\f')

    # Restore unicode escapes
    for i, match in enumerate(unicode_matches):
        protected = protected.replace(f'{placeholder}UNICODE{i}', match)

    return protected


class BloodHoundConnector:
    """Simple BloodHound connector for both BHCE and Legacy"""

    def __init__(self, bh_type: str, ip: str, username: Optional[str] = None, 
                 password: Optional[str] = None, api_key: Optional[str] = None, api_key_id: Optional[str] = None, timeout: int = 120):
        self.bh_type = bh_type  # 'bhce' or 'legacy'
        self.ip = ip
        self.username = username
        self.password = password
        self.api_key = api_key
        self.api_key_id = api_key_id
        self.timeout = timeout
        self.users_data = {}

    def _bhce_signed_request(self, method: str, uri: str, base_url: str, body: Optional[bytes] = None) -> requests.Response:
        """
        Make a signed request to BloodHound CE API using HMAC-SHA256 authentication.
        
        According to BloodHound CE API documentation, API key authentication uses
        hash-based message authentication code (HMAC) with the following signature chain:
        1. OperationKey: HMAC(api_key, method + uri)
        2. DateKey: HMAC(OperationKey, RFC3339_datetime[:13])  # truncated to hour
        3. Signature: HMAC(DateKey, body)  # body can be empty
        
        Args:
            method: HTTP method (GET, POST, etc.)
            uri: API endpoint path (e.g., '/api/version')
            base_url: Base URL of BloodHound CE instance
            body: Optional request body as bytes
            
        Returns:
            requests.Response object
        """
        # Initialize HMAC digester with API key as secret
        digester = hmac.new(self.api_key.encode(), None, hashlib.sha256)
        
        # OperationKey: HMAC digest of method + URI (no delimiter)
        # Example: GET/api/v2/test/resource
        digester.update(f'{method}{uri}'.encode())
        digester = hmac.new(digester.digest(), None, hashlib.sha256)
        
        # DateKey: HMAC digest of RFC3339 datetime truncated to hour
        # Example: 2020-12-01T23:59:60Z -> 2020-12-01T23
        datetime_formatted = datetime.datetime.now().astimezone().isoformat('T')
        digester.update(datetime_formatted[:13].encode())
        digester = hmac.new(digester.digest(), None, hashlib.sha256)
        
        # Body signing: HMAC digest of request body (or empty)
        if body is not None:
            digester.update(body)
        
        # Build headers with HMAC signature
        headers = {
            'Authorization': f'bhesignature {self.api_key_id}',
            'RequestDate': datetime_formatted,
            'Signature': base64.b64encode(digester.digest()).decode(),
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        
        # Make the signed request
        return requests.request(
            method=method,
            url=f'{base_url}{uri}',
            headers=headers,
            data=body,
            timeout=self.timeout
        )

    def connect_and_query(self) -> bool:
        """Connect to BloodHound and query high-value users"""
        try:
            if self.bh_type == 'bhce':
                return self._query_bhce()
            elif self.bh_type == 'legacy':
                return self._query_legacy()
            else:
                warn(f"Unknown BloodHound type: {self.bh_type}")
                return False
        except Exception as e:
            warn(f"BloodHound connection failed: {e}")
            return False

    def _query_bhce(self) -> bool:
        """Query BHCE via API"""
        # BHCE typically runs on port 8080
        base_url = f"http://{self.ip}:8080"

        # Get authentication headers
        try:
            # Choose authentication method
            use_api_key = self.api_key and self.api_key_id
            
            if use_api_key:
                info("Using API key authentication for BloodHound CE")
                # Test connection with HMAC-signed request
                response = self._bhce_signed_request('GET', '/api/version', base_url)
            else:
                # BHCE uses token-based authentication with username/password
                if not self.username or not self.password:
                    warn("BloodHound authentication requires either API key/ID pair or username/password")
                    return False
                    
                login_data = {
                    "login_method": "secret",
                    "username": self.username,
                    "secret": self.password
                }

                # Get authentication token
                login_response = requests.post(f"{base_url}/api/v2/login", json=login_data, timeout=10)
                if login_response.status_code == 401:
                    warn("BloodHound login failed - invalid credentials")
                    return False
                elif login_response.status_code != 200:
                    warn(f"BloodHound login failed - HTTP {login_response.status_code}")
                    return False

                # Extract token from response (with JSON sanitization)
                sanitized_response = _sanitize_json_response(login_response.text)
                token_data = json.loads(sanitized_response)
                if 'data' not in token_data or 'session_token' not in token_data['data']:
                    warn("BloodHound login failed - no token in response")
                    return False

                token = token_data['data']['session_token']
                headers = {
                    'Authorization': f'Bearer {token}',
                    'Content-Type': 'application/json',
                    'accept': 'application/json',
                    'Prefer': '0'
                }
                
                # Test connection with token
                response = requests.get(f"{base_url}/api/version", headers=headers, timeout=10)
            if response.status_code != 200:
                warn(f"BloodHound connection failed - HTTP {response.status_code}")
                return False

            good(f"Connected to BHCE at {self.ip}:8080")
            info("Collecting high-value user data - this may take a moment depending on database size and connection speed...")

        except requests.exceptions.ConnectionError:
            warn(f"BloodHound BHCE connection failed at {self.ip}:8080")
            warn("Check if BHCE is running and accessible")
            return False
        except requests.exceptions.Timeout:
            warn(f"BloodHound BHCE connection timed out at {self.ip}:8080")
            return False

        # Comprehensive query for BHCE - simplified format that BHCE actually supports
        # BHCE requires path-based queries, not direct property returns
        comprehensive_query = """
        MATCH (n)
        WHERE coalesce(n.system_tags, "") CONTAINS "admin_tier_0"
           OR n.highvalue = true
           OR n.admincount = true
        MATCH p = (n)-[:MemberOf*0..]->(g:Group)
        RETURN p
        """

        # Single comprehensive query for all users
        query_data = {
            "query": comprehensive_query,
            "include_properties": True
        }

        try:
            if use_api_key:
                # Use HMAC-signed request for API key authentication
                body = json.dumps(query_data).encode('utf-8')
                response = self._bhce_signed_request('POST', '/api/v2/graphs/cypher', base_url, body)
            else:
                # Use Bearer token for username/password authentication
                response = requests.post(
                    f"{base_url}/api/v2/graphs/cypher",
                    headers=headers,
                    json=query_data,
                    timeout=self.timeout
                )

            if response.status_code != 200:
                warn(f"BloodHound BHCE query failed - HTTP {response.status_code}")
                if response.status_code == 400:
                    warn("Query format error - check Cypher syntax")
                return False

            # Parse response with JSON sanitization
            sanitized_response = _sanitize_json_response(response.text)
            result = json.loads(sanitized_response)

            # Parse BHCE results - handle the actual BHCE response format
            if 'data' in result:
                response_data = result['data']
                users_found = set()  # Track unique users

                # BHCE returns nodes in a different format than expected
                if 'nodes' in response_data:
                    # Handle direct node results (from simple user queries)
                    nodes = response_data['nodes']
                    for node_id, node_data in nodes.items():
                        if node_data.get('kind') == 'User':
                            properties = node_data.get('properties', {})
                            # Get group memberships for this user
                            username = properties.get('samaccountname', '')
                            if use_api_key:
                                group_sids, group_names = self._get_user_groups_bhce_hmac(
                                    username, base_url
                                )
                            else:
                                group_sids, group_names = self._get_user_groups_bhce(
                                    username, headers, base_url
                                )
                            properties['group_sids'] = group_sids
                            properties['group_names'] = group_names
                            self._process_bhce_user(properties, users_found)

                elif isinstance(response_data, list):
                    # Handle list format (from path queries)
                    # Paths contain user→group relationships via MemberOf edges
                    for item in response_data:
                        if isinstance(item, dict) and 'segments' in item:
                            # Extract user and their group memberships from path
                            user_node = None
                            group_sids = []
                            group_names = []

                            for segment in item.get('segments', []):
                                start_node = segment.get('start', {})
                                end_node = segment.get('end', {})

                                # Find the user node (should be at start of path)
                                if start_node.get('labels') and 'User' in start_node['labels']:
                                    if user_node is None:
                                        user_node = start_node.get('properties', {})

                                # Collect groups from end nodes
                                if end_node.get('labels') and 'Group' in end_node['labels']:
                                    group_props = end_node.get('properties', {})
                                    group_sid = group_props.get('objectid', '')
                                    group_name = group_props.get('name', '')
                                    if group_sid and group_sid not in group_sids:
                                        group_sids.append(group_sid)
                                        group_names.append(group_name)

                            # Process user with collected group memberships
                            if user_node:
                                user_node['group_sids'] = group_sids
                                user_node['group_names'] = group_names
                                self._process_bhce_user(user_node, users_found)

                        # Handle direct user results (from fallback query)
                        elif isinstance(item, dict):
                            sam = _safe_get_sam(item, 'samaccountname')
                            if sam and sam not in users_found:
                                self._process_bhce_user(item, users_found)

                good(f"Retrieved {len(self.users_data)} high-value users from BHCE")
                return True
            else:
                warn("No data found in BHCE response")
                return True

        except requests.exceptions.Timeout:
            warn("BloodHound BHCE query timed out")
            return False

    def _query_legacy(self) -> bool:
        """Query Legacy BloodHound via Neo4j Bolt"""
        if GraphDatabase is None:
            warn("neo4j library not installed - required for Legacy BloodHound connection")
            warn("Install with: pip install neo4j")
            return False

        # Legacy BloodHound typically uses port 7687
        uri = f"bolt://{self.ip}:7687"

        try:
            driver = GraphDatabase.driver(uri, auth=(self.username, self.password))

            # Test connection
            with driver.session() as session:
                result = session.run("MATCH (n) RETURN count(n) LIMIT 1")
                result.single()[0]  # This will raise an exception if connection fails

            good(f"Connected to Legacy BloodHound at {self.ip}:7687")
            info("Collecting high-value user data - this may take a moment depending on database size and connection speed...")

        except Exception as e:
            if "authentication" in str(e).lower() or "credentials" in str(e).lower():
                warn("BloodHound login failed - invalid credentials")
            else:
                warn(f"BloodHound Legacy connection failed at {self.ip}:7687")
                warn("Check if Neo4j is running and accessible")
            return False

        # Comprehensive query for both high-value and Tier 0 users
        # This combines high-value detection with Tier 0 group membership
        comprehensive_query = """
        MATCH (u:User)
        WHERE u.highvalue = true
           OR u.admincount = true
        OPTIONAL MATCH (u)-[:MemberOf*1..]->(g:Group)
        WITH u, properties(u) as all_props, collect(g.name) as groups, collect(g.objectid) as group_sids
        RETURN u.samaccountname AS SamAccountName, all_props, groups, group_sids
        ORDER BY SamAccountName
        UNION
        MATCH (u:User)-[:MemberOf*1..]->(g:Group)
        WHERE g.objectid =~ 'S-1-5-32-544.*'
           OR g.objectid =~ '.*-512$'
           OR g.objectid =~ '.*-519$'
           OR g.objectid =~ '.*-518$'
           OR g.objectid =~ '.*-516$'
           OR g.objectid =~ '.*-526$'
           OR g.objectid =~ '.*-527$'
           OR g.objectid =~ '.*-500$'
        OPTIONAL MATCH (u)-[:MemberOf*1..]->(all_g:Group)
        WITH u, properties(u) as all_props, collect(all_g.name) as groups, collect(all_g.objectid) as group_sids
        RETURN u.samaccountname AS SamAccountName, all_props, groups, group_sids
        ORDER BY SamAccountName
        """

        try:
            with driver.session() as session:
                users_found = set()

                # Single comprehensive query instead of multiple queries
                try:
                    result = session.run(comprehensive_query)
                    for record in result:
                        self._process_legacy_user(record, users_found)

                    if len(users_found) == 0:
                        warn("No high-value or Tier 0 users found in Legacy BloodHound")
                    else:
                        good(f"Retrieved {len(users_found)} high-value users from Legacy BloodHound")

                except Exception as e:
                    warn(f"Legacy BloodHound query failed: {e}")
                    return False

            driver.close()
            return True

        except Exception as e:
            try:
                driver.close()
            except Exception:
                pass
            warn(f"BloodHound query execution failed: {e}")
            return False

    def _get_user_groups_bhce_hmac(self, username: str, base_url: str) -> tuple:
        """Get group memberships for a user in BHCE using HMAC-signed request"""
        if not username:
            return [], []

        try:
            # Query for this user's group memberships using samaccountname
            group_query = f"""
            MATCH (u:User {{samaccountname: "{username}"}})-[:MemberOf*1..]->(g:Group)
            RETURN g
            """

            query_data = {
                "query": group_query,
                "include_properties": True
            }

            body = json.dumps(query_data).encode('utf-8')
            response = self._bhce_signed_request('POST', '/api/v2/graphs/cypher', base_url, body)

            if response.status_code == 200:
                # Parse response with JSON sanitization
                sanitized_response = _sanitize_json_response(response.text)
                result = json.loads(sanitized_response)
                group_sids = []
                group_names = []

                # Parse the response to extract group data
                if 'data' in result and 'nodes' in result['data']:
                    nodes = result['data']['nodes']
                    for node_id, node_data in nodes.items():
                        if node_data.get('kind') == 'Group':
                            properties = node_data.get('properties', {}) or {}
                            objectid = properties.get('objectid', '') or ''
                            name = properties.get('name', '') or ''

                            if objectid:
                                group_sids.append(objectid)
                                group_names.append(name)

                return group_sids, group_names
            else:
                return [], []

        except Exception:
            return [], []

    def _get_user_groups_bhce(self, username: str, headers: dict, base_url: str) -> tuple:
        """Get group memberships for a user in BHCE"""
        if not username:
            return [], []

        try:
            # Query for this user's group memberships using samaccountname
            group_query = f"""
            MATCH (u:User {{samaccountname: "{username}"}})-[:MemberOf*1..]->(g:Group)
            RETURN g
            """

            query_data = {
                "query": group_query,
                "include_properties": True
            }

            response = requests.post(
                f"{base_url}/api/v2/graphs/cypher",
                headers=headers,
                json=query_data,
                timeout=10
            )

            if response.status_code == 200:
                # Parse response with JSON sanitization
                sanitized_response = _sanitize_json_response(response.text)
                result = json.loads(sanitized_response)
                group_sids = []
                group_names = []

                # Parse the response to extract group data
                if 'data' in result and 'nodes' in result['data']:
                    nodes = result['data']['nodes']
                    for node_id, node_data in nodes.items():
                        if node_data.get('kind') == 'Group':
                            properties = node_data.get('properties', {}) or {}
                            objectid = properties.get('objectid', '') or ''
                            name = properties.get('name', '') or ''

                            if objectid:
                                group_sids.append(objectid)
                                group_names.append(name)

                return group_sids, group_names
            else:
                return [], []

        except Exception:
            return [], []

    def _process_bhce_user(self, user_data: dict, users_found: set):
        """Process a user from BHCE format and add to users_data"""
        sam = _safe_get_sam(user_data, 'samaccountname')
        if not sam or sam in users_found:
            return

        users_found.add(sam)
        self.users_data[sam] = {
            'sid': user_data.get('objectid', user_data.get('sid', '')) or '',
            'samaccountname': sam,
            'domain': user_data.get('domain', '') or '',
            'admincount': user_data.get('admincount', False),
            'pwdlastset': user_data.get('pwdlastset'),
            'lastlogon': user_data.get('lastlogon'),
            'system_tags': user_data.get('system_tags', '') or '',
            'highvalue': user_data.get('highvalue', False),
            'groups': user_data.get('group_sids', []) or [],  # Actual group SIDs
            'group_names': user_data.get('group_names', []) or []
        }

    def _process_legacy_user(self, record, users_found: set):
        """Process a user from Legacy BloodHound format (matches README query)"""
        sam = _safe_get_sam(record, 'SamAccountName')
        if not sam or sam in users_found:
            return

        users_found.add(sam)
        all_props = record.get('all_props', {}) or {}  # Ensure it's never None
        groups = record.get('groups', []) or []        # Ensure it's never None
        group_sids = record.get('group_sids', []) or []  # Ensure it's never None

        # Ensure all_props is a dictionary
        if not isinstance(all_props, dict):
            all_props = {}

        self.users_data[sam] = {
            'SamAccountName': sam,
            'all_props': all_props,
            'groups': group_sids,  # SIDs for compatibility with existing code
            'group_names': groups,  # Display names
            # Extract common fields from all_props for compatibility (with None safety)
            'sid': all_props.get('objectid', '') or '',
            'samaccountname': sam,
            'domain': all_props.get('domain', '') or '',
            'admincount': all_props.get('admincount', False),
            'pwdlastset': all_props.get('pwdlastset'),
            'lastlogon': all_props.get('lastlogon'),
        }

    def search_node_by_name(self, name: str, node_type: str = "Computer") -> Optional[Dict[str, str]]:
        """
        Search for a node in BloodHound by name and return its node_id and objectId.
        
        Args:
            name: Node name to search for (e.g., "DC01.DOMAIN.LOCAL" or "ADMIN@DOMAIN.LOCAL")
            node_type: Type of node ("Computer" or "User")
            
        Returns:
            Dict with 'node_id' and 'object_id' keys, or None if not found
            Example: {"node_id": "19", "object_id": "S-1-5-21-...-1105"}
        """
        if self.bh_type != 'bhce':
            warn("search_node_by_name only supported for BHCE")
            return None
            
        base_url = f"http://{self.ip}:8080"
        query = f'MATCH (n:{node_type} {{name: "{name}"}}) RETURN n'
        
        try:
            # Use API key authentication if available
            if self.api_key and self.api_key_id:
                body = json.dumps({"query": query}, separators=(',', ':')).encode()
                response = self._bhce_signed_request('POST', '/api/v2/graphs/cypher', base_url, body)
            else:
                # Fall back to token authentication (would need to implement token storage)
                warn("Token authentication for search_node_by_name not implemented yet")
                return None
                
            if response.status_code == 200:
                data = response.json()
                nodes = data.get("data", {}).get("nodes", {})
                
                if nodes:
                    # Get first (and should be only) node
                    node_id = list(nodes.keys())[0]
                    node_data = nodes[node_id]
                    
                    return {
                        "node_id": node_id,
                        "object_id": node_data.get("objectId", ""),
                        "label": node_data.get("label", "")
                    }
            else:
                warn(f"BloodHound search failed: HTTP {response.status_code}")
                return None
                
        except Exception as e:
            warn(f"Error searching for {node_type} {name}: {e}")
            return None

    def query_domain_by_netbios(self, netbios_name: str) -> Optional[Dict[str, str]]:
        """
        Query BloodHound for domain by NETBIOS name using STARTS WITH matching.
        
        This handles NETBIOS → FQDN resolution for cross-domain tasks:
        - "THESIMPSONS" → "THESIMPSONS.SPRINGFIELD.LOCAL"
        - "DEV" → "DEV.CONTOSO.COM"
        
        Args:
            netbios_name: NETBIOS domain name (e.g., "THESIMPSONS", "DEV")
            
        Returns:
            Dict with 'name' (FQDN) and 'objectid' (domain SID), or None if not found
        """
        if self.bh_type != 'bhce':
            warn("Domain query only supported for BloodHound CE")
            return None
            
        try:
            # Handle both "hostname" and "http://hostname:port" formats
            if self.ip.startswith('http://') or self.ip.startswith('https://'):
                base_url = self.ip.rstrip('/')
            else:
                base_url = f"http://{self.ip}:8080"
            
            # Build Cypher query with case-insensitive STARTS WITH
            # Note: Must add '.' after NETBIOS to avoid matching parent domains
            # Example: "SPRINGFIELD." matches "SPRINGFIELD.LOCAL" not "THESIMPSONS.SPRINGFIELD.LOCAL"
            query_data = {
                "query": f"MATCH (d:Domain) WHERE toLower(d.name) STARTS WITH '{netbios_name.lower()}.' RETURN d"
            }
            
            # Choose authentication method
            use_api_key = self.api_key and self.api_key_id
            
            if use_api_key:
                body = json.dumps(query_data).encode('utf-8')
                response = self._bhce_signed_request('POST', '/api/v2/graphs/cypher', base_url, body)
            else:
                # Use Bearer token authentication (not implemented here, needs login flow)
                warn("Domain query requires API key authentication")
                return None
            
            # Handle response
            if response.status_code == 404:
                # BloodHound returns 404 for empty results - not an error
                return None
            elif response.status_code == 200:
                data = response.json()
                nodes = data.get('data', {}).get('nodes', {})
                
                if len(nodes) == 0:
                    return None
                elif len(nodes) == 1:
                    # Perfect match!
                    node = list(nodes.values())[0]
                    return {
                        'name': node.get('label'),
                        'objectid': node.get('objectId')
                    }
                else:
                    # Multiple matches - extremely rare but possible
                    # Log warning and return first match
                    domain_names = [n.get('label') for n in nodes.values()]
                    warn(f"Multiple domains match NETBIOS '{netbios_name}': {domain_names}")
                    node = list(nodes.values())[0]
                    return {
                        'name': node.get('label'),
                        'objectid': node.get('objectId')
                    }
            else:
                warn(f"Domain query failed: HTTP {response.status_code}")
                return None
                
        except Exception as e:
            warn(f"Error querying domain '{netbios_name}': {e}")
            return None

    def query_user_by_upn(self, upn: str) -> Optional[Dict[str, str]]:
        """
        Query BloodHound for user by UPN (User Principal Name).
        
        Validates that a user exists in BloodHound and retrieves their node info.
        Used for cross-domain user validation without requiring LDAP queries.
        
        Args:
            upn: User Principal Name (e.g., "ADMINISTRATOR@THESIMPSONS.SPRINGFIELD.LOCAL")
            
        Returns:
            Dict with 'name' (UPN), 'objectid' (user SID), and 'node_id' (BH node ID), or None if not found
        """
        if self.bh_type != 'bhce':
            warn("User query only supported for BloodHound CE")
            return None
            
        try:
            # Handle both "hostname" and "http://hostname:port" formats
            if self.ip.startswith('http://') or self.ip.startswith('https://'):
                base_url = self.ip.rstrip('/')
            else:
                base_url = f"http://{self.ip}:8080"
            
            # Build Cypher query - match by name (which is UPN for users in BloodHound)
            # Use case-insensitive matching for reliability
            query_data = {
                "query": f"MATCH (u:User) WHERE toLower(u.name) = '{upn.lower()}' RETURN u"
            }
            
            # Choose authentication method
            use_api_key = self.api_key and self.api_key_id
            
            if use_api_key:
                body = json.dumps(query_data).encode('utf-8')
                response = self._bhce_signed_request('POST', '/api/v2/graphs/cypher', base_url, body)
            else:
                warn("User query requires API key authentication")
                return None
            
            # Handle response
            if response.status_code == 404:
                # BloodHound returns 404 for empty results - not an error
                return None
            elif response.status_code == 200:
                data = response.json()
                nodes = data.get('data', {}).get('nodes', {})
                
                if len(nodes) == 0:
                    return None
                elif len(nodes) == 1:
                    # User found!
                    node_id = list(nodes.keys())[0]
                    node = list(nodes.values())[0]
                    return {
                        'name': node.get('label'),
                        'objectid': node.get('objectId'),
                        'node_id': node_id
                    }
                else:
                    # Multiple matches - should never happen for UPN (unique), but handle it
                    warn(f"Multiple users match UPN '{upn}': {[n.get('label') for n in nodes.values()]}")
                    node_id = list(nodes.keys())[0]
                    node = list(nodes.values())[0]
                    return {
                        'name': node.get('label'),
                        'objectid': node.get('objectId'),
                        'node_id': node_id
                    }
            else:
                warn(f"User query failed: HTTP {response.status_code}")
                return None
                
        except Exception as e:
            warn(f"Error querying user '{upn}': {e}")
            return None

    def validate_and_resolve_cross_domain_user(self, netbios_domain: str, username: str) -> Optional[Dict[str, str]]:
        """
        Complete cross-domain user resolution workflow:
        1. Resolve NETBIOS domain to FQDN via BloodHound
        2. Construct UPN with resolved FQDN
        3. Validate user exists in BloodHound
        4. Return user info with SID and node ID
        
        This replaces LDAP-based resolution and works across domain trusts
        without requiring additional credentials or network access.
        
        Args:
            netbios_domain: NETBIOS domain name (e.g., "THESIMPSONS", "DEV")
            username: Username without domain (e.g., "ADMINISTRATOR")
            
        Returns:
            Dict with 'name' (full UPN), 'objectid' (SID), 'node_id', 'domain_fqdn', and 'error_reason', 
            or None if not found (with error_reason indicating what failed)
        """
        # Step 1: Resolve domain
        domain_info = self.query_domain_by_netbios(netbios_domain)
        if not domain_info:
            return {'error_reason': 'domain_not_found', 'domain': netbios_domain}
        
        domain_fqdn = domain_info['name']
        
        # Step 2: Construct UPN and query for user
        upn = f"{username.upper()}@{domain_fqdn}"
        user_info = self.query_user_by_upn(upn)
        
        if not user_info:
            return {
                'error_reason': 'user_not_found', 
                'domain': netbios_domain,
                'domain_fqdn': domain_fqdn,
                'username': username,
                'upn': upn
            }
        
        # Step 3: Return combined info
        return {
            'name': user_info['name'],
            'objectid': user_info['objectid'],
            'node_id': user_info['node_id'],
            'domain_fqdn': domain_fqdn,
            'domain_sid': domain_info['objectid'],
            'error_reason': None  # Success
        }

    def get_users_data(self) -> Dict[str, Any]:
        """Get the retrieved users data"""
        return self.users_data

    def save_to_file(self, filepath: str) -> bool:
        """Save users data to JSON file (compatible with --bh-data)"""
        try:
            # Convert to list format (compatible with existing HighValueLoader)
            users_list = list(self.users_data.values())

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(users_list, f, indent=2, default=str)

            good(f"BloodHound data saved to {filepath}")
            return True

        except Exception as e:
            warn(f"Failed to save BloodHound data: {e}")
            return False


def connect_bloodhound(args) -> Optional[Dict[str, Any]]:
    """
    Connect to BloodHound and retrieve high-value users data
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        Dictionary of users data or None if connection failed
    """
    if not args.bh_live:
        return None

    # Determine BloodHound type
    bh_type = 'bhce' if args.bhce else 'legacy'
    is_legacy = bh_type == 'legacy'

    # Extract just the hostname/IP from the connector URI
    # The connector expects just the hostname, as it adds its own ports
    from ..output.bloodhound import extract_host_from_connector
    connector_host = extract_host_from_connector(args.bh_connector)

    display_type = 'BHCE' if args.bhce else 'Legacy'
    good(f"Connecting to {display_type} BloodHound at {connector_host}...")

    # Create connector and attempt connection
    connector = BloodHoundConnector(
        bh_type=bh_type,
        ip=connector_host,  # Just the hostname, connector adds ports
        username=args.bh_user,
        password=args.bh_password,
        api_key=getattr(args, 'bh_api_key', None),
        api_key_id=getattr(args, 'bh_api_key_id', None),
        timeout=getattr(args, 'bh_timeout', 120)
    )

    if connector.connect_and_query():
        users_data = connector.get_users_data()

        # Save to file if requested
        if args.bh_save:
            connector.save_to_file(args.bh_save)

        return users_data
    else:
        warn("BloodHound connection failed - continuing without high-value data")
        return None
