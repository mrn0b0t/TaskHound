# TaskHound

**Windows Privileged Scheduled Task Discovery Tool** for fun and profit.

TaskHound hunts for Windows scheduled tasks that run with privileged accounts and stored credentials. It enumerates tasks over SMB, parses XMLs, and identifies high-value attack opportunities through BloodHound export support.

## Key Features

- **Tier 0 Detection**: Automatically tries to identifiy tasks running as Domain Admins, Enterprise Admins, and other Tier 0 accounts.
- **BloodHound Integration**: Supports CSV/JSON exports with group membership analysis
- **Offline Analysis**: Process previously collected XML files
- **BOF**: BOF implementation for AdaptixC2 (see [BOF/README.md](BOF/README.md))

## Quick Start

```bash
# Install
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install .

# Basic usage
taskhound -u 'homer.simpson' -p 'P@ssw0rd' -d 'thesimpsons.local' -t 'TARGET_HOST'

# With BloodHound data support
taskhound -u 'homer.simpson' -p 'P@ssw0rd' -d 'thesimpsons.local' -t 'TARGET_HOST' --bh-data bloodhound_export.json
```

## Demo Output

```
TTTTT  AAA   SSS  K   K H   H  OOO  U   U N   N DDDD
  T   A   A S     K  K  H   H O   O U   U NN  N D   D
  T   AAAAA  SSS  KKK   HHHHH O   O U   U N N N D   D
  T   A   A     S K  K  H   H O   O U   U N  NN D   D
  T   A   A SSSS  K   K H   H  OOO   UUU  N   N DDDD

                     by 0xr0BIT

[+] High Value target data loaded
[+] moe.thesimpsons.local: Connected via SMB
[+] moe.thesimpsons.local: Local Admin Access confirmed
[*] moe.thesimpsons.local: Crawling Scheduled Tasks (skipping \Microsoft for speed)
[+] moe.thesimpsons.local: Found 7 tasks, privileged 2

[TIER-0] Windows\System32\Tasks\BackupTask
        Enabled : True
        RunAs   : THESIMPSONS\Administrator
        What    : C:\Scripts\backup.exe --daily
        Author  : THESIMPSONS\Administrator  
        Date    : 2025-09-18T23:04:37.3089851
        Reason  : Tier 0 group membership: Domain Admins, Administrators, Enterprise Admins
        Password Analysis : Password changed BEFORE task creation - stored password likely valid
        Next Step: DPAPI Dump / Task Manipulation

[PRIV] Windows\System32\Tasks\MaintenanceTask
        Enabled : True
        RunAs   : THESIMPSONS\marge.simpson
        What    : C:\Tools\cleanup.exe
        Author  : THESIMPSONS\Administrator
        Date    : 2025-09-18T23:05:43.0854575
        Reason  : High Value match found
        Password Analysis : Password changed BEFORE task creation - stored password likely valid
        Next Step: DPAPI Dump / Task Manipulation

[TASK] Windows\System32\Tasks\SIDTask  
        Enabled : True
        RunAs   : Administrator (S-1-5-21-3211413907-14631080-1147255650-500)
        What    : C:\Windows\System32\cmd.exe /c backup
        Author  : SYSTEM
        Date    : 2025-09-15T08:15:22.1234567

[TASK] Windows\System32\Tasks\UserTask
        Enabled : False
        RunAs   : THESIMPSONS\bart.simpson
        What    : C:\Windows\System32\notepad.exe
        Author  : THESIMPSONS\bart.simpson
        Date    : 2025-09-18T12:30:15.1234567

================================================================================
SUMMARY
================================================================================
HOSTNAME                | TIER-0_TASKS | PRIVILEGED_TASKS | NORMAL_TASKS
------------------------------------------------------------------------
moe.thesimpsons.local   | 1            | 1                | 6           
================================================================================
[+] Check the output above or your saved files for detailed task information
```

## BloodHound Integration

### Tier 0 Detection
TaskHound automatically detects default Tier 0 accounts based on group memberships:
- **Schema Admins**
- **Enterprise Admins** 
- **Domain Admins**
- **Administrators**
- **etc...**

### Data Export from BloodHound

TaskHound accepts CSV or JSON files with the following required fields:
- `SamAccountName` (required)  
- `sid` (required)
- `groups` or `group_names` (optional, for Tier 0 detection)
- `pwdlastset` and `lastlogon` (optional, for password age analysis)

#### Quick High-Value Marking (Warning: can be heavy and cause False Positives)
```cypher
// Mark all accounts with "ADMIN" in the name as high-value
MATCH (n) WHERE toUpper(n.name) CONTAINS "ADMIN"
OR toUpper(n.azname) CONTAINS "ADMIN"  
OR toUpper(n.objectid) CONTAINS "ADMIN"
SET n.highvalue = true, n.highvaluereason = 'Node matched ADMIN keyword'
RETURN n
```

#### Basic High-Value Users Query
```cypher
MATCH (u:User {highvalue:true})
RETURN u.samaccountname AS SamAccountName, u.objectid as sid
ORDER BY u.samaccountname
```

#### Enhanced Query with Group Memberships
```cypher
MATCH (u:User {highvalue:true})
OPTIONAL MATCH (u)-[:MemberOf*1..]->(g:Group)
WITH u, collect(g.name) as groups, collect(g.objectid) as group_sids
RETURN u.samaccountname AS SamAccountName, u.objectid as sid,
       groups as group_names, group_sids as groups,
       u.pwdlastset as pwdlastset, u.lastlogon as lastlogon
ORDER BY u.samaccountname
```

#### Lazy Query - Export ALL BloodHound Attributes (Recommended)
```cypher
MATCH (u:User {highvalue:true})
OPTIONAL MATCH (u)-[:MemberOf*1..]->(g:Group)
WITH u, properties(u) as all_props, collect(g.name) as groups, collect(g.objectid) as group_sids
RETURN u.samaccountname AS SamAccountName, all_props, groups, group_sids
ORDER BY SamAccountName
```

> **Note**: The lazy query format only works with JSON export. The `all_props` field contains all BloodHound user attributes automatically, making it much more maintainable than manually specifying each field.

## SID Resolution

TaskHound tries to automatically resolve SIDs to samaccountnames for improved readability when encountered in a task.
Before using any outbound connection, it will try to resolve them using the supplied BloodHound data.
If there is no data found or wasn't supplied, taskhound will then try to look up the SID via LDAP unless supressed with `--no-ldap`

> **NOTE**: To use this reliably with kerberos auth you need a working krb5.conf.  

## EXPERIMENTAL Features

> **WARNING**  
> Features in this section are **UNSAFE** for production environments. Limited testing has been done in lab environments. Don't blame me if something blows up your op or gets you busted. You have been warned.

### Credential Guard Detection

Checks remote registry for Credential Guard status to determine DPAPI dump feasibility. Results include `"credential_guard": true/false` in output.

### BOF Implementation
See [BOF/README.md](BOF/README.md) for a Beacon Object File implementation of the core collection functionality.

## Full Usage Reference

```
Usage: taskhound [-h] [-u USERNAME] [-p PASSWORD] [-d DOMAIN] [--hashes HASHES] 
                 [-k] [-t TARGET] [--targets-file TARGETS_FILE] [--dc-ip DC_IP]
                 [--offline OFFLINE] [--bh-data BH_DATA] [--include-ms] 
                 [--include-local] [--include-all] [--unsaved-creds] [--no-ldap]
                 [--credguard-detect] [--plain PLAIN] [--json JSON] [--csv CSV] 
                 [--backup BACKUP] [--no-summary] [--debug]

Authentication:
  -u, --username        Username (required for online mode)
  -p, --password        Password (omit with -k for Kerberos/ccache)  
  -d, --domain          Domain (required for online mode)
  --hashes HASHES       NTLM hashes (LM:NT or NT-only format)
  -k, --kerberos        Use Kerberos authentication (supports ccache)

Targets:
  -t, --target          Single target hostname/IP
  --targets-file        File with targets, one per line
  --dc-ip               Domain controller IP (required for Kerberos without DNS)

Scanning:
  --offline OFFLINE     Parse previously collected XML files from directory
  --bh-data BH_DATA     BloodHound export file (CSV/JSON) for high-value detection
  --include-ms          Include \Microsoft tasks (WARNING: very slow)
  --include-local       Include local system accounts (NT AUTHORITY\SYSTEM, etc.)
  --include-all         Include ALL tasks (combines --include-ms, --include-local, 
                        --unsaved-creds - WARNING: very slow and noisy)
  --unsaved-creds       Show tasks without stored credentials
  --no-ldap             Disable LDAP queries for SID resolution
  --credguard-detect    EXPERIMENTAL: Detect Credential Guard via remote registry

Output:
  --plain PLAIN         Save plain text output per target
  --json JSON           Export results to JSON file  
  --csv CSV             Export results to CSV file
  --backup BACKUP       Save raw XML files for offline analysis
  --no-summary          Disable summary table (shown by default)
  --debug               Enable debug output and full stack traces
```

## OPSEC Considerations

TaskHound relies heavily on impacket for SMB/RPC/Kerberos operations. Standard impacket IOCs apply.
**If you really care about OPSEC**: Use the BOF implementation or collect tasks manually, then analyze offline.

## Roadmap

When caffeine intake and free time align:
- Support custom Tier-0 mappings instead of just the default ones
- Support for more languages via custom mapping logic
- True BloodHound Community Edition export compatibility
- OpenGraph integration for attack path mapping  
- Dedicated NetExec module (PR in Review)
- Automated credential blob extraction for offline decryption

## Disclaimer

TaskHound is strictly an **audit and educational tool**. Use only in environments you own or where you have explicit authorization to test. Seriously. Don't be a jerk.

## Contributing

PRs welcome. Don't expect wonders though - half of this was caffeine-induced vibe-coding.

## License

Use responsibly. No warranty provided. See `LICENSE` for details.
