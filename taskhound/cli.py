import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

from .config import build_parser, validate_args
from .engine import process_offline_directory, process_target
from .engine_async import (
    AsyncConfig,
    AsyncTaskHound,
    aggregate_results,
    print_summary as print_async_summary,
)
from .laps import (
    LAPSCache,
    LAPSConnectionError,
    LAPSEmptyCacheError,
    LAPSFailure,
    get_laps_passwords,
    print_laps_summary,
)
from .opengraph import generate_opengraph_files
from .output.bloodhound import upload_opengraph_to_bloodhound
from .output.printer import print_results
from .output.summary import print_summary_table
from .output.writer import write_csv, write_json, write_plain
from .parsers.highvalue import HighValueLoader
from .utils.cache_manager import init_cache
from .utils.date_parser import parse_timestamp
from .utils.helpers import BANNER, normalize_targets
from .utils.logging import debug, good, info, set_verbosity, warn
from .utils.network import verify_ldap_connection


def main():
    print(BANNER)
    ap = build_parser()
    args = ap.parse_args()

    # Set verbosity early
    set_verbosity(args.verbose, args.debug)

    validate_args(args)

    # Initialize Cache
    cache_file = Path(args.cache_file) if args.cache_file else None
    cache = init_cache(ttl_hours=args.cache_ttl / 3600, enabled=not args.no_cache, cache_file=cache_file)
    if args.clear_cache:
        cache.invalidate()
        info("Cache cleared")

    # Auto-enable icon setting on first run if OpenGraph is enabled
    if args.bh_opengraph and cache.is_new_db and not args.bh_set_icon:
        info("First run detected: Enabling custom icon for Scheduled Tasks in BloodHound")
        args.bh_set_icon = True

    # Load HighValue data - either from file or live BloodHound connection
    hv = None
    hv_loaded = False

    # Try BloodHound live connection first
    bh_connector = None
    if args.bh_live:
        try:
            from .connectors import connect_bloodhound

            users_data, bh_connector = connect_bloodhound(args)
            if users_data:
                # Create a temporary HighValueLoader with the live data
                hv = HighValueLoader("")  # Empty path since we have live data

                # Convert timestamps to datetime objects (like HighValueLoader.load() does)
                for _, user_data in users_data.items():
                    if "pwdlastset" in user_data:
                        user_data["pwdlastset"] = parse_timestamp(user_data["pwdlastset"])
                    if "lastlogon" in user_data:
                        user_data["lastlogon"] = parse_timestamp(user_data["lastlogon"])

                hv.hv_users = users_data
                hv.hv_sids = {}

                # Build SID lookup from users data
                for sam, user_data in users_data.items():
                    if "sid" in user_data and user_data["sid"]:
                        hv.hv_sids[user_data["sid"].upper()] = user_data
                        hv.hv_sids[user_data["sid"].upper()]["sam"] = sam

                hv.loaded = True
                hv.format_type = "bloodhound_live"
                hv_loaded = True
                good(f"Live BloodHound data loaded ({len(users_data)} users)")

                # Test LDAP SID resolution capability
                verify_ldap_connection(
                    args.domain,
                    args.dc_ip,
                    args.username,
                    args.password,
                    args.hashes,
                    args.kerberos,
                    args.no_ldap,
                    args.ldap_domain,
                    args.ldap_user,
                    args.ldap_password,
                    args.ldap_hashes,
                    hv,
                )
            # No else clause needed - connector already prints specific error messages

        except ImportError as e:
            warn(f"BloodHound connector not available: {e}")
            warn("Continuing without high-value data")

    # Fall back to file-based loading if no live connection
    elif args.bh_data:
        hv = HighValueLoader(args.bh_data)
        if hv.load():
            good("High Value target data loaded from file")
            hv_loaded = True
        else:
            warn("Failed to load High Value target data from file")

    # Initialize LAPS if requested (online mode only)
    laps_cache: Optional[LAPSCache] = None
    laps_failures: List[LAPSFailure] = []
    laps_successes: int = 0

    if getattr(args, "laps", False) and not args.offline:
        info("LAPS mode enabled - querying Active Directory for LAPS passwords...")
        try:
            laps_cache = get_laps_passwords(
                dc_ip=args.dc_ip,
                domain=args.domain,
                username=args.username,
                password=args.password,
                hashes=args.hashes,
                kerberos=args.kerberos,
                laps_user_override=getattr(args, "laps_user", None),
                use_cache=not args.no_cache,
            )
            stats = laps_cache.get_statistics()
            good(f"LAPS: Loaded {stats['usable']} usable passwords ({stats['mslaps']} Windows LAPS, {stats['legacy']} Legacy LAPS)")
            if stats["encrypted"] > 0:
                warn(f"LAPS: {stats['encrypted']} encrypted passwords failed to decrypt (check MS-GKDI access)")
        except LAPSConnectionError as e:
            print(f"[!] LAPS initialization failed: {e}")
            print("[!] Cannot continue with LAPS mode - check your credentials and DC connectivity")
            sys.exit(1)
        except LAPSEmptyCacheError as e:
            print(f"[!] {e}")
            print("[!] No LAPS passwords found - your account may lack read permissions")
            print("[!] Required permissions: 'Read ms-Mcs-AdmPwd' or 'Read msLAPS-Password' on computer objects")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Unexpected LAPS error: {e}")
            if args.debug:
                import traceback
                traceback.print_exc()
            sys.exit(1)

    # Process based on mode
    all_rows: List[Dict] = []

    if args.offline:
        # Offline mode: process XML files from directory
        lines = process_offline_directory(
            offline_dir=args.offline,
            hv=hv,
            show_unsaved_creds=args.unsaved_creds,
            include_local=args.include_local,
            all_rows=all_rows,
            debug=args.debug,
            no_ldap=args.no_ldap,
            dpapi_key=args.dpapi_key,
            concise=not args.verbose,
        )
        print_results(lines)
    else:
        # Online mode: process targets via SMB
        # Build targets list
        targets = []
        if args.target:
            # Support comma-separated targets: -t 192.168.1.1,192.168.1.2,192.168.1.3
            for t in args.target.split(","):
                t = t.strip()
                if t:
                    targets.append(t)
        if args.targets_file:
            with open(args.targets_file, encoding="utf-8") as f:
                targets.extend([line.strip() for line in f if line.strip()])

        # Normalize (append domain for short names; leave IPs as-is)
        targets = normalize_targets(targets, args.domain)

        # Common kwargs for process_target
        process_kwargs = dict(
            domain=args.domain,
            username=args.username,
            password=args.password,
            kerberos=args.kerberos,
            dc_ip=args.dc_ip,
            include_ms=args.include_ms,
            include_local=args.include_local,
            hv=hv,
            debug=args.debug,
            hashes=args.hashes,
            show_unsaved_creds=args.unsaved_creds,
            backup_dir=args.backup,
            credguard_detect=args.credguard_detect,
            no_ldap=args.no_ldap,
            ldap_domain=args.ldap_domain,
            ldap_user=args.ldap_user,
            ldap_password=args.ldap_password,
            ldap_hashes=args.ldap_hashes,
            loot=args.loot,
            dpapi_key=args.dpapi_key,
            bh_connector=bh_connector,
            concise=not args.verbose,
            timeout=args.timeout,
            opsec=args.opsec,
            laps_cache=laps_cache,
            validate_creds=args.validate_creds,
        )

        # Parallel mode (--threads > 1)
        if args.threads > 1:
            async_config = AsyncConfig(
                workers=args.threads,
                rate_limit=args.rate_limit,
                timeout=args.timeout,
                show_progress=True,
            )
            async_engine = AsyncTaskHound(async_config)

            start_time = time.perf_counter()
            results = async_engine.run(targets, process_target, **process_kwargs)
            elapsed_ms = (time.perf_counter() - start_time) * 1000

            # Aggregate results
            all_rows, laps_failures, laps_successes = aggregate_results(results)

            # Print results (already captured in results)
            for result in results:
                if result.lines:
                    print_results(result.lines)
                if args.plain and result.lines:
                    write_plain(args.plain, result.target, result.lines)

            # Print summary
            print_async_summary(results, laps_failures, laps_successes, elapsed_ms)

        else:
            # Sequential mode (default, --threads 1)
            for tgt in targets:
                lines, laps_result = process_target(
                    target=tgt,
                    all_rows=all_rows,
                    **process_kwargs,
                )
                # Track LAPS results
                if laps_result is not None:
                    if laps_result is True:
                        laps_successes += 1
                    elif isinstance(laps_result, LAPSFailure):
                        laps_failures.append(laps_result)
                print_results(lines)
                if args.plain and lines:
                    write_plain(args.plain, tgt, lines)

    # Exports
    # Auto-generate JSON if OpenGraph is enabled and no explicit JSON output was specified
    if args.bh_opengraph and not args.json:
        # Create output directory if it doesn't exist
        import os

        os.makedirs(args.bh_output, exist_ok=True)

        # Generate JSON path
        json_path = f"{args.bh_output}/taskhound_data.json"

        # Warn if file already exists (will be overwritten)
        if os.path.exists(json_path):
            warn(f"OpenGraph will overwrite existing file: {json_path}")

        # Inform user about auto-generation and how to customize
        info(f"Auto-generating JSON for OpenGraph: {json_path}")
        info("To use a different path, specify --json <path>")

        args.json = json_path

    if args.json:
        write_json(args.json, all_rows)
    if args.csv:
        write_csv(args.csv, all_rows)
    if args.opengraph:
        generate_opengraph_files(args.opengraph, all_rows)

    # Print summary by default (unless disabled)
    if not args.no_summary:
        backup_dir = args.backup if hasattr(args, "backup") and args.backup else None
        print_summary_table(all_rows, backup_dir, hv_loaded)
        
        # Print LAPS summary if LAPS was used
        if laps_cache is not None:
            print_laps_summary(laps_cache, laps_successes, laps_failures)

    # BloodHound OpenGraph Integration
    if args.bh_opengraph:
        from .config_model import BloodHoundConfig

        print()
        info("BloodHound OpenGraph Integration")
        print("-" * 50)

        # Create consolidated config from args
        bh_config = BloodHoundConfig.from_args_and_config(args)

        # Build LDAP config for fallback resolution
        # Use dedicated LDAP credentials if provided, otherwise use main auth
        ldap_domain = getattr(args, "ldap_domain", None) or args.domain
        ldap_user = getattr(args, "ldap_user", None) or args.username
        ldap_password = getattr(args, "ldap_password", None) or args.password

        ldap_config = None
        if ldap_domain and ldap_user and (ldap_password or args.hashes):
            ldap_config = {
                "domain": ldap_domain,
                "dc_ip": args.dc_ip,
                "username": ldap_user,
                "password": ldap_password,
                "hashes": args.hashes,
                "kerberos": args.kerberos,
            }
            debug("LDAP fallback enabled for objectId resolution")
        else:
            info("LDAP fallback disabled - missing credentials")

        # Create connector if credentials exist
        bh_connector = None
        if bh_config.has_credentials():
            from .connectors.bloodhound import BloodHoundConnector
            from .output.bloodhound import extract_host_from_connector

            host = extract_host_from_connector(bh_config.bh_connector)
            bh_connector = BloodHoundConnector(
                bh_type=bh_config.bh_type or "bhce",
                ip=host,
                username=bh_config.bh_username,
                password=bh_config.bh_password,
                api_key=bh_config.bh_api_key,
                api_key_id=bh_config.bh_api_key_id,
            )

        # Generate OpenGraph files with BloodHound API integration for objectId resolution
        opengraph_file = generate_opengraph_files(
            output_dir=bh_config.bh_output,
            tasks=all_rows,
            bh_connector=bh_connector,
            ldap_config=ldap_config,
            allow_orphans=getattr(args, "allow_orphans", False),
        )

        # Upload to BloodHound if not disabled and we have credentials
        if not bh_config.bh_no_upload:
            if bh_config.has_credentials():
                print()
                success = upload_opengraph_to_bloodhound(
                    opengraph_file=opengraph_file,
                    bloodhound_url=bh_config.bh_connector,
                    username=bh_config.bh_username,
                    password=bh_config.bh_password,
                    api_key=bh_config.bh_api_key,
                    api_key_id=bh_config.bh_api_key_id,
                    set_icon=bh_config.bh_set_icon,
                    force_icon=bh_config.bh_force_icon,
                    icon_name=bh_config.bh_icon,
                    icon_color=bh_config.bh_color,
                )

                if not success:
                    warn("OpenGraph upload failed - files are still saved locally")
                    warn("You can upload manually via BloodHound UI")
            else:
                warn("No BloodHound credentials available - skipping upload")
                warn("Configure credentials in config/bh_connector.config or use CLI flags")
        else:
            info(f"OpenGraph file generated: {opengraph_file}")
            info("Upload disabled with --bh-no-upload")
