import os

_VERBOSE = False
_DEBUG = False


def set_verbosity(verbose: bool, debug: bool):
    global _VERBOSE, _DEBUG
    _VERBOSE = verbose
    _DEBUG = debug
    # Also set env var for compatibility with other modules that might check it
    if debug:
        os.environ["TASKHOUND_DEBUG"] = "1"


def status(msg: str):
    """Always print status message (concise output)"""
    print(msg)


def good(msg: str):
    if _VERBOSE or _DEBUG:
        print(f"[+] {msg}")


def warn(msg: str):
    print(f"[!] {msg}")


def error(msg: str):
    print(f"[-] {msg}")


def info(msg: str):
    if _VERBOSE or _DEBUG:
        print(f"[*] {msg}")


def debug(msg: str, exc_info: bool = False):
    """Debug logging - only prints if DEBUG environment variable is set or debug flag is enabled"""
    if _DEBUG or os.getenv("DEBUG") or os.getenv("TASKHOUND_DEBUG"):
        print(f"[DEBUG] {msg}")
        if exc_info:
            import traceback

            traceback.print_exc()
