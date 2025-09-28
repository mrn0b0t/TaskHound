import os


def good(msg: str):
    print(f"[+] {msg}")


def warn(msg: str):
    print(f"[!] {msg}")


def info(msg: str):
    print(f"[*] {msg}")


def debug(msg: str, exc_info: bool = False):
    """Debug logging - only prints if DEBUG environment variable is set or debug flag is enabled"""
    if os.getenv('DEBUG') or os.getenv('TASKHOUND_DEBUG'):
        print(f"[DEBUG] {msg}")
        if exc_info:
            import traceback
            traceback.print_exc()
