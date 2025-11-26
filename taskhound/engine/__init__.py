# Engine package for task processing.
#
# This package provides the main processing functions for both online
# (live SMB) and offline (previously collected) task enumeration.

# Re-export SMB functions for backward compatibility with tests that patch
# these at the engine module level (e.g., @patch("taskhound.engine.smb_connect"))
from ..smb.connection import smb_connect
from ..smb.tasks import crawl_tasks
from .helpers import sort_tasks_by_priority
from .offline import process_offline_directory
from .online import process_target

__all__ = [
    "process_target",
    "process_offline_directory",
    "sort_tasks_by_priority",
    "smb_connect",
    "crawl_tasks",
]
