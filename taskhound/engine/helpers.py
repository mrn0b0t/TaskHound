# Helper utilities for task processing.
#
# Contains shared helper functions used by both online and offline
# processing modules.

from typing import List


def sort_tasks_by_priority(lines: List[str]) -> List[str]:
    """
    Sort task blocks by priority: TIER-0 > PRIV > TASK.

    Task blocks are separated by headers like [TIER-0], [PRIV], [TASK].
    This function groups lines into blocks and sorts them by priority.

    Args:
        lines: List of output lines containing task blocks

    Returns:
        Sorted list of lines with TIER-0 tasks first, then PRIV, then TASK
    """
    if not lines:
        return lines

    # Group lines into task blocks (each block starts with a header like [TIER-0])
    blocks = []
    current_block = []

    for line in lines:
        if line.startswith("\n[") and current_block:
            # Start of new block, save the previous one
            blocks.append(current_block)
            current_block = [line]
        else:
            current_block.append(line)

    # Don't forget the last block
    if current_block:
        blocks.append(current_block)

    # Define priority order
    def get_block_priority(block):
        if not block:
            return 3  # Unknown/default priority

        first_line = block[0]
        if "[TIER-0]" in first_line:
            return 0
        elif "[PRIV]" in first_line:
            return 1
        elif "[TASK]" in first_line:
            return 2
        else:
            return 3

    # Sort blocks by priority
    sorted_blocks = sorted(blocks, key=get_block_priority)

    # Flatten back to a single list
    result = []
    for block in sorted_blocks:
        result.extend(block)

    return result
