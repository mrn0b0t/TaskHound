"""
Test suite for engine helper functions.

Tests cover:
- sort_tasks_by_priority function
- Task block parsing and grouping
- Priority ordering (TIER-0 > PRIV > TASK)
"""

import pytest

from taskhound.engine.helpers import sort_tasks_by_priority


# ============================================================================
# Unit Tests: sort_tasks_by_priority
# ============================================================================


class TestSortTasksByPriority:
    """Tests for sort_tasks_by_priority function"""

    def test_empty_list(self):
        """Should return empty list for empty input"""
        result = sort_tasks_by_priority([])
        assert result == []

    def test_single_tier0_block(self):
        """Should return single TIER-0 block unchanged"""
        lines = [
            "\n[TIER-0] High Priority Task",
            "  - Task details here",
            "  - More details"
        ]
        result = sort_tasks_by_priority(lines)
        assert result == lines

    def test_single_priv_block(self):
        """Should return single PRIV block unchanged"""
        lines = [
            "\n[PRIV] Privileged Task",
            "  - Task details"
        ]
        result = sort_tasks_by_priority(lines)
        assert result == lines

    def test_single_task_block(self):
        """Should return single TASK block unchanged"""
        lines = [
            "\n[TASK] Regular Task",
            "  - Task details"
        ]
        result = sort_tasks_by_priority(lines)
        assert result == lines

    def test_tier0_sorted_first(self):
        """TIER-0 should be sorted before PRIV"""
        lines = [
            "\n[PRIV] Privileged Task",
            "  - PRIV details",
            "\n[TIER-0] High Priority Task",
            "  - TIER-0 details"
        ]
        result = sort_tasks_by_priority(lines)
        
        # TIER-0 should come first
        assert "[TIER-0]" in result[0]
        assert "[PRIV]" in result[2]

    def test_priv_sorted_before_task(self):
        """PRIV should be sorted before TASK"""
        lines = [
            "\n[TASK] Regular Task",
            "  - TASK details",
            "\n[PRIV] Privileged Task",
            "  - PRIV details"
        ]
        result = sort_tasks_by_priority(lines)
        
        # PRIV should come first
        assert "[PRIV]" in result[0]
        assert "[TASK]" in result[2]

    def test_full_priority_order(self):
        """Should sort in order: TIER-0 > PRIV > TASK"""
        lines = [
            "\n[TASK] Regular Task",
            "  - TASK details",
            "\n[TIER-0] High Priority Task",
            "  - TIER-0 details",
            "\n[PRIV] Privileged Task",
            "  - PRIV details"
        ]
        result = sort_tasks_by_priority(lines)
        
        # Check order
        tier0_index = next(i for i, l in enumerate(result) if "[TIER-0]" in l)
        priv_index = next(i for i, l in enumerate(result) if "[PRIV]" in l)
        task_index = next(i for i, l in enumerate(result) if "[TASK]" in l)
        
        assert tier0_index < priv_index < task_index

    def test_multiple_same_priority(self):
        """Should handle multiple blocks of same priority"""
        lines = [
            "\n[TASK] Task 1",
            "  - Task 1 details",
            "\n[TASK] Task 2",
            "  - Task 2 details",
            "\n[TIER-0] Important",
            "  - Important details"
        ]
        result = sort_tasks_by_priority(lines)
        
        # TIER-0 should be first
        assert "[TIER-0]" in result[0]

    def test_preserves_block_content(self):
        """Should preserve all lines within a block"""
        lines = [
            "\n[PRIV] Task",
            "  Line 1",
            "  Line 2",
            "  Line 3",
            "\n[TIER-0] Another Task",
            "  Important Line"
        ]
        result = sort_tasks_by_priority(lines)
        
        # All original lines should be present
        assert len(result) == len(lines)
        assert "Line 1" in result[3]  # Should be after TIER-0 block
        assert "Line 2" in result[4]
        assert "Line 3" in result[5]

    def test_unknown_header_sorted_last(self):
        """Unknown headers should be sorted last"""
        lines = [
            "\n[TIER-0] Important Task",
            "  - Details",
            "\n[UNKNOWN] Mystery Task",
            "  - Mystery details"
        ]
        result = sort_tasks_by_priority(lines)
        
        # TIER-0 should be first, UNKNOWN last
        assert "[TIER-0]" in result[0]
        assert "[UNKNOWN]" in result[2]

    def test_lines_without_header_grouped(self):
        """Lines without headers should be grouped together"""
        lines = [
            "Initial line without header",
            "\n[TASK] Task Block",
            "  - Task details"
        ]
        result = sort_tasks_by_priority(lines)
        
        # Should preserve structure
        assert len(result) == len(lines)

    def test_none_input_handled(self):
        """Should handle None-like falsy input"""
        result = sort_tasks_by_priority([])
        assert result == []

    def test_complex_multi_block(self):
        """Should handle complex multi-block input"""
        lines = [
            "\n[TASK] Regular Task 1",
            "  - Details 1",
            "  - More details 1",
            "\n[TIER-0] Admin Task",
            "  - Admin details",
            "\n[PRIV] Service Task",
            "  - Service details",
            "\n[TASK] Regular Task 2",
            "  - Details 2"
        ]
        result = sort_tasks_by_priority(lines)
        
        # Verify ordering
        tier0_pos = next(i for i, l in enumerate(result) if "[TIER-0]" in l)
        priv_pos = next(i for i, l in enumerate(result) if "[PRIV]" in l)
        
        # All TASK blocks should come after TIER-0 and PRIV
        for i, line in enumerate(result):
            if "[TASK]" in line:
                assert i > tier0_pos
                assert i > priv_pos
