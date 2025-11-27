"""Tests for taskhound/opengraph/writer.py module."""

import pytest
import os
import tempfile
import json
from unittest.mock import patch, MagicMock, Mock
from pathlib import Path

from taskhound.opengraph.writer import (
    generate_opengraph_files,
)


class TestGenerateOpengraphFiles:
    """Tests for generate_opengraph_files function."""

    def test_empty_tasks_list(self):
        """Test with empty tasks list."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("taskhound.opengraph.writer.warn"):
                with patch("taskhound.opengraph.writer.info"):
                    generate_opengraph_files(
                        output_dir=tmpdir,
                        tasks=[],
                    )
            # Should not crash with empty list

    def test_filters_failure_rows(self):
        """Test that FAILURE rows are filtered out."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tasks = [
                {"type": "FAILURE", "host": "FAILED_HOST"},
                {"type": "TASK", "host": "VALID_HOST", "runas": "DOMAIN\\user"},
            ]
            with patch("taskhound.opengraph.writer.warn"):
                with patch("taskhound.opengraph.writer.info"):
                    with patch("taskhound.opengraph.writer.debug"):
                        generate_opengraph_files(
                            output_dir=tmpdir,
                            tasks=tasks,
                        )

    def test_with_taskrow_objects(self):
        """Test conversion of TaskRow objects to dicts."""
        from taskhound.models.task import TaskRow
        
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a mock TaskRow
            task_row = TaskRow(
                host="SERVER.DOMAIN.LOCAL",
                path="\\TestTask",
                author="DOMAIN\\admin",
                runas="DOMAIN\\service",
            )
            
            with patch("taskhound.opengraph.writer.warn"):
                with patch("taskhound.opengraph.writer.info"):
                    with patch("taskhound.opengraph.writer.debug"):
                        generate_opengraph_files(
                            output_dir=tmpdir,
                            tasks=[task_row],
                        )

    def test_extracts_domain_from_fqdn(self):
        """Test domain extraction from FQDN hostnames."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tasks = [
                {"host": "SERVER.CORP.LOCAL", "runas": "service", "task_name": "Test"},
            ]
            with patch("taskhound.opengraph.writer.warn"):
                with patch("taskhound.opengraph.writer.info"):
                    with patch("taskhound.opengraph.writer.debug"):
                        generate_opengraph_files(
                            output_dir=tmpdir,
                            tasks=tasks,
                        )

    def test_handles_na_runas(self):
        """Test handling of N/A runas values."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tasks = [
                {"host": "SERVER.DOMAIN.LOCAL", "runas": "N/A", "task_name": "Test"},
            ]
            with patch("taskhound.opengraph.writer.warn"):
                with patch("taskhound.opengraph.writer.info"):
                    with patch("taskhound.opengraph.writer.debug"):
                        generate_opengraph_files(
                            output_dir=tmpdir,
                            tasks=tasks,
                        )

    def test_with_bloodhound_connector(self):
        """Test with BloodHound connector for resolution."""
        with tempfile.TemporaryDirectory() as tmpdir:
            mock_connector = MagicMock()
            mock_connector.users_data = {}
            
            tasks = [
                {"host": "SERVER.DOMAIN.LOCAL", "runas": "DOMAIN\\user", "task_name": "Test"},
            ]
            
            with patch("taskhound.opengraph.writer.warn"):
                with patch("taskhound.opengraph.writer.info"):
                    with patch("taskhound.opengraph.writer.debug"):
                        with patch("taskhound.opengraph.writer.resolve_object_ids_chunked") as mock_resolve:
                            mock_resolve.return_value = ({}, {})
                            generate_opengraph_files(
                                output_dir=tmpdir,
                                tasks=tasks,
                                bh_connector=mock_connector,
                            )

    def test_with_computer_sids_mapping(self):
        """Test with pre-computed computer SIDs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tasks = [
                {"host": "SERVER.DOMAIN.LOCAL", "runas": "DOMAIN\\user", "task_name": "Test"},
            ]
            computer_sids = {"SERVER.DOMAIN.LOCAL": "S-1-5-21-123456789-1234567890-1234567890-1001"}
            
            with patch("taskhound.opengraph.writer.warn"):
                with patch("taskhound.opengraph.writer.info"):
                    with patch("taskhound.opengraph.writer.debug"):
                        generate_opengraph_files(
                            output_dir=tmpdir,
                            tasks=tasks,
                            computer_sids=computer_sids,
                        )

    def test_allow_orphans_flag(self):
        """Test allow_orphans flag behavior."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tasks = [
                {"host": "ORPHAN.DOMAIN.LOCAL", "runas": "orphan_user", "task_name": "Test"},
            ]
            
            with patch("taskhound.opengraph.writer.warn"):
                with patch("taskhound.opengraph.writer.info"):
                    with patch("taskhound.opengraph.writer.debug"):
                        generate_opengraph_files(
                            output_dir=tmpdir,
                            tasks=tasks,
                            allow_orphans=True,
                        )


class TestDomainExtraction:
    """Tests for domain extraction helper logic."""

    def test_simple_fqdn(self):
        """Test domain extraction from simple FQDN."""
        # Helper function is internal, test through generate_opengraph_files
        with tempfile.TemporaryDirectory() as tmpdir:
            tasks = [
                {"host": "DC01.CORP.LOCAL", "runas": "admin", "task_name": "Test"},
            ]
            with patch("taskhound.opengraph.writer.warn"):
                with patch("taskhound.opengraph.writer.info"):
                    with patch("taskhound.opengraph.writer.debug"):
                        generate_opengraph_files(
                            output_dir=tmpdir,
                            tasks=tasks,
                        )

    def test_short_hostname(self):
        """Test with short hostname (no domain)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tasks = [
                {"host": "SERVER", "runas": "localuser", "task_name": "Test"},
            ]
            with patch("taskhound.opengraph.writer.warn"):
                with patch("taskhound.opengraph.writer.info"):
                    with patch("taskhound.opengraph.writer.debug"):
                        generate_opengraph_files(
                            output_dir=tmpdir,
                            tasks=tasks,
                        )

    def test_multi_level_domain(self):
        """Test with multi-level domain."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tasks = [
                {"host": "SERVER.CHILD.CORP.LOCAL", "runas": "admin", "task_name": "Test"},
            ]
            with patch("taskhound.opengraph.writer.warn"):
                with patch("taskhound.opengraph.writer.info"):
                    with patch("taskhound.opengraph.writer.debug"):
                        generate_opengraph_files(
                            output_dir=tmpdir,
                            tasks=tasks,
                        )


class TestEdgeCases:
    """Edge case tests for opengraph writer."""

    def test_unknown_host(self):
        """Test handling of UNKNOWN_HOST."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tasks = [
                {"host": "UNKNOWN_HOST", "runas": "user", "task_name": "Test"},
            ]
            with patch("taskhound.opengraph.writer.warn"):
                with patch("taskhound.opengraph.writer.info"):
                    with patch("taskhound.opengraph.writer.debug"):
                        generate_opengraph_files(
                            output_dir=tmpdir,
                            tasks=tasks,
                        )

    def test_empty_hostname(self):
        """Test handling of empty hostname."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tasks = [
                {"host": "", "runas": "user", "task_name": "Test"},
            ]
            with patch("taskhound.opengraph.writer.warn"):
                with patch("taskhound.opengraph.writer.info"):
                    with patch("taskhound.opengraph.writer.debug"):
                        generate_opengraph_files(
                            output_dir=tmpdir,
                            tasks=tasks,
                        )

    def test_empty_runas(self):
        """Test handling of empty runas."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tasks = [
                {"host": "SERVER.DOMAIN.LOCAL", "runas": "", "task_name": "Test"},
            ]
            with patch("taskhound.opengraph.writer.warn"):
                with patch("taskhound.opengraph.writer.info"):
                    with patch("taskhound.opengraph.writer.debug"):
                        generate_opengraph_files(
                            output_dir=tmpdir,
                            tasks=tasks,
                        )

    def test_whitespace_in_values(self):
        """Test handling of whitespace in values."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tasks = [
                {"host": "  SERVER.DOMAIN.LOCAL  ", "runas": "  user  ", "task_name": "Test"},
            ]
            with patch("taskhound.opengraph.writer.warn"):
                with patch("taskhound.opengraph.writer.info"):
                    with patch("taskhound.opengraph.writer.debug"):
                        generate_opengraph_files(
                            output_dir=tmpdir,
                            tasks=tasks,
                        )
