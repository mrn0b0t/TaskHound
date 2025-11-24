import pytest
from unittest.mock import Mock, patch
from taskhound.engine import process_target
from taskhound.output.summary import print_summary_table
import io
import sys

class TestCrawlFailure:
    
    @patch("taskhound.engine.smb_connect")
    def test_crawl_failure_silent_disappearance(self, mock_smb):
        # Mock smb_connect to return a mock SMB object
        mock_conn = Mock()
        mock_smb.return_value = mock_conn
        
        # Mock listPath to raise exception (simulating Access Denied on root)
        mock_conn.listPath.side_effect = Exception("Access Denied")
        
        all_rows = []
        target = "crawl-failed-host"
        
        # Call process_target
        process_target(
            target=target,
            domain="DOMAIN",
            username="user",
            password="password",
            kerberos=False,
            dc_ip=None,
            include_ms=False,
            include_local=False,
            hv=None,
            debug=False,
            all_rows=all_rows
        )
        
        # Verify all_rows contains the failure (host should NOT disappear now)
        assert len(all_rows) == 1
        assert all_rows[0]["host"] == target
        assert all_rows[0]["type"] == "FAILURE"
        assert "Access Denied" in all_rows[0]["reason"]
        
        # Verify summary table SHOWS the host
        captured_output = io.StringIO()
        sys.stdout = captured_output
        
        print_summary_table(all_rows)
        
        sys.stdout = sys.__stdout__
        output = captured_output.getvalue()
        
        assert target in output
        # Check for part of the error message since it might be truncated
        assert "Failed to access" in output
