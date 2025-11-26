import io
import sys
import unittest
from unittest.mock import MagicMock, patch

from taskhound.auth import AuthContext
from taskhound.engine import process_target
from taskhound.models.task import TaskType
from taskhound.output.summary import print_summary_table
from taskhound.utils.logging import set_verbosity


class TestLoggingOutput(unittest.TestCase):

    def setUp(self):
        # Reset verbosity
        set_verbosity(False, False)
        self.capturedOutput = io.StringIO()
        sys.stdout = self.capturedOutput

    def tearDown(self):
        sys.stdout = sys.__stdout__

    @patch("taskhound.engine.online.smb_connect")
    @patch("taskhound.engine.online.crawl_tasks")
    def test_concise_output_success(self, mock_crawl, mock_connect):
        # Mock success
        mock_connect.return_value = MagicMock()
        mock_crawl.return_value = []

        auth = AuthContext(username="user", password="pass", domain="domain")
        all_rows = []
        process_target("target", all_rows, auth=auth)

        output = self.capturedOutput.getvalue()
        self.assertIn("[Collecting] target ...", output)
        self.assertIn("[Collecting] target [+]", output)
        self.assertIn("[TaskCount] 0 Tasks, N/A Privileged", output)
        # Should NOT contain verbose logs
        self.assertNotIn("Connected via SMB", output)

    @patch("taskhound.engine.online.smb_connect")
    def test_concise_output_failure(self, mock_connect):
        # Mock failure
        mock_connect.side_effect = Exception("Connection failed")

        auth = AuthContext(username="user", password="pass", domain="domain")
        all_rows = []
        process_target("target", all_rows, auth=auth)

        output = self.capturedOutput.getvalue()
        self.assertIn("[Collecting] target [-] (Connection failed)", output)

        # Verify failure row added
        self.assertEqual(len(all_rows), 1)
        self.assertEqual(all_rows[0].type, TaskType.FAILURE.value)
        self.assertEqual(all_rows[0].reason, "SMB connection failed: Connection failed")

    def test_summary_table_failure(self):
        all_rows = [
            {"host": "host1", "type": "TASK"},
            {"host": "host2", "type": "FAILURE", "reason": "Unreachable"}
        ]

        print_summary_table(all_rows)
        output = self.capturedOutput.getvalue()

        self.assertIn("host1", output)
        self.assertIn("host2", output)
        # Rich table uses ✓ for success and ✗ for failure
        self.assertIn("✓", output)
        self.assertIn("✗", output)
        self.assertIn("Unreachable", output)

    def test_verbosity_flags(self):
        from taskhound.utils.logging import debug, good, info

        # Test default (Quiet)
        set_verbosity(False, False)
        info("Info message")
        good("Good message")
        debug("Debug message")
        output = self.capturedOutput.getvalue()
        self.assertEqual(output, "") # Nothing should be printed

        # Test Verbose
        self.capturedOutput.truncate(0)
        self.capturedOutput.seek(0)
        set_verbosity(True, False)
        info("Info message")
        good("Good message")
        debug("Debug message")
        output = self.capturedOutput.getvalue()
        self.assertIn("Info message", output)
        self.assertIn("Good message", output)
        self.assertNotIn("Debug message", output)

        # Test Debug
        self.capturedOutput.truncate(0)
        self.capturedOutput.seek(0)
        set_verbosity(False, True)
        info("Info message")
        good("Good message")
        debug("Debug message")
        output = self.capturedOutput.getvalue()
        self.assertIn("Info message", output)
        self.assertIn("Good message", output)
        self.assertIn("Debug message", output)

if __name__ == "__main__":
    unittest.main()
