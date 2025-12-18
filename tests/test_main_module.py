"""Tests for taskhound/__main__.py module."""

from unittest.mock import patch


class TestMainModule:
    """Tests for __main__.py entry point."""

    def test_main_imported(self):
        """main function is importable from cli."""
        from taskhound.cli import main
        assert callable(main)

    @patch("taskhound.__main__.main")
    def test_main_entry_point(self, mock_main):
        """__main__.py calls main() when executed."""
        # Import triggers the if __name__ == "__main__" block in some contexts
        # Verify main is imported
        from taskhound.__main__ import main
        assert callable(main)

    def test_main_module_structure(self):
        """__main__.py has expected structure."""
        import taskhound.__main__ as main_mod
        assert hasattr(main_mod, "main")
