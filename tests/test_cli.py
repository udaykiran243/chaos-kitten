"""Tests for Chaos Kitten CLI commands."""

import pytest
from typer.testing import CliRunner
from chaos_kitten.cli import app
from chaos_kitten import __version__

runner = CliRunner()


class TestCLICommands:
    """Test suite for CLI commands."""

    def test_version_command(self):
        """Test the version command displays correct version and exits successfully."""
        result = runner.invoke(app, ["version"])
        
        # Assert successful exit
        assert result.exit_code == 0
        
        # Assert version output contains expected format
        assert "Chaos Kitten v" in result.stdout
        assert __version__ in result.stdout
        
        # Assert no errors in stderr
        assert result.stderr == ""
        
        # Assert no NameError or stack trace in output
        assert "NameError" not in result.stdout
        assert "Traceback" not in result.stdout
        assert "Exception" not in result.stdout

    def test_version_command_output_format(self):
        """Test that version command output follows expected format."""
        result = runner.invoke(app, ["version"])
        
        # Check for the exact format with rich formatting
        expected_output = f"Chaos Kitten v{__version__}"
        assert expected_output in result.stdout
        
        # Ensure it's not just the version string but properly formatted
        assert result.exit_code == 0
        assert len(result.stdout.strip()) > 0
