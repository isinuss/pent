"""Tests for pent.py — Click CLI commands."""

import os
import sys
from unittest.mock import patch, MagicMock

import pytest
from click.testing import CliRunner

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pent import cli


@pytest.fixture
def runner():
    return CliRunner()


class TestCLIHelp:

    def test_help(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "PENT" in result.output

    def test_recon_help(self, runner):
        result = runner.invoke(cli, ["recon", "--help"])
        assert result.exit_code == 0
        assert "target" in result.output.lower() or "TARGET" in result.output

    def test_scan_help(self, runner):
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0

    def test_webtest_help(self, runner):
        result = runner.invoke(cli, ["webtest", "--help"])
        assert result.exit_code == 0

    def test_guide_help(self, runner):
        result = runner.invoke(cli, ["guide", "--help"])
        assert result.exit_code == 0


class TestCLICommands:

    @patch("pent.ReconModule")
    @patch("pent.show_banner")
    def test_recon_invokes_module(self, mock_banner, mock_mod_class, runner):
        mock_instance = MagicMock()
        mock_mod_class.return_value = mock_instance
        result = runner.invoke(cli, ["recon", "example.com"])
        mock_instance.run.assert_called_once()

    @patch("pent.VulnScannerModule")
    @patch("pent.show_banner")
    def test_scan_invokes_module(self, mock_banner, mock_mod_class, runner):
        mock_instance = MagicMock()
        mock_mod_class.return_value = mock_instance
        result = runner.invoke(cli, ["scan", "example.com"])
        mock_instance.run.assert_called_once()

    @patch("pent.WebTesterModule")
    @patch("pent.show_banner")
    def test_webtest_invokes_module(self, mock_banner, mock_mod_class, runner):
        mock_instance = MagicMock()
        mock_mod_class.return_value = mock_instance
        result = runner.invoke(cli, ["webtest", "https://example.com"])
        mock_instance.run.assert_called_once()

    @patch("pent.JSAnalyzerModule")
    @patch("pent.show_banner")
    def test_jsanalyze_invokes_module(self, mock_banner, mock_mod_class, runner):
        mock_instance = MagicMock()
        mock_mod_class.return_value = mock_instance
        result = runner.invoke(cli, ["jsanalyze", "https://example.com"])
        mock_instance.analyze.assert_called_once()

    @patch("pent.GuideModule")
    @patch("pent.show_banner")
    def test_guide_invokes_module(self, mock_banner, mock_mod_class, runner):
        mock_instance = MagicMock()
        mock_mod_class.return_value = mock_instance
        result = runner.invoke(cli, ["guide"])
        mock_instance.run.assert_called_once()

    def test_recon_missing_target(self, runner):
        result = runner.invoke(cli, ["recon"])
        assert result.exit_code != 0
