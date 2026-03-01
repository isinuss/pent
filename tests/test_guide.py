"""Tests for modules/guide.py — methodology guides (pure data, no I/O)."""

from io import StringIO

import pytest

from rich.console import Console
from modules.guide import GuideModule, METHODOLOGIES


def _make_module():
    console = Console(file=StringIO(), force_terminal=False)
    return GuideModule(console)


class TestMETHODOLOGIES:

    def test_all_topics_present(self):
        expected = ["recon", "web", "api", "bugbounty", "mobile", "network", "report_writing", "google_dorks"]
        for topic in expected:
            assert topic in METHODOLOGIES

    def test_each_has_title_and_content(self):
        for key, data in METHODOLOGIES.items():
            assert "title" in data, f"{key} missing title"
            assert "content" in data, f"{key} missing content"

    def test_content_not_empty(self):
        for key, data in METHODOLOGIES.items():
            assert len(data["content"]) > 50, f"{key} content too short"


class TestGuideModule:

    def test_list_topics(self):
        mod = _make_module()
        mod.list_topics()
        # Should not raise

    def test_show_valid_topic(self):
        mod = _make_module()
        mod.show_topic("recon")
        # Should not raise

    def test_show_invalid_topic(self):
        mod = _make_module()
        mod.show_topic("nonexistent")
        # Should not crash

    def test_run_with_topic(self):
        mod = _make_module()
        mod.run(topic="web")
        # Should not raise

    def test_run_without_topic(self):
        mod = _make_module()
        mod.run()
        # Should not raise

    def test_run_none_topic(self):
        mod = _make_module()
        mod.run(topic=None)
        # Should not raise
