"""Tests for terminal color utilities."""

import os
from io import StringIO
from unittest.mock import patch

from gdoc2netcfg.utils.terminal import colorize, use_color


class TestUseColor:
    def test_false_when_not_tty(self):
        stream = StringIO()
        assert use_color(stream) is False

    def test_true_when_tty(self):
        stream = StringIO()
        stream.isatty = lambda: True
        assert use_color(stream) is True

    @patch.dict(os.environ, {"NO_COLOR": "1"})
    def test_no_color_env_disables_color(self):
        stream = StringIO()
        stream.isatty = lambda: True
        assert use_color(stream) is False

    @patch.dict(os.environ, {"NO_COLOR": ""})
    def test_no_color_empty_string_allows_color(self):
        """NO_COLOR="" (empty) should not disable color per convention."""
        stream = StringIO()
        stream.isatty = lambda: True
        assert use_color(stream) is True

    def test_stream_without_isatty(self):
        """Streams without isatty attribute should not use color."""

        class FakeStream:
            pass

        assert use_color(FakeStream()) is False


class TestColorize:
    def test_wraps_text_when_enabled(self):
        result = colorize("hello", "32", True)
        assert result == "\033[32mhello\033[0m"

    def test_passthrough_when_disabled(self):
        result = colorize("hello", "32", False)
        assert result == "hello"

    def test_bright_red_code(self):
        result = colorize("error", "91", True)
        assert result == "\033[91merror\033[0m"

    def test_empty_string(self):
        assert colorize("", "32", True) == "\033[32m\033[0m"
        assert colorize("", "32", False) == ""
