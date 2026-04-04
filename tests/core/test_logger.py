"""Tests for core logger."""

from __future__ import annotations

import logging

from rich.logging import RichHandler

from dnsight.core.logger import configure, get_logger


class TestGetLogger:
    def test_root_logger(self) -> None:
        log = get_logger()
        assert log.name == "dnsight"

    def test_named_logger(self) -> None:
        log = get_logger("config")
        assert log.name == "dnsight.config"

    def test_nested_name(self) -> None:
        log = get_logger("core.config")
        assert log.name == "dnsight.core.config"

    def test_module_name_not_doubled(self) -> None:
        """``__name__`` from a package module is ``dnsight.*``; avoid ``dnsight.dnsight.``."""
        log = get_logger("dnsight.orchestrator")
        assert log.name == "dnsight.orchestrator"

    def test_same_name_returns_same_logger(self) -> None:
        assert get_logger("x") is get_logger("x")


class TestConfigure:
    def setup_method(self) -> None:
        root = logging.getLogger("dnsight")
        root.handlers.clear()

    def test_adds_handler(self) -> None:
        configure()
        root = logging.getLogger("dnsight")
        assert len(root.handlers) == 1
        assert isinstance(root.handlers[0], logging.StreamHandler)

    def test_sets_level(self) -> None:
        configure(level=logging.DEBUG)
        root = logging.getLogger("dnsight")
        assert root.level == logging.DEBUG

    def test_no_duplicate_handlers(self) -> None:
        configure()
        configure()
        root = logging.getLogger("dnsight")
        assert len(root.handlers) == 1

    def test_custom_format(self) -> None:
        fmt = "%(message)s"
        configure(format_string=fmt)
        root = logging.getLogger("dnsight")
        assert root.handlers[0].formatter
        assert root.handlers[0].formatter._fmt == fmt

    def test_custom_format_ignores_rich(self) -> None:
        configure(format_string="%(levelname)s %(message)s", use_rich=True)
        root = logging.getLogger("dnsight")
        assert isinstance(root.handlers[0], logging.StreamHandler)
        assert not isinstance(root.handlers[0], RichHandler)

    def test_use_rich_handler(self) -> None:
        configure(use_rich=True)
        root = logging.getLogger("dnsight")
        assert isinstance(root.handlers[0], RichHandler)
        assert root.handlers[0].formatter is not None

    def test_detailed_plain_format(self) -> None:
        configure(detailed_log=True)
        root = logging.getLogger("dnsight")
        fmt = root.handlers[0].formatter
        assert fmt is not None
        assert "lineno" in fmt._fmt

    def test_simple_plain_format(self) -> None:
        configure(detailed_log=False)
        root = logging.getLogger("dnsight")
        fmt = root.handlers[0].formatter
        assert fmt is not None
        assert "lineno" not in fmt._fmt
