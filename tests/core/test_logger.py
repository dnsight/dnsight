"""Tests for core logger."""

from __future__ import annotations

import logging

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
