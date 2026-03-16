"""Package logger for dnsight. Singleton-style: use get_logger() everywhere.

The application or CLI should call configure() or attach its own handler so
that log output is visible. Format includes name, level, message, and
filename:lineno for traceability.
"""

from __future__ import annotations

import logging


__all__ = ["configure", "get_logger"]

_ROOT_NAME = "dnsight"


def get_logger(name: str | None = None) -> logging.Logger:
    """Return the package logger. Singleton-style: same name => same logger.

    Args:
        name: If None, returns the root package logger "dnsight". If provided,
            returns "dnsight.<name>" for hierarchical logging and line-of-code
            context (e.g. get_logger("config") or get_logger("core.config")).

    Returns:
        The Logger instance.
    """
    if name is None:
        return logging.getLogger(_ROOT_NAME)
    return logging.getLogger(f"{_ROOT_NAME}.{name}")


def configure(level: int = logging.INFO, format_string: str | None = None) -> None:
    """Add a StreamHandler to the root dnsight logger with the given level and format.

    Call from the application or CLI so that logs are visible. If not called,
    the library does not attach handlers (library best practice).

    Args:
        level: Logging level (default INFO).
        format_string: Log format. Default includes name, level, message, and
            filename:lineno. Example: "%(name)s %(levelname)s %(message)s
            (%(filename)s:%(lineno)d)".
    """
    if format_string is None:
        format_string = "%(name)s %(levelname)s %(message)s (%(filename)s:%(lineno)d)"
    root = logging.getLogger(_ROOT_NAME)
    if not root.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(level)
        handler.setFormatter(logging.Formatter(format_string))
        root.addHandler(handler)
    root.setLevel(level)
