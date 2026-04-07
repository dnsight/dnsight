"""Package logger for dnsight. Singleton-style: use get_logger() everywhere.

The application or CLI should call configure() or attach its own handler so
that log output is visible. :func:`configure` can attach a plain stderr handler
or a Rich-based handler with level-coloured output.
"""

from __future__ import annotations

import logging
import sys


__all__ = ["configure", "get_logger"]

_ROOT_NAME = "dnsight"

_FMT_SIMPLE = "%(levelname)s %(message)s"
_FMT_DETAILED = "%(levelname)s %(message)s · %(name)s (%(filename)s:%(lineno)d)"


def get_logger(name: str | None = None) -> logging.Logger:
    """Return the package logger. Singleton-style: same name => same logger.

    Args:
        name: If None, returns the root package logger "dnsight". If provided,
            returns "dnsight.<suffix>" for hierarchical logging. A *name* starting
            with ``"dnsight."`` (e.g. :data:`__name__` from a submodule) uses the
            remainder as *suffix* so the hierarchy is not doubled.

    Returns:
        The Logger instance.
    """
    if name is None:
        return logging.getLogger(_ROOT_NAME)
    suffix = name.removeprefix(f"{_ROOT_NAME}.")
    return logging.getLogger(f"{_ROOT_NAME}.{suffix}")


def configure(
    level: int = logging.INFO,
    format_string: str | None = None,
    *,
    detailed_log: bool = False,
    use_rich: bool = False,
    rich_tracebacks: bool = False,
) -> None:
    """Attach a single handler on the ``dnsight`` root logger.

    Replaces any existing handlers on that logger so repeated calls do not stack
    handlers.

    Args:
        level: Minimum level for the logger and handler.
        format_string: If set, used with a plain :class:`~logging.StreamHandler`
            on stderr. Overrides *detailed_log* and *use_rich*.
        detailed_log: When *format_string* is unset and *use_rich* is False,
            include ``filename:lineno`` in the format. When *use_rich* is True,
            enables Rich's path column (similar effect).
        use_rich: Use :class:`rich.logging.RichHandler` on stderr with level
            colours and optional tracebacks. Ignored if *format_string* is set.
        rich_tracebacks: When *use_rich* is True, render exception tracebacks
            with Rich (only affects records with exception info).
    """
    root = logging.getLogger(_ROOT_NAME)
    for h in root.handlers[:]:
        root.removeHandler(h)

    if format_string is not None:
        handler: logging.Handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(format_string))
    elif use_rich:
        from rich.console import Console
        from rich.logging import RichHandler

        msg_fmt = "%(message)s · %(name)s"
        handler = RichHandler(
            console=Console(stderr=True),
            show_time=False,
            show_level=True,
            show_path=detailed_log,
            rich_tracebacks=rich_tracebacks,
            enable_link_path=sys.stderr.isatty(),
            markup=False,
        )
        handler.setFormatter(logging.Formatter(msg_fmt))
    else:
        handler = logging.StreamHandler(sys.stderr)
        fmt = _FMT_DETAILED if detailed_log else _FMT_SIMPLE
        handler.setFormatter(logging.Formatter(fmt))

    handler.setLevel(level)
    root.addHandler(handler)
    root.setLevel(level)
