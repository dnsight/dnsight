"""Singleton STARTTLS probe for MX checks.

Tests replace the module-level probe with :class:`FakeStartTLSProbe` to
avoid real SMTP connections.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from enum import StrEnum
import re
import ssl
from typing import Protocol, runtime_checkable


__all__ = [
    "AsyncStartTLSProbe",
    "FakeStartTLSProbe",
    "StartTLSOutcome",
    "StartTLSProbe",
    "StartTLSProbeResult",
    "get_starttls_probe",
    "reset_starttls_probe",
    "set_starttls_probe",
]


class StartTLSOutcome(StrEnum):
    """High-level result of a port-25 STARTTLS probe."""

    OK = "ok"
    NOT_SUPPORTED = "not_supported"
    FAILED = "failed"


@dataclass(frozen=True)
class StartTLSProbeResult:
    """Outcome of probing SMTP STARTTLS on a host."""

    outcome: StartTLSOutcome
    detail: str | None = None


@runtime_checkable
class StartTLSProbe(Protocol):
    """Protocol for async SMTP STARTTLS probes."""

    async def probe(
        self, host: str, *, port: int = 25, timeout_seconds: float
    ) -> StartTLSProbeResult: ...


_probe: StartTLSProbe | None = None


def get_starttls_probe() -> StartTLSProbe:
    """Return the module-level probe, creating :class:`AsyncStartTLSProbe` if needed."""
    global _probe  # noqa: PLW0603
    if _probe is None:
        _probe = AsyncStartTLSProbe()
    return _probe


def set_starttls_probe(probe: StartTLSProbe) -> None:
    """Replace the module-level probe (for tests)."""
    global _probe  # noqa: PLW0603
    _probe = probe


def reset_starttls_probe() -> None:
    """Reset the module-level probe so the next get creates a new instance."""
    global _probe  # noqa: PLW0603
    _probe = None


_CODE_LINE = re.compile(rb"^(\d{3})")


@dataclass(frozen=True)
class _EhloRead:
    data: bytes
    error: StartTLSProbeResult | None


class AsyncStartTLSProbe:
    """Real SMTP STARTTLS handshake on port 25 (asyncio + TLS)."""

    async def probe(
        self, host: str, *, port: int = 25, timeout_seconds: float
    ) -> StartTLSProbeResult:
        """Connect, EHLO, and verify STARTTLS is offered and upgrades."""
        try:
            conn = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout_seconds
            )
        except TimeoutError:
            return StartTLSProbeResult(
                StartTLSOutcome.FAILED, f"connection timed out after {timeout_seconds}s"
            )
        except OSError as exc:
            return StartTLSProbeResult(StartTLSOutcome.FAILED, str(exc))

        reader: asyncio.StreamReader
        writer: asyncio.StreamWriter
        reader, writer = conn
        try:
            gr = await self._read_smtp_greeting(reader, timeout_seconds)
            if gr is not None:
                return gr

            await self._send_line(writer, b"EHLO dnsight.local\r\n")
            ehlo_res = await self._read_multiline_250(reader, timeout_seconds)
            if ehlo_res.error is not None:
                return ehlo_res.error
            ehlo_blob = ehlo_res.data

            if b"STARTTLS" not in ehlo_blob.upper():
                return StartTLSProbeResult(
                    StartTLSOutcome.NOT_SUPPORTED,
                    "STARTTLS not advertised in EHLO response",
                )

            await self._send_line(writer, b"STARTTLS\r\n")
            try:
                line = await asyncio.wait_for(
                    reader.readline(), timeout=timeout_seconds
                )
            except TimeoutError:
                return StartTLSProbeResult(
                    StartTLSOutcome.FAILED, "timeout waiting for STARTTLS reply"
                )
            if not line.upper().startswith(b"220"):
                text = line.decode(errors="replace").strip()
                return StartTLSProbeResult(
                    StartTLSOutcome.NOT_SUPPORTED, f"STARTTLS rejected: {text}"
                )

            ssl_ctx = ssl.create_default_context()
            try:
                await writer.start_tls(ssl_ctx, server_hostname=host)
            except ssl.SSLError as exc:
                return StartTLSProbeResult(
                    StartTLSOutcome.FAILED, f"TLS handshake failed: {exc}"
                )
            except OSError as exc:
                return StartTLSProbeResult(
                    StartTLSOutcome.FAILED, f"TLS handshake failed: {exc}"
                )

            return StartTLSProbeResult(StartTLSOutcome.OK, None)
        finally:
            writer.close()
            with contextlib.suppress(OSError):
                await writer.wait_closed()

    async def _read_smtp_greeting(
        self, reader: asyncio.StreamReader, timeout: float
    ) -> StartTLSProbeResult | None:
        while True:
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            except TimeoutError:
                return StartTLSProbeResult(
                    StartTLSOutcome.FAILED, f"SMTP read timed out after {timeout}s"
                )
            if not line:
                return StartTLSProbeResult(
                    StartTLSOutcome.FAILED, "unexpected EOF before SMTP greeting"
                )
            if line.startswith(b"220"):
                return None

    async def _read_multiline_250(
        self, reader: asyncio.StreamReader, timeout: float
    ) -> _EhloRead:
        buf = bytearray()
        while True:
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            except TimeoutError:
                return _EhloRead(
                    b"",
                    StartTLSProbeResult(
                        StartTLSOutcome.FAILED, f"SMTP read timed out after {timeout}s"
                    ),
                )
            if not line:
                return _EhloRead(
                    b"",
                    StartTLSProbeResult(
                        StartTLSOutcome.FAILED, "unexpected EOF during EHLO"
                    ),
                )
            buf.extend(line)
            m = _CODE_LINE.match(line)
            if not m:
                continue
            code = m.group(1)
            if code != b"250":
                return _EhloRead(
                    b"",
                    StartTLSProbeResult(
                        StartTLSOutcome.FAILED,
                        f"EHLO failed: {line.decode(errors='replace')!r}",
                    ),
                )
            if line[3:4] == b" ":
                break
            if line[3:4] != b"-":
                break
        return _EhloRead(bytes(buf), None)

    async def _send_line(self, writer: asyncio.StreamWriter, data: bytes | str) -> None:
        if isinstance(data, str):
            writer.write(data.encode())
        else:
            writer.write(data)
        await writer.drain()


class FakeStartTLSProbe:
    """Test double: pre-configured ``(host, port)`` → probe result."""

    def __init__(
        self, results: dict[tuple[str, int], StartTLSProbeResult] | None = None
    ) -> None:
        self._results: dict[tuple[str, int], StartTLSProbeResult] = results or {}

    async def probe(
        self, host: str, *, port: int = 25, timeout_seconds: float
    ) -> StartTLSProbeResult:
        key = (host.lower().rstrip("."), port)
        if key not in self._results:
            return StartTLSProbeResult(
                StartTLSOutcome.FAILED, f"no fake STARTTLS result for {host!r}:{port}"
            )
        return self._results[key]
