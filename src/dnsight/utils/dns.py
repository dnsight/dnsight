"""Singleton async DNS resolver for dnsight checks.

Module-level singleton with ``get_resolver()`` / ``set_resolver()`` /
``reset_resolver()``.  Checks call ``get_resolver()`` in their ``_get``
and ``_check`` methods; tests call ``set_resolver(FakeDNSResolver(...))``
to avoid real network I/O.

The ``AsyncDNSResolver`` wraps :mod:`dns.asyncresolver` and raises
``CheckError`` on DNS failures so checks receive a uniform exception
type.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

import dns.asyncresolver
from dns.exception import DNSException

from dnsight.core.exceptions import CheckError


__all__ = [
    "AsyncDNSResolver",
    "DNSResolver",
    "FakeDNSResolver",
    "get_resolver",
    "reset_resolver",
    "set_resolver",
]


@runtime_checkable
class DNSResolver(Protocol):
    """Protocol that all DNS resolver implementations must satisfy.

    Checks depend on this protocol, not on a concrete class, so custom
    resolvers (e.g. caching, logging, or alternative backends) can be
    swapped in via ``set_resolver()``.
    """

    async def resolve_txt(self, name: str) -> list[str]: ...
    async def resolve_mx(self, name: str) -> list[tuple[int, str]]: ...
    async def resolve_caa(self, name: str) -> list[tuple[int, str, str]]: ...
    async def resolve_ns(self, name: str) -> list[str]: ...
    async def resolve_ds(self, name: str) -> list[tuple[int, int, int, bytes]]: ...
    async def resolve_dnskey(self, name: str) -> list[dict[str, Any]]: ...


_resolver: DNSResolver | None = None


def get_resolver() -> DNSResolver:
    """Return the current module-level resolver, creating one if needed.

    Returns:
        The active resolver instance.
    """
    global _resolver  # noqa: PLW0603
    if _resolver is None:
        _resolver = AsyncDNSResolver()
    return _resolver


def set_resolver(resolver: DNSResolver) -> None:
    """Replace the module-level resolver (primarily for testing).

    Args:
        resolver: Any object satisfying the ``DNSResolver`` protocol.
    """
    global _resolver  # noqa: PLW0603
    _resolver = resolver


def reset_resolver() -> None:
    """Reset the module-level resolver to ``None``.

    The next call to ``get_resolver()`` will create a fresh
    ``AsyncDNSResolver``.
    """
    global _resolver  # noqa: PLW0603
    _resolver = None


class AsyncDNSResolver:
    """Async DNS resolver wrapping :mod:`dns.asyncresolver`.

    Each method resolves a single record type and returns structured
    Python data.  All DNS failures are translated to ``CheckError``.

    Args:
        nameservers: Optional list of nameserver IPs (e.g.
            ``["8.8.8.8", "8.8.4.4"]``).  When provided, queries use
            these servers instead of the OS default.  Pass ``None``
            (the default) to use system-configured resolvers.
    """

    def __init__(self, nameservers: list[str] | None = None) -> None:
        self._inner = dns.asyncresolver.Resolver()
        if nameservers:
            self._inner.nameservers = nameservers

    async def resolve_txt(self, name: str) -> list[str]:
        """Resolve TXT records for *name*.

        Args:
            name: DNS name to query (e.g. ``"_dmarc.example.com"``).

        Returns:
            List of concatenated TXT record strings.

        Raises:
            CheckError: On any DNS resolution failure.
        """
        try:
            answer = await self._inner.resolve(name, "TXT")
            return [
                b"".join(rdata.strings).decode("utf-8", errors="replace")
                for rdata in answer
            ]
        except DNSException as exc:
            raise CheckError(f"DNS TXT lookup failed for {name}: {exc}") from exc

    async def resolve_mx(self, name: str) -> list[tuple[int, str]]:
        """Resolve MX records for *name*.

        Args:
            name: DNS name to query.

        Returns:
            List of ``(preference, exchange)`` tuples sorted by preference.

        Raises:
            CheckError: On any DNS resolution failure.
        """
        try:
            answer = await self._inner.resolve(name, "MX")
            results: list[tuple[int, str]] = [
                (rdata.preference, str(rdata.exchange).rstrip(".")) for rdata in answer
            ]
            return sorted(results, key=lambda t: t[0])
        except DNSException as exc:
            raise CheckError(f"DNS MX lookup failed for {name}: {exc}") from exc

    async def resolve_caa(self, name: str) -> list[tuple[int, str, str]]:
        """Resolve CAA records for *name*.

        Args:
            name: DNS name to query.

        Returns:
            List of ``(flags, tag, value)`` tuples.

        Raises:
            CheckError: On any DNS resolution failure.
        """
        try:
            answer = await self._inner.resolve(name, "CAA")
            return [(rdata.flags, rdata.tag.decode(), rdata.value) for rdata in answer]
        except DNSException as exc:
            raise CheckError(f"DNS CAA lookup failed for {name}: {exc}") from exc

    async def resolve_ns(self, name: str) -> list[str]:
        """Resolve NS records for *name*.

        Args:
            name: DNS name to query.

        Returns:
            List of nameserver hostnames.

        Raises:
            CheckError: On any DNS resolution failure.
        """
        try:
            answer = await self._inner.resolve(name, "NS")
            return [str(rdata.target).rstrip(".") for rdata in answer]
        except DNSException as exc:
            raise CheckError(f"DNS NS lookup failed for {name}: {exc}") from exc

    async def resolve_ds(self, name: str) -> list[tuple[int, int, int, bytes]]:
        """Resolve DS records for *name*.

        Args:
            name: DNS name to query.

        Returns:
            List of ``(key_tag, algorithm, digest_type, digest)`` tuples.

        Raises:
            CheckError: On any DNS resolution failure.
        """
        try:
            answer = await self._inner.resolve(name, "DS")
            return [
                (rdata.key_tag, rdata.algorithm, rdata.digest_type, rdata.digest)
                for rdata in answer
            ]
        except DNSException as exc:
            raise CheckError(f"DNS DS lookup failed for {name}: {exc}") from exc

    async def resolve_dnskey(self, name: str) -> list[dict[str, Any]]:
        """Resolve DNSKEY records for *name*.

        Args:
            name: DNS name to query.

        Returns:
            List of dicts with ``flags``, ``protocol``, ``algorithm``,
            and ``key`` (bytes).

        Raises:
            CheckError: On any DNS resolution failure.
        """
        try:
            answer = await self._inner.resolve(name, "DNSKEY")
            return [
                {
                    "flags": rdata.flags,
                    "protocol": rdata.protocol,
                    "algorithm": rdata.algorithm,
                    "key": rdata.key,
                }
                for rdata in answer
            ]
        except DNSException as exc:
            raise CheckError(f"DNS DNSKEY lookup failed for {name}: {exc}") from exc


class FakeDNSResolver:
    """Test double returning pre-configured records.

    Records are keyed by ``"name/TYPE"`` (e.g. ``"_dmarc.example.com/TXT"``).
    If a key is missing, ``CheckError`` is raised, matching real resolver
    behaviour.

    Args:
        records: Mapping of ``"name/TYPE"`` to list of results in the
            same shape as the corresponding ``resolve_*`` method.
    """

    def __init__(self, records: dict[str, list[Any]] | None = None) -> None:
        self._records: dict[str, list[Any]] = records or {}

    def _get(self, name: str, rtype: str) -> list[Any]:
        key = f"{name}/{rtype}"
        if key not in self._records:
            raise CheckError(f"no {rtype} record for {name}")
        return list(self._records[key])

    async def resolve_txt(self, name: str) -> list[str]:
        """Return pre-configured TXT records or raise ``CheckError``."""
        return self._get(name, "TXT")

    async def resolve_mx(self, name: str) -> list[tuple[int, str]]:
        """Return pre-configured MX records or raise ``CheckError``."""
        return self._get(name, "MX")

    async def resolve_caa(self, name: str) -> list[tuple[int, str, str]]:
        """Return pre-configured CAA records or raise ``CheckError``."""
        return self._get(name, "CAA")

    async def resolve_ns(self, name: str) -> list[str]:
        """Return pre-configured NS records or raise ``CheckError``."""
        return self._get(name, "NS")

    async def resolve_ds(self, name: str) -> list[tuple[int, int, int, bytes]]:
        """Return pre-configured DS records or raise ``CheckError``."""
        return self._get(name, "DS")

    async def resolve_dnskey(self, name: str) -> list[dict[str, Any]]:
        """Return pre-configured DNSKEY records or raise ``CheckError``."""
        return self._get(name, "DNSKEY")
