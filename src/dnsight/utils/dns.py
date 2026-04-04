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

from dataclasses import dataclass
from typing import Any, Protocol, TypedDict, cast, runtime_checkable

import dns.asyncresolver
from dns.exception import DNSException
import dns.flags
import dns.message
import dns.resolver
import dns.reversename

from dnsight.core.exceptions import CheckError


class DNSKEYDict(TypedDict):
    """Structured DNSKEY row returned by ``resolve_dnskey`` / fakes."""

    flags: int
    protocol: int
    algorithm: int
    key: bytes


@dataclass(frozen=True)
class DnssecQueryResult:
    """DNS response from a DNSSEC-aware query (EDNS DO bit set).

    ``message`` is the full DNS response; ``rcode`` and ``ad`` are copied for
    convenience.
    """

    rcode: int
    ad: bool
    message: dns.message.Message


__all__ = [
    "AsyncDNSResolver",
    "DNSKEYDict",
    "DNSResolver",
    "DnssecQueryResult",
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
    async def resolve_a(self, name: str) -> list[str]: ...
    async def resolve_aaaa(self, name: str) -> list[str]: ...
    async def resolve_cname(self, name: str) -> list[str]: ...
    async def resolve_dname(self, name: str) -> list[str]: ...
    async def resolve_srv(self, name: str) -> list[tuple[int, int, int, str]]: ...
    async def resolve_ptr(self, ipv4: str) -> list[str]: ...
    async def resolve_caa(self, name: str) -> list[tuple[int, str, str]]: ...
    async def resolve_ns(self, name: str) -> list[str]: ...
    async def resolve_ds(self, name: str) -> list[tuple[int, int, int, bytes]]: ...
    async def resolve_dnskey(self, name: str) -> list[DNSKEYDict]: ...
    async def query_dnssec(self, name: str, rdtype: str) -> DnssecQueryResult: ...


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

    def _resolver_dnssec(self) -> dns.asyncresolver.Resolver:
        """Clone resolver settings with EDNS0 + DO for DNSSEC validation."""
        r = dns.asyncresolver.Resolver()
        r.nameservers = list(self._inner.nameservers)
        r.use_edns(0, dns.flags.DO, 4096)
        return r

    async def query_dnssec(self, name: str, rdtype: str) -> DnssecQueryResult:
        """Resolve *name* for *rdtype* with EDNS0 DO; return full DNS message.

        NXDOMAIN and NODATA are not errors: the response message is returned so
        callers can inspect authority (NSEC/NSEC3).
        """
        r = self._resolver_dnssec()
        try:
            ans = await r.resolve(name, rdtype)
        except dns.resolver.NXDOMAIN as exc:
            responses = exc.kwargs.get("responses") or {}
            msg: dns.message.Message | None = None
            for _q, response in responses.items():
                msg = response
                break
            if msg is None:
                raise CheckError(
                    f"DNS NXDOMAIN without response for {name} {rdtype}"
                ) from exc
            return DnssecQueryResult(
                rcode=msg.rcode(), ad=bool(msg.flags & dns.flags.AD), message=msg
            )
        except dns.resolver.NoAnswer as exc:
            msg = cast(dns.message.Message, exc.response())  # type: ignore[no-untyped-call]
            return DnssecQueryResult(
                rcode=msg.rcode(), ad=bool(msg.flags & dns.flags.AD), message=msg
            )
        except DNSException as exc:
            raise CheckError(f"DNS lookup failed for {name} {rdtype}: {exc}") from exc
        msg = ans.response
        return DnssecQueryResult(
            rcode=msg.rcode(), ad=bool(msg.flags & dns.flags.AD), message=msg
        )

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

    async def resolve_a(self, name: str) -> list[str]:
        """Resolve IPv4 A records for *name*.

        Args:
            name: DNS name to query.

        Returns:
            List of IPv4 addresses as dotted-quad strings.

        Raises:
            CheckError: On any DNS resolution failure.
        """
        try:
            answer = await self._inner.resolve(name, "A")
            return [str(rdata) for rdata in answer]
        except DNSException as exc:
            raise CheckError(f"DNS A lookup failed for {name}: {exc}") from exc

    async def resolve_aaaa(self, name: str) -> list[str]:
        """Resolve IPv6 AAAA records for *name*."""
        try:
            answer = await self._inner.resolve(name, "AAAA")
            return [str(rdata) for rdata in answer]
        except DNSException as exc:
            raise CheckError(f"DNS AAAA lookup failed for {name}: {exc}") from exc

    async def resolve_cname(self, name: str) -> list[str]:
        """Resolve CNAME targets for *name* (trailing dots stripped)."""
        try:
            answer = await self._inner.resolve(name, "CNAME")
            return [str(rdata.target).rstrip(".") for rdata in answer]
        except DNSException as exc:
            raise CheckError(f"DNS CNAME lookup failed for {name}: {exc}") from exc

    async def resolve_dname(self, name: str) -> list[str]:
        """Resolve DNAME targets for *name* (trailing dots stripped)."""
        try:
            answer = await self._inner.resolve(name, "DNAME")
            return [str(rdata.target).rstrip(".") for rdata in answer]
        except DNSException as exc:
            raise CheckError(f"DNS DNAME lookup failed for {name}: {exc}") from exc

    async def resolve_srv(self, name: str) -> list[tuple[int, int, int, str]]:
        """Resolve SRV records for *name*.

        Returns:
            List of ``(priority, weight, port, target)`` tuples (target without
            trailing dot).
        """
        try:
            answer = await self._inner.resolve(name, "SRV")
            return [
                (
                    rdata.priority,
                    rdata.weight,
                    rdata.port,
                    str(rdata.target).rstrip("."),
                )
                for rdata in answer
            ]
        except DNSException as exc:
            raise CheckError(f"DNS SRV lookup failed for {name}: {exc}") from exc

    async def resolve_ptr(self, ipv4: str) -> list[str]:
        """Resolve PTR records for an IPv4 address.

        Args:
            ipv4: IPv4 address in dotted-quad form.

        Returns:
            PTR target hostnames (trailing dots stripped).

        Raises:
            CheckError: On any DNS resolution failure.
        """
        try:
            rev = dns.reversename.from_address(ipv4)
            answer = await self._inner.resolve(rev, "PTR")
            return [str(rdata.target).rstrip(".") for rdata in answer]
        except DNSException as exc:
            raise CheckError(f"DNS PTR lookup failed for {ipv4}: {exc}") from exc

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
            out: list[tuple[int, str, str]] = []
            for rdata in answer:
                tag = (
                    rdata.tag.decode()
                    if isinstance(rdata.tag, bytes)
                    else str(rdata.tag)
                )
                val = rdata.value
                if isinstance(val, bytes):
                    val = val.decode("utf-8", errors="replace")
                else:
                    val = str(val)
                out.append((rdata.flags, tag, val))
            return out
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
            name: The **child zone apex** (e.g. ``example.com``). The ``DS`` RRset
                is published at the delegation point; pass the same FQDN as the
                zone being audited (RFC 4034).

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

    async def resolve_dnskey(self, name: str) -> list[DNSKEYDict]:
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
    For PTR, use the reverse zone name for the IPv4 address, e.g.
    ``"4.3.2.1.in-addr.arpa/PTR"`` (same form as
    ``dns.reversename.from_address`` with ``omit_final_dot=True``).
    If a key is missing, ``CheckError`` is raised, matching real resolver
    behaviour.

    Args:
        records: Mapping of ``"name/TYPE"`` to list of results in the
            same shape as the corresponding ``resolve_*`` method.
        dnssec_messages: Optional mapping of ``"name/TYPE"`` to a full
            :class:`dns.message.Message` for :meth:`query_dnssec`.
    """

    def __init__(
        self,
        records: dict[str, list[Any]] | None = None,
        *,
        dnssec_messages: dict[str, dns.message.Message] | None = None,
    ) -> None:
        self._records: dict[str, list[Any]] = records or {}
        self._dnssec_messages: dict[str, dns.message.Message] = dnssec_messages or {}

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

    async def resolve_a(self, name: str) -> list[str]:
        """Return pre-configured A records or raise ``CheckError``."""
        return self._get(name, "A")

    async def resolve_aaaa(self, name: str) -> list[str]:
        """Return pre-configured AAAA records or raise ``CheckError``."""
        return self._get(name, "AAAA")

    async def resolve_cname(self, name: str) -> list[str]:
        """Return pre-configured CNAME targets or raise ``CheckError``."""
        return self._get(name, "CNAME")

    async def resolve_dname(self, name: str) -> list[str]:
        """Return pre-configured DNAME targets or raise ``CheckError``."""
        return self._get(name, "DNAME")

    async def resolve_srv(self, name: str) -> list[tuple[int, int, int, str]]:
        """Return pre-configured SRV tuples or raise ``CheckError``."""
        return self._get(name, "SRV")

    async def resolve_ptr(self, ipv4: str) -> list[str]:
        """Return pre-configured PTR records or raise ``CheckError``."""
        rev = dns.reversename.from_address(ipv4)
        key_name = rev.to_text(omit_final_dot=True)
        return self._get(key_name, "PTR")

    async def resolve_caa(self, name: str) -> list[tuple[int, str, str]]:
        """Return pre-configured CAA records or raise ``CheckError``."""
        return self._get(name, "CAA")

    async def resolve_ns(self, name: str) -> list[str]:
        """Return pre-configured NS records or raise ``CheckError``."""
        return self._get(name, "NS")

    async def resolve_ds(self, name: str) -> list[tuple[int, int, int, bytes]]:
        """Return pre-configured DS records or raise ``CheckError``."""
        return self._get(name, "DS")

    async def resolve_dnskey(self, name: str) -> list[DNSKEYDict]:
        """Return pre-configured DNSKEY records or raise ``CheckError``."""
        return self._get(name, "DNSKEY")

    async def query_dnssec(self, name: str, rdtype: str) -> DnssecQueryResult:
        """Return a pre-built DNS message for ``query_dnssec``."""
        key = f"{name}/{rdtype.upper()}"
        if key not in self._dnssec_messages:
            raise CheckError(f"no dnssec response for {name} {rdtype}")
        msg = self._dnssec_messages[key]
        return DnssecQueryResult(
            rcode=msg.rcode(), ad=bool(msg.flags & dns.flags.AD), message=msg
        )
