"""Tests for utils/dns singleton, AsyncDNSResolver, and FakeDNSResolver."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

from dns.exception import DNSException
import pytest

from dnsight.core.exceptions import CheckError
from dnsight.utils.dns import (
    AsyncDNSResolver,
    FakeDNSResolver,
    get_resolver,
    reset_resolver,
    set_resolver,
)


class TestSingleton:
    def test_get_creates_async_resolver(self) -> None:
        resolver = get_resolver()
        assert isinstance(resolver, AsyncDNSResolver)

    def test_get_returns_same_instance(self) -> None:
        a = get_resolver()
        b = get_resolver()
        assert a is b

    def test_set_overrides(self) -> None:
        fake = FakeDNSResolver()
        set_resolver(fake)
        assert get_resolver() is fake

    def test_reset_clears(self) -> None:
        fake = FakeDNSResolver()
        set_resolver(fake)
        reset_resolver()
        resolver = get_resolver()
        assert isinstance(resolver, AsyncDNSResolver)
        assert resolver is not fake


class TestFakeDNSResolver:
    async def test_resolve_txt(self) -> None:
        fake = FakeDNSResolver({"_dmarc.example.com/TXT": ["v=DMARC1; p=reject"]})
        result = await fake.resolve_txt("_dmarc.example.com")
        assert result == ["v=DMARC1; p=reject"]

    async def test_resolve_txt_missing_raises(self) -> None:
        fake = FakeDNSResolver()
        with pytest.raises(CheckError, match="no TXT record"):
            await fake.resolve_txt("missing.example.com")

    async def test_resolve_mx(self) -> None:
        fake = FakeDNSResolver({"example.com/MX": [(10, "mail.example.com")]})
        result = await fake.resolve_mx("example.com")
        assert result == [(10, "mail.example.com")]

    async def test_resolve_mx_missing_raises(self) -> None:
        fake = FakeDNSResolver()
        with pytest.raises(CheckError):
            await fake.resolve_mx("missing.example.com")

    async def test_resolve_caa(self) -> None:
        fake = FakeDNSResolver({"example.com/CAA": [(0, "issue", "letsencrypt.org")]})
        result = await fake.resolve_caa("example.com")
        assert result == [(0, "issue", "letsencrypt.org")]

    async def test_resolve_caa_missing_raises(self) -> None:
        fake = FakeDNSResolver()
        with pytest.raises(CheckError):
            await fake.resolve_caa("missing.example.com")

    async def test_resolve_ns(self) -> None:
        fake = FakeDNSResolver(
            {"example.com/NS": ["ns1.example.com", "ns2.example.com"]}
        )
        result = await fake.resolve_ns("example.com")
        assert result == ["ns1.example.com", "ns2.example.com"]

    async def test_resolve_ns_missing_raises(self) -> None:
        fake = FakeDNSResolver()
        with pytest.raises(CheckError):
            await fake.resolve_ns("missing.example.com")

    async def test_resolve_ds(self) -> None:
        fake = FakeDNSResolver({"example.com/DS": [(12345, 8, 2, b"\xab\xcd")]})
        result = await fake.resolve_ds("example.com")
        assert result == [(12345, 8, 2, b"\xab\xcd")]

    async def test_resolve_ds_missing_raises(self) -> None:
        fake = FakeDNSResolver()
        with pytest.raises(CheckError):
            await fake.resolve_ds("missing.example.com")

    async def test_resolve_dnskey(self) -> None:
        key_data = {"flags": 257, "protocol": 3, "algorithm": 8, "key": b"\x01\x02"}
        fake = FakeDNSResolver({"example.com/DNSKEY": [key_data]})
        result = await fake.resolve_dnskey("example.com")
        assert result == [key_data]

    async def test_resolve_dnskey_missing_raises(self) -> None:
        fake = FakeDNSResolver()
        with pytest.raises(CheckError):
            await fake.resolve_dnskey("missing.example.com")

    async def test_returns_copy_of_records(self) -> None:
        records = {"example.com/TXT": ["v=spf1 -all"]}
        fake = FakeDNSResolver(records)
        result = await fake.resolve_txt("example.com")
        result.append("extra")
        result2 = await fake.resolve_txt("example.com")
        assert len(result2) == 1

    async def test_empty_records(self) -> None:
        fake = FakeDNSResolver({"example.com/TXT": []})
        result = await fake.resolve_txt("example.com")
        assert result == []


# -- AsyncDNSResolver tests --------------------------------------------------


def _make_rdata_txt(*text_parts: bytes) -> Any:
    """Create a mock TXT rdata with .strings attribute."""
    return SimpleNamespace(strings=list(text_parts))


def _make_rdata_mx(preference: int, exchange: str) -> Any:
    return SimpleNamespace(preference=preference, exchange=exchange)


def _make_rdata_caa(flags: int, tag: str, value: str) -> Any:
    return SimpleNamespace(flags=flags, tag=tag.encode(), value=value)


def _make_rdata_ns(target: str) -> Any:
    return SimpleNamespace(target=target)


def _make_rdata_ds(
    key_tag: int, algorithm: int, digest_type: int, digest: bytes
) -> Any:
    return SimpleNamespace(
        key_tag=key_tag, algorithm=algorithm, digest_type=digest_type, digest=digest
    )


def _make_rdata_dnskey(flags: int, protocol: int, algorithm: int, key: bytes) -> Any:
    return SimpleNamespace(flags=flags, protocol=protocol, algorithm=algorithm, key=key)


class TestAsyncDNSResolver:
    def test_constructor_default(self) -> None:
        resolver = AsyncDNSResolver()
        assert resolver._inner is not None

    def test_constructor_with_nameservers(self) -> None:
        resolver = AsyncDNSResolver(nameservers=["8.8.8.8", "8.8.4.4"])
        assert resolver._inner.nameservers == ["8.8.8.8", "8.8.4.4"]

    async def test_resolve_txt_success(self) -> None:
        resolver = AsyncDNSResolver()
        mock_answer = [_make_rdata_txt(b"v=DMARC1; p=reject")]
        with patch.object(
            resolver._inner, "resolve", new=AsyncMock(return_value=mock_answer)
        ):
            result = await resolver.resolve_txt("_dmarc.example.com")
        assert result == ["v=DMARC1; p=reject"]

    async def test_resolve_txt_error(self) -> None:
        resolver = AsyncDNSResolver()
        with (
            patch.object(
                resolver._inner,
                "resolve",
                new=AsyncMock(side_effect=DNSException("fail")),
            ),
            pytest.raises(CheckError, match="DNS TXT lookup failed"),
        ):
            await resolver.resolve_txt("bad.example.com")

    async def test_resolve_mx_success(self) -> None:
        resolver = AsyncDNSResolver()
        mock_answer = [
            _make_rdata_mx(20, "mail2.example.com."),
            _make_rdata_mx(10, "mail1.example.com."),
        ]
        with patch.object(
            resolver._inner, "resolve", new=AsyncMock(return_value=mock_answer)
        ):
            result = await resolver.resolve_mx("example.com")
        assert result == [(10, "mail1.example.com"), (20, "mail2.example.com")]

    async def test_resolve_mx_error(self) -> None:
        resolver = AsyncDNSResolver()
        with (
            patch.object(
                resolver._inner,
                "resolve",
                new=AsyncMock(side_effect=DNSException("fail")),
            ),
            pytest.raises(CheckError, match="DNS MX lookup failed"),
        ):
            await resolver.resolve_mx("bad.example.com")

    async def test_resolve_caa_success(self) -> None:
        resolver = AsyncDNSResolver()
        mock_answer = [_make_rdata_caa(0, "issue", "letsencrypt.org")]
        with patch.object(
            resolver._inner, "resolve", new=AsyncMock(return_value=mock_answer)
        ):
            result = await resolver.resolve_caa("example.com")
        assert result == [(0, "issue", "letsencrypt.org")]

    async def test_resolve_caa_error(self) -> None:
        resolver = AsyncDNSResolver()
        with (
            patch.object(
                resolver._inner,
                "resolve",
                new=AsyncMock(side_effect=DNSException("fail")),
            ),
            pytest.raises(CheckError, match="DNS CAA lookup failed"),
        ):
            await resolver.resolve_caa("bad.example.com")

    async def test_resolve_ns_success(self) -> None:
        resolver = AsyncDNSResolver()
        mock_answer = [
            _make_rdata_ns("ns1.example.com."),
            _make_rdata_ns("ns2.example.com."),
        ]
        with patch.object(
            resolver._inner, "resolve", new=AsyncMock(return_value=mock_answer)
        ):
            result = await resolver.resolve_ns("example.com")
        assert result == ["ns1.example.com", "ns2.example.com"]

    async def test_resolve_ns_error(self) -> None:
        resolver = AsyncDNSResolver()
        with (
            patch.object(
                resolver._inner,
                "resolve",
                new=AsyncMock(side_effect=DNSException("fail")),
            ),
            pytest.raises(CheckError, match="DNS NS lookup failed"),
        ):
            await resolver.resolve_ns("bad.example.com")

    async def test_resolve_ds_success(self) -> None:
        resolver = AsyncDNSResolver()
        mock_answer = [_make_rdata_ds(12345, 8, 2, b"\xab\xcd")]
        with patch.object(
            resolver._inner, "resolve", new=AsyncMock(return_value=mock_answer)
        ):
            result = await resolver.resolve_ds("example.com")
        assert result == [(12345, 8, 2, b"\xab\xcd")]

    async def test_resolve_ds_error(self) -> None:
        resolver = AsyncDNSResolver()
        with (
            patch.object(
                resolver._inner,
                "resolve",
                new=AsyncMock(side_effect=DNSException("fail")),
            ),
            pytest.raises(CheckError, match="DNS DS lookup failed"),
        ):
            await resolver.resolve_ds("bad.example.com")

    async def test_resolve_dnskey_success(self) -> None:
        resolver = AsyncDNSResolver()
        mock_answer = [_make_rdata_dnskey(257, 3, 8, b"\x01\x02")]
        with patch.object(
            resolver._inner, "resolve", new=AsyncMock(return_value=mock_answer)
        ):
            result = await resolver.resolve_dnskey("example.com")
        assert result == [
            {"flags": 257, "protocol": 3, "algorithm": 8, "key": b"\x01\x02"}
        ]

    async def test_resolve_dnskey_error(self) -> None:
        resolver = AsyncDNSResolver()
        with (
            patch.object(
                resolver._inner,
                "resolve",
                new=AsyncMock(side_effect=DNSException("fail")),
            ),
            pytest.raises(CheckError, match="DNS DNSKEY lookup failed"),
        ):
            await resolver.resolve_dnskey("bad.example.com")
