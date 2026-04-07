"""Tests for config defaults."""

from __future__ import annotations

from dnsight.core.config.defaults import (
    DEFAULT_DMARC_POLICY,
    DEFAULT_DMARC_RUA_REQUIRED,
    DEFAULT_DNS_PROVIDER,
    DEFAULT_GLOBAL_CONCURRENCY_LIMIT,
    DEFAULT_GLOBAL_MAX_RPS,
    DNS_PROVIDER_NAMESERVERS,
)


class TestDefaults:
    def test_dns_provider(self) -> None:
        assert DEFAULT_DNS_PROVIDER == "system"
        assert isinstance(DEFAULT_DNS_PROVIDER, str)

    def test_global_max_rps(self) -> None:
        assert DEFAULT_GLOBAL_MAX_RPS == 50.0
        assert isinstance(DEFAULT_GLOBAL_MAX_RPS, float)

    def test_global_concurrency_limit(self) -> None:
        assert DEFAULT_GLOBAL_CONCURRENCY_LIMIT == 10
        assert isinstance(DEFAULT_GLOBAL_CONCURRENCY_LIMIT, int)

    def test_dmarc_policy(self) -> None:
        assert DEFAULT_DMARC_POLICY == "reject"

    def test_dmarc_rua_required(self) -> None:
        assert DEFAULT_DMARC_RUA_REQUIRED is True


class TestDNSProviderNameservers:
    def test_has_google(self) -> None:
        assert "google" in DNS_PROVIDER_NAMESERVERS
        assert DNS_PROVIDER_NAMESERVERS["google"] == ["8.8.8.8", "8.8.4.4"]

    def test_has_cloudflare(self) -> None:
        assert "cloudflare" in DNS_PROVIDER_NAMESERVERS
        assert DNS_PROVIDER_NAMESERVERS["cloudflare"] == ["1.1.1.1", "1.0.0.1"]

    def test_has_quad9(self) -> None:
        assert "quad9" in DNS_PROVIDER_NAMESERVERS
        assert DNS_PROVIDER_NAMESERVERS["quad9"] == ["9.9.9.9", "149.112.112.112"]

    def test_has_opendns(self) -> None:
        assert "opendns" in DNS_PROVIDER_NAMESERVERS
        assert DNS_PROVIDER_NAMESERVERS["opendns"] == [
            "208.67.222.222",
            "208.67.220.220",
        ]

    def test_system_not_in_nameservers(self) -> None:
        assert "system" not in DNS_PROVIDER_NAMESERVERS

    def test_all_entries_are_list_of_strings(self) -> None:
        for provider, servers in DNS_PROVIDER_NAMESERVERS.items():
            assert isinstance(servers, list), f"{provider} is not a list"
            for s in servers:
                assert isinstance(s, str), f"{provider} entry {s!r} is not a string"
