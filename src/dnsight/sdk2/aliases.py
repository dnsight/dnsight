"""Experimental SDK aliases — same bindings as :mod:`dnsight.sdk.aliases` (alternate import path)."""

from __future__ import annotations

from dnsight.checks.caa.models import CAAData, CaaGenerateParams
from dnsight.checks.dkim.models import DKIMData
from dnsight.checks.dmarc.models import DMARCData, DMARCGenerateParams
from dnsight.checks.dnssec.models import DNSSECData
from dnsight.checks.headers import HeadersGenerateParams, HstsGenerateParams
from dnsight.checks.headers.models import HeadersData
from dnsight.checks.mx.models import MXData, MXGenerateParams
from dnsight.checks.spf.models import SPFData, SPFGenerateParams
from dnsight.core.config.blocks import (
    CaaConfig,
    DkimConfig,
    DmarcConfig,
    DnssecConfig,
    HeadersConfig,
    MxConfig,
    SpfConfig,
)
from dnsight.sdk._bindings import (
    CheckRunAsyncCallable,
    CheckRunBinder,
    CheckRunSyncCallable,
    GenerateBinder,
    GenerateCallable,
)


__all__ = [
    "check_caa",
    "check_caa_sync",
    "check_dkim",
    "check_dkim_sync",
    "check_dmarc",
    "check_dmarc_sync",
    "check_dnssec",
    "check_dnssec_sync",
    "check_headers",
    "check_headers_sync",
    "check_mx",
    "check_mx_sync",
    "check_spf",
    "check_spf_sync",
    "generate_caa",
    "generate_dmarc",
    "generate_headers",
    "generate_mx",
    "generate_spf",
]

_caa_b = CheckRunBinder[CAAData, CaaConfig](
    "caa", summary="Run the Certification Authority Authorization (CAA) check."
)
check_caa: CheckRunAsyncCallable[CAAData, CaaConfig] = _caa_b.async_run()
check_caa_sync: CheckRunSyncCallable[CAAData, CaaConfig] = _caa_b.sync()
del _caa_b

_dkim_b = CheckRunBinder[DKIMData, DkimConfig]("dkim", summary="Run the DKIM check.")
check_dkim: CheckRunAsyncCallable[DKIMData, DkimConfig] = _dkim_b.async_run()
check_dkim_sync: CheckRunSyncCallable[DKIMData, DkimConfig] = _dkim_b.sync()
del _dkim_b

_dnssec_b = CheckRunBinder[DNSSECData, DnssecConfig](
    "dnssec", summary="Run the DNSSEC check."
)
check_dnssec: CheckRunAsyncCallable[DNSSECData, DnssecConfig] = _dnssec_b.async_run()
check_dnssec_sync: CheckRunSyncCallable[DNSSECData, DnssecConfig] = _dnssec_b.sync()
del _dnssec_b

_headers_b = CheckRunBinder[HeadersData, HeadersConfig](
    "headers", summary="Run the HTTP security headers check."
)
check_headers: CheckRunAsyncCallable[HeadersData, HeadersConfig] = (
    _headers_b.async_run()
)
check_headers_sync: CheckRunSyncCallable[HeadersData, HeadersConfig] = _headers_b.sync()
del _headers_b

_mx_b = CheckRunBinder[MXData, MxConfig]("mx", summary="Run the MX check.")
check_mx: CheckRunAsyncCallable[MXData, MxConfig] = _mx_b.async_run()
check_mx_sync: CheckRunSyncCallable[MXData, MxConfig] = _mx_b.sync()
del _mx_b

_spf_b = CheckRunBinder[SPFData, SpfConfig]("spf", summary="Run the SPF check.")
check_spf: CheckRunAsyncCallable[SPFData, SpfConfig] = _spf_b.async_run()
check_spf_sync: CheckRunSyncCallable[SPFData, SpfConfig] = _spf_b.sync()
del _spf_b

_dmarc_b = CheckRunBinder[DMARCData, DmarcConfig](
    "dmarc", summary="Run the DMARC check."
)
check_dmarc: CheckRunAsyncCallable[DMARCData, DmarcConfig] = _dmarc_b.async_run()
check_dmarc_sync: CheckRunSyncCallable[DMARCData, DmarcConfig] = _dmarc_b.sync()
del _dmarc_b

generate_caa: GenerateCallable[CaaGenerateParams] = GenerateBinder[CaaGenerateParams](
    "caa", summary="Generate CAA records from parameters."
).build()

generate_dmarc: GenerateCallable[DMARCGenerateParams] = GenerateBinder[
    DMARCGenerateParams
]("dmarc", summary="Generate a DMARC TXT record.").build()

generate_spf: GenerateCallable[SPFGenerateParams] = GenerateBinder[SPFGenerateParams](
    "spf", summary="Generate an SPF TXT record."
).build()

generate_mx: GenerateCallable[MXGenerateParams] = GenerateBinder[MXGenerateParams](
    "mx", summary="Generate MX RDATA lines (preference and mail host per line)."
).build()

generate_headers: GenerateCallable[HeadersGenerateParams] = GenerateBinder[
    HeadersGenerateParams
](
    "headers",
    default_factory=HstsGenerateParams,
    summary="Generate a CSP or HSTS header line (defaults to HSTS when params omitted).",
).build()
