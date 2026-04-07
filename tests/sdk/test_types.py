"""Smoke tests for :mod:`dnsight.sdk.types` re-exports."""

from __future__ import annotations

from dnsight.checks.base import BaseGenerateParams as DirectBase
from dnsight.checks.caa.models import CaaGenerateParams as DirectCaa
from dnsight.checks.dmarc.models import DMARCGenerateParams as DirectDmarc
from dnsight.checks.headers import CspGenerateParams as DirectCsp
from dnsight.checks.headers import HeadersGenerateParams as DirectHeaders
from dnsight.checks.headers import HstsGenerateParams as DirectHsts
from dnsight.checks.mx.models import MXGenerateParams as DirectMx
from dnsight.checks.spf.models import SPFGenerateParams as DirectSpf
from dnsight.sdk import (
    BaseGenerateParams,
    CaaGenerateParams,
    CspGenerateParams,
    DMARCGenerateParams,
    HeadersGenerateParams,
    HstsGenerateParams,
    MXGenerateParams,
    SPFGenerateParams,
)
from dnsight.sdk import types as sdk_types


def test_sdk_package_types_match_checks_modules() -> None:
    assert BaseGenerateParams is DirectBase
    assert CaaGenerateParams is DirectCaa
    assert CspGenerateParams is DirectCsp
    assert DMARCGenerateParams is DirectDmarc
    assert HeadersGenerateParams is DirectHeaders
    assert HstsGenerateParams is DirectHsts
    assert MXGenerateParams is DirectMx
    assert SPFGenerateParams is DirectSpf


def test_sdk_types_submodule_matches_package_exports() -> None:
    assert sdk_types.BaseGenerateParams is BaseGenerateParams
    assert sdk_types.DMARCGenerateParams is DMARCGenerateParams
