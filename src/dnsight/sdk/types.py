"""Re-export generate parameter types for SDK and CLI consumers.

Callers that must not import :mod:`dnsight.checks` directly (e.g. the CLI) can
import concrete parameter types from here for :func:`dnsight.sdk.generate.generate`
and ``generate_*`` aliases.
"""

from __future__ import annotations

from dnsight.checks.base import BaseGenerateParams
from dnsight.checks.caa.models import CaaGenerateParams
from dnsight.checks.dmarc.models import DMARCGenerateParams
from dnsight.checks.headers import (
    CspGenerateParams,
    HeadersGenerateParams,
    HstsGenerateParams,
)
from dnsight.checks.mx.models import MXGenerateParams, MXGenerateTarget
from dnsight.checks.spf.models import SPFGenerateParams


__all__ = [
    "BaseGenerateParams",
    "CaaGenerateParams",
    "CspGenerateParams",
    "DMARCGenerateParams",
    "HeadersGenerateParams",
    "HstsGenerateParams",
    "MXGenerateParams",
    "MXGenerateTarget",
    "SPFGenerateParams",
]
