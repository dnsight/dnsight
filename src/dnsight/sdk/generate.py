"""Generic record generation via the registry."""

from __future__ import annotations

from dnsight.checks.base import BaseGenerateParams
from dnsight.core.exceptions import CapabilityError
from dnsight.core.models import GeneratedRecord
from dnsight.core.registry import get_check_def
from dnsight.core.types import Capability


__all__ = ["generate"]


def generate(check_name: str, *, params: BaseGenerateParams) -> GeneratedRecord:
    """Generate a DNS record for *check_name* and return a :class:`GeneratedRecord`.

    Args:
        check_name: Name of the check to generate.
        params: Parameters for generation.
    """
    import dnsight.checks  # noqa: F401

    defn = get_check_def(check_name)
    if Capability.GENERATE not in defn.capabilities:
        raise CapabilityError(check_name, str(Capability.GENERATE))
    result: GeneratedRecord = defn.cls().generate(params=params)
    return result
