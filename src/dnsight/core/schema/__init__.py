"""Schema types for config and check data — shared validation, single import.

When you change a check's ``FooData`` model, its ``FooConfig`` block in
``core/config/blocks.py``, or default field semantics, review the matching
``FooSchema`` in ``core/schema/`` (and vice versa) so annotated field types stay
aligned across config, parsing, and check output.
"""

from __future__ import annotations

from dnsight.core.schema.caa import CaaSchema
from dnsight.core.schema.dkim import DkimSchema
from dnsight.core.schema.dmarc import DmarcSchema
from dnsight.core.schema.dnssec import DnssecSchema
from dnsight.core.schema.headers import HeadersSchema
from dnsight.core.schema.mx import MxSchema
from dnsight.core.schema.spf import SpfSchema


class Schemas:
    """Namespace for check-specific schema types. Reduces import complexity."""

    Caa = CaaSchema
    Dnssec = DnssecSchema
    Dmarc = DmarcSchema
    Dkim = DkimSchema
    Headers = HeadersSchema
    Mx = MxSchema
    Spf = SpfSchema


# Re-export for type annotations (mypy resolves DmarcSchema.PolicyStr)
__all__ = [
    "CaaSchema",
    "DkimSchema",
    "DnssecSchema",
    "DmarcSchema",
    "HeadersSchema",
    "MxSchema",
    "SpfSchema",
    "Schemas",
]
