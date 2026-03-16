"""Schema types for config and check data — shared validation, single import."""

from __future__ import annotations

from dnsight.core.schema.dmarc import DmarcSchema


class Schemas:
    """Namespace for check-specific schema types. Reduces import complexity."""

    Dmarc = DmarcSchema


# Re-export for type annotations (mypy resolves DmarcSchema.PolicyStr)
__all__ = ["DmarcSchema", "Schemas"]
