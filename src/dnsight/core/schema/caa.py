"""CAA schema types — shared by CaaConfig, CAAData, CaaGenerateParams."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field


__all__ = ["CaaSchema"]


class CaaSchema:
    """CAA field types — shared by CaaConfig and generation params."""

    RequiredIssuersList = Annotated[
        list[str],
        Field(
            description="CA domain names that must be allowed by effective CAA issue tags."
        ),
    ]
    NamesList = Annotated[
        list[str],
        Field(
            description="Extra hostnames (labels or FQDNs) under the audited zone to check."
        ),
    ]
    MaxEnumerationDepthInt = Annotated[
        int,
        Field(
            ge=0,
            le=50,
            description="Max CNAME/DNAME chain depth during name discovery.",
        ),
    ]
    MaxNamesInt = Annotated[
        int,
        Field(
            ge=1, le=10_000, description="Max distinct names to enumerate and check."
        ),
    ]
