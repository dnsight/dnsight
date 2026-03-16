"""DMARC schema types — shared by DmarcConfig, DMARCData, DMARCGenerateParams."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field


__all__ = ["DmarcSchema"]


class DmarcSchema:
    """DMARC field types — shared by DmarcConfig, DMARCData, DMARCGenerateParams."""

    PolicyStr = Annotated[
        str,
        Field(
            pattern="^(none|quarantine|reject)$",
            description="p= value: none, quarantine, or reject",
        ),
    ]
    SubdomainPolicyStr = Annotated[
        str | None,
        Field(
            default=None,
            pattern="^(none|quarantine|reject)$",
            description="sp= value if set",
        ),
    ]
    PercentageInt = Annotated[int, Field(ge=0, le=100, description="pct= value, 0-100")]
    AlignmentStr = Annotated[
        str, Field(pattern="^(r|s)$", description="adkim/aspf value: r or s")
    ]
    AlignmentStrictnessBool = Annotated[
        bool, Field(description="If True, recommend strict (s).")
    ]
    ReportingURIsList = Annotated[
        list[str], Field(description="rua/ruf value: mailto or http URIs")
    ]
