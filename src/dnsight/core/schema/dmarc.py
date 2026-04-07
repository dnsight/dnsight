"""DMARC schema types — shared by DmarcConfig, DMARCData, DMARCGenerateParams."""

from __future__ import annotations

from typing import Annotated, Final, Literal, TypeAlias

from pydantic import Field


__all__ = ["DmarcSchema"]


class DmarcSchema:
    """DMARC field types — shared by DmarcConfig, DMARCData, DMARCGenerateParams."""

    PolicyLiteral: TypeAlias = Literal["none", "quarantine", "reject"]  # NOSONAR S6794
    AlignmentLiteral: TypeAlias = Literal["r", "s"]  # NOSONAR S6794
    POLICY_VALUES: Final[tuple[str, ...]] = ("none", "quarantine", "reject")
    ALIGNMENT_VALUES: Final[tuple[str, ...]] = ("r", "s")

    PolicyStr = Annotated[
        PolicyLiteral, Field(description="p= value: none, quarantine, or reject")
    ]
    SubdomainPolicyStr = Annotated[
        PolicyLiteral | None, Field(default=None, description="sp= value if set")
    ]
    PercentageInt = Annotated[int, Field(ge=0, le=100, description="pct= value, 0-100")]
    AlignmentStr = Annotated[
        AlignmentLiteral, Field(description="adkim/aspf value: r or s")
    ]
    AlignmentStrictnessBool = Annotated[
        bool, Field(description="If True, recommend strict (s).")
    ]
    ReportingURIsList = Annotated[
        list[str], Field(description="rua/ruf value: mailto or http URIs")
    ]
