"""SPF schema types — shared by SpfConfig, SPFData, SpfGenerateParams."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field


__all__ = ["SpfSchema"]


class SpfSchema:
    """SPF field types — shared by SpfConfig, SPFData, SpfGenerateParams."""

    DispositionStr = Annotated[
        str,
        Field(
            pattern=r"^[+?~-]all$",
            description="Terminal all mechanism: +all, -all, ~all, or ?all",
        ),
    ]
    LookupLimitInt = Annotated[
        int,
        Field(
            ge=1, le=50, description="Max DNS lookups for SPF (RFC 7208 default 10)."
        ),
    ]
    RequiredDispositionLiteral = Literal["-all", "~all", "?all", "+all"]
