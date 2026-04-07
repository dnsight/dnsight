"""SPF schema types — shared by SpfConfig, SPFData, SpfGenerateParams."""

from __future__ import annotations

from typing import Annotated, Final, Literal, TypeAlias

from pydantic import Field


__all__ = ["SpfSchema"]


class SpfSchema:
    """SPF field types — shared by SpfConfig, SPFData, SpfGenerateParams."""

    DispositionLiteral: TypeAlias = Literal[
        "+all", "-all", "~all", "?all"
    ]  # NOSONAR S6794
    RequiredDispositionLiteral: TypeAlias = DispositionLiteral  # NOSONAR S6794
    DISPOSITION_VALUES: Final[tuple[str, ...]] = ("-all", "~all", "?all", "+all")

    DispositionStr = Annotated[
        DispositionLiteral,
        Field(description="Terminal all mechanism: +all, -all, ~all, or ?all"),
    ]
    LookupLimitInt = Annotated[
        int,
        Field(
            ge=1, le=50, description="Max DNS lookups for SPF (RFC 7208 default 10)."
        ),
    ]
