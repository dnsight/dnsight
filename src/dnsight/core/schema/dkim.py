"""DKIM schema types — shared by DkimConfig and validation."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field


__all__ = ["DkimSchema"]


class DkimSchema:
    """DKIM field types — shared by DkimConfig and checks."""

    MinKeyBitsInt = Annotated[
        int,
        Field(ge=512, le=16384, description="Minimum RSA key size in bits for DKIM."),
    ]
    SelectorsList = Annotated[
        list[str],
        Field(description="DKIM selector names to query (before common defaults)."),
    ]
    DisallowedAlgorithmsList = Annotated[
        list[str],
        Field(
            description=(
                "Lowercase names matching k= or hash algorithms (e.g. sha1) to flag."
            )
        ),
    ]
