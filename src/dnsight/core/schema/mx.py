"""MX check schema types — shared by MxConfig and validation."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field


__all__ = ["MxSchema"]


class MxSchema:
    """MX field types — shared by MxConfig and checks."""

    MxPreferenceInt = Annotated[
        int,
        Field(
            ge=0, le=65535, description="MX preference (lower values are preferred)."
        ),
    ]
    MxExchangeStr = Annotated[
        str,
        Field(
            min_length=1, max_length=253, description="Mail exchange hostname (FQDN)."
        ),
    ]
    CheckPtrBool = Annotated[
        bool, Field(description="Whether to verify reverse DNS (PTR) for each MX host.")
    ]
    CheckStarttlsBool = Annotated[
        bool,
        Field(
            description="Whether to probe SMTP STARTTLS on port 25 for each MX host."
        ),
    ]
    StarttlsTimeoutSeconds = Annotated[
        float,
        Field(
            gt=0,
            le=600,
            description="Seconds to wait per STARTTLS connection and read phase.",
        ),
    ]
