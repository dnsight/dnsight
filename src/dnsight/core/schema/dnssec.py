"""DNSSEC schema types — shared by DnssecConfig and validation."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field


__all__ = ["DnssecSchema"]


class DnssecSchema:
    """DNSSEC field types — shared by DnssecConfig and checks."""

    SignatureExpiryDaysWarningInt = Annotated[
        int, Field(ge=0, le=3650, description="Days before RRSIG expiry to warn.")
    ]
    DisallowedAlgorithmsList = Annotated[
        list[str],
        Field(
            description=(
                "DNSSEC algorithm numbers (e.g. '1') or names (e.g. 'RSAMD5') "
                "to flag as weak."
            )
        ),
    ]
