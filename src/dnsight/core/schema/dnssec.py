"""DNSSEC schema types — shared by DnssecConfig and validation."""

from __future__ import annotations

from typing import Annotated, Final

from pydantic import Field


__all__ = ["DnssecSchema"]


class DnssecSchema:
    """DNSSEC field types — shared by DnssecConfig and checks."""

    #: Tab-completion hints for ``--disallowed-algorithms`` (IANA numbers / names); the
    #: check matches after uppercasing and removing hyphens.
    WEAK_ALGORITHM_COMPLETION_HINTS: Final[tuple[str, ...]] = (
        "1",
        "3",
        "5",
        "6",
        "12",
        "RSAMD5",
        "DSA",
        "RSASHA1",
        "DSANSEC3SHA1",
        "ECCGOST",
    )

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
