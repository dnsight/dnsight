"""DKIM schema types — shared by DkimConfig and validation."""

from __future__ import annotations

from typing import Annotated, Final

from pydantic import Field

import dnsight.core.config.defaults as _defaults


__all__ = ["DkimSchema"]


class DkimSchema:
    """DKIM field types — shared by DkimConfig and checks."""

    #: Same tuple as :data:`dnsight.core.config.defaults.DEFAULT_DKIM_COMMON_SELECTORS`.
    COMMON_SELECTOR_SUGGESTIONS: Final[tuple[str, ...]] = (
        _defaults.DEFAULT_DKIM_COMMON_SELECTORS
    )
    #: Tab-completion hints for ``--disallowed-algorithms`` (weak k=/hash tokens); the
    #: check still accepts any string that matches its normalisation rules.
    WEAK_ALGORITHM_COMPLETION_HINTS: Final[tuple[str, ...]] = (
        "md5",
        "rsa-md5",
        "sha1",
        "rsa-sha1",
    )

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
