"""Headers check schema types — shared by HeadersConfig and validation."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field


__all__ = ["HeadersSchema"]


class HeadersSchema:
    """Headers field types — shared by HeadersConfig and checks."""

    RequireList = Annotated[
        list[str],
        Field(
            min_length=1,
            description="Short tokens (e.g. HSTS, CSP) mapped to HTTP header names.",
        ),
    ]
    UrlsList = Annotated[
        list[str],
        Field(
            description="Explicit HTTPS URLs to probe; empty uses https://domain and https://www.domain."
        ),
    ]
