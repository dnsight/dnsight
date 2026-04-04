"""Headers check schema types — shared by HeadersConfig and validation."""

from __future__ import annotations

from typing import Annotated, Final

from pydantic import Field


__all__ = ["HeadersSchema"]


class HeadersSchema:
    """Headers field types — shared by HeadersConfig and checks."""

    #: Normalised token (uppercase, spaces/hyphens → underscores) to canonical HTTP
    #: header name for lookup; see the headers check rules.
    REQUIRE_TOKEN_TO_HEADER_NAME: Final[dict[str, str]] = {
        "HSTS": "Strict-Transport-Security",
        "CSP": "Content-Security-Policy",
        "X_FRAME_OPTIONS": "X-Frame-Options",
        "PERMISSIONS_POLICY": "Permissions-Policy",
        "X_CONTENT_TYPE_OPTIONS": "X-Content-Type-Options",
    }

    #: User-facing labels for CLI completion (normalise to keys in
    #: :attr:`REQUIRE_TOKEN_TO_HEADER_NAME`).
    REQUIRE_TOKEN_LABELS: Final[tuple[str, ...]] = (
        "HSTS",
        "CSP",
        "X-Frame-Options",
        "Permissions-Policy",
        "X-Content-Type-Options",
    )

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
