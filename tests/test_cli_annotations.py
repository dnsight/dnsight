"""Stable re-exports from :mod:`dnsight.cli.annotations`."""

from __future__ import annotations

import dnsight.cli.annotations as annotations


def test_annotations_all_exports_resolve() -> None:
    for name in annotations.__all__:
        assert getattr(annotations, name) is not None
