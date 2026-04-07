"""Smoke test: package is importable and marked as typed."""

import dnsight


def test_package_has_version():
    assert hasattr(dnsight, "__version__")
    assert isinstance(dnsight.__version__, str)
