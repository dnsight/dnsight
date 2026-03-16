"""dnsight — DNS, email, and web security hygiene."""

from importlib.metadata import PackageNotFoundError, version


try:
    raw = version("dnsight")
    # hatch-vcs: clean version for releases, dev.local for untagged builds
    __version__ = raw if "dev" not in raw else "dev.local"
except PackageNotFoundError:
    __version__ = "dev.local"

__all__ = ["__version__"]
