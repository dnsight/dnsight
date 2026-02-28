try:
    from importlib.metadata import version

    raw = version("dnsight")
    # Show clean version for releases, "dev" for untagged local builds
    __version__ = raw if "dev" not in raw else "dev.local"
except Exception:
    __version__ = "dev"
