"""Typer command registration for dnsight."""

from __future__ import annotations

import typer

from dnsight.cli.commands.audit import register_audit
from dnsight.cli.commands.caa import register_caa
from dnsight.cli.commands.config import register_config
from dnsight.cli.commands.dkim import register_dkim
from dnsight.cli.commands.dmarc import register_dmarc
from dnsight.cli.commands.dnssec import register_dnssec
from dnsight.cli.commands.docs_cmd import register_docs
from dnsight.cli.commands.headers import register_headers
from dnsight.cli.commands.mx import register_mx
from dnsight.cli.commands.spf import register_spf
from dnsight.cli.commands.version import register_version, version_cmd


__all__ = ["register_commands", "version_cmd"]


def register_commands(app: typer.Typer) -> None:
    """Attach all per-check command groups in stable order."""
    register_version(app)
    register_docs(app)
    register_audit(app)
    register_config(app)
    # Checks
    register_caa(app)
    register_dkim(app)
    register_dmarc(app)
    register_dnssec(app)
    register_headers(app)
    register_mx(app)
    register_spf(app)
