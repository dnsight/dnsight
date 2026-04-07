# MX check

**Ground truth:** This check’s code (`__init__.py`, `rules.py`, `models.py`), its config slice under [`core/schema/`](../../core/schema/), tests under [`tests/checks/`](../../../../tests/checks/), and YAML merge rules in [`core/config/parser/README.md`](../../core/config/parser/README.md). Repo-wide conventions: [`AGENTS.md`](../../../../AGENTS.md).

## Flow (summary)

1. **DNS** — Resolve `MX` for the domain; detect missing or duplicate-priority issues.
2. **Per MX host** — Optional connectivity checks (e.g. STARTTLS) per config; PTR and related rules when enabled.

See `mx/rules.py` for the ordered rule functions. For a full narrative and diagram when the check grows, extend this file similarly to SPF/CAA.
