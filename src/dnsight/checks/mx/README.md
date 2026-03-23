# MX check

Normative behaviour: [checks-reference.md — MX](../../../../.plan/v2/reference/checks-reference.md).

## Flow (summary)

1. **DNS** — Resolve `MX` for the domain; detect missing or duplicate-priority issues.
2. **Per MX host** — Optional connectivity checks (e.g. STARTTLS) per config; PTR and related rules when enabled.

See `mx/rules.py` for the ordered rule functions. For a full narrative and diagram when the check grows, extend this file similarly to SPF/CAA.
