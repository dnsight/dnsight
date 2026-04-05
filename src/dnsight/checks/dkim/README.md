# DKIM check

Normative behaviour: [checks-reference.md — DKIM](../../../../.plan/v2/reference/checks-reference.md).

## Flow (summary)

1. **Selectors** — If ``dkim.selectors`` is **empty**, dnsight **discovers** by probing
   common selector names (see ``DEFAULT_DKIM_COMMON_SELECTORS`` in config defaults).
   Missing TXT on a probe is not an issue; the check **passes** if at least one probe
   yields a policy-valid key. If **non-empty**, those names are **required** (missing
   or invalid TXT is an issue); dnsight also probes other common names and flags
   **unexpected** TXT as an issue (align DNS with your allowlist or remove stale keys).
2. **Parse and validate** — Parse DKIM key records; evaluate algorithm, key length, and syntax.

`DKIMCheck` is CHECK-only (`BaseCheck[DKIMData, BaseGenerateParams]`). See [checks/base.py](../base.py) for the second type parameter convention.

SPF does not have an analogous allowlist today; it always evaluates the apex SPF TXT
and flatten rules from ``spf`` config.
