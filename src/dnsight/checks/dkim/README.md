# DKIM check

Normative behaviour: [checks-reference.md — DKIM](../../../../.plan/v2/reference/checks-reference.md).

## Flow (summary)

1. **Selectors** — Resolve TXT at configured (or discovered) selector DNS names.
2. **Parse and validate** — Parse DKIM key records; evaluate algorithm, key length, and syntax; emit issues per selector outcome.

`DKIMCheck` is CHECK-only (`BaseCheck[DKIMData, BaseGenerateParams]`). See [checks/base.py](../base.py) for the second type parameter convention.
