# DMARC check

Normative behaviour: [checks-reference.md — DMARC](../../../../.plan/v2/reference/checks-reference.md).

## Probe and validation order

1. **DNS** — Resolve `_dmarc.<domain>` `TXT`.
2. **Select** — `process_raw_records` picks a `v=DMARC1` record and flags multiple-record issues.
3. **Parse** — `parse_dmarc_record` builds `DMARCData` from tags.
4. **Rules** — Sequential rules: policy strength, subdomain policy, RUA, RUF, pct, alignment — each returns issues/recommendations using descriptor-backed severities.

`get_dmarc` fetches and parses one record. `check_dmarc` adds validation for missing/invalid DNS (dedicated partial results) then runs the rule list.

## Control flow (check)

```mermaid
flowchart TD
  start[check_dmarc] --> txt[resolve_txt _dmarc]
  txt --> raw[process_raw_records]
  raw --> parse[parse_dmarc_record]
  parse --> r1[rule_policy_strength]
  r1 --> r2[rule_subdomain_policy]
  r2 --> r3[rule_rua]
  r3 --> r4[rule_ruf]
  r4 --> r5[rule_pct]
  r5 --> r6[rule_alignment]
  r6 --> out[CheckResult]
```
