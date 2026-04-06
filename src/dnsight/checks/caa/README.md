# CAA check

**Ground truth:** This check’s code (`__init__.py`, `rules.py`, `models.py`), its config slice under [`core/schema/`](../../core/schema/), tests under [`tests/checks/`](../../../../tests/checks/), and YAML merge rules in [`core/config/parser/README.md`](../../core/config/parser/README.md). Repo-wide conventions: [`AGENTS.md`](../../../../AGENTS.md).

## Probe and validation order

1. **Inventory** — `gather_caa_data` enumerates CAA (and related names per config) via the resolver; builds wire-level view and `CAAData.names_checked`.
2. **Validation** — `apply_caa_validation` checks issuer/issue wildcards, syntax, policy vs config, and optional strict recommendations.
3. **crt.sh (optional)** — If `cross_reference_crt_sh` is enabled, `crt_sh_issues` uses HTTP to compare discovered issuers against certificate transparency.

DNS first, then pure validation, then optional HTTP cross-reference.

## Control flow (check)

```mermaid
flowchart TD
  start[check_caa] --> gather[gather_caa_data DNS]
  gather --> val[apply_caa_validation]
  val --> crt{cross_reference_crt_sh?}
  crt -->|yes| http[crt_sh_issues HTTP]
  crt -->|no| done[CheckResult]
  http --> done
```

## Sequence (crt.sh branch)

```mermaid
sequenceDiagram
  participant Check as check_caa
  participant DNS as Resolver
  participant HTTP as HTTPClient
  Check->>DNS: CAA / related names
  DNS-->>Check: RRs
  Check->>Check: apply_caa_validation
  Check->>HTTP: crt.sh query if enabled
  HTTP-->>Check: CT data
  Check->>Check: merge issues
```
