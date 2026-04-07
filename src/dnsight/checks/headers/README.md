# HTTP security headers check

**Ground truth:** This check’s code (`__init__.py`, `rules.py`, `models.py`), its config slice under [`core/schema/`](../../core/schema/), tests under [`tests/checks/`](../../../../tests/checks/), and YAML merge rules in [`core/config/parser/README.md`](../../core/config/parser/README.md). Repo-wide conventions: [`AGENTS.md`](../../../../AGENTS.md).

## Probe and validation order

1. **Probe URLs** — `fetch_headers_data` tries configured HTTPS (and fallbacks) with the shared HTTP client; records response headers or fetch error in `HeadersData`.
2. **Validate** — `validate_headers` evaluates required tokens (HSTS, CSP, etc.) against config and builds per-token `HeaderResult` entries inside the result.

`HeadersData` holds the full fetch outcome; each `HeaderResult` is one policy token’s pass/fail state.

## Control flow (check)

```mermaid
flowchart TD
  start[check_headers] --> fetch[fetch_headers_data HEAD/GET probes]
  fetch --> val[validate_headers]
  val --> out[CheckResult with issues and recommendations]
```

## Sequence (HTTP ordering)

```mermaid
sequenceDiagram
  participant Check as check_headers
  participant HTTP as HTTPClient
  Check->>HTTP: probe URL 1
  HTTP-->>Check: response or CheckError mapped
  Check->>HTTP: next probe if needed
  Check->>Check: validate_headers on HeadersData
```
