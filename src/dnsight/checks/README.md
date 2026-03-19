# Checks

This package contains dnsight's check implementations. Each check fetches data (DNS, HTTP), parses it into a typed model, validates against policy or best practice, and returns a `CheckResult`. The **BaseCheck** ABC and registry pattern are the reusable foundation for all checks.

## Check structure

Each check is a **package** under `checks/<name>/` (e.g. `checks/dmarc/`). The check class and its public API always live in **`checks/<name>/__init__.py`** so that opening the check shows the check first.

**Optional modules** (add only when they improve readability):

- **`models.py`** — Issue and recommendation ID enums, descriptor maps, and the check’s data/params types (`*Data`, `*GenerateParams`). Use when IDs and data would clutter `__init__.py`. Typically ~100–200 lines for a complex check; smaller for simple ones.
- **`rules.py`** — When present, define validation rules and helpers as **module-level functions**. See **Rules module pattern** below.

**Resulting layout:**

- **Simple check:** Single file `checks/<name>/__init__.py`.
- **Average check:** `__init__.py` + `models.py` (no `rules.py` if validation stays small).
- **Complex check:** `__init__.py` + `models.py` + `rules.py`.

Dependencies: `models.py` imports only from `checks.base` and `core`. `rules.py` imports from `.models` and `core`/`utils`. `__init__.py` imports from `.models` and optionally `.rules`, and re-exports the public API. No separate helpers-only file; helpers live in `rules.py` when that file exists.

### Rules module pattern

When a check has a `rules.py` module, define rules and helpers as **module-level functions and constants**:

- **Module-level constants** — Use a leading `_` for parser-only or comparison tables (e.g. `_POLICY_STRENGTH`) so they stay module-local. Reserve unprefixed constants for values shared with the check class in `__init__.py` (e.g. `DMARC1_PREFIX`).
- **Public functions** (called from the check class in `__init__.py`, or covered by unit tests) have no leading underscore and belong in `__all__` only if they are part of that intentional surface.
- **Internal helpers** (used only within `rules.py`) use a leading `_` and are omitted from `__all__`.
- **Check as controller** — The check class orchestrates flow (DNS, parsing, validation, result building) and calls each rule individually; it does not use a `run_all`-style wrapper.
- **Named imports** — `from dnsight.checks.xxx.rules import rule_foo, rule_bar, SOME_CONSTANT`.

## BaseCheck ABC contract

Defined in [`base.py`](base.py).

### Class variables (declare in subclass)

- **`name`** — `ClassVar[str]`: Stable lowercase identifier used by the registry and config (e.g. `"dmarc"`, `"spf"`).
- **`capabilities`** — `ClassVar[frozenset[Capability]]`: Declared capabilities: `CHECK`, `GENERATE`, `FLATTEN`.

### Public methods (on BaseCheck)

- **`get(domain, config=, throttler=)`** → `CheckDataT`: Fetch and parse without validation. Calls `throttler.wait()` if provided, then delegates to `_get()`.
- **`check(domain, config=, throttler=)`** → `CheckResult[CheckDataT]`: Fetch, parse, and validate. Raises `CapabilityError` if `CHECK` not in capabilities. Calls `throttler.wait()` if provided, then delegates to `_check()`.
- **`generate(config=)`** → `GeneratedRecord`: Generate a DNS record from config. Raises `CapabilityError` if `GENERATE` not in capabilities. Delegates to `_generate()`.

### Abstract methods (implement in subclass)

- **`_get(domain, config=)`** → `CheckDataT`: Fetch and parse only.
- **`_check(domain, config=)`** → `CheckResult[CheckDataT]`: Fetch, parse, and validate.

### Optional override

- **`_generate(config=)`** → `GeneratedRecord`: Override only if the check declares `GENERATE`. The base raises `NotImplementedError` if a subclass declares `GENERATE` but does not override.

### BaseCheckData

All check data types (e.g. `DMARCData`, `SPFData`) extend `BaseCheckData`: a frozen Pydantic model. It provides a common type bound for `BaseCheck[CheckDataT]` and a place for shared behaviour.

## Implementing a new check

1. **Create a package** `checks/<name>/` (e.g. `checks/spf/`) with at least **`__init__.py`** containing:
   - The check class extending `BaseCheck[XxxData, XxxGenerateParams]`, with `name` and `capabilities` class variables.
   - Static methods as the direct public API: `get_xxx(domain, config=)`, `check_xxx(domain, config=)`, and optionally `generate_xxx(config=)`.
   - Implementations of `_get` and `_check` that delegate to those static methods (and `_generate` if applicable).
   - Re-exports so that `from dnsight.checks.xxx import get_xxx, check_xxx, XxxCheck, ...` works.

   Optionally add **`models.py`** (IssueId, RecommendationId, descriptor maps, `*Data`, `*GenerateParams`) and **`rules.py`** (validation rules and helpers) when the check is complex enough; see **Check structure** above.

2. **Use the registry**: Apply the `@register` decorator to the check class so it is discovered at import time.

3. **Add a config slice**: In `core/config/blocks.py`, add a config block for the check (e.g. `XxxConfig`) and include it in the root `Config` if needed. See [core/config/README.md](../core/config/README.md).

4. **I/O**: Use `get_resolver()` from `dnsight.utils.dns` and/or `get_http_client()` from `dnsight.utils.http` inside `_get` / `_check`. Do not thread resolver or client through function signatures; the singleton is swapped in tests via `set_resolver()` / `set_http_client()`. See [utils/README.md](../utils/README.md).

5. **Tests**: Use `FakeDNSResolver` and `FakeHTTPClient` via `set_resolver()` / `set_http_client()` so tests do not perform real network I/O. The test suite's `conftest.py` resets these singletons after each test.

## Registry integration

The registry lives in `dnsight.core.registry`. Checks self-register at import time using the `@register` decorator on the check class. The class must have `name` and `capabilities` class variables.

- **`register`** — Decorator: `@register` on the check class.
- **`get(name)`** — Look up a check by name; raises `CheckNotFoundError` if missing.
- **`all_checks()`** — Return all registered `CheckDefinition` instances.
- **`supporting(capability)`** — Return definitions that support the given capability (e.g. `Capability.GENERATE`).

`CheckDefinition` is a frozen dataclass with `name`, `cls`, and `capabilities`.

## Public API layers

Each check exposes three distinct entry points with different intended consumers:

- **Module-level functions** (`check_dmarc`, `get_dmarc`) — primary SDK/CLI surface; re-exported at `dnsight.checks`.
- **Class static methods** (`DMARCCheck.check_dmarc`) — same implementations; for callers who import the class as a single unit.
- **Instance method via BaseCheck** (`DMARCCheck().check(domain, throttler=t)`) — orchestrator only; capability-gated and throttle-aware.

Module-level functions are the **primary SDK surface** and are re-exported at `dnsight.checks`. The class statics are aliases to the same implementations. Instance methods are only called by the orchestrator.

## Reference implementation

The [**dmarc**](dmarc/) package is the canonical check: `dmarc/__init__.py` defines `DMARCCheck` with `@register`, static methods as public API, and `_get`/`_check`/`_generate` bridges to `BaseCheck`; `models.py` holds IDs, descriptor maps, and data/params types; `rules.py` defines validation rules and helpers as module-level functions. Use it as the template for new checks.
