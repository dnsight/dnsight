# Checks

This package contains dnsight's check implementations. Each check fetches data (DNS, HTTP), parses it into a typed model, validates against policy or best practice, and returns a `CheckResult`. The **BaseCheck** ABC and registry pattern are the reusable foundation for all checks.

## Check structure

Each check is a **package** under `checks/<name>/` (e.g. `checks/dmarc/`). The check class and its public API always live in **`checks/<name>/__init__.py`** so that opening the check shows the check first.

**Optional modules** (add only when they improve readability):

- **`models.py`** — Issue and recommendation ID enums, descriptor maps, and the check’s data/params types (`*Data`, `*GenerateParams`). Use when IDs and data would clutter `__init__.py`. Typically ~100–200 lines for a complex check; smaller for simple ones.
- **`rules.py`** — When present, use an `XxxRules` class (e.g. `DMARCRules`) to group validation rules and helpers. See **Rules class pattern** below.

**Resulting layout:**

- **Simple check:** Single file `checks/<name>/__init__.py`.
- **Average check:** `__init__.py` + `models.py` (no `rules.py` if validation stays small).
- **Complex check:** `__init__.py` + `models.py` + `rules.py`.

Dependencies: `models.py` imports only from `checks.base` and `core`. `rules.py` imports from `.models` and `core`/`utils`. `__init__.py` imports from `.models` and optionally `.rules`, and re-exports the public API. No separate helpers-only file; helpers live in `rules.py` when that file exists.

### Rules class pattern

When a check has a `rules.py` module, use an `XxxRules` class (e.g. `DMARCRules`) to group rules and helpers:

- **Class attributes** for constants (e.g. `DMARC1_PREFIX`, `POLICY_STRENGTH`).
- **Public static methods** (used by the check class) have no leading underscore — they are part of the package API.
- **Internal static methods** (used only by other methods in the same class) use a leading `_` to signal they are not for external use.
- **Check as controller** — The check class orchestrates flow (DNS, parsing, validation, result building) and calls each rule individually; it does not use a `run_all`-style wrapper.
- **Single import** — `from dnsight.checks.xxx.rules import XxxRules`, then `XxxRules.method()`.

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

## Reference implementation

The [**dmarc**](dmarc/) package is the canonical check: `dmarc/__init__.py` defines `DMARCCheck` with `@register` and static methods `get_dmarc` / `check_dmarc` / `generate_dmarc`; optional `models.py` holds IDs, descriptors, and data types; optional `rules.py` defines `DMARCRules` with static methods for validation rules and helpers. DMARCCheck imports `DMARCRules` and calls each rule individually. Use it as the template for new checks.
