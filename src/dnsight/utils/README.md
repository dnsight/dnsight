# Utils — I/O for checks

This package provides the DNS resolver and HTTP client used by checks. Both follow a **singleton pattern** with a get/set/reset API. Checks call `get_resolver()` or `get_http_client()` inside their `_get` / `_check` methods; tests replace the singleton with fakes to avoid real network I/O.

## Protocol-based design

Checks depend on **protocols**, not concrete classes:

- **`DNSResolver`** ([`dns.py`](dns.py)) — Runtime-checkable protocol. Any implementation (real resolver, fake, caching wrapper) can be injected via `set_resolver()`.
- **`HTTPClient`** ([`http.py`](http.py)) — Runtime-checkable protocol. Any implementation (real client, fake, mock) can be injected via `set_http_client()`.

This keeps checks testable and allows custom backends (e.g. logging, rate limiting) without changing check code.

## Singleton API

### DNS resolver

- **`get_resolver()`** — Returns the current resolver. If none is set, creates and stores a default `AsyncDNSResolver`.
- **`set_resolver(resolver)`** — Replace the module-level resolver (e.g. with `FakeDNSResolver` in tests).
- **`reset_resolver()`** — Set the resolver to `None`. The next `get_resolver()` call will create a new default.

### HTTP client

- **`get_http_client()`** — Returns the current client. If none is set, creates and stores a default `AsyncHTTPClient`.
- **`set_http_client(client)`** — Replace the module-level client (e.g. with `FakeHTTPClient` in tests).
- **`reset_http_client()`** — Set the client to `None`. The next `get_http_client()` call will create a new default.

## DNS resolver — available methods

`DNSResolver` and `AsyncDNSResolver` provide:

| Method             | Returns                                   | Use case              |
|--------------------|-------------------------------------------|------------------------|
| `resolve_txt(name)`  | `list[str]`                              | TXT records (e.g. DMARC, SPF) |
| `resolve_mx(name)`   | `list[tuple[int, str]]` (preference, exchange) | MX records        |
| `resolve_caa(name)`  | `list[tuple[int, str, str]]`             | CAA records           |
| `resolve_ns(name)`   | `list[str]`                              | NS records            |
| `resolve_ds(name)`   | `list[tuple[int, int, int, bytes]]`      | DS records            |
| `resolve_dnskey(name)` | `list[dict[str, Any]]`                 | DNSKEY records        |

All DNS failures are translated to `CheckError` so checks see a uniform exception type. Checks catch these (and similar HTTP failures), map recoverable cases into `CheckResult` with `status`/`error`/`issues` as appropriate, and only let unexpected failures propagate—see each check’s `_check` implementation.

## HTTP client — available methods

`HTTPClient` and `AsyncHTTPClient` provide:

- **`get(url, **kwargs)`** → `HTTPResponse`
- **`head(url, **kwargs)`** → `HTTPResponse`

`HTTPResponse` is a frozen Pydantic model with `status_code`, `headers` (dict), and `text`. Transport and protocol errors are translated to `CheckError`. As with DNS, header checks translate failures into `CheckResult` fields instead of leaking raw transport errors to callers.

## FakeDNSResolver

Defined in [`dns.py`](dns.py). Test double that returns pre-configured records.

- **Constructor**: `FakeDNSResolver(records=None)`. `records` is a dict keyed by `"name/TYPE"` (e.g. `"_dmarc.example.com/TXT"`). Values are lists in the same shape as the corresponding `resolve_*` return type.
- **Missing key**: If a requested `name`/type is not in the dict, `FakeDNSResolver` raises `CheckError`, matching real resolver behaviour.

Example:

```python
from dnsight.utils.dns import FakeDNSResolver, set_resolver

set_resolver(FakeDNSResolver({
    "_dmarc.example.com/TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
}))
```

## FakeHTTPClient

Defined in [`http.py`](http.py). Test double that returns pre-configured responses.

- **Constructor**: `FakeHTTPClient(responses=None)`. `responses` is a dict mapping URL to `HTTPResponse` instances.
- **Missing URL**: If a requested URL is not in the dict, `FakeHTTPClient` raises `CheckError`, matching real client behaviour.

Example:

```python
from dnsight.utils.http import FakeHTTPClient, HTTPResponse, set_http_client

set_http_client(FakeHTTPClient({
    "https://example.com": HTTPResponse(status_code=200, headers={}, text=""),
}))
```

## Testing recipe

1. In a test, call `set_resolver(FakeDNSResolver(...))` and/or `set_http_client(FakeHTTPClient(...))` before running the code under test.
2. The test suite's `conftest.py` uses an autouse fixture that calls `reset_resolver()` and `reset_http_client()` after each test, so singletons do not leak between tests.
3. Do not rely on the default resolver/client in tests; always set fakes so the test does not perform real network I/O.
