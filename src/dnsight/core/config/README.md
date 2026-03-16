# Config

This package holds the config model and target-based resolution used by dnsight. Config blocks are **mergeable** and **frozen**; resolution is done by the **ConfigManager** using pattern matching and a per-run cache.

## MergeableConfig

Defined in [`mergeable.py`](mergeable.py). Base for all config blocks. All blocks are frozen Pydantic models.

- **`merge(partial)`** — Returns a **new** instance with `partial`'s explicitly-set fields merged into `self`. Recurses into nested `MergeableConfig` children. Only fields that were set on `partial` (e.g. via `model_fields_set`) are applied; the base is never mutated.
- **`resolve(config=, partial=, **kwargs)`** — Class method. Layers `config` → `partial` → `kwargs` into a single resolved instance. Each layer only applies explicitly-set fields. Use for one-off resolution (e.g. CLI overlay).

Merge is copy-then-merge: the receiver is not modified. Use the returned instance.

## Config blocks

Defined in [`blocks.py`](blocks.py). All extend `MergeableConfig` and use defaults from [`defaults.py`](defaults.py).

| Block            | Purpose                          |
|------------------|----------------------------------|
| `ResolverConfig` | DNS provider preset (system, google, cloudflare, etc.); `resolved_nameservers()` |
| `ThrottleConfig` | `global_max_rps`, `global_max_concurrency` |
| `DmarcConfig`    | `policy`, `rua_required`         |
| `SpfConfig`      | `policy`                         |
| `Config`         | Root: `resolver`, `throttle`, `dmarc`, `spf` |

Adding a new check-specific block: subclass `MergeableConfig`, add fields with `Field(default=...)`, then add a field to `Config` (e.g. `xxx: XxxConfig = Field(default=XxxConfig(), ...)`).

## ConfigManager

Defined in [`config_manager.py`](config_manager.py). Resolves config **per target** (domain/path).

- **Inputs**: `targets` (list of `Target`), `target_configs` (ordered dict of pattern → `TargetConfig`), `default_target_config` (`Config`), `default_target_checks` (`TargetChecks`), and optional `global_max_rps` / `global_max_concurrency`.
- **`resolve(domain_or_target, path=None)`** — Returns a `ResolvedTargetConfig` for that target. Call forms: pass a `Target`; or `(domain: str, path: str | None)`; or a single normalised target string.
- **Cache**: `resolved_configs` is a mutable dict on the instance; each (domain, path) is resolved once per run and cached. Not thread-safe.

**Precedence**: Default config and default checks are merged with every matching rule in `target_configs`, in definition order. For each rule, `Pattern.matches(pattern, target)` must be true, and the target must not match any entry in that rule's `exclude` list. Later rules merge on top of earlier ones.

## TargetChecks

Defined in [`targets.py`](targets.py). Stores enabled check names as a **`frozenset[str]`**.

- There are **no check-specific fields** in `TargetChecks`. The registry (`core/registry.py`) is the single source of truth for valid check names; config only stores strings.
- Adding a new check never requires changing `TargetChecks` or this module — just register the check and use its name in config.
- `TargetConfig` (per-pattern rule) carries an optional `checks: ChecksUpdate` — either `ChecksReplace(enabled=...)` or `ChecksDelta(add=..., remove=...)`. Parsed from YAML via `parse_checks()`.

## ResolvedTargetConfig

The result of `ConfigManager.resolve(...)`: a frozen dataclass with `checks: TargetChecks` and `config: Config`. This is what the orchestrator uses per target to know which checks to run and with what config.

## Adding a new config slice

To add config for a new check (e.g. `xxx`):

1. **Add a block in `blocks.py`**: Create `class XxxConfig(MergeableConfig):` with the needed fields and defaults (use `defaults.py` for constants). Add `xxx: XxxConfig = Field(default=XxxConfig(), ...)` to `Config`.
2. **Wire the parser**: In the versioned config parser (e.g. [`parser/versions/v1.py`](parser/versions/v1.py)), map the YAML keys for that check onto `XxxConfig` when building rule config (see existing `dmarc` / `spf` field maps).

No change is required in `TargetChecks` or the registry; only the new block and root `Config` need to be extended.
