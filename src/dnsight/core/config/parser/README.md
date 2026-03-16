# Config parser — versioned file loading

This package loads the dnsight config from YAML files and dispatches to a **version-specific parser** based on the `version` key. Each version is a single callable that turns a raw dict into a `ConfigManager`.

## Architecture

1. **Entry point**: [`file.py`](file.py) — `config_manager_from_file(path)`.
   - Resolves the path, requires `.yaml` or `.yml`.
   - Reads and parses YAML with `safe_load`.
   - Requires a top-level `version` key (integer). Raises `ConfigError` if missing or invalid.
   - Looks up the parser in `VERSION_PARSERS[version]` and calls it with the full parsed dict.
   - Returns the resulting `ConfigManager`.

2. **Version registry**: [`versions/__init__.py`](versions/__init__.py) — `VERSION_PARSERS: dict[int, VersionParser]`.
   - Maps version number → parser callable (e.g. `{1: parse_v1}`).

3. **Version parsers**: One module per version under [`versions/`](versions/) (e.g. `v1.py` with `parse_v1`). Each parser is responsible for the entire shape of that version’s YAML and returns a `ConfigManager`.

## VersionParser protocol

Defined in [`versions/base.py`](versions/base.py):

```python
class VersionParser(Protocol):
    def __call__(self, data: dict[str, Any]) -> ConfigManager: ...
```

Any callable that accepts a `dict[str, Any]` (the parsed YAML) and returns a `ConfigManager` satisfies the protocol. Typically a module exposes a single function, e.g. `parse_v1`.

## Adding a new version

1. **Add a parser module**: e.g. `versions/vN.py` with a function `parse_vN(data: dict[str, Any]) -> ConfigManager` that builds `Config`, `Target`, `TargetConfig`, etc. and returns `ConfigManager(...)`.
2. **Register it**: In `versions/__init__.py`, add the import and extend `VERSION_PARSERS`: e.g. `VERSION_PARSERS[N] = parse_vN`.
3. **Document the format**: Add an example YAML under `versions/examples/` (e.g. `vN.yaml`) and document field mappings in the parser module docstring or this README.

No changes are required in `file.py`; it already dispatches via `VERSION_PARSERS`.

## V1 format reference

- **Example file**: [`versions/examples/v1.yaml`](versions/examples/v1.yaml).
- **Parser**: [`versions/v1.py`](versions/v1.py) — `parse_v1(data)`.

Top-level keys:

- **`version`** (required): Must be `1`.
- **`resolver`**: Optional. `provider`: `system` | `google` | `cloudflare` | `quad9` | `opendns`.
- **`targets`**: List of `{ domain, paths? }`. Each target gets one or more `(domain, path)` entries; default path is `"/"`.
- **`throttle`**: Optional global throttle. `rps`, `concurrency`.
- **`config`**: List of rules. Each rule has:
  - **`include`** (required): Pattern (e.g. `"*"`, `"*.example.com"`, `"corp.example.com"`).
  - **`exclude`**: Optional pattern or list of patterns; matching targets skip this rule.
  - **`checks`**: Optional. List of check names → `ChecksReplace`; or string with `+name`/`-name` → `ChecksDelta`.
  - **`rps`** / **`concurrency`**: Optional; merged into `ThrottleConfig`.
  - **`dmarc`**: Optional. V1 uses `required_policy` → mapped to `DmarcConfig.policy`; `rua_required` → `DmarcConfig.rua_required`.
  - **`spf`**: Optional. `policy` → `SpfConfig.policy`.

A rule with **`include: "*"`** and **no `exclude`** is treated as the **default rule**: its config and checks become the default target config and default target checks. All other rules are stored in `target_configs` keyed by pattern and applied in order when resolving a target.
