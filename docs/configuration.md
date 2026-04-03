# Configuration (`dnsight.yaml`)

dnsight loads a single YAML file (commonly `dnsight.yaml`), discovered from the current working directory or set via `--config` / the `DNSIGHT_CONFIG` discovery rules described in the CLI.

## Version

The file must declare **`version: 1`**. Loading is dispatched to the v1 parser in the package.

## Top-level keys (v1)

| Key | Required | Purpose |
| --- | --- | --- |
| `version` | yes | Must be integer `1`. |
| `resolver` | no | DNS provider preset: `system`, `google`, `cloudflare`, `quad9`, `opendns`. |
| `targets` | no* | Manifest: list of targets (`domain`, optional `paths`, optional `subdomains`). |
| `throttle` | no | Global `rps` and `concurrency`. |
| `strict_recommendations` | no | If true, recommend strictest best practice; if false, align recommendations to configured policy. |
| `config` | no | Ordered list of pattern rules (`include`, optional `exclude`, `checks`, per-check blocks, throttle overrides). |

\*Required for manifest-style CLI runs when you omit domains on the command line.

## Rules and precedence

- Rules are applied in order; later matching rules override earlier ones for the same target.
- A rule with `include: "*"` and no `exclude` acts as the **default** rule for targets that match.

For the full field list and merge behaviour, see the maintainer reference in the repository:

- [Config parser README](https://github.com/dnsight/dnsight/blob/main/src/dnsight/core/config/parser/README.md)

## Example

The canonical sample shipped with the package matches **`dnsight config example`**. The same file lives in the repo at
[`src/dnsight/core/config/parser/versions/examples/v1.yaml`](https://github.com/dnsight/dnsight/blob/main/src/dnsight/core/config/parser/versions/examples/v1.yaml).

## CLI helpers

- `dnsight config validate` — validate a file (or stdin as `-`), same rules as the SDK.
- `dnsight config example` — print the sample v1 YAML.
