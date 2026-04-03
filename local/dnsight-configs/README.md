# Local dnsight configuration (not committed)

This directory is for **your own** `dnsight.yaml` files—experiments, org-specific
manifests, or copies of production config. Nothing here is required for
`just test`; the default test suite uses fakes and ephemeral YAML under `tests/`.

## Optional local starter

You can keep a multi-domain manifest here (for example `company-portfolio.dnsight.yaml`)
with real domains and `headers.urls`. Those files are **gitignored**—they do not ship
with the repo and are not part of docs or CI. Use `dnsight config example` for a
generic template, or maintain your own YAML in this directory.

## Quick start

From the repository root (with the CLI installed, e.g. `just install`):

```bash
dnsight config example > local/dnsight-configs/example.yaml
# edit example.yaml, then:
dnsight --config local/dnsight-configs/example.yaml config validate
dnsight --config local/dnsight-configs/example.yaml audit example.com
```

If the file defines `targets`, you can run a manifest-style audit without
passing domains on the command line:

```bash
dnsight --config local/dnsight-configs/example.yaml audit
```

## Caveats

- Audits use **real** DNS and HTTP (unless you replace resolver/client in code).
  Results depend on the live internet; corporate or sandboxed networks may block
  outbound queries.
- Do **not** rely on this folder for CI. Keep secrets and internal hostnames out
  of git; only this `README.md` is tracked (other files under
  `local/dnsight-configs/` are gitignored).
