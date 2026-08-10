# steve-cli

`steve-cli` makes one attested, end-to-end encrypted request through
`steve-sdk`. It sends GET without a body and POST with `--data` or `--json`.
The response body is written alone to stdout; PCR trust status is written to
stderr.

## Pinned PCRs

With no trust flag, the CLI loads `.caution/trusted_hashes.json`:

```bash
cargo run -p steve-cli -- https://secure.example/health
```

Repeat `--pcrs` to approve complete current and next profiles during a
migration. All files are validated before any network traffic:

```bash
cargo run -p steve-cli -- \
  --pcrs current.json \
  --pcrs next.json \
  'https://secure.example/status?required=true'
```

`--trusted-hashes-file` is an alias for `--pcrs`. The CLI preserves the query
and ignores any URL fragment.

## Trust on first use

`--tofu-store` enrolls PCR0/1/2 after the first session has passed Nitro,
transcript, suite, binder, and confirmation checks. Later processes must match
the stored profile:

```bash
cargo run -p steve-cli -- \
  --tofu-store .steve-pcr-trust.json \
  https://secure.example/health

cargo run -p steve-cli -- \
  --tofu-store .steve-pcr-trust.json \
  https://secure.example/health
```

The versioned JSON store is keyed by origin/context and key-exchange suite. It
uses a sibling lock and atomic durable replacement, and never replaces an
existing record. The file is the trust boundary: protect and back it up.
Deleting or replacing it reopens first-use enrollment. The CLI never
auto-updates PCRs.

## Validation and X-Wing

Dry-run validates the URL, request options, and selected policy without
networking or creating/modifying a TOFU store. A missing TOFU store is valid;
malformed existing state is not.

```bash
cargo run -p steve-cli -- \
  --dry-run \
  --tofu-store .steve-pcr-trust.json \
  https://secure.example/health

cargo run -p steve-cli -- \
  --key-exchange XWING-DRAFT10 \
  --pcrs xwing.json \
  https://secure.example/health
```

The CLI intentionally is not a curl replacement. It does not follow redirects
or retry requests. Duplicate header names are rejected because the E2P request
format stores headers as a map.
