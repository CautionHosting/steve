# STEVE E2E

## Local and CI

Prerequisites: Docker with Compose, Node dependencies, and a Playwright browser.

```bash
npm --prefix steve-js-sdk ci --ignore-scripts
npm --prefix steve-js-sdk exec -- playwright install --with-deps chromium
make test-e2e
```

`make test-e2e` runs browser/WASM and Rust against signed synthetic STEVE for
both `X25519` and `XWING-DRAFT10`. Synthetic evidence does not prove Nitro.
The browser gate covers pinned success and rejection, TOFU enrollment and
rotation, worker-restart persistence, selected-PCR conflict, storage failure,
preservation of the previous accepted session after a failed explicit rotation,
and explicit protected `client.send()` routing. Rejections do not reach the
application endpoint.

Focused runs:

```bash
STEVE_KEY_EXCHANGE=XWING-DRAFT10 make test-e2e
STEVE_E2E_BROWSER=firefox make test-e2e
```

On macOS, run the separate generated Swift/UniFFI smoke gate with:

```bash
make test-swift
```

It requires Command Line Tools and Docker, but not full Xcode, signing, an
Apple developer account, or an iOS project. The static library and generated
`SteveSDK`/`SteveSDKFFI` files stay under `target/`. The gate covers pinned
X25519 and Swift-owned TOFU with XWING-DRAFT10, including an additional PCR3,
rotation, concurrent requests, binary bodies, repeated headers, callback
failure, and wrong-suite rejection. It verifies that the Swift callback receives
exactly PCR0/1/2/3. Successful runs report each exercised boundary. The runner
skips browser/WASM asset generation and uses a one-second shutdown timeout only
for its disposable Swift-test containers. It always runs both suites; a
configured `STEVE_KEY_EXCHANGE` is reported and ignored. Signed synthetic
evidence does not prove Nitro hardware.

Manual UI:

```bash
./scripts/test-e2e.sh up
# http://127.0.0.1:3000/local/  - synthetic verifier
# http://127.0.0.1:3000/nitro/  - AWS verifier and editable remote target
./scripts/test-e2e.sh logs
./scripts/test-e2e.sh down
```

The profiles use separate service-worker scopes and SDK builds.

## Production Nitro

Deploy the `steve-test-fixture/v1` app without Caution debug mode. Its
`e2e_encryption.cors_origins` must include:

- `http://localhost:3000`
- `http://127.0.0.1:3000`

Before deploying, confirm the platform will build the intended STEVE commit:

```bash
curl -fsS https://<platform>/.well-known/caution/build-inputs | jq .steve
```

After deploying, reproduce the EIF and obtain trusted PCR0/1/2:

```bash
export STEVE_REMOTE_ORIGIN=https://secure.example
export STEVE_KEY_EXCHANGE=XWING-DRAFT10
caution verify --attestation-url "$STEVE_REMOTE_ORIGIN/attestation"
```

Run the full browser/WASM and Rust gate:

```bash
export STEVE_TRUSTED_HASHES=/path/to/independently/verified/trusted_hashes.json
export STEVE_EXPECTED_PCR0="$(jq -er .pcr0 "$STEVE_TRUSTED_HASHES")"
export STEVE_EXPECTED_PCR1="$(jq -er .pcr1 "$STEVE_TRUSTED_HASHES")"
export STEVE_EXPECTED_PCR2="$(jq -er .pcr2 "$STEVE_TRUSTED_HASHES")"
make test-e2e-nitro
```

Run components while debugging:

```bash
make test-e2e-nitro-browser
make test-e2e-nitro-rust
```

All Nitro targets require independently obtained, exact, nonzero PCRs. The
browser and Rust SDKs enforce them during session establishment and test a
mutated-profile rejection before application traffic. The browser gate also
enrolls PCR0/1/2 with TOFU after confirmation, matches the record on rotation,
and matches it again after a service-worker restart. This proves continuity,
not first-use workload identity. Run the gate once for the X-Wing deployment
and once for X25519. Normal remote requests have a 10-second deadline; only the
controlled timeout scenario uses 3 seconds. The gate does not retry application
requests.

Remote Nitro tests are opt-in release tests, not untrusted pull-request jobs.
