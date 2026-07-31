# Steve Javascript SDK

JavaScript service worker for client side facilitation of steve.

## Quick Start

1. Copy the complete `dist/` tree to your app's public directory. X-Wing needs
   the fixed self-hosted `dist/xwing/steve_xwing_wasm_bg.wasm` asset beside the
   module service worker. Its generated JavaScript bindings are statically
   bundled into `enclave-sw.js`.

2. Add to your app:

```javascript
import { registerEnclaveServiceWorker } from '/register.js'

const client = await registerEnclaveServiceWorker()
await client.initialize() // Optional eager establishment
```

The worker establishes an attestation-bound v2 session and encrypts intercepted application requests through `/e2p/v2/request`.

X25519 WebCrypto is the default. X-Wing is fail-closed and must be pinned
explicitly; it never falls back to X25519:

```javascript
const client = await registerEnclaveServiceWorker({
  config: { expectedKeyExchange: 'XWING-DRAFT10' }
})
```

The configured suite is exact and client-pinned; the session response and
attestation binding must both match it. The worker does not negotiate a suite
or make a metadata preflight request.

## Browser support

The SDK requires module service workers, ES2020, WebCrypto
(SHA-256, HKDF, and AES-GCM), and WebAssembly. X25519 mode additionally
requires WebCrypto X25519; X-Wing requires a CSP that permits instantiating the
same-origin WASM asset. Missing capabilities fail closed; there is no classic
service-worker or cryptographic fallback.

The release E2E gate uses Chromium (installed Google Chrome on macOS).
Playwright Firefox and WebKit are supported opt-in test engines, but are not a
numeric minimum-version guarantee. Applications should test their supported
browser versions explicitly before publishing a compatibility claim.

For X-Wing, the bundle contains the SHA-256 digest of the exact WASM emitted by
the same build. The worker fetches that fixed same-origin asset without cache,
verifies the digest, and only then instantiates it. This detects a bundle/asset
mismatch; it does not establish first-load trust if an attacker can replace
both `enclave-sw.js` and the WASM asset.

`initialize()` is an idempotent eager warm-up. Use it when the application
wants attestation failure to surface before its first protected request. It is
not required for correctness: a protected request establishes a session
lazily, and does the same after a service-worker restart loses in-memory
session state.

## Session diagnostics

`client.getStatus()` preserves the legacy `initialized`, `attestation`,
`lastKeyRotation`, and `protocolVersion` fields and also reports:

- lifecycle `state` and in-progress handshake `stage`;
- protocol, key-establishment suite, KDF, and record protection;
- base64url session ID and transcript hash, establishment trigger, and rotation time;
- verifier profile/trust anchor and machine-readable attestation and binding checks.

An `expectedPcrPolicy` result of `not-checked` is deliberate: current v2 reports
PCR evidence but does not compare it with an independently supplied workload
policy. Diagnostics never include private keys, shared secrets, derived keys,
binders, nonces, or application plaintext.

## Configuration

```javascript
registerEnclaveServiceWorker({
  config: {
    enclaveOrigin: 'https://secure.example',
    passthroughPaths: ['/enclave-sw.js', '/register.js', '/attestation-widget.js'],
    excludePrefixes: ['/attestation', '/e2p/'],
    emitEncryptedPayloads: false,
    requestTimeoutMs: 30000,
    expectedKeyExchange: 'X25519'
  }
})
```

`enclaveOrigin` is the absolute HTTP(S) origin where STEVE is exposed. It
defaults to the service worker's origin. For a cross-origin deployment, allow
the browser application's origin in `STEVE_CORS_ORIGINS` and address the
enclave explicitly:

```javascript
const response = await fetch('https://secure.example/hello')
```

The worker encrypts requests only when their origin matches `enclaveOrigin`;
unrelated cross-origin requests are left untouched. Default bootstrap scripts
pass through only for `GET` and `HEAD` requests on the service worker's own
origin. A top-level document `GET /` also passes through so the page can repair
lost worker configuration; fetches and non-GET requests to `/` remain
protected. Exact paths added through `passthroughPaths` are also plaintext only
for `GET` and `HEAD`. An intentionally plaintext POST route must instead use an
`excludePrefixes` entry and accept the broader prefix-based exclusion.
STEVE rejects wildcard CORS configuration, so cross-origin deployments must
list each allowed browser origin explicitly.

`emitEncryptedPayloads` defaults to `false`. Debug tools may enable it to
receive `encrypted-request` and `encrypted-response` events with the endpoint,
session ID, sequence, size, and exact CBOR envelope encoded as base64url. These
events contain no plaintext or key material, but still expose traffic metadata.

`requestTimeoutMs` bounds each protected application transaction. It defaults
to 30 seconds and accepts finite integer values from 1 second through 5
minutes. Session establishment has a separate fixed 10-second deadline.
Transport timeouts and outer 5xx responses fail only the affected request;
definite protocol, session, replay, or authentication failures reset the secure
session.

The SDK never automatically retries a protected application request. If a
response times out, the enclave may already have executed the request, so
callers must apply their own idempotency policy before retrying.

The three v2 protocol endpoints are fixed and cannot be reconfigured; the
`/e2p/` prefix is always kept in `excludePrefixes` even if the option is
overridden, so the worker can never intercept its own protocol traffic. Passthrough rules only control service-worker interception. STEVE rejects plaintext application traffic by default; deployments that intentionally need legacy forwarding must set `STEVE_ALLOW_PLAINTEXT_FALLBACK=true`.

STEVE applies its configured CORS policy only to `/e2p/v2/*`. Plaintext
fallback routes retain the upstream application's CORS policy.

## Build

```bash
make build
# Equivalent: npm run build
```

`dist/` is a committed release artifact and only the digest-pinned StageX build
may replace it. `make build` is the no-cache artifact-refresh operation; do not
run it before the repository production checks, which build into temporary
directories without replacing `dist/`. The Rust stage builds the matching
`wasm32-unknown-unknown` standard library, installs exactly
`wasm-bindgen-cli` 0.2.106, fetches the locked Cargo graph, and compiles with
network access disabled, one codegen unit, and stable build-path remapping. The
Node stage runs `npm ci --ignore-scripts`,
statically bundles the generated bindings and their WASM digest, runs the
production package checks, and copies the fixed WASM asset into `dist/xwing/`.

There is no supported host build for browser artifacts. The other artifact
targets also use the same StageX WASM builder and write only ignored test or
inspection outputs:

```bash
make build-wasm  # fresh WASM + JS glue in ignored wasm-pkg/
cmp wasm-pkg/steve_xwing_wasm_bg.wasm dist/xwing/steve_xwing_wasm_bg.wasm
make test-wasm   # RustCrypto/WASM interoperability tests inside StageX
make build-test-assets  # local-eval + production assets in ignored E2E output
```

The repository `test-production-fast` target compares committed `dist/` with
one cache-enabled temporary StageX build. `test-production` compares committed
`dist/` with a clean temporary StageX build and then byte-compares a second
no-cache build. This establishes same-builder temporal determinism;
independent reproducibility still requires a second builder or operator.
Dependency acquisition, including the exact-version locked
`wasm-bindgen-cli` install, remains network-enabled, so this check is not a
claim of fully offline input provenance.

Local Node.js is still useful for `npm test` and Playwright, but local Rust,
`wasm-bindgen`, or esbuild versions never produce browser artifacts.
