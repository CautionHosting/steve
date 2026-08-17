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

const client = await registerEnclaveServiceWorker({
  config: {
    pcrPolicy: {
      mode: 'pinned',
      profiles: [{ PCR0: pcr0Hex, PCR1: pcr1Hex, PCR2: pcr2Hex }]
    }
  }
})
await client.initialize() // Optional eager establishment
```

The worker establishes an attestation-bound v2 session and encrypts intercepted application requests through `/e2p/v2/request`.

X25519 WebCrypto is the default. X-Wing is fail-closed and must be pinned
explicitly; it never falls back to X25519:

```javascript
const client = await registerEnclaveServiceWorker({
  config: {
    expectedKeyExchange: 'XWING-DRAFT10',
    pcrPolicy: {
      mode: 'pinned',
      profiles: [{ PCR0: pcr0Hex, PCR1: pcr1Hex, PCR2: pcr2Hex }]
    }
  }
})
```

The configured suite is exact and client-pinned; the session response and
attestation binding must both match it. The worker does not negotiate a suite
or make a metadata preflight request. Omitting `pcrPolicy` retains compatibility
mode: PCRs are reported as `not-checked` and do not authenticate the expected
deployment.

## Browser support

The SDK requires module service workers, ES2020, WebCrypto
(SHA-256, HKDF, and AES-GCM), Cache Storage, IndexedDB, and WebAssembly. X25519 mode additionally
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
- verifier profile/trust anchor and machine-readable attestation and binding checks;
- PCR trust as `not-checked`, `pinned`, `tofu-enrolled`, or `tofu-matched`.

`attestation.checks.expectedPcrPolicy` is derived from the same result: it is
`not-checked` when PCR policy is omitted and `verified` when a configured
policy succeeds. Diagnostics never include private keys, shared secrets, derived keys,
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
    expectedKeyExchange: 'X25519',
    pcrPolicy: {
      mode: 'pinned',
      profiles: [{ PCR0: pcr0Hex, PCR1: pcr1Hex, PCR2: pcr2Hex }]
    }
  }
})
```

`pcrPolicy` is optional for backward compatibility. When omitted on a fresh
worker, PCR evidence is reported but not checked. A pinned policy accepts one
or more complete profiles:

```javascript
const pinned = {
  mode: 'pinned',
  profiles: [
    { PCR0: oldPcr0, PCR1: oldPcr1, PCR2: oldPcr2 },
    { PCR0: newPcr0, PCR1: newPcr1, PCR2: newPcr2, PCR3: newPcr3 }
  ]
}
```

Each profile must contain nonzero 96-hex-character PCR0, PCR1, and PCR2 values
and may add PCR3 through PCR255. The worker accepts only one whole matching
profile; it never combines values from different profiles. Unselected
attested PCRs are ignored.

TOFU records PCR0/1/2 and optional additional indices:

```javascript
const tofu = { mode: 'tofu', additionalPcrIndices: [3, 8] }
```

Additional indices must be integers from 0 through 255. PCR0/1/2 and duplicate
indices are harmless and canonicalize to the sorted union with mandatory
PCR0/1/2. The worker enrolls exactly that selected set after attestation,
session binding, and key confirmation succeed. Later sessions must match the
complete stored record. The record is namespaced by worker scope, enclave
origin, and suite, but not by selected indices; changing the selected set
therefore conflicts until the application explicitly migrates browser storage.
The SDK exposes no TOFU-record migration API: `replacePcrPolicy()`, clearing the
configured policy, and `reset()` do not modify an enrolled record. Re-enrollment
therefore requires an explicit origin-controlled storage migration or clearing
all site data for the origin.

Configuration calls are partial updates. Omitting `pcrPolicy` retains a stored
policy; only `pcrPolicy: null` clears it. Clearing policy or calling `reset()`
does not delete TOFU records. A fresh worker permits only the fixed bootstrap
assets until configuration is restored or received; configuration or PCR
storage failure blocks protected traffic locally without a network fallback.
Target, suite, and policy changes invalidate the active session. Every initial
session and rotation rechecks policy before the new session is published.

Pinned profiles authenticate a deployment only if the expected PCR values
arrive through an independently authenticated channel. Automatic browser TOFU
provides continuity, not first-use identity. Losing the TOFU record or clearing
all same-origin site data reopens enrollment. Losing only the persisted policy
configuration fails closed while its policy-required marker remains. An
attacker able to replace the same-origin page, worker, or configuration remains
outside this feature's trust guarantee.

## Client API

Use `client.send()` when a call must enter the worker's protected E2P path
without relying on fetch interception:

```javascript
const { response, sessionId } = await client.send('/api/secret', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ operation: 'read' })
})
```

The path must be origin-relative: it begins with one `/` and contains no origin,
authority, or fragment. The only request options are `method`, `headers`, and
`body`; the call supplies no implicit browser credentials or cookies. STEVE does
not follow an upstream redirect and returns its `3xx` response. A redirect of
the outer protocol request fails, and the SDK never retries. The result contains
a normal `Response` and the base64url ID of the session that protected the
request. This API guarantees routing through the active worker, subject to the
same same-origin bootstrap trust boundary described above.

`initialize()`, `rotateSession()`, and `reset()` return the resulting status.
`rotateKey()` remains an alias for compatibility. `getStatus()` reads status
without changing session state. `waitForInitialization()` returns immediately
when ready or waits and propagates the underlying establishment error.

Policy changes remain authoritative in the worker:

```javascript
const current = await client.getPcrPolicy()
const { policy, status } = await client.replacePcrPolicy(nextPolicy)
```

`replacePcrPolicy()` validates and persists a pinned or TOFU policy, or `null`
to clear it, then resets the active session before returning. It does not
attest against the new policy; the next `initialize()` or protected request does
that. It also does not replace or delete an existing TOFU record.

Client methods reject with `SteveError`, which has machine-readable `code` and
`stage` fields, a diagnostic `message`, and `httpStatus` for an outer protocol
HTTP rejection. Code may branch on documented `code` values but must retain a
default path for unknown future codes; it must not parse `message`. Intercepted
`fetch()` calls retain their HTTP error response behavior; use `client.send()`
when structured failures are required.

Stable registration and control codes are `SERVICE_WORKER_UNAVAILABLE`,
`SERVICE_WORKER_REGISTRATION`, `SERVICE_WORKER_INSTALLATION`,
`SERVICE_WORKER_ACTIVATION_TIMEOUT`, `SERVICE_WORKER_FAILED`, `MESSAGE_TIMEOUT`,
and `INITIALIZATION_TIMEOUT`. Request and protocol codes are `INVALID_REQUEST`,
`CONFIGURATION_UNAVAILABLE`, `TIMEOUT`, `ABORTED`, `TRANSPORT`, `HTTP_STATUS`,
`ATTESTATION_INVALID`, and `CONFIRMATION_INVALID`. PCR codes are
`PCR_POLICY_INVALID`, `PCR_POLICY_MISMATCH`, `ATTESTED_PCR_INVALID`,
`PCR_TRUST_MISMATCH`, and `PCR_TRUST_STORAGE`. Other failures use a
stage-derived `*_FAILED` code.

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
overridden, so the worker can never intercept its own protocol traffic.
Passthrough rules only control service-worker interception. STEVE rejects
plaintext application traffic by default while forwarding the default
root-scope bootstrap (`GET /` and safe-method requests for the fixed bootstrap
assets). Custom scopes or passthrough paths need matching narrow ingress routes.
Deployments that intentionally need legacy application forwarding must set
`STEVE_ALLOW_PLAINTEXT_FALLBACK=true`.

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
