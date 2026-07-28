# STEVE

**S**ecure **T**ransport **E**ncryption **V**ia **E**nclave

End-to-end encryption for browser applications communicating with AWS Nitro Enclaves. With the v2 browser client active, application traffic is encrypted in the service worker and decrypted only inside the enclave.

> [!IMPORTANT]
> v2 supports process-pinned X25519 or X-Wing draft-10 sessions and binds the
> selected suite into the transcript and Nitro evidence. X-Wing protects
> session secrecy independently of expected-deployment identity, but does not
> provide trusted first-load bootstrap, expected-PCR delivery, or fail-closed
> plaintext routing.

## Architecture

```mermaid
flowchart LR
    subgraph Client
        APP_C[Application]
        SDK[STEVE SDK]
    end

    subgraph Host["Host (Untrusted)"]
        TLS[TLS Proxy]
    end

    subgraph Enclave["Enclave (Trusted)"]
        STEVE[STEVE]
        APP_E[Application]
    end

    APP_C <-->|Plaintext| SDK
    SDK <-->|"TLS + E2E Encrypted"| TLS
    TLS <-->|"E2E Encrypted<br/>(TLS terminated)"| STEVE
    STEVE <-->|Plaintext| APP_E

    style Host fill:#722,stroke:#500,color:#fff
    style Enclave fill:#246,stroke:#135,color:#fff
    style TLS fill:#944,stroke:#722,color:#fff
    style STEVE fill:#48a,stroke:#246,color:#fff
    style APP_E fill:#48a,stroke:#246,color:#fff
```

## Two Layers of Encryption

| Layer | From | To | Purpose |
|-------|------|-----|---------|
| **TLS** | Client | Host Proxy | Transport security (terminated at host) |
| **E2E** | STEVE SDK | STEVE | Application security (terminated in enclave) |

For requests intercepted by the active v2 worker, the host terminates TLS but only sees encrypted E2E payloads.

## How It Works

1. **Session request**: The client generates a nonce and ephemeral X25519 or X-Wing key, sends its pinned suite, and commits to its origin.
2. **Attested key exchange**: STEVE uses its process-fixed suite and asks Nitro to attest the suite, transcript, nonce, session ID, origin context, and key-derived binder.
3. **Verification and confirmation**: The client verifies the expected suite in the response and Nitro binding, then confirms possession of the derived keys.
4. **Request Flow**:
   - Application makes request through STEVE SDK
   - SDK encrypts payload with AES-256-GCM
   - Request travels over TLS to host proxy
   - Host terminates TLS, forwards E2E-encrypted payload to enclave
   - STEVE decrypts, forwards plaintext to enclave application
5. **Response Flow**: Responses use the reverse-direction key and the request sequence.

## Components

| Component | Location | Description |
|-----------|----------|-------------|
| `steve` | Enclave | Rust proxy - decrypts requests, encrypts responses |
| `steve-sdk` | Client (Rust) | Rust SDK for native applications |
| `steve-js-sdk` | Client (Browser) | Service worker for web applications |

At startup `steve` writes enclave metadata to `E2P_METADATA_FILE` (default
`/metadata.json`), which bootproofd embeds as attestation `user_data`. In v2
this carries `{"e2p_protocol_version":2,"e2p_key_exchange":"..."}` — the v1
persistent `verifying_key` is intentionally gone, since attestation is now
bound per session.

`STEVE_KEY_EXCHANGE` accepts only `X25519` or `XWING-DRAFT10`. Omission selects
X25519. The suite is fixed for the process lifetime; changing it requires a
new enclave build/deployment.

## Security Properties

- **E2E Encryption**: Data encrypted client ↔ enclave (AES-256-GCM)
- **Attestation-Bound Keys**: Fresh Nitro evidence commits to the exact v2 session transcript and derived key binder
- **Hybrid Session Secrecy**: X-Wing combines ML-KEM-768 and X25519; X25519 remains the compatibility default
- **Downgrade Resistance**: Clients pin the suite and verify the wire response, transcript, and attestation binding without fallback
- **Replay Resistance**: Directional keys, derived IVs, authenticated sequences, and a 64-entry server replay window
- **Host Isolation**: On the v2 path, the host sees only ciphertext despite terminating TLS

Current limitations:

- Expected PCR values are not enforced by the browser client.
- Plaintext requests are still forwarded when the service worker is absent; fail-closed routing is deferred.
- The first-load service-worker bootstrap is not independently trusted.
- A host can route a client to another legitimate enclave using the same pinned suite unless expected deployment identity is supplied independently.
- Browser WASM must not be described as inherently constant-time; its supported-browser side-channel posture requires independent review.

## Usage

### Browser (JavaScript)

```javascript
import { registerEnclaveServiceWorker } from 'steve-js-sdk';

const client = await registerEnclaveServiceWorker();
await client.initialize(); // Optional eager establishment

// Same-origin fetch() calls are now transparently E2E encrypted
const response = await fetch('/api/secret');
```

For a browser application hosted on another origin, configure the enclave
origin and fetch it explicitly:

```javascript
const client = await registerEnclaveServiceWorker({
  config: {
    enclaveOrigin: 'https://secure.example',
    expectedKeyExchange: 'XWING-DRAFT10',
    requestTimeoutMs: 30000
  }
});
await client.initialize(); // Optional eager establishment

const response = await fetch('https://secure.example/api/secret');
```

`expectedKeyExchange` defaults to `X25519`; X-Wing deployments must set
`XWING-DRAFT10` explicitly. Initialization, CSP, response, or
attestation failures abort without X25519 fallback.

`initialize()` eagerly establishes the session and is recommended when the
application wants attestation failures before its first protected request. It
is idempotent and optional: the first protected request establishes a session
when needed. If the browser restarts the service worker and its in-memory
session is lost, the next protected request establishes a fresh session.

`client.getStatus()` reports the worker lifecycle and safe session diagnostics:
the protocol and key-establishment suite, KDF and record protection, base64url
session ID and transcript hash, establishment trigger and rotation time, and
attestation checks. PCRs are reported evidence only; v2 does not yet compare
them with an independently supplied expected-PCR policy. Status never includes
private keys, shared secrets, derived traffic keys, binders, nonces, or
application plaintext.

Set `STEVE_CORS_ORIGINS` to the browser application's origin (for example,
`http://localhost:3000`). STEVE applies that policy only to `/e2p/v2/*`;
plaintext fallback routes retain the upstream application's CORS policy.
Wildcard origins are rejected; production deployments must list each allowed
browser origin explicitly.

Protected application transactions default to a 30-second deadline
(`requestTimeoutMs` accepts 1,000 through 300,000 milliseconds). Transport
failures do not reset an otherwise valid secure session. The SDK does not
automatically retry timed-out requests because the upstream operation may
already have executed.

The native Rust SDK remains separate follow-up work; this branch contains the
server and browser/WASM implementation.

## Validation

```bash
make test    # Fast Rust and JavaScript unit tests
make verify  # Full StageX, packaging, and dual-suite browser gate
```

Focused targets are `test-wasm`, `test-production`, and `test-e2e`.

## Local E2E

The Docker harness runs the real browser SDK, STEVE protocol implementation,
and a test upstream using pinned StageX `linux/amd64` images. It uses signed
synthetic Nitro-shaped evidence rooted in public test keys; it validates the
protocol and attestation bindings, not Nitro hardware authenticity or isolation.

Install the local JavaScript dependencies once:

```bash
npm --prefix steve-js-sdk ci --ignore-scripts
```

Here `npm ci` means a clean, lockfile-exact dependency install; it does not
configure a CI service. The SDK's project-scoped npm policy permits only Git
dependencies declared directly in its `package.json`. Docker builds all E2E
JavaScript and WASM artifacts through the pinned StageX toolchain; no host Rust
target or `wasm-bindgen` installation is used.

Run both X25519 and X-Wing suites with Chromium:

```bash
./scripts/test-e2e.sh
```

On macOS the test uses installed Google Chrome. Elsewhere, install Playwright
Chromium once with `npm --prefix steve-js-sdk exec playwright install chromium`.
To run both suites with Playwright Firefox:

```bash
npm --prefix steve-js-sdk exec playwright install firefox
STEVE_E2E_BROWSER=firefox ./scripts/test-e2e.sh
```

Select `webkit` the same way. To run only one suite, set the server's fixed
suite and the browser's configured expectation with one variable:

```bash
STEVE_KEY_EXCHANGE=XWING-DRAFT10 \
STEVE_E2E_BROWSER=chromium \
./scripts/test-e2e.sh
```

For the manual demo:

```bash
./scripts/test-e2e.sh up
# Open http://127.0.0.1:3000
./scripts/test-e2e.sh logs
./scripts/test-e2e.sh down
```

The demo uses the same StageX asset build, but does not require Playwright or
its browser downloads.

The demo accepts an application request body and shows the exact encrypted
request/response envelopes alongside the plaintext visible to the browser
before encryption and after decryption. Wire capture is enabled only by the
demo; the SDK defaults it off.

Production exclusion checks are a separate packaging gate:

```bash
./scripts/test-production-exclusions.sh
```
