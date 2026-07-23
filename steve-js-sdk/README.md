# Steve Javascript SDK

JavaScript service worker for client side facilitation of steve.

## Quick Start

1. Copy `dist/enclave-sw.js` and `dist/register.js` to your app's public directory

2. Add to your app:

```javascript
import { registerEnclaveServiceWorker } from '/register.js'

const client = await registerEnclaveServiceWorker()
await client.initialize()
```

The worker establishes an attestation-bound v2 session and encrypts intercepted application requests through `/e2p/v2/request`.

## Configuration

```javascript
registerEnclaveServiceWorker({
  config: {
    enclaveOrigin: 'https://secure.example',
    passthroughPaths: ['/', '/enclave-sw.js', '/register.js', '/attestation-widget.js'],
    excludePrefixes: ['/attestation', '/e2p/'],
    requestTimeoutMs: 30000
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
unrelated cross-origin requests are left untouched. Default bootstrap paths
apply only on the service worker's own origin, so `/` on a separately hosted
enclave remains protected.

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
overridden, so the worker can never intercept its own protocol traffic. Passthrough rules only control service-worker interception; STEVE still permits plaintext fallback until separate fail-closed routing work lands.

STEVE applies its configured CORS policy only to `/e2p/v2/*`. Plaintext
fallback routes retain the upstream application's CORS policy.

## Build

```bash
make build
```
