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
    passthroughPaths: ['/', '/enclave-sw.js', '/register.js', '/attestation-widget.js'],
    excludePrefixes: ['/attestation', '/e2p/']
  }
})
```

The three v2 protocol endpoints are fixed and cannot be reconfigured. Passthrough rules only control service-worker interception; STEVE still permits plaintext fallback until separate fail-closed routing work lands.

## Build

```bash
make build
```
