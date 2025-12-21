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

All requests are now encrypted except `/attestation` and `/e2p/`.

## Configuration

```javascript
registerEnclaveServiceWorker({
  config: {
    attestationEndpoint: '/attestation',
    keyExchangeEndpoint: '/e2p/v1/create_shared_key',
    excludePaths: ['/attestation', '/e2p/', '/public/']
  }
})
```

## Build

```bash
make build
```
