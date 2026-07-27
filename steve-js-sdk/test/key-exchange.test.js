import assert from 'node:assert/strict';
import test from 'node:test';

import {
  XWING_WASM_PATH,
  createClientKeyExchange,
  initializeVerifiedXWingModule
} from '../src/key-exchange.js';
import {
  X25519_KEY_EXCHANGE,
  XWING_KEY_EXCHANGE
} from '../src/protocol-v2.js';

test('X25519 remains a WebCrypto client and derives the server secret', async () => {
  const client = await createClientKeyExchange(X25519_KEY_EXCHANGE);
  const server = await crypto.subtle.generateKey(
    { name: 'X25519' },
    true,
    ['deriveBits']
  );
  const clientPublicKey = await crypto.subtle.importKey(
    'raw',
    client.publicKey,
    { name: 'X25519' },
    false,
    []
  );
  const expected = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'X25519', public: clientPublicKey },
    server.privateKey,
    256
  ));
  const serverPublicKey = new Uint8Array(
    await crypto.subtle.exportKey('raw', server.publicKey)
  );

  assert.equal(client.keyExchange, X25519_KEY_EXCHANGE);
  assert.deepEqual(await client.decapsulate(serverPublicKey), expected);
  await assert.rejects(
    () => client.decapsulate(serverPublicKey),
    /already consumed/u
  );
});

test('X-Wing uses only the fixed relative self-hosted WASM module', async () => {
  let freed = 0;
  let decapsulated = 0;
  const wasmSharedSecret = new Uint8Array(32).fill(9);
  class FakeXWingClient {
    public_key() {
      return new Uint8Array(1216).fill(7);
    }

    decapsulate_and_destroy(ciphertext) {
      assert.equal(ciphertext.length, 1120);
      decapsulated += 1;
      return wasmSharedSecret;
    }

    free() {
      freed += 1;
    }
  }
  const client = await createClientKeyExchange(
    XWING_KEY_EXCHANGE,
    async () => ({ XWingClient: FakeXWingClient })
  );

  assert.equal(XWING_WASM_PATH, './xwing/steve_xwing_wasm_bg.wasm');
  assert.equal(client.keyExchange, XWING_KEY_EXCHANGE);
  assert.equal(client.publicKey.length, 1216);
  const received = await client.decapsulate(new Uint8Array(1120));
  assert.equal(received, wasmSharedSecret, 'shared secret must not be copied in JS');
  assert.deepEqual(received, new Uint8Array(32).fill(9));
  assert.equal(decapsulated, 1);
  assert.equal(freed, 1);
  await assert.rejects(
    () => client.decapsulate(new Uint8Array(1120)),
    /already consumed/u
  );
});

test('verified X-Wing loader hashes the exact fixed asset before initialization', async () => {
  const wasmBytes = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]);
  const expectedDigest = Buffer.from(
    await crypto.subtle.digest('SHA-256', wasmBytes)
  ).toString('hex');
  let initializedWith;
  let captured;
  class FakeXWingClient {}

  const module = await initializeVerifiedXWingModule({
    initialize: async options => {
      initializedWith = options.module_or_path;
    },
    XWingClient: FakeXWingClient,
    expectedDigest,
    wasmUrl: new URL('https://app.example/xwing/steve_xwing_wasm_bg.wasm'),
    fetchImpl: async (url, options) => {
      captured = { url: String(url), options };
      return new Response(wasmBytes);
    }
  });

  assert.equal(module.XWingClient, FakeXWingClient);
  assert.deepEqual(initializedWith, wasmBytes);
  assert.deepEqual(captured, {
    url: 'https://app.example/xwing/steve_xwing_wasm_bg.wasm',
    options: {
      cache: 'no-store',
      credentials: 'same-origin',
      redirect: 'error'
    }
  });
});

test('tampered X-Wing WASM aborts before initialization with no X25519 fallback', async () => {
  let initialized = 0;
  let clientsCreated = 0;
  class FakeXWingClient {
    constructor() {
      clientsCreated += 1;
    }
  }

  await assert.rejects(
    () => createClientKeyExchange(
      XWING_KEY_EXCHANGE,
      () => initializeVerifiedXWingModule({
        initialize: async () => {
          initialized += 1;
        },
        XWingClient: FakeXWingClient,
        expectedDigest: '00'.repeat(32),
        wasmUrl: new URL('https://app.example/xwing/steve_xwing_wasm_bg.wasm'),
        fetchImpl: async () => new Response(new Uint8Array([1]))
      })
    ),
    /integrity check failed/u
  );
  assert.equal(initialized, 0);
  assert.equal(clientsCreated, 0);
});

test('X-Wing fetch and CSP initialization failures are fatal with no fallback', async t => {
  let clientsCreated = 0;
  class FakeXWingClient {
    constructor() {
      clientsCreated += 1;
    }
  }
  const wasmBytes = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]);
  const expectedDigest = Buffer.from(
    await crypto.subtle.digest('SHA-256', wasmBytes)
  ).toString('hex');

  await t.test('asset fetch failure', async () => {
    await assert.rejects(
      () => createClientKeyExchange(
        XWING_KEY_EXCHANGE,
        () => initializeVerifiedXWingModule({
          initialize: async () => {},
          XWingClient: FakeXWingClient,
          expectedDigest,
          fetchImpl: async () => {
            throw new Error('WASM fetch blocked');
          }
        })
      ),
      /WASM fetch blocked/u
    );
  });

  await t.test('CSP initialization failure', async () => {
    await assert.rejects(
      () => createClientKeyExchange(
        XWING_KEY_EXCHANGE,
        () => initializeVerifiedXWingModule({
          initialize: async () => {
            throw new Error('CSP blocked WebAssembly');
          },
          XWingClient: FakeXWingClient,
          expectedDigest,
          fetchImpl: async () => new Response(wasmBytes)
        })
      ),
      /CSP blocked WebAssembly/u
    );
  });

  assert.equal(clientsCreated, 0);
});
