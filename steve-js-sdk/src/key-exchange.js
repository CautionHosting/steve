import {
  X25519_KEY_EXCHANGE,
  XWING_KEY_EXCHANGE,
  requireKeyExchange
} from './protocol-v2.js';
import initializeXWing, { XWingClient } from './xwing-bindings.js';

// The generated bindings are statically bundled into the module service
// worker. Only this fixed same-origin WASM asset is fetched at runtime.
export const XWING_WASM_PATH = './xwing/steve_xwing_wasm_bg.wasm';
export const XWING_WASM_SHA256 =
  typeof __STEVE_XWING_WASM_SHA256__ === 'undefined'
    ? null
    : __STEVE_XWING_WASM_SHA256__;

export function createVerifiedXWingModuleLoader(initializer) {
  if (typeof initializer !== 'function') {
    throw new TypeError('X-Wing module initializer must be a function');
  }
  let cached;
  return function loadModule() {
    if (!cached) {
      const attempt = Promise.resolve().then(initializer);
      const guarded = attempt.catch(error => {
        if (cached === guarded) cached = undefined;
        throw error;
      });
      cached = guarded;
    }
    return cached;
  };
}

export const loadVerifiedXWingModule = createVerifiedXWingModuleLoader(
  () => initializeVerifiedXWingModule({
      initialize: initializeXWing,
      XWingClient
  })
);

export async function initializeVerifiedXWingModule({
  initialize,
  XWingClient,
  fetchImpl = globalThis.fetch,
  expectedDigest = XWING_WASM_SHA256,
  wasmUrl = new URL(XWING_WASM_PATH, import.meta.url)
}) {
  if (typeof initialize !== 'function' || typeof XWingClient !== 'function') {
    throw new Error('invalid self-hosted X-Wing WASM bindings');
  }
  if (!/^[0-9a-f]{64}$/u.test(expectedDigest || '')) {
    throw new Error('X-Wing WASM build digest is unavailable');
  }

  const response = await fetchImpl(wasmUrl, {
    cache: 'no-store',
    credentials: 'same-origin',
    redirect: 'error'
  });
  if (!response.ok) {
    throw new Error(`X-Wing WASM asset fetch failed with HTTP ${response.status}`);
  }
  const wasmBytes = new Uint8Array(await response.arrayBuffer());
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', wasmBytes));
  const actualDigest = Array.from(
    digest,
    byte => byte.toString(16).padStart(2, '0')
  ).join('');
  if (actualDigest !== expectedDigest) {
    throw new Error('X-Wing WASM asset integrity check failed');
  }

  await initialize({ module_or_path: wasmBytes });
  return { XWingClient };
}

export async function createClientKeyExchange(
  keyExchange,
  xwingModuleLoader
) {
  requireKeyExchange(keyExchange);
  if (keyExchange === X25519_KEY_EXCHANGE) return createX25519Client();
  if (keyExchange === XWING_KEY_EXCHANGE) {
    if (typeof xwingModuleLoader !== 'function') {
      throw new Error('X-Wing WASM loader is unavailable');
    }
    return createXWingClient(xwingModuleLoader);
  }
  throw new Error(`unsupported key exchange: ${keyExchange}`);
}

async function createX25519Client() {
  let keyPair = await crypto.subtle.generateKey(
    { name: 'X25519' },
    true,
    ['deriveBits']
  );
  const publicKey = new Uint8Array(
    await crypto.subtle.exportKey('raw', keyPair.publicKey)
  );
  let consumed = false;

  return {
    keyExchange: X25519_KEY_EXCHANGE,
    publicKey,
    async decapsulate(serverKeyMaterial) {
      if (consumed) throw new Error('X25519 client already consumed');
      consumed = true;
      const privateKey = keyPair.privateKey;
      keyPair = null;
      const serverPublicKey = await crypto.subtle.importKey(
        'raw',
        serverKeyMaterial,
        { name: 'X25519' },
        false,
        []
      );
      return new Uint8Array(await crypto.subtle.deriveBits(
        { name: 'X25519', public: serverPublicKey },
        privateKey,
        256
      ));
    },
    destroy() {
      consumed = true;
      keyPair = null;
    }
  };
}

async function createXWingClient(moduleLoader) {
  const module = await moduleLoader();
  if (typeof module?.XWingClient !== 'function') {
    throw new Error('invalid self-hosted X-Wing WASM module');
  }
  const client = new module.XWingClient();
  const publicKey = client.public_key();
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 1216) {
    client.free?.();
    throw new Error('invalid X-Wing client key material');
  }
  let consumed = false;
  let freed = false;
  const destroy = () => {
    if (!freed) {
      freed = true;
      client.free?.();
    }
  };

  return {
    keyExchange: XWING_KEY_EXCHANGE,
    publicKey,
    async decapsulate(serverKeyMaterial) {
      if (consumed) throw new Error('X-Wing client already consumed');
      consumed = true;
      try {
        const sharedSecret = client.decapsulate_and_destroy(serverKeyMaterial);
        if (!(sharedSecret instanceof Uint8Array) || sharedSecret.length !== 32) {
          sharedSecret?.fill?.(0);
          throw new Error('invalid X-Wing shared secret');
        }
        return sharedSecret;
      } finally {
        destroy();
      }
    },
    destroy() {
      consumed = true;
      destroy();
    }
  };
}
