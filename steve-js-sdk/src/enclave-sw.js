import { verify } from 'tee-attestation-js/nitro';
import { encode as encodeCBOR, decode as decodeCBOR } from 'tee-attestation-js/lib/cbor';

let CONFIG = {
  attestationEndpoint: '/attestation',
  keyExchangeEndpoint: '/e2p/v1/create_shared_key',
  passthroughPaths: ['/', '/enclave-sw.js', '/register.js', '/attestation-widget.js'],
  excludePrefixes: ['/attestation', '/e2p/'],
  keyRotationInterval: 30 * 60 * 1000,
  emitEncryptedPayloads: false
};

let state = {
  sessionKey: null,
  verifyingKey: null,
  enclaveEncryptedSharedKey: null,
  attestationResult: null,
  initialized: false,
  initPromise: null,
  lastKeyRotation: null,
  error: null
};

self.addEventListener('install', () => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(clients.claim());
});

self.addEventListener('message', (event) => {
  handleMessage(event);
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  const isPassthrough = CONFIG.passthroughPaths.includes(url.pathname);
  const isExcluded = CONFIG.excludePrefixes.some(prefix => url.pathname.startsWith(prefix));
  if (isPassthrough || isExcluded) {
    return;
  }
  event.respondWith(handleEncryptedRequest(event.request));
});

async function handleMessage(event) {
  const { type } = event.data;
  const port = event.ports[0];

  switch (type) {
    case 'get-status':
      port?.postMessage({
        type: 'status',
        initialized: state.initialized,
        error: state.error,
        attestation: state.attestationResult ? {
          verified: state.attestationResult.verified,
          pcrs: state.attestationResult.pcrs,
          moduleId: state.attestationResult.moduleId
        } : null,
        lastKeyRotation: state.lastKeyRotation
      });
      break;

    case 'initialize':
      try {
        await ensureInitialized();
        port?.postMessage({ type: 'initialized', success: true });
      } catch (error) {
        port?.postMessage({ type: 'initialized', success: false, error: error.message });
      }
      break;

    case 'rotate-key':
      try {
        await rotateSessionKey();
        port?.postMessage({ type: 'key-rotated', success: true });
      } catch (error) {
        port?.postMessage({ type: 'key-rotated', success: false, error: error.message });
      }
      break;

    case 'reset':
      resetState();
      port?.postMessage({ type: 'reset', success: true });
      break;

    case 'configure':
      CONFIG = { ...CONFIG, ...event.data.config };
      port?.postMessage({ type: 'configured', success: true, config: CONFIG });
      break;
  }
}

async function handleEncryptedRequest(request) {
  try {
    await ensureInitialized();
    await checkKeyRotation();

    const url = new URL(request.url);
    const encryptedRequest = await encryptRequest(request);

    if (CONFIG.emitEncryptedPayloads) {
      const encryptedBody = new Uint8Array(await encryptedRequest.clone().arrayBuffer());
      notifyClients('encrypted-request', {
        path: url.pathname,
        size: encryptedBody.length,
        payload: bytesToHex(encryptedBody.slice(0, 64)) + (encryptedBody.length > 64 ? '...' : '')
      });
    }

    const response = await fetch(encryptedRequest);

    if (!response.ok && response.status >= 500) {
      throw new Error(`Server error: ${response.status}`);
    }

    if (CONFIG.emitEncryptedPayloads) {
      const encryptedResponse = new Uint8Array(await response.clone().arrayBuffer());
      notifyClients('encrypted-response', {
        status: response.status,
        size: encryptedResponse.length,
        payload: bytesToHex(encryptedResponse.slice(0, 64)) + (encryptedResponse.length > 64 ? '...' : '')
      });
    }

    return await decryptResponse(response);
  } catch (error) {
    notifyClients('error', { message: error.message, url: request.url });
    return new Response(JSON.stringify({ error: error.message }), {
      status: 502,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function ensureInitialized() {
  if (state.initialized) {
    return;
  }

  if (state.initPromise) {
    return state.initPromise;
  }

  state.initPromise = initializeSecureChannel();

  try {
    await state.initPromise;
  } finally {
    state.initPromise = null;
  }
}

async function initializeSecureChannel() {
  try {
    notifyClients('status', { stage: 'requesting-attestation' });

    const nonce = crypto.getRandomValues(new Uint8Array(32));

    const response = await fetch(CONFIG.attestationEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ nonce: Array.from(nonce) })
    });

    if (!response.ok) {
      throw new Error(`Attestation request failed: ${response.status}`);
    }

    const jsonResponse = await response.json();
    if (jsonResponse.error) {
      throw new Error(jsonResponse.error);
    }

    const attestationB64 = jsonResponse.attestation_document;
    if (!attestationB64) {
      throw new Error('No attestation document in response');
    }

    const attestationBytes = Uint8Array.from(atob(attestationB64), c => c.charCodeAt(0));

    notifyClients('status', { stage: 'verifying-attestation' });

    const result = await verify(attestationBytes, { nonce });

    if (!result.verified) {
      throw new Error(`Attestation verification failed: ${result.error}`);
    }

    state.attestationResult = result;

    if (!result.userData?.verifying_key) {
      throw new Error('No verifying key in attestation user data');
    }

    state.verifyingKey = new Uint8Array(result.userData.verifying_key);

    notifyClients('status', { stage: 'establishing-channel' });

    await performKeyExchange();

    state.initialized = true;
    state.error = null;
    state.lastKeyRotation = Date.now();

    notifyClients('initialized', {
      pcrs: result.pcrs,
      moduleId: result.moduleId
    });

  } catch (error) {
    state.error = error.message;
    notifyClients('error', { message: error.message, stage: 'initialization' });
    throw error;
  }
}

async function performKeyExchange() {
  const ourKeyPair = await crypto.subtle.generateKey(
    { name: 'X25519' },
    true,
    ['deriveBits']
  );

  const ourPublicKeyRaw = await crypto.subtle.exportKey('raw', ourKeyPair.publicKey);
  const ourPublicKeyBytes = new Uint8Array(ourPublicKeyRaw);

  const nonce = crypto.getRandomValues(new Uint8Array(16));

  const response = await fetch(CONFIG.keyExchangeEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      public_key_bytes: Array.from(ourPublicKeyBytes),
      nonce: Array.from(nonce)
    })
  });

  if (!response.ok) {
    throw new Error(`Key exchange failed: ${response.status}`);
  }

  const data = await response.json();

  const theirPublicKeyBytes = new Uint8Array(data.public_key);
  const signature = new Uint8Array(data.signature);
  state.enclaveEncryptedSharedKey = new Uint8Array(data.enclave_encrypted_shared_key);

  const messageToVerify = new Uint8Array(nonce.length + theirPublicKeyBytes.length);
  messageToVerify.set(nonce, 0);
  messageToVerify.set(theirPublicKeyBytes, nonce.length);

  const verifyingKey = await crypto.subtle.importKey(
    'raw',
    state.verifyingKey,
    { name: 'Ed25519' },
    false,
    ['verify']
  );

  const signatureValid = await crypto.subtle.verify(
    { name: 'Ed25519' },
    verifyingKey,
    signature,
    messageToVerify
  );

  if (!signatureValid) {
    throw new Error('Key exchange signature verification failed');
  }

  const theirPublicKey = await crypto.subtle.importKey(
    'raw',
    theirPublicKeyBytes,
    { name: 'X25519' },
    false,
    []
  );

  const sharedSecret = await crypto.subtle.deriveBits(
    { name: 'X25519', public: theirPublicKey },
    ourKeyPair.privateKey,
    256
  );

  const hkdfKey = await crypto.subtle.importKey(
    'raw',
    sharedSecret,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );

  state.sessionKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode('key') },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function checkKeyRotation() {
  if (!state.lastKeyRotation) return;

  const elapsed = Date.now() - state.lastKeyRotation;
  if (elapsed >= CONFIG.keyRotationInterval) {
    await rotateSessionKey();
  }
}

async function rotateSessionKey() {
  if (!state.initialized || !state.verifyingKey) {
    throw new Error('Cannot rotate key: not initialized');
  }

  notifyClients('status', { stage: 'rotating-key' });

  await performKeyExchange();
  state.lastKeyRotation = Date.now();

  notifyClients('key-rotated', { timestamp: state.lastKeyRotation });
}

async function encryptRequest(request) {
  const url = new URL(request.url);
  const body = await request.arrayBuffer();

  const iv = crypto.getRandomValues(new Uint8Array(12));

  const plaintext = encodeCBOR({
    method: request.method,
    path: url.pathname + url.search,
    headers: Object.fromEntries(request.headers),
    body: body.byteLength > 0 ? new Uint8Array(body) : null
  });

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    state.sessionKey,
    plaintext
  );

  const encryptedBody = new Uint8Array(iv.length + ciphertext.byteLength);
  encryptedBody.set(iv, 0);
  encryptedBody.set(new Uint8Array(ciphertext), iv.length);

  return new Request(url.href, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/octet-stream',
      'X-E2P-Key': btoa(String.fromCharCode(...state.enclaveEncryptedSharedKey)),
      'X-E2P-Original-Method': request.method
    },
    body: encryptedBody
  });
}

async function decryptResponse(response) {
  const encrypted = new Uint8Array(await response.arrayBuffer());

  if (encrypted.length < 12) {
    throw new Error('Invalid encrypted response: too short');
  }

  const iv = encrypted.slice(0, 12);
  const ciphertext = encrypted.slice(12);

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    state.sessionKey,
    ciphertext
  );

  const decoded = decodeCBOR(new Uint8Array(plaintext));
  const bodyBytes = decoded.body instanceof Uint8Array
    ? decoded.body
    : new Uint8Array(0);

  return new Response(bodyBytes, {
    status: decoded.status || 200,
    headers: decoded.headers || {}
  });
}

function resetState() {
  state = {
    sessionKey: null,
    verifyingKey: null,
    enclaveEncryptedSharedKey: null,
    attestationResult: null,
    initialized: false,
    initPromise: null,
    lastKeyRotation: null,
    error: null
  };
}

async function notifyClients(type, data) {
  const allClients = await self.clients.matchAll({ type: 'window' });
  for (const client of allClients) {
    client.postMessage({ type: `enclave:${type}`, ...data });
  }
}
