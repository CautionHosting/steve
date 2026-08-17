import assert from 'node:assert/strict';
import test from 'node:test';
import { encode as encodeCBOR } from 'tee-attestation-js/lib/cbor';
import {
  Direction,
  MessageType,
  SequenceTracker,
  X25519_KEY_EXCHANGE,
  XWING_KEY_EXCHANGE,
  decodeBase64Url,
  decodeEnvelope,
  deriveMaterial,
  encodeEnvelope,
  seal
} from '../src/protocol-v2.js';

// enclave-sw.js is a service-worker script: it calls self.addEventListener()
// at module top-level. Stub the minimal SW globals it needs before import so
// those calls are no-ops instead of throwing in Node.
const cachedResponses = new Map();
const policyMarkers = new Set();
const pcrTrustRecords = new Map();
let cacheOpenError = null;
let cachePutGate = null;
let pcrStorageError = null;
let captureClientMessages = false;
const clientMessages = [];
globalThis.self = {
  addEventListener: () => {},
  location: { origin: 'https://example.test' },
  registration: { scope: 'https://example.test/' },
  clients: {
    matchAll: async () => captureClientMessages
      ? [{ postMessage: message => clientMessages.push(message) }]
      : []
  },
  caches: {
    async open() {
      if (cacheOpenError) throw cacheOpenError;
      return {
        async match(key) {
          return cachedResponses.get(key)?.clone();
        },
        async put(key, response) {
          if (cachePutGate) {
            cachePutGate.enter();
            await cachePutGate.release;
          }
          cachedResponses.set(key, response.clone());
        }
      };
    }
  }
};
globalThis.self.__STEVE_PCR_STORAGE_TEST__ = {
  async isPolicyRequired(scope) {
    if (pcrStorageError) throw pcrStorageError;
    return policyMarkers.has(scope);
  },
  async setPolicyRequired(scope, required) {
    if (pcrStorageError) throw pcrStorageError;
    if (required) policyMarkers.add(scope);
    else policyMarkers.delete(scope);
  },
  async loadOrInsert(key, observed) {
    if (pcrStorageError) throw pcrStorageError;
    if (pcrTrustRecords.has(key)) {
      return { status: 'existing', pcrs: pcrTrustRecords.get(key) };
    }
    pcrTrustRecords.set(key, structuredClone(observed));
    return { status: 'inserted' };
  }
};
globalThis.__STEVE_ENABLE_TEST_HOOKS__ = true;

await import('../src/enclave-sw.js');
const { handleMessage, configure, hasValidSession, resetState, ensureSession, getState, getConfig,
  protocolFetch, readBoundedResponse, resolveProtocolUrl, shouldProtectRequest, resetConfig,
  handleProtectedRequest, protectedSend, withDeadline, ProtocolHttpError, ProtocolTimeoutError,
  ProtocolTransportError,
  isRequestLocalFailure,
  configureAndPersist, configCacheKey, getConfigRestoreError, initializeConfig,
  persistConfig, restoreConfig, lifecycleState, statusMessage, rotateSession,
  finalizePcrTrust,
  errorDetails, isConfigurationReady, getConfigGeneration,
  setEstablishSession, resetEstablishSession } = globalThis.self.__ENCLAVE_SW_TEST__;

const ROTATION_INTERVAL_MS = 25 * 60 * 1000;
const originalFetch = globalThis.fetch;

await initializeConfig();
await configureAndPersist({});

function isProtected(url, init) {
  return shouldProtectRequest(new Request(url, init));
}

test.afterEach(async () => {
  captureClientMessages = false;
  clientMessages.length = 0;
  resetState();
  resetConfig();
  resetEstablishSession();
  cacheOpenError = null;
  cachePutGate = null;
  pcrStorageError = null;
  policyMarkers.clear();
  pcrTrustRecords.clear();
  globalThis.self.registration.scope = 'https://example.test/';
  cachedResponses.clear();
  await initializeConfig();
  await configureAndPersist({});
  globalThis.fetch = originalFetch;
});

test('protocol responses are read within their byte limit', async () => {
  assert.deepEqual(await readBoundedResponse(new Response(null), 4), new Uint8Array());
  assert.deepEqual(
    await readBoundedResponse(new Response(new Uint8Array([1, 2, 3, 4])), 4),
    new Uint8Array([1, 2, 3, 4])
  );
});

test('protocol responses reject declared and streamed overflow', async () => {
  await assert.rejects(
    () => readBoundedResponse(new Response(new Uint8Array([1]), {
      headers: { 'Content-Length': '5' }
    }), 4),
    /protocol response too large/u
  );

  let cancelled = false;
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array([1, 2, 3]));
      controller.enqueue(new Uint8Array([4, 5]));
    },
    cancel() {
      cancelled = true;
    }
  });
  await assert.rejects(
    () => readBoundedResponse(new Response(stream), 4),
    /protocol response too large/u
  );
  assert.equal(cancelled, true);
});

test('configure() cannot drop the /e2p/ protocol prefix', () => {
  configure({ excludePrefixes: ['/attestation'] });
  const excludePrefixes = getConfig().excludePrefixes;
  assert.ok(excludePrefixes.includes('/e2p/'), 'protocol prefix must remain excluded');
  assert.ok(excludePrefixes.includes('/attestation'), 'user-supplied prefix must be kept');
});

test('configure() de-duplicates the forced prefix across repeated calls', () => {
  configure({ excludePrefixes: ['/e2p/', '/foo'] });
  configure({ excludePrefixes: ['/bar'] });
  const excludePrefixes = getConfig().excludePrefixes;
  assert.equal(excludePrefixes.filter(p => p === '/e2p/').length, 1);
  assert.ok(excludePrefixes.includes('/bar'));
});

test('configure() cannot drop capture-proof bootstrap paths', () => {
  configure({ passthroughPaths: ['/custom-bootstrap.js'] });
  const passthroughPaths = getConfig().passthroughPaths;

  for (const path of [
    '/enclave-sw.js',
    '/register.js',
    '/attestation-widget.js',
    '/xwing/steve_xwing_wasm_bg.wasm'
  ]) {
    assert.ok(passthroughPaths.includes(path), `${path} must remain passthrough`);
    assert.equal(isProtected(`https://example.test${path}`), false);
  }
  assert.ok(!passthroughPaths.includes('/'));
  assert.ok(passthroughPaths.includes('/custom-bootstrap.js'));
});

test('built-in bootstrap passthrough is limited to safe methods', () => {
  for (const path of [
    '/enclave-sw.js',
    '/register.js',
    '/attestation-widget.js',
    '/xwing/steve_xwing_wasm_bg.wasm'
  ]) {
    assert.equal(isProtected(`https://example.test${path}`), false);
    assert.equal(isProtected(`https://example.test${path}`, { method: 'HEAD' }), false);
    assert.equal(isProtected(`https://example.test${path}`, { method: 'POST' }), true);
  }
});

test('built-in bootstrap passthrough follows the service worker scope', () => {
  globalThis.self.registration.scope = 'https://example.test/local/';

  for (const path of [
    '/local/enclave-sw.js',
    '/local/register.js',
    '/local/attestation-widget.js',
    '/local/xwing/steve_xwing_wasm_bg.wasm'
  ]) {
    assert.equal(isProtected(`https://example.test${path}`), false);
    assert.equal(isProtected(`https://example.test${path}`, { method: 'HEAD' }), false);
    assert.equal(isProtected(`https://example.test${path}`, { method: 'POST' }), true);
  }
});

test('scope root navigation remains available when persisted config is lost', () => {
  globalThis.self.registration.scope = 'https://example.test/local/';
  const scopedRequest = (method = 'GET') => ({
    url: 'https://example.test/local/',
    method,
    mode: 'navigate',
    destination: 'document'
  });

  assert.equal(shouldProtectRequest(scopedRequest()), false);
  assert.equal(isProtected('https://example.test/local/'), true);
  assert.equal(shouldProtectRequest(scopedRequest('POST')), true);
});

test('configured passthrough paths are limited to safe methods', () => {
  configure({ passthroughPaths: ['/custom-bootstrap.js'] });

  assert.equal(isProtected('https://example.test/custom-bootstrap.js'), false);
  assert.equal(
    isProtected('https://example.test/custom-bootstrap.js', { method: 'HEAD' }),
    false
  );
  assert.equal(
    isProtected('https://example.test/custom-bootstrap.js', { method: 'POST' }),
    true
  );
  assert.equal(
    isProtected('https://example.test/custom-bootstrap.js', { method: 'PUT' }),
    true
  );
});

test('same-origin interception remains the default', () => {
  assert.equal(getConfig().enclaveOrigin, 'https://example.test');
  assert.equal(isProtected('https://example.test/data'), true);
  assert.equal(isProtected('https://example.test/'), true);
  assert.equal(isProtected('https://example.test/', { method: 'POST' }), true);
  assert.equal(
    shouldProtectRequest({
      url: 'https://example.test/',
      method: 'GET',
      mode: 'navigate',
      destination: 'document'
    }),
    false
  );
  assert.equal(isProtected('https://other.test/data'), false);
});

test('cross-origin enclave configuration protects only the enclave origin', () => {
  configure({ enclaveOrigin: 'https://secure.example/' });

  assert.equal(getConfig().enclaveOrigin, 'https://secure.example');
  assert.equal(isProtected('https://secure.example/'), true);
  assert.equal(isProtected('https://secure.example/data?q=1'), true);
  assert.equal(isProtected('https://secure.example/e2p/v2/request'), false);
  assert.equal(isProtected('https://secure.example/attestation'), false);
  assert.equal(isProtected('https://example.test/data'), false);
  assert.equal(isProtected('https://other.test/data'), false);
});

test('configuration survives a service-worker global restart', async () => {
  configure({
    enclaveOrigin: 'https://secure.example',
    requestTimeoutMs: 1234
  });
  await persistConfig();

  resetConfig();
  await restoreConfig();

  assert.equal(getConfig().enclaveOrigin, 'https://secure.example');
  assert.equal(getConfig().requestTimeoutMs, 1234);
});

test('configuration cache entries are isolated by service-worker scope', async () => {
  globalThis.self.registration.scope = 'https://example.test/app-a/';
  await configureAndPersist({ enclaveOrigin: 'https://enclave-a.example' });
  const appAKey = configCacheKey();

  globalThis.self.registration.scope = 'https://example.test/app-b/';
  await configureAndPersist({ enclaveOrigin: 'https://enclave-b.example' });
  const appBKey = configCacheKey();

  assert.notEqual(appAKey, appBKey);

  resetConfig();
  globalThis.self.registration.scope = 'https://example.test/app-a/';
  await restoreConfig();
  assert.equal(getConfig().enclaveOrigin, 'https://enclave-a.example');

  resetConfig();
  globalThis.self.registration.scope = 'https://example.test/app-b/';
  await restoreConfig();
  assert.equal(getConfig().enclaveOrigin, 'https://enclave-b.example');
});

test('a failed config restore leaves bootstrap available and can be repaired', async () => {
  cacheOpenError = new Error('config storage unavailable');
  await initializeConfig();

  assert.match(getConfigRestoreError(), /config storage unavailable/u);
  assert.equal(isProtected('https://example.test/register.js'), false);
  assert.equal(isProtected('https://example.test/application-data'), true);

  cacheOpenError = null;
  await configureAndPersist({ enclaveOrigin: 'https://secure.example' });

  assert.equal(getConfigRestoreError(), null);
  resetConfig();
  await initializeConfig();
  assert.equal(getConfig().enclaveOrigin, 'https://secure.example');
});

test('enclaveOrigin must be an absolute HTTP(S) origin', () => {
  for (const value of [
    '',
    '/relative',
    'ftp://secure.example',
    'https://user@secure.example',
    'https://secure.example/path',
    'https://secure.example?query=1',
    'https://secure.example/#fragment'
  ]) {
    assert.throws(
      () => configure({ enclaveOrigin: value }),
      /absolute HTTP\(S\) origin/
    );
  }
});

test('requestTimeoutMs must be finite and bounded', () => {
  for (const value of [0, 999, 300001, 1.5, Infinity, '30000']) {
    assert.throws(
      () => configure({ requestTimeoutMs: value }),
      /requestTimeoutMs must be an integer between 1000 and 300000/u
    );
  }

  configure({ requestTimeoutMs: 1000 });
  assert.equal(getConfig().requestTimeoutMs, 1000);
  configure({ requestTimeoutMs: 300000 });
  assert.equal(getConfig().requestTimeoutMs, 300000);
});

test('expectedKeyExchange defaults to X25519 and only accepts exact suites', () => {
  assert.equal(getConfig().expectedKeyExchange, X25519_KEY_EXCHANGE);

  configure({ expectedKeyExchange: XWING_KEY_EXCHANGE });
  assert.equal(getConfig().expectedKeyExchange, XWING_KEY_EXCHANGE);
  assert.equal(statusMessage().protocol.keyEstablishment, XWING_KEY_EXCHANGE);

  for (const value of ['x25519', 'XWING', '', null]) {
    assert.throws(
      () => configure({ expectedKeyExchange: value }),
      /unsupported key exchange/u
    );
  }
});

test('PCR policy configuration is strict, normalized, retained when omitted, and explicitly clearable', () => {
  const upper = 'AB'.repeat(48);
  configure({
    pcrPolicy: {
      mode: 'pinned',
      profiles: [{ PCR2: upper, PCR0: upper, PCR1: upper }]
    }
  });
  assert.deepEqual(getConfig().pcrPolicy, {
    mode: 'pinned',
    profiles: [{ PCR0: upper.toLowerCase(), PCR1: upper.toLowerCase(), PCR2: upper.toLowerCase() }]
  });

  configure({ requestTimeoutMs: 1234 });
  assert.equal(getConfig().pcrPolicy.mode, 'pinned');
  configure({ pcrPolicy: null });
  assert.equal(getConfig().pcrPolicy, null);
  assert.throws(
    () => configure({ pcrPolicy: { mode: 'pinned', profiles: [] } }),
    /at least one profile/u
  );
});

test('persisted PCR policy cannot silently downgrade when its cached configuration is lost', async () => {
  const value = '12'.repeat(48);
  await configureAndPersist({
    pcrPolicy: {
      mode: 'pinned',
      profiles: [{ PCR0: value, PCR1: value, PCR2: value }]
    }
  });
  assert.equal(policyMarkers.has('https://example.test/'), true);

  cachedResponses.clear();
  resetConfig();
  await initializeConfig();

  assert.equal(isConfigurationReady(), false);
  assert.match(getConfigRestoreError(), /persisted PCR policy configuration is missing/u);
  await assert.rejects(
    configureAndPersist({}),
    /persisted PCR policy configuration is missing/u
  );
  assert.equal(policyMarkers.has('https://example.test/'), true);

  await configureAndPersist({ pcrPolicy: null });
  assert.equal(isConfigurationReady(), true);
  assert.equal(policyMarkers.has('https://example.test/'), false);
});

test('only explicit pcrPolicy null clears the durable policy marker', async () => {
  const value = '12'.repeat(48);
  await configureAndPersist({
    pcrPolicy: {
      mode: 'pinned',
      profiles: [{ PCR0: value, PCR1: value, PCR2: value }]
    }
  });
  await configureAndPersist({ requestTimeoutMs: 1234 });
  assert.equal(policyMarkers.has('https://example.test/'), true);
  assert.equal(getConfig().pcrPolicy.mode, 'pinned');

  await configureAndPersist({ pcrPolicy: null });
  assert.equal(policyMarkers.has('https://example.test/'), false);
  assert.equal(getConfig().pcrPolicy, null);
});

test('get-pcr-policy waits for policy replacement persistence', async () => {
  const original = '12'.repeat(48);
  const replacement = '13'.repeat(48);
  await configureAndPersist({
    pcrPolicy: {
      mode: 'pinned',
      profiles: [{ PCR0: original, PCR1: original, PCR2: original }]
    }
  });

  let releasePut;
  let markPutEntered;
  const putEntered = new Promise(resolve => { markPutEntered = resolve; });
  cachePutGate = {
    enter: markPutEntered,
    release: new Promise(resolve => { releasePut = resolve; })
  };
  const replacing = configureAndPersist({
    pcrPolicy: {
      mode: 'pinned',
      profiles: [{ PCR0: replacement, PCR1: replacement, PCR2: replacement }]
    }
  });
  await putEntered;

  let response;
  const reading = handleMessage({
    data: { type: 'get-pcr-policy' },
    ports: [{ postMessage: value => { response = value; } }]
  });
  await Promise.resolve();
  assert.equal(response, undefined);

  releasePut();
  await replacing;
  await reading;
  assert.equal(response.success, true);
  assert.equal(response.policy.profiles[0].PCR0, replacement);
});

test('PCR policy storage failure blocks configuration and secure sessions', async () => {
  pcrStorageError = new Error('PCR policy storage failed');
  const value = '12'.repeat(48);

  await assert.rejects(
    configureAndPersist({
      pcrPolicy: {
        mode: 'pinned',
        profiles: [{ PCR0: value, PCR1: value, PCR2: value }]
      }
    }),
    /PCR policy storage failed/u
  );
  assert.equal(isConfigurationReady(), false);
  await assert.rejects(ensureSession(), /PCR policy storage failed/u);
});

test('protocol requests use the configured enclave origin without credentials or cache bypass', async () => {
  configure({ enclaveOrigin: 'https://secure.example' });
  let captured;
  globalThis.fetch = async (url, options) => {
    captured = { url, options };
    return new Response(null, { status: 204 });
  };

  assert.equal(
    resolveProtocolUrl('/e2p/v2/session'),
    'https://secure.example/e2p/v2/session'
  );
  await protocolFetch('/e2p/v2/session', new Uint8Array([1, 2, 3]));

  assert.equal(captured.url, 'https://secure.example/e2p/v2/session');
  assert.equal(captured.options.method, 'POST');
  assert.equal(captured.options.credentials, 'omit');
  assert.equal(captured.options.cache, undefined);
  assert.equal(captured.options.headers['Content-Type'], 'application/cbor');
});

test('withDeadline rejects a never-settling operation', async () => {
  await assert.rejects(
    withDeadline(10, null, () => new Promise(() => {}), 'test deadline expired'),
    error => error instanceof ProtocolTimeoutError
      && error.message === 'test deadline expired'
  );
});

test('external aborts and transient HTTP failures are request-local', async () => {
  const controller = new AbortController();
  const pending = withDeadline(
    1000,
    controller.signal,
    () => new Promise(() => {}),
    'should not time out'
  );
  controller.abort();

  await assert.rejects(pending, error => isRequestLocalFailure(error));
  assert.equal(isRequestLocalFailure(new TypeError('programming error')), false);
  assert.equal(
    isRequestLocalFailure(new ProtocolTransportError(new TypeError('network failure'))),
    true
  );
  assert.equal(isRequestLocalFailure(new ProtocolHttpError(403, 'v2 request')), true);
  assert.equal(isRequestLocalFailure(new ProtocolHttpError(404, 'v2 request')), true);
  assert.equal(isRequestLocalFailure(new ProtocolHttpError(408, 'v2 request')), true);
  assert.equal(isRequestLocalFailure(new ProtocolHttpError(413, 'v2 request')), true);
  assert.equal(isRequestLocalFailure(new ProtocolHttpError(429, 'v2 request')), true);
  assert.equal(isRequestLocalFailure(new ProtocolHttpError(500, 'v2 request')), true);
  assert.equal(isRequestLocalFailure(new ProtocolHttpError(401, 'v2 request')), false);
});

test('withDeadline removes its timer after successful completion', async () => {
  let aborted = false;
  const result = await withDeadline(10, null, signal => {
    signal.addEventListener('abort', () => { aborted = true; }, { once: true });
    return 'complete';
  }, 'should not time out');

  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(result, 'complete');
  assert.equal(aborted, false);
});

test('changing enclaveOrigin discards a session established for the old enclave', async () => {
  setEstablishSession(async () => ({ id: 'session-a', createdAt: Date.now() }));
  await ensureSession();
  assert.equal(getState().session.id, 'session-a');

  configure({ enclaveOrigin: 'https://secure.example' });
  assert.equal(getState().session, null);
});

test('changing PCR policy discards a session established under the old policy', async () => {
  setEstablishSession(async () => ({ id: 'session-a', createdAt: Date.now() }));
  await ensureSession();
  const value = '12'.repeat(48);

  configure({
    pcrPolicy: {
      mode: 'pinned',
      profiles: [{ PCR0: value, PCR1: value, PCR2: value }]
    }
  });

  assert.equal(getState().session, null);
});

test('TOFU finalization reports enrollment then match over the exact configured set', async () => {
  configure({ pcrPolicy: { mode: 'tofu', additionalPcrIndices: [3] } });
  const snapshot = getConfig();
  const generation = getConfigGeneration();
  const targetState = getState();
  const observedPcrs = {
    PCR0: '10'.repeat(48),
    PCR1: '11'.repeat(48),
    PCR2: '12'.repeat(48),
    PCR3: '13'.repeat(48)
  };
  const signal = new AbortController().signal;

  assert.equal(
    await finalizePcrTrust(
      snapshot,
      generation,
      targetState,
      observedPcrs,
      null,
      signal
    ),
    'tofu-enrolled'
  );
  assert.equal(
    await finalizePcrTrust(
      snapshot,
      generation,
      targetState,
      observedPcrs,
      null,
      signal
    ),
    'tofu-matched'
  );
});

test('a configuration update queued before PCR finalization prevents stale enrollment', async () => {
  configure({ pcrPolicy: { mode: 'tofu' } });
  const snapshot = getConfig();
  const generation = getConfigGeneration();
  const targetState = getState();
  const configuration = configureAndPersist({ requestTimeoutMs: 1234 });
  const finalization = finalizePcrTrust(
    snapshot,
    generation,
    targetState,
    {
      PCR0: '10'.repeat(48),
      PCR1: '11'.repeat(48),
      PCR2: '12'.repeat(48)
    },
    null,
    new AbortController().signal
  );

  await configuration;
  await assert.rejects(finalization, /configuration changed during session establishment/u);
  assert.equal(pcrTrustRecords.size, 0);
});

test('structured worker errors have stable code, stage, and optional HTTP status', () => {
  assert.deepEqual(errorDetails(new ProtocolHttpError(429, 'request', 'v2 request')), {
    code: 'HTTP_STATUS',
    stage: 'request',
    message: 'v2 request rejected (429)',
    httpStatus: 429
  });
  assert.deepEqual(errorDetails(new Error('bad rotation'), 'rotation'), {
    code: 'ROTATION_FAILED',
    stage: 'rotation',
    message: 'bad rotation'
  });
});

test('hasValidSession: false for null/undefined session', () => {
  assert.equal(hasValidSession(null), false);
  assert.equal(hasValidSession(undefined), false);
});

test('hasValidSession: true for a freshly created session', () => {
  assert.equal(hasValidSession({ createdAt: Date.now() }), true);
});

test('hasValidSession: false once past the rotation interval', () => {
  const stale = { createdAt: Date.now() - ROTATION_INTERVAL_MS - 1 };
  assert.equal(hasValidSession(stale), false);
});

test('a reset() during in-flight session establishment is not clobbered by the stale promise', async () => {
  let releaseEstablish;
  const pending = new Promise(resolve => { releaseEstablish = resolve; });
  setEstablishSession(() => pending.then(() => ({ id: 'session-a', createdAt: Date.now() })));

  const establishing = ensureSession();

  // Simulate a concurrent 'reset' service-worker message arriving before the
  // in-flight establishSession() call resolves.
  resetState();
  const stateAfterReset = getState();

  releaseEstablish();
  const resolvedSession = await establishing;

  // The promise still resolves with the session it built...
  assert.equal(resolvedSession.id, 'session-a');
  // ...but must not be written back into the (reset) module state, since a
  // newer generation has since taken over.
  assert.equal(getState().session, null);
  assert.equal(getState(), stateAfterReset);
});

test('failed session establishment clears the shared promise for a retry', async () => {
  setEstablishSession(async () => {
    throw new Error('temporary attestation failure');
  });
  await assert.rejects(ensureSession(), /temporary attestation failure/u);
  assert.equal(getState().sessionPromise, null);
  assert.equal(lifecycleState(), 'error');
  assert.equal(statusMessage().stage, null);
  assert.match(statusMessage().error, /temporary attestation failure/u);

  setEstablishSession(async () => ({ id: 'session-b', createdAt: Date.now() }));
  assert.equal((await ensureSession()).id, 'session-b');
});

function diagnosticSession(fill, createdAt = Date.now()) {
  return {
    id: new Uint8Array(16).fill(fill),
    keyExchange: X25519_KEY_EXCHANGE,
    transcriptHash: new Uint8Array(32).fill(fill + 1),
    material: { secretMarker: 'derived-key-material-must-not-appear' },
    createdAt,
    confirmation: 'verified',
    attestation: {
      verified: true,
      profile: 'aws-nitro',
      trustAnchor: 'AWS Nitro root CA',
      synthetic: false,
      pcrs: { PCR0: 'reported-pcr' },
      pcrTrust: 'not-checked',
      moduleId: 'test-module',
      checks: {
        certificateChain: 'verified',
        nonceBinding: 'verified',
        sessionBinding: 'verified',
        keyConfirmation: 'verified',
        expectedPcrPolicy: 'not-checked'
      }
    }
  };
}

test('status reports an idle production verifier without claiming workload policy', () => {
  const status = statusMessage();

  assert.equal(status.state, 'idle');
  assert.equal(status.stage, null);
  assert.equal(status.initialized, false);
  assert.equal(status.session, null);
  assert.equal(status.attestation, null);
  assert.deepEqual(status.protocol, {
    id: 'STEVE-E2P-V2',
    version: 2,
    keyEstablishment: 'X25519',
    keyDerivation: 'HKDF-SHA256',
    recordProtection: 'AES-256-GCM'
  });
  assert.deepEqual(status.attestationVerifier, {
    id: 'aws-nitro',
    trustAnchor: 'AWS Nitro root CA',
    synthetic: false
  });
  assert.equal(status.protocolVersion, 2);
  assert.equal(status.lastKeyRotation, null);
});

test('status tracks eager establishment and exposes only safe session diagnostics', async () => {
  let resolveSession;
  const session = diagnosticSession(3);
  const heldSession = new Promise(resolve => { resolveSession = resolve; });
  setEstablishSession(() => heldSession);

  const pending = ensureSession('explicit-initialize');
  assert.equal(lifecycleState(), 'establishing');
  assert.equal(statusMessage().stage, 'creating-session');

  resolveSession(session);
  await pending;
  const status = statusMessage();
  const serialized = JSON.stringify(status);

  assert.equal(status.state, 'ready');
  assert.equal(status.initialized, true);
  assert.equal(status.session.trigger, 'explicit-initialize');
  assert.equal(status.session.confirmation, 'verified');
  assert.equal(typeof status.session.id, 'string');
  assert.equal(typeof status.session.transcriptHash, 'string');
  assert.equal(status.session.establishedAt, session.createdAt);
  assert.equal(status.session.rotatesAt, session.createdAt + ROTATION_INTERVAL_MS);
  assert.equal(status.attestation.checks.expectedPcrPolicy, 'not-checked');
  assert.equal(status.attestation.pcrTrust, 'not-checked');
  assert.equal(status.lastKeyRotation, session.createdAt);
  assert.equal(serialized.includes('derived-key-material-must-not-appear'), false);
  assert.equal(serialized.includes('secretMarker'), false);
  assert.equal('material' in status.session, false);
});

test('ready status reports the exact established X-Wing suite', async () => {
  const session = {
    ...diagnosticSession(9),
    keyExchange: XWING_KEY_EXCHANGE
  };
  setEstablishSession(async () => session);

  await ensureSession('explicit-initialize');

  assert.equal(
    statusMessage().protocol.keyEstablishment,
    XWING_KEY_EXCHANGE
  );
});

test('status distinguishes lazy establishment and session rotation triggers', async () => {
  setEstablishSession(async () => diagnosticSession(5));
  await ensureSession();
  assert.equal(statusMessage().session.trigger, 'protected-request');

  setEstablishSession(async () => diagnosticSession(7));
  const rotation = rotateSession();
  assert.equal(lifecycleState(), 'rotating');
  assert.equal(statusMessage().stage, 'creating-session');
  await rotation;

  assert.equal(statusMessage().state, 'ready');
  assert.equal(statusMessage().session.trigger, 'rotation');
});

test('failed explicit rotation preserves the previously accepted session', async () => {
  const original = diagnosticSession(5);
  setEstablishSession(async () => original);
  await ensureSession();
  setEstablishSession(async () => {
    throw new Error('PCR policy rejected rotation');
  });

  await assert.rejects(rotateSession(), /PCR policy rejected rotation/u);
  assert.equal(getState().session, original);
  assert.equal(statusMessage().state, 'ready');
});

async function installFakeSession() {
  const session = {
    id: new Uint8Array(16).fill(7),
    material: await deriveMaterial(
      new Uint8Array(32).fill(8),
      new Uint8Array(32).fill(9)
    ),
    sequences: new SequenceTracker(),
    createdAt: Date.now(),
    enclaveOrigin: getConfig().enclaveOrigin,
    configGeneration: getConfigGeneration(),
    keyExchange: X25519_KEY_EXCHANGE,
    attestation: {
      verified: true,
      pcrs: {},
      pcrTrust: 'not-checked',
      moduleId: 'test-module'
    }
  };
  setEstablishSession(async () => session);
  await ensureSession();
  return session;
}

async function validProtocolResponse(
  options,
  session,
  applicationStatus = 200,
  headers = [['content-type', 'text/plain']]
) {
  const requestEnvelope = decodeEnvelope(new Uint8Array(options.body));
  const plaintext = encodeCBOR({
    status: applicationStatus,
    headers,
    body: null,
    error: applicationStatus >= 400 ? 'application rejected' : null
  });
  const ciphertext = await seal(
    session.material,
    Direction.SERVER_TO_CLIENT,
    MessageType.APPLICATION,
    session.id,
    requestEnvelope.sequenceValue,
    plaintext
  );
  return new Response(
    encodeEnvelope(session.id, requestEnvelope.sequenceValue, ciphertext),
    { status: 200, headers: { 'Content-Type': 'application/cbor' } }
  );
}

test('protected responses preserve repeated headers', async () => {
  const session = await installFakeSession();
  globalThis.fetch = (url, options) => validProtocolResponse(
    options,
    session,
    200,
    [['x-repeat', 'one'], ['x-repeat', 'two']]
  );

  const response = await handleProtectedRequest(new Request('https://example.test/headers'));

  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-repeat'), 'one, two');
});

test('protectedSend returns non-secret metadata for the accepted exchange', async () => {
  const session = await installFakeSession();
  let requestEnvelope;
  let responseEnvelope;
  globalThis.fetch = async (url, options) => {
    requestEnvelope = new Uint8Array(options.body);
    const response = await validProtocolResponse(options, session, 201);
    responseEnvelope = new Uint8Array(await response.clone().arrayBuffer());
    return response;
  };

  const result = await protectedSend({
    path: '/items?q=1',
    method: 'POST',
    headers: [['content-type', 'text/plain']],
    body: new TextEncoder().encode('payload')
  });

  assert.equal(result.status, 201);
  assert.equal(result.sessionId.length, 22);
  const requestCiphertext = decodeEnvelope(requestEnvelope).ciphertext;
  const responseCiphertext = decodeEnvelope(responseEnvelope).ciphertext;
  assert.deepEqual(result.exchange, {
    protocolName: 'STEVE-E2P-V2',
    protection: 'AES-256-GCM',
    sessionId: result.sessionId,
    sequence: '1',
    keyExchange: 'X25519',
    pcrTrust: 'not-checked',
    outerStatus: 200,
    requestPlaintextBytes: requestCiphertext.length - 16,
    requestCiphertextBytes: requestCiphertext.length,
    requestEnvelopeBytes: requestEnvelope.length,
    responseEnvelopeBytes: responseEnvelope.length,
    responseCiphertextBytes: responseCiphertext.length,
    responsePlaintextBytes: responseCiphertext.length - 16
  });
  assert.doesNotMatch(JSON.stringify(result.exchange), /payload/u);
});

test('protectedSend reports each sequence and authenticated application error', async () => {
  const session = await installFakeSession();
  globalThis.fetch = (url, options) => validProtocolResponse(options, session, 404);

  const first = await protectedSend({ path: '/missing', headers: [], body: new Uint8Array() });
  const second = await protectedSend({ path: '/missing', headers: [], body: new Uint8Array() });

  assert.equal(first.status, 404);
  assert.equal(first.exchange.sequence, '1');
  assert.equal(second.exchange.sequence, '2');
  assert.equal(first.exchange.sessionId, second.exchange.sessionId);
});

test('protectedSend rejects invalid paths without exchange metadata', async () => {
  await installFakeSession();
  await assert.rejects(
    protectedSend({ path: 'https://other.test/items', headers: [], body: new Uint8Array() }),
    error => error.code === 'INVALID_REQUEST'
      && error.stage === 'request'
      && !Object.hasOwn(error, 'exchange')
  );
});

test('protected responses reject malformed header pairs', async () => {
  const session = await installFakeSession();
  globalThis.fetch = (url, options) => validProtocolResponse(
    options,
    session,
    200,
    [['x-repeat']]
  );

  const response = await handleProtectedRequest(new Request('https://example.test/headers'));

  assert.equal(response.status, 502);
});

test('opt-in wire traces expose encrypted envelopes but not application plaintext', async () => {
  const session = await installFakeSession();
  configure({ emitEncryptedPayloads: true });
  captureClientMessages = true;
  clientMessages.length = 0;
  globalThis.fetch = (url, options) => validProtocolResponse(options, session);

  const response = await handleProtectedRequest(new Request('https://example.test/echo', {
    method: 'POST',
    body: 'manual-debug-secret'
  }));

  assert.equal(response.status, 200);
  const wireEvents = clientMessages.filter(message =>
    ['enclave:encrypted-request', 'enclave:encrypted-response'].includes(message.type)
  );
  assert.equal(wireEvents.length, 2);
  for (const event of wireEvents) {
    assert.equal(event.endpoint, '/e2p/v2/request');
    assert.equal(event.sessionId.length, 22);
    assert.equal(event.sequence, '1');
    assert.equal(decodeBase64Url(event.envelope).length, event.size);
    assert.doesNotMatch(JSON.stringify(event), /manual-debug-secret/u);
  }
  assert.equal(
    decodeEnvelope(decodeBase64Url(wireEvents[0].envelope)).sequenceValue,
    1n
  );
});

test('a transient request failure does not poison a concurrent sibling', async () => {
  const session = await installFakeSession();
  let calls = 0;
  let rejectFirst;
  const firstFetch = new Promise((_, reject) => { rejectFirst = reject; });
  globalThis.fetch = async (url, options) => {
    calls += 1;
    if (calls === 1) return firstFetch;
    const response = await validProtocolResponse(options, session);
    rejectFirst(new TypeError('transient network failure'));
    return response;
  };

  const responses = await Promise.all([
    handleProtectedRequest(new Request('https://example.test/first')),
    handleProtectedRequest(new Request('https://example.test/second'))
  ]);

  assert.deepEqual(responses.map(response => response.status).sort(), [200, 502]);
  assert.equal(getState().session, session);
  assert.equal(await session.sequences.allocate(), 3n);
});

test('outer 413 retires only the oversized request', async () => {
  const session = await installFakeSession();
  let calls = 0;
  let resolveOversized;
  let markOversizedStarted;
  let markSiblingStarted;
  const oversizedStarted = new Promise(resolve => { markOversizedStarted = resolve; });
  const siblingStarted = new Promise(resolve => { markSiblingStarted = resolve; });
  const oversizedResponse = new Promise(resolve => { resolveOversized = resolve; });
  globalThis.fetch = async (url, options) => {
    calls += 1;
    if (calls === 1) {
      markOversizedStarted();
      return oversizedResponse;
    }
    markSiblingStarted();
    return validProtocolResponse(options, session);
  };

  const oversizedPromise = handleProtectedRequest(
    new Request('https://example.test/oversized')
  );
  await oversizedStarted;
  const siblingPromise = handleProtectedRequest(
    new Request('https://example.test/sibling')
  );
  await siblingStarted;
  resolveOversized(new Response(null, { status: 413 }));
  const [oversized, sibling] = await Promise.all([oversizedPromise, siblingPromise]);

  assert.equal(oversized.status, 502);
  assert.equal(sibling.status, 200);
  assert.equal(getState().session, session);
  assert.equal(await session.sequences.allocate(), 3n);
});

test('retiring a failed oldest request unblocks the 64-entry request window', async () => {
  const session = await installFakeSession();
  let rejectFirst;
  const firstFetch = new Promise((_, reject) => { rejectFirst = reject; });
  globalThis.fetch = async (url, options) => {
    const sequence = decodeEnvelope(new Uint8Array(options.body)).sequenceValue;
    if (sequence === 1n) return firstFetch;
    const response = await validProtocolResponse(options, session);
    if (sequence === 64n) {
      queueMicrotask(() => rejectFirst(new TypeError('oldest request failed')));
    }
    return response;
  };

  const responses = await Promise.all(
    Array.from(
      { length: 65 },
      (_, index) => handleProtectedRequest(
        new Request(`https://example.test/request-${index + 1}`)
      )
    )
  );

  assert.equal(responses.filter(response => response.status === 502).length, 1);
  assert.equal(responses.filter(response => response.status === 200).length, 64);
  assert.equal(getState().session, session);
  assert.equal(await session.sequences.allocate(), 66n);
});

test('a hung protected fetch times out without resetting the session', async () => {
  const session = await installFakeSession();
  configure({ requestTimeoutMs: 1000 });
  globalThis.fetch = () => new Promise(() => {});

  const response = await handleProtectedRequest(
    new Request('https://example.test/hung')
  );

  assert.equal(response.status, 504);
  assert.equal(getState().session, session);
  assert.equal(await session.sequences.allocate(), 2n);
});

test('outer 500 is request-local but invalid-session 401 resets the session', async () => {
  const session = await installFakeSession();
  globalThis.fetch = async () => new Response(null, { status: 500 });
  const transient = await handleProtectedRequest(
    new Request('https://example.test/transient')
  );

  assert.equal(transient.status, 502);
  assert.equal(getState().session, session);

  globalThis.fetch = async () => new Response(null, { status: 401 });
  const fatal = await handleProtectedRequest(
    new Request('https://example.test/invalid-session')
  );

  assert.equal(fatal.status, 502);
  assert.equal(getState().session, null);
  assert.throws(
    () => session.sequences.accept(2n, 2n),
    /v2 request rejected \(401\)/u
  );
});

test('an encrypted application 401 does not reset the secure session', async () => {
  const session = await installFakeSession();
  globalThis.fetch = (url, options) => validProtocolResponse(options, session, 401);

  const response = await handleProtectedRequest(
    new Request('https://example.test/application-unauthorized')
  );

  assert.equal(response.status, 401);
  assert.equal(getState().session, session);
});

test('an invalid protected response resets the secure session', async () => {
  const session = await installFakeSession();
  captureClientMessages = true;
  globalThis.fetch = async () => new Response(new Uint8Array([0]), { status: 200 });

  const response = await handleProtectedRequest(
    new Request('https://example.test/invalid-response?token=secret')
  );

  assert.equal(response.status, 502);
  assert.equal(getState().session, null);
  const errorMessage = clientMessages.find(message => message.type === 'enclave:error');
  assert.equal(errorMessage.url, 'https://example.test/invalid-response');
  assert.equal(errorMessage.operation, 'request');
  assert.throws(
    () => session.sequences.accept(1n, 1n),
    /unsupported envelope version/u
  );
});

test('session establishment errors identify the initialization operation', async () => {
  captureClientMessages = true;
  const mismatch = new Error('attested PCRs did not match');
  mismatch.code = 'PCR_POLICY_MISMATCH';
  mismatch.stage = 'pcr-policy';
  setEstablishSession(async () => { throw mismatch; });

  const response = await handleProtectedRequest(
    new Request('https://example.test/initialization-failure')
  );

  assert.equal(response.status, 502);
  const errorMessage = clientMessages.find(message => message.type === 'enclave:error');
  assert.equal(errorMessage.operation, 'initialization');
  assert.equal(errorMessage.code, 'PCR_POLICY_MISMATCH');
  assert.equal(errorMessage.stage, 'pcr-policy');
});

test('an oversized protected response resets the secure session', async () => {
  const session = await installFakeSession();
  globalThis.fetch = async () => new Response(new Uint8Array([0]), {
    status: 200,
    headers: { 'Content-Length': String(32 * 1024 * 1024 + 64 * 1024 + 1) }
  });

  const response = await handleProtectedRequest(
    new Request('https://example.test/oversized-response')
  );

  assert.equal(response.status, 502);
  assert.equal(getState().session, null);
  assert.throws(
    () => session.sequences.accept(1n, 1n),
    /protocol response too large/u
  );
});
