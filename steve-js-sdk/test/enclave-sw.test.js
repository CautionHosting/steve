import assert from 'node:assert/strict';
import test from 'node:test';
import { encode as encodeCBOR } from 'tee-attestation-js/lib/cbor';
import {
  Direction,
  MessageType,
  SequenceTracker,
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
let cacheOpenError = null;
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
          cachedResponses.set(key, response.clone());
        }
      };
    }
  }
};

await import('../src/enclave-sw.js');
const { configure, hasValidSession, resetState, ensureSession, getState, getConfig,
  protocolFetch, resolveProtocolUrl, shouldProtectUrl, resetConfig,
  handleProtectedRequest, withDeadline, ProtocolHttpError, ProtocolTimeoutError,
  ProtocolTransportError,
  isRequestLocalFailure,
  configureAndPersist, configCacheKey, getConfigRestoreError, initializeConfig,
  persistConfig, restoreConfig, lifecycleState, statusMessage, rotateSession,
  setEstablishSession, resetEstablishSession } = globalThis.self.__ENCLAVE_SW_TEST__;

const ROTATION_INTERVAL_MS = 25 * 60 * 1000;
const originalFetch = globalThis.fetch;

test.afterEach(async () => {
  captureClientMessages = false;
  clientMessages.length = 0;
  resetState();
  resetConfig();
  resetEstablishSession();
  cacheOpenError = null;
  globalThis.self.registration.scope = 'https://example.test/';
  cachedResponses.clear();
  await initializeConfig();
  globalThis.fetch = originalFetch;
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

  for (const path of ['/', '/enclave-sw.js', '/register.js', '/attestation-widget.js']) {
    assert.ok(passthroughPaths.includes(path), `${path} must remain passthrough`);
    assert.equal(shouldProtectUrl(`https://example.test${path}`), false);
  }
  assert.ok(passthroughPaths.includes('/custom-bootstrap.js'));
});

test('same-origin interception remains the default', () => {
  assert.equal(getConfig().enclaveOrigin, 'https://example.test');
  assert.equal(shouldProtectUrl('https://example.test/data'), true);
  assert.equal(shouldProtectUrl('https://example.test/'), false);
  assert.equal(shouldProtectUrl('https://other.test/data'), false);
});

test('cross-origin enclave configuration protects only the enclave origin', () => {
  configure({ enclaveOrigin: 'https://secure.example/' });

  assert.equal(getConfig().enclaveOrigin, 'https://secure.example');
  assert.equal(shouldProtectUrl('https://secure.example/'), true);
  assert.equal(shouldProtectUrl('https://secure.example/data?q=1'), true);
  assert.equal(shouldProtectUrl('https://secure.example/e2p/v2/request'), false);
  assert.equal(shouldProtectUrl('https://secure.example/attestation'), false);
  assert.equal(shouldProtectUrl('https://example.test/data'), false);
  assert.equal(shouldProtectUrl('https://other.test/data'), false);
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
  assert.equal(shouldProtectUrl('https://example.test/register.js'), false);
  assert.equal(shouldProtectUrl('https://example.test/application-data'), true);

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

test('protocol requests use the configured enclave origin without credentials', async () => {
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
  assert.equal(status.lastKeyRotation, session.createdAt);
  assert.equal(serialized.includes('derived-key-material-must-not-appear'), false);
  assert.equal(serialized.includes('secretMarker'), false);
  assert.equal('material' in status.session, false);
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

async function installFakeSession() {
  const session = {
    id: new Uint8Array(16).fill(7),
    material: await deriveMaterial(
      new Uint8Array(32).fill(8),
      new Uint8Array(32).fill(9)
    ),
    sequences: new SequenceTracker(),
    createdAt: Date.now(),
    attestation: { verified: true, pcrs: {}, moduleId: 'test-module' }
  };
  setEstablishSession(async () => session);
  await ensureSession();
  return session;
}

async function validProtocolResponse(options, session, applicationStatus = 200) {
  const requestEnvelope = decodeEnvelope(new Uint8Array(options.body));
  const plaintext = encodeCBOR({
    status: applicationStatus,
    headers: { 'content-type': 'text/plain' },
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

  const [failed, succeeded] = await Promise.all([
    handleProtectedRequest(new Request('https://example.test/first')),
    handleProtectedRequest(new Request('https://example.test/second'))
  ]);

  assert.equal(failed.status, 502);
  assert.equal(succeeded.status, 200);
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
  globalThis.fetch = async () => new Response(new Uint8Array([0]), { status: 200 });

  const response = await handleProtectedRequest(
    new Request('https://example.test/invalid-response')
  );

  assert.equal(response.status, 502);
  assert.equal(getState().session, null);
  assert.throws(
    () => session.sequences.accept(1n, 1n),
    /unsupported envelope version/u
  );
});
